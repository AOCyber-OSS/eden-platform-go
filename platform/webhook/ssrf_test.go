package webhook_test

import (
	"context"
	"errors"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/google/uuid"
	"go.aocyber.ai/eden-platform-go/platform/webhook"
)

// hostResolver is a hand-built stub resolver: host -> fixed IPs.
type hostResolver map[string][]string

func (r hostResolver) LookupIPAddr(_ context.Context, host string) ([]net.IPAddr, error) {
	ips, ok := r[host]
	if !ok {
		return nil, &net.DNSError{Err: "no such host", Name: host, IsNotFound: true}
	}
	out := make([]net.IPAddr, 0, len(ips))
	for _, s := range ips {
		out = append(out, net.IPAddr{IP: net.ParseIP(s)})
	}
	return out, nil
}

// secretServer stands in for an internal service / metadata endpoint: it
// counts hits and answers with a body that must never be stored.
func secretServer(t *testing.T, tls bool) (*httptest.Server, *int32) {
	t.Helper()
	var hits int32
	h := http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		atomic.AddInt32(&hits, 1)
		_, _ = w.Write([]byte("internal-secret"))
	})
	var srv *httptest.Server
	if tls {
		srv = httptest.NewTLSServer(h)
	} else {
		srv = httptest.NewServer(h)
	}
	t.Cleanup(srv.Close)
	return srv, &hits
}

func srvPort(t *testing.T, srv *httptest.Server) string {
	t.Helper()
	_, p, err := net.SplitHostPort(srv.Listener.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	return p
}

// onlyDelivery triggers one event and returns the resulting delivery row.
func onlyDelivery(t *testing.T, svc *webhook.Service, store *memStore, companyID uuid.UUID) webhook.WebhookDelivery {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	if err := svc.Trigger(ctx, companyID, "test.event", `{"x":1}`); err != nil {
		t.Fatalf("Trigger: %v", err)
	}
	if err := svc.Shutdown(ctx); err != nil {
		t.Fatalf("Shutdown: %v", err)
	}
	store.mu.Lock()
	defer store.mu.Unlock()
	if len(store.deliveries) != 1 {
		t.Fatalf("deliveries = %d, want 1", len(store.deliveries))
	}
	for _, d := range store.deliveries {
		return d
	}
	return webhook.WebhookDelivery{}
}

func assertBlockedDelivery(t *testing.T, d webhook.WebhookDelivery, hits *int32) {
	t.Helper()
	if n := atomic.LoadInt32(hits); n != 0 {
		t.Fatalf("internal target got %d hits, want 0", n)
	}
	if d.Status == "success" {
		t.Fatalf("delivery status = success, want a failure")
	}
	if strings.Contains(d.ResponseBody, "internal-secret") {
		t.Fatalf("internal response body was stored: %q", d.ResponseBody)
	}
	// The failure must be the egress policy, not an incidental network
	// error (an unresolvable name or a timeout would also mean 0 hits).
	if !strings.Contains(d.ResponseBody, "blocked by egress policy") && !strings.Contains(d.ResponseBody, "disallowed target URL") {
		t.Fatalf("delivery failed for a non-policy reason: %q", d.ResponseBody)
	}
}

func TestRegister_RejectsUnsafeURLs(t *testing.T) {
	for _, raw := range []string{
		"", "not a url", "://missing-scheme", "ftp://example.com/hook", "file:///etc/passwd",
		"http://hooks.example.com/plain-http", // https only
		"https://127.0.0.1/hook", "https://localhost/hook", "https://api.localhost/hook",
		"https://10.0.0.5/hook", "https://172.16.3.4/hook", "https://192.168.1.10/hook",
		"https://169.254.169.254/latest/meta-data/", "https://metadata.google.internal/computeMetadata/v1/",
		"https://[::1]/hook", "https://[fd00::1]/hook", "https://[fe80::1]/hook", "https://[::ffff:10.0.0.1]/hook",
		"https:///no-host",
	} {
		store := newMemStore()
		svc := webhook.NewService(store)
		_, err := svc.Register(context.Background(), uuid.New(), raw, "s", []string{"*"})
		if !errors.Is(err, webhook.ErrInvalidURL) {
			t.Errorf("Register(%q) = %v, want ErrInvalidURL", raw, err)
		}
		if n := len(store.hooks); n != 0 {
			t.Errorf("Register(%q) stored %d webhooks, want 0", raw, n)
		}
	}
}

func TestRegister_AcceptsPublicHTTPS(t *testing.T) {
	store := newMemStore()
	svc := webhook.NewService(store)
	// No DNS at register time: the address is checked when delivery dials.
	wh, err := svc.Register(context.Background(), uuid.New(), "https://hooks.example.com/eden?x=1", "s", []string{"*"})
	if err != nil {
		t.Fatalf("Register = %v, want nil", err)
	}
	if wh.URL != "https://hooks.example.com/eden?x=1" {
		t.Fatalf("stored URL %q", wh.URL)
	}
}

func TestDeliver_HostnameResolvingToLoopbackIsBlocked(t *testing.T) {
	inner, hits := secretServer(t, true)
	store := newMemStore()
	svc := webhook.NewService(store, webhook.WithResolver(hostResolver{"internal.example": {"127.0.0.1"}}))
	companyID := uuid.New()
	if _, err := svc.Register(context.Background(), companyID, "https://internal.example:"+srvPort(t, inner)+"/hook", "s", []string{"*"}); err != nil {
		t.Fatalf("Register: %v", err)
	}
	assertBlockedDelivery(t, onlyDelivery(t, svc, store, companyID), hits)
}

// TestDeliver_RevalidatesStoredURL covers rows written before Register
// validated anything: delivery must refuse them too.
func TestDeliver_RevalidatesStoredURL(t *testing.T) {
	inner, hits := secretServer(t, false)
	store := newMemStore()
	companyID := uuid.New()
	if _, err := store.CreateWebhook(context.Background(), companyID, inner.URL+"/legacy", "s", []string{"*"}); err != nil {
		t.Fatal(err)
	}
	svc := webhook.NewService(store)
	assertBlockedDelivery(t, onlyDelivery(t, svc, store, companyID), hits)
}

func TestDeliver_RedirectToPrivateIsBlocked(t *testing.T) {
	inner, innerHits := secretServer(t, true)
	for name, target := range map[string]string{
		"private_literal":       "https://169.254.169.254/latest/meta-data/",
		"name_resolving_inside": "https://internal.example:" + srvPort(t, inner) + "/admin",
		"loopback_literal":      "https://127.0.0.2:" + srvPort(t, inner) + "/admin",
	} {
		t.Run(name, func(t *testing.T) {
			outer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				http.Redirect(w, r, target, http.StatusTemporaryRedirect)
			}))
			defer outer.Close()

			store := newMemStore()
			svc := webhook.NewService(store,
				webhook.WithInsecureTargets("127.0.0.1"), // the first hop only
				webhook.WithResolver(hostResolver{"internal.example": {"127.0.0.1"}}),
			)
			companyID := uuid.New()
			if _, err := svc.Register(context.Background(), companyID, outer.URL+"/hook", "s", []string{"*"}); err != nil {
				t.Fatalf("Register: %v", err)
			}
			assertBlockedDelivery(t, onlyDelivery(t, svc, store, companyID), innerHits)
		})
	}
}

func TestInsecureTargets_OptInDeliversToListedHostOnly(t *testing.T) {
	var hits int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		atomic.AddInt32(&hits, 1)
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	store := newMemStore()
	svc := webhook.NewService(store, webhook.WithInsecureTargets("127.0.0.1"))
	companyID := uuid.New()
	if _, err := svc.Register(context.Background(), companyID, srv.URL+"/hook", "s", []string{"*"}); err != nil {
		t.Fatalf("Register (listed host) = %v", err)
	}
	if d := onlyDelivery(t, svc, store, companyID); d.Status != "success" || atomic.LoadInt32(&hits) != 1 {
		t.Fatalf("delivery = %+v hits=%d, want success with 1 hit", d, hits)
	}
	if _, err := svc.Register(context.Background(), companyID, "http://10.0.0.1/hook", "s", []string{"*"}); !errors.Is(err, webhook.ErrInvalidURL) {
		t.Fatalf("Register (unlisted private host) = %v, want ErrInvalidURL", err)
	}
}
