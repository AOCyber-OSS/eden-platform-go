package webfetch

import (
	"context"
	"errors"
	"net"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"
)

// mapResolver is a hand-built stub resolver: host -> fixed answer, or error.
type mapResolver struct {
	ips  map[string][]string
	errs map[string]error
}

func (r mapResolver) LookupIPAddr(_ context.Context, host string) ([]net.IPAddr, error) {
	if err, ok := r.errs[host]; ok {
		return nil, err
	}
	ips, ok := r.ips[host]
	if !ok {
		return nil, &net.DNSError{Err: "no such host", Name: host, IsNotFound: true}
	}
	out := make([]net.IPAddr, 0, len(ips))
	for _, s := range ips {
		out = append(out, net.IPAddr{IP: net.ParseIP(s)})
	}
	return out, nil
}

// countingServer is an httptest server on 127.0.0.1 that counts hits.
func countingServer(t *testing.T, h http.HandlerFunc) (*httptest.Server, *int32) {
	t.Helper()
	var hits int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		atomic.AddInt32(&hits, 1)
		if h != nil {
			h(w, r)
			return
		}
		_, _ = w.Write([]byte("internal-secret"))
	}))
	t.Cleanup(srv.Close)
	return srv, &hits
}

func port(t *testing.T, srv *httptest.Server) string {
	t.Helper()
	_, p, err := net.SplitHostPort(srv.Listener.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	return p
}

func TestFetch_LookupFailureIsPolicyViolation(t *testing.T) {
	p := SafeDefault()
	p.Resolver = mapResolver{errs: map[string]error{"flaky.example": errors.New("stub SERVFAIL")}}
	c, err := NewClient(p)
	if err != nil {
		t.Fatal(err)
	}
	_, err = c.Fetch(context.Background(), "http://flaky.example/")
	if !errors.Is(err, ErrPolicyViolation) {
		t.Fatalf("Fetch = %v, want ErrPolicyViolation (lookup failure must fail closed)", err)
	}
}

func TestFetch_HostnameResolvingToLoopbackIsBlockedAtDial(t *testing.T) {
	srv, hits := countingServer(t, nil)
	p := SafeDefault()
	p.Resolver = mapResolver{ips: map[string][]string{"rebind.example": {"127.0.0.1"}}}
	c, _ := NewClient(p)

	_, err := c.Fetch(context.Background(), "http://rebind.example:"+port(t, srv)+"/")
	if !errors.Is(err, ErrPolicyViolation) {
		t.Fatalf("Fetch = %v, want ErrPolicyViolation", err)
	}
	if n := atomic.LoadInt32(hits); n != 0 {
		t.Fatalf("loopback server got %d hits, want 0", n)
	}
}

func TestFetch_RedirectToHostResolvingToMetadataIsBlocked(t *testing.T) {
	inner, innerHits := countingServer(t, nil)
	outer, _ := countingServer(t, func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, "http://metadata.rebind.example:"+port(t, inner)+"/latest/meta-data/", http.StatusFound)
	})
	p := SafeDefault()
	p.AllowHostsRegexp = []string{`^127\.0\.0\.1$`} // the first hop only
	p.Resolver = mapResolver{ips: map[string][]string{"metadata.rebind.example": {"169.254.169.254"}}}
	c, _ := NewClient(p)

	_, err := c.Fetch(context.Background(), outer.URL+"/start")
	if !errors.Is(err, ErrPolicyViolation) {
		t.Fatalf("Fetch = %v, want ErrPolicyViolation on redirect to metadata", err)
	}
	if n := atomic.LoadInt32(innerHits); n != 0 {
		t.Fatalf("redirect target got %d hits, want 0", n)
	}
}

func TestFetch_RedirectToPrivateLiteralIsBlocked(t *testing.T) {
	outer, _ := countingServer(t, func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, "http://10.0.0.1/admin", http.StatusFound)
	})
	p := SafeDefault()
	p.AllowHostsRegexp = []string{`^127\.0\.0\.1$`}
	c, _ := NewClient(p)
	if _, err := c.Fetch(context.Background(), outer.URL); !errors.Is(err, ErrPolicyViolation) {
		t.Fatalf("Fetch = %v, want ErrPolicyViolation", err)
	}
}

func TestFetch_BlocksIPv6Literals(t *testing.T) {
	c, _ := NewClient(SafeDefault())
	for _, target := range []string{
		"http://[::1]/", "http://[fd00::1]/", "http://[fe80::1]/", "http://[::ffff:127.0.0.1]/", "http://[::ffff:169.254.169.254]/",
	} {
		if _, err := c.Fetch(context.Background(), target); !errors.Is(err, ErrPolicyViolation) {
			t.Errorf("Fetch(%s) = %v, want ErrPolicyViolation", target, err)
		}
	}
}
