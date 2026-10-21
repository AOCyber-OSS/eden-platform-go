package main

import (
	"context"
	"encoding/json"
	"io"
	"net"
	"net/http"
	"testing"
	"time"

	"go.aocyber.ai/eden-platform-go/internal/aoid/composition"
	"go.aocyber.ai/eden-platform-go/internal/aoid/config"
	"go.aocyber.ai/eden-platform-go/internal/aoid/discovery"
	"go.aocyber.ai/eden-platform-go/internal/aoid/fixtures"
	"go.aocyber.ai/eden-platform-go/internal/aoid/jwks"
	"go.aocyber.ai/eden-platform-go/internal/aoid/server"
)

// TestBootService_FullStack boots the full aoid HTTP service via the
// production wiring (composition + fixtures + AddRoutes) and asserts
// every well-known + issuer-stub endpoint replies as documented. This
// is the integration check for 29-03 that the boot code threads
// composition.Services through the routes correctly.
func TestBootService_FullStack(t *testing.T) {
	cfg := &config.Config{
		ListenAddr:      ":0",
		Issuer:          "http://aoid-boot.test",
		ShutdownTimeout: time.Second,
	}

	svcs, err := composition.BuildInMemory(cfg)
	if err != nil {
		t.Fatalf("BuildInMemory: %v", err)
	}
	t.Cleanup(func() { _ = svcs.Close() })

	if _, err := fixtures.Seed(context.Background(), svcs); err != nil {
		t.Fatalf("Seed: %v", err)
	}

	srv := server.New(cfg)
	srv.AddRoutes(func(mux *http.ServeMux) {
		mux.HandleFunc("/.well-known/openid-configuration", discovery.Handler(cfg))
		mux.HandleFunc("/oauth2/token", discovery.IssuerNotActive)
		mux.HandleFunc("/oauth2/authorize", discovery.IssuerNotActive)
		mux.HandleFunc("/oauth2/userinfo", discovery.IssuerNotActive)
		mux.HandleFunc("/.well-known/jwks.json", jwks.Handler(svcs.JWTManager))
	})

	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- srv.Start(ctx, ln) }()

	// The test's own transport, so the cleanup can close every connection
	// it holds before the server shuts down.
	tr := http.DefaultTransport.(*http.Transport).Clone()
	client := &http.Client{Transport: tr, Timeout: 5 * time.Second}
	t.Cleanup(func() {
		// Close the client's connections first. The transport can dial a
		// spare connection that never carries a request: a Body.Close before
		// EOF returns its connection to the pool only after a background
		// drain, so the next request finds no idle connection and dials one.
		// The server sees the spare as StateNew, which http.Server.Shutdown
		// treats as idle only once it is 5s old, so it outlives the 1s
		// ShutdownTimeout and Shutdown returns context.DeadlineExceeded (a
		// -race and load sensitive flake; runForTest in internal/aoid/server
		// had the same one).
		tr.CloseIdleConnections()
		cancel()
		select {
		case err := <-done:
			if err != nil {
				t.Errorf("server: %v", err)
			}
		case <-time.After(3 * time.Second):
			t.Error("shutdown timeout")
		}
	})

	base := "http://" + ln.Addr().String()
	// get reads the body to EOF before closing it, so the connection is back
	// in the pool before the next request starts (no spare dial).
	get := func(t *testing.T, path string) (int, []byte) {
		t.Helper()
		r, err := client.Get(base + path)
		if err != nil {
			t.Fatalf("get %s: %v", path, err)
		}
		defer r.Body.Close()
		body, err := io.ReadAll(r.Body)
		if err != nil {
			t.Fatalf("read %s: %v", path, err)
		}
		return r.StatusCode, body
	}

	deadline := time.Now().Add(2 * time.Second)
	for {
		r, err := client.Get(base + "/readyz")
		if err == nil {
			_, _ = io.Copy(io.Discard, r.Body)
			r.Body.Close()
			if r.StatusCode == http.StatusOK {
				break
			}
		}
		if time.Now().After(deadline) {
			t.Fatal("readyz never returned 200")
		}
		time.Sleep(20 * time.Millisecond)
	}

	t.Run("discovery", func(t *testing.T) {
		_, body := get(t, "/.well-known/openid-configuration")
		var doc map[string]any
		if err := json.Unmarshal(body, &doc); err != nil {
			t.Fatalf("decode: %v", err)
		}
		if doc["service_status"] != "scaffold" {
			t.Errorf("service_status = %v", doc["service_status"])
		}
		if doc["issuer"] != "http://aoid-boot.test" {
			t.Errorf("issuer = %v", doc["issuer"])
		}
	})

	t.Run("jwks", func(t *testing.T) {
		_, body := get(t, "/.well-known/jwks.json")
		var set struct {
			Keys []map[string]any `json:"keys"`
		}
		if err := json.Unmarshal(body, &set); err != nil {
			t.Fatalf("decode: %v", err)
		}
		if len(set.Keys) < 1 {
			t.Errorf("expected >=1 key, got %d", len(set.Keys))
		}
	})

	t.Run("issuer_endpoints_503", func(t *testing.T) {
		for _, p := range []string{"/oauth2/token", "/oauth2/authorize", "/oauth2/userinfo"} {
			status, body := get(t, p)
			if status != http.StatusServiceUnavailable {
				t.Errorf("%s status=%d body=%s", p, status, body)
			}
		}
	})
}
