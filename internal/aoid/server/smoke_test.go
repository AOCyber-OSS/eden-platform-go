package server_test

// End-to-end smoke test that boots the full aoid HTTP service, exercises
// every public endpoint, and tears it down cleanly. Provides the same
// coverage as the CI smoke step but inside `go test ./...` so local
// developers catch regressions without needing Docker.

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

func TestSmoke_FullService(t *testing.T) {
	cfg := &config.Config{
		Issuer:             "http://aoid-smoke.test",
		AccessTokenExpiry:  15 * time.Minute,
		RefreshTokenExpiry: 7 * 24 * time.Hour,
		ShutdownTimeout:    2 * time.Second,
		Release:            "smoke",
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
	client := &http.Client{Transport: tr, Timeout: 2 * time.Second}
	t.Cleanup(func() {
		// Close the client's connections first. The transport can dial a
		// spare connection that never carries a request: a Body.Close before
		// EOF returns its connection to the pool only after a background
		// drain, so the next request finds no idle connection and dials one.
		// The server sees the spare as StateNew, which http.Server.Shutdown
		// treats as idle only once it is 5s old, so it outlives the 2s
		// ShutdownTimeout and Shutdown returns context.DeadlineExceeded (a
		// -race and load sensitive flake; runForTest had the same one).
		tr.CloseIdleConnections()
		cancel()
		select {
		case err := <-done:
			if err != nil {
				t.Errorf("server error: %v", err)
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
			t.Fatalf("readyz never returned 200; last err=%v", err)
		}
		time.Sleep(20 * time.Millisecond)
	}

	t.Run("healthz", func(t *testing.T) {
		status, raw := get(t, "/healthz")
		if status != http.StatusOK {
			t.Errorf("status = %d", status)
		}
		var body map[string]any
		if err := json.Unmarshal(raw, &body); err != nil {
			t.Errorf("decode: %v", err)
		}
		if body["status"] == nil {
			t.Errorf("missing status field")
		}
	})

	t.Run("discovery", func(t *testing.T) {
		status, body := get(t, "/.well-known/openid-configuration")
		if status != http.StatusOK {
			t.Errorf("status = %d", status)
		}
		var doc map[string]any
		if err := json.Unmarshal(body, &doc); err != nil {
			t.Fatalf("decode: %v", err)
		}
		if doc["service_status"] != "scaffold" {
			t.Errorf("service_status = %v", doc["service_status"])
		}
		if doc["issuer"] != "http://aoid-smoke.test" {
			t.Errorf("issuer = %v", doc["issuer"])
		}
		if doc["jwks_uri"] == nil {
			t.Errorf("jwks_uri missing")
		}
	})

	t.Run("jwks_has_keys", func(t *testing.T) {
		status, body := get(t, "/.well-known/jwks.json")
		if status != http.StatusOK {
			t.Errorf("status = %d", status)
		}
		var set struct {
			Keys []map[string]any `json:"keys"`
		}
		if err := json.Unmarshal(body, &set); err != nil {
			t.Fatalf("decode: %v", err)
		}
		if len(set.Keys) < 1 {
			t.Errorf("expected at least 1 key, got %d", len(set.Keys))
		}
		if set.Keys[0]["alg"] != "ML-DSA-65" {
			t.Errorf("alg = %v", set.Keys[0]["alg"])
		}
	})

	t.Run("issuer_endpoints_503", func(t *testing.T) {
		for _, path := range []string{"/oauth2/token", "/oauth2/authorize", "/oauth2/userinfo"} {
			status, body := get(t, path)
			if status != http.StatusServiceUnavailable {
				t.Errorf("%s status = %d", path, status)
			}
			var b map[string]string
			if err := json.Unmarshal(body, &b); err != nil {
				t.Errorf("decode %s: %v", path, err)
			}
			if b["error"] != "issuer_not_active" {
				t.Errorf("%s error = %q", path, b["error"])
			}
		}
	})
}
