package auth_test

// #96: the OIDC callback JIT-provisions (and admits by domain allowlist) only
// when the ID token says email_verified is true. A missing claim counts as
// false. An existing member signs in as before, because no JIT happens.
//
// Also the #1058 follow-up: a state that does not validate is a typed
// ErrSSOInvalidState and maps to 400, logged at WARN.

import (
	"bytes"
	"context"
	"errors"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	"go.aocyber.ai/eden-platform-go/platform/auth"
	"go.aocyber.ai/eden-platform-go/platform/rbac"
)

// loginVerified has ten's IdP assert email with the given email_verified
// claim (nil omits it), then restores the IdP default (true).
func (w *ssoTenantWorld) loginVerified(ten tenant, email string, verified any) ssoLogin {
	w.t.Helper()
	ten.IdP.emailVerified = verified
	defer func() { ten.IdP.emailVerified = true }()
	return w.loginVia(ten, email)
}

func TestSSOEmailVerified_TrueIsProvisioned(t *testing.T) {
	w := newSSOTenantWorld(t)
	w.assertJITProvisioned(w.loginVerified(w.A, "new@tenant-a.example", true), w.A, w.B, "new@tenant-a.example")
	// Wrong tenant: A's verified IdP still cannot JIT into B's domain.
	w.assertJITRefused(w.loginVerified(w.A, "new@tenant-b.example", true), "new@tenant-b.example")
}

func TestSSOEmailVerified_FalseIsRefused(t *testing.T) {
	w := newSSOTenantWorld(t)
	w.assertJITRefused(w.loginVerified(w.A, "new@tenant-a.example", false), "new@tenant-a.example")
	if n := len(w.store.auditsWithAction("auth.sso.login_refused")); n != 1 {
		t.Errorf("refusal audits = %d, want 1", n)
	}
	// Wrong tenant: B's config is unaffected by A's unverified assertion.
	w.assertJITProvisioned(w.loginVerified(w.B, "new@tenant-b.example", true), w.B, w.A, "new@tenant-b.example")
}

func TestSSOEmailVerified_MissingIsRefused(t *testing.T) {
	w := newSSOTenantWorld(t)
	w.assertJITRefused(w.loginVerified(w.A, "new@tenant-a.example", nil), "new@tenant-a.example")
	w.assertJITProvisioned(w.loginVerified(w.B, "new@tenant-b.example", true), w.B, w.A, "new@tenant-b.example")
}

func TestSSOEmailVerified_StringValues(t *testing.T) {
	for _, tc := range []struct {
		claim any
		admit bool
	}{
		{"true", true},
		{"TRUE", true},
		{"false", false},
		{"", false},
		{"yes", false},
		{1, false},
	} {
		w := newSSOTenantWorld(t)
		email := "new@tenant-a.example"
		got := w.loginVerified(w.A, email, tc.claim)
		if tc.admit {
			w.assertJITProvisioned(got, w.A, w.B, email)
		} else {
			w.assertJITRefused(got, email)
		}
	}
}

func TestSSOEmailVerified_ExistingMemberUnverifiedSignsIn(t *testing.T) {
	w := newSSOTenantWorld(t)
	alice := w.member(w.A.ID, "alice@tenant-a.example", rbac.AdminRoleID)
	victim := w.member(w.B.ID, "victim@tenant-b.example", rbac.OwnerRoleID)

	got := w.loginVerified(w.A, alice.Email, false)
	if got.Status != http.StatusOK {
		t.Fatalf("status = %d, want 200 for an existing member", got.Status)
	}
	if got.Claims.UserID != alice.ID.String() || got.Claims.CompanyID != w.A.ID.String() {
		t.Errorf("claims = %s/%s, want alice in tenant A", got.Claims.UserID, got.Claims.CompanyID)
	}
	// Wrong tenant: another tenant's user is still refused, verified or not.
	w.assertRefused(w.loginVerified(w.A, victim.Email, true), w.A, victim)
}

// captureSlog swaps the default logger for one writing to a buffer.
func captureSlog(t *testing.T) *bytes.Buffer {
	t.Helper()
	var buf bytes.Buffer
	prev := slog.Default()
	slog.SetDefault(slog.New(slog.NewTextHandler(&buf, &slog.HandlerOptions{Level: slog.LevelDebug})))
	t.Cleanup(func() { slog.SetDefault(prev) })
	return &buf
}

func TestSSOInvalidState_Is400AndWarn(t *testing.T) {
	w := newSSOTenantWorld(t)

	// A well-formed state signed by a different key.
	otherJWT, err := auth.NewJWTManager(auth.JWTConfig{
		Issuer:             "eden-platform-test",
		AccessTokenExpiry:  time.Minute,
		RefreshTokenExpiry: time.Hour,
	})
	if err != nil {
		t.Fatalf("NewJWTManager: %v", err)
	}
	other := auth.NewSSOService(w.store, otherJWT, "https://api.example.test")
	allowLoopbackIdPForTest(other)
	_, foreign, err := other.InitiateOIDC(context.Background(), w.A.ID, "oidc", "json")
	if err != nil {
		t.Fatalf("InitiateOIDC: %v", err)
	}

	for name, state := range map[string]string{
		"garbage":     "not-a-state",
		"foreign key": foreign,
	} {
		t.Run(name, func(t *testing.T) {
			logs := captureSlog(t)
			_, _, err := w.svc.HandleOIDCCallbackWithState(context.Background(), "fixture-code", state)
			if !errors.Is(err, auth.ErrSSOInvalidState) {
				t.Errorf("err = %v, want ErrSSOInvalidState", err)
			}
			req := httptest.NewRequest(http.MethodGet, "/auth/oidc/callback?code=fixture-code&state="+url.QueryEscape(state), nil)
			rec := httptest.NewRecorder()
			w.mux.ServeHTTP(rec, req)
			if rec.Code != http.StatusBadRequest {
				t.Errorf("status = %d, want 400", rec.Code)
			}
			if bodyHasToken(rec.Body.Bytes()) {
				t.Errorf("an invalid-state callback returned tokens")
			}
			out := logs.String()
			if strings.Contains(out, "level=ERROR") || !strings.Contains(out, "level=WARN") {
				t.Errorf("want a WARN and no ERROR log, got %q", out)
			}
		})
	}

	// The refusal itself is unchanged: an unverified JIT is still 403.
	w.assertJITRefused(w.loginVerified(w.A, "new@tenant-a.example", false), "new@tenant-a.example")
}
