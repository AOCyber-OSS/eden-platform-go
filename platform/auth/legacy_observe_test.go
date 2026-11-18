package auth

import (
	"bytes"
	"log/slog"
	"strings"
	"testing"
	"time"
)

// newObservedManager returns a window-open manager whose legacy hook and
// logger are captured.
func newObservedManager(t *testing.T) (*JWTManager, *[]string, *bytes.Buffer) {
	t.Helper()
	var seen []string
	buf := &bytes.Buffer{}
	m, err := NewJWTManager(JWTConfig{
		Issuer: "test", AccessTokenExpiry: time.Minute, RefreshTokenExpiry: time.Hour,
		LegacyUntypedCutoff: time.Now().Add(time.Hour),
		OnLegacyUntyped:     func(use string) { seen = append(seen, use) },
		Logger:              slog.New(slog.NewTextHandler(buf, nil)),
	})
	if err != nil {
		t.Fatalf("NewJWTManager: %v", err)
	}
	return m, &seen, buf
}

// TestLegacyUntyped_HookReportsInferredType: every accepted legacy token is
// reported with its inferred type; typed tokens and refused ones are not.
func TestLegacyUntyped_HookReportsInferredType(t *testing.T) {
	m, seen, _ := newObservedManager(t)
	if _, err := m.ValidateAccessToken(legacyAccessToken(t, m)); err != nil {
		t.Fatal(err)
	}
	if _, err := m.ValidateRefreshToken(legacyRefreshToken(t, m)); err != nil {
		t.Fatal(err)
	}
	if _, err := m.ValidateShortLivedToken(legacyShortLivedToken(t, m)); err != nil {
		t.Fatal(err)
	}
	_, _ = m.ValidateAccessToken(legacyRefreshToken(t, m)) // refused: not reported
	_, _ = m.ValidateAccessToken(mintKind(t, m, kindAccess)) // typed: not reported
	want := []string{TokenUseAccess, TokenUseRefresh, TokenUseShortLived}
	if strings.Join(*seen, ",") != strings.Join(want, ",") {
		t.Errorf("hook saw %v, want %v", *seen, want)
	}
}

// TestLegacyUntyped_LogRateLimited: one warning per inferred type per
// interval, however many legacy tokens arrive.
func TestLegacyUntyped_LogRateLimited(t *testing.T) {
	m, _, buf := newObservedManager(t)
	for i := 0; i < 5; i++ {
		if _, err := m.ValidateAccessToken(legacyAccessToken(t, m)); err != nil {
			t.Fatal(err)
		}
	}
	if n := strings.Count(buf.String(), "legacy untyped token accepted"); n != 1 {
		t.Errorf("logged %d times in one interval, want 1:\n%s", n, buf.String())
	}
	m.now = func() time.Time { return time.Now().Add(legacyLogInterval + time.Second) }
	m.config.LegacyUntypedCutoff = time.Now().Add(2 * time.Hour)
	if _, err := m.ValidateAccessToken(legacyAccessToken(t, m)); err != nil {
		t.Fatal(err)
	}
	if n := strings.Count(buf.String(), "legacy untyped token accepted"); n != 2 {
		t.Errorf("logged %d times after the interval, want 2", n)
	}
}

// TestApplyLegacyUntypedEnv: a consumer drives the window from its own env.
func TestApplyLegacyUntypedEnv(t *testing.T) {
	env := map[string]string{
		EnvRejectLegacyUntyped: "true",
		EnvLegacyUntypedCutoff: "2026-12-01T00:00:00Z",
	}
	var cfg JWTConfig
	if err := ApplyLegacyUntypedEnv(&cfg, func(k string) string { return env[k] }); err != nil {
		t.Fatalf("ApplyLegacyUntypedEnv: %v", err)
	}
	if !cfg.RejectLegacyUntyped {
		t.Error("RejectLegacyUntyped not set from env")
	}
	if !cfg.LegacyUntypedCutoff.Equal(time.Date(2026, 12, 1, 0, 0, 0, 0, time.UTC)) {
		t.Errorf("cutoff = %v", cfg.LegacyUntypedCutoff)
	}
	var empty JWTConfig
	if err := ApplyLegacyUntypedEnv(&empty, func(string) string { return "" }); err != nil || empty.RejectLegacyUntyped || !empty.LegacyUntypedCutoff.IsZero() {
		t.Errorf("unset env changed config: %+v err=%v", empty, err)
	}
	if err := ApplyLegacyUntypedEnv(&empty, func(k string) string {
		if k == EnvLegacyUntypedCutoff {
			return "next tuesday"
		}
		return ""
	}); err == nil {
		t.Error("bad cutoff accepted")
	}
}
