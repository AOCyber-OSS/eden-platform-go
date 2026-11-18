package auth

import (
	"testing"
	"time"

	"github.com/golang-jwt/jwt/v5"
)

// newWindowManager returns a manager whose legacy window is open (cutoff an
// hour from now), independent of DefaultLegacyUntypedCutoff and the date the
// test runs on.
func newWindowManager(t *testing.T) *JWTManager {
	t.Helper()
	m, err := NewJWTManager(JWTConfig{
		Issuer:              "test",
		AccessTokenExpiry:   time.Minute,
		RefreshTokenExpiry:  time.Hour,
		LegacyUntypedCutoff: time.Now().Add(time.Hour),
	})
	if err != nil {
		t.Fatalf("NewJWTManager: %v", err)
	}
	return m
}

// TestTokenUse_CrossTypeMatrix (issue #80): every token type is accepted by
// its own validator and rejected by every other one. Before the fix all
// ML-DSA-65 tokens shared one key and carried no type, so a refresh token,
// an SSO/social state token or an AO ID ID token all passed
// ValidateAccessToken (and vice versa).
func TestTokenUse_CrossTypeMatrix(t *testing.T) {
	m := newTestJWTManager(t)
	for _, kind := range allTokenKinds {
		tok := mintKind(t, m, kind)
		for name, validate := range validators {
			want := acceptedBy[kind] == name
			if got := validate(m, tok); got != want {
				t.Errorf("%s token: %s accepted=%v, want %v", kind, name, got, want)
			}
		}
	}
}

// TestTokenUse_LegacyAccessAcceptedInWindow: an access token minted by the
// previous release (no token_use) still validates before the migration
// cutoff, so a deploy does not 401 every live session.
func TestTokenUse_LegacyAccessAcceptedInWindow(t *testing.T) {
	m := newWindowManager(t)
	claims, err := m.ValidateAccessToken(legacyAccessToken(t, m))
	if err != nil {
		t.Fatalf("legacy access token rejected inside the window: %v", err)
	}
	if claims.UserID != "user-1" {
		t.Errorf("UserID = %q, want user-1", claims.UserID)
	}
}

// TestTokenUse_LegacyRefreshAcceptedInWindow: a pre-#80 refresh token (no
// token_use, no uid, 7-day lifetime) can still be rotated in the window.
func TestTokenUse_LegacyRefreshAcceptedInWindow(t *testing.T) {
	m := newWindowManager(t)
	claims, err := m.ValidateRefreshToken(legacyRefreshToken(t, m))
	if err != nil {
		t.Fatalf("legacy refresh token rejected inside the window: %v", err)
	}
	if claims.Subject != "user-1" {
		t.Errorf("Subject = %q, want user-1", claims.Subject)
	}
}

// TestTokenUse_LegacyShortLivedAcceptedInWindow: a social/SSO state minted by
// a not-yet-rolled replica (no token_use, 10-minute lifetime) still validates.
func TestTokenUse_LegacyShortLivedAcceptedInWindow(t *testing.T) {
	m := newWindowManager(t)
	if _, err := m.ValidateShortLivedToken(legacyShortLivedToken(t, m)); err != nil {
		t.Fatalf("legacy short-lived token rejected inside the window: %v", err)
	}
}

// TestTokenUse_LegacyRejectedAfterCutoff: the window is bounded. From the
// cutoff on, every untyped token is rejected by every validator.
func TestTokenUse_LegacyRejectedAfterCutoff(t *testing.T) {
	m := newWindowManager(t)
	m.now = func() time.Time { return m.config.LegacyUntypedCutoff }
	for name, tok := range map[string]string{
		"access": legacyAccessToken(t, m), "refresh": legacyRefreshToken(t, m),
		"short_lived": legacyShortLivedToken(t, m), "id": legacyIDToken(t, m),
	} {
		for vname, validate := range validators {
			if validate(m, tok) {
				t.Errorf("legacy %s token accepted by %s after the cutoff", name, vname)
			}
		}
	}
}

// TestTokenUse_RejectLegacyUntypedFlag: the flag closes the window before the
// cutoff.
func TestTokenUse_RejectLegacyUntypedFlag(t *testing.T) {
	m := newWindowManager(t)
	m.config.RejectLegacyUntyped = true
	if _, err := m.ValidateAccessToken(legacyAccessToken(t, m)); err == nil {
		t.Error("legacy access token accepted with RejectLegacyUntyped set")
	}
	if _, err := m.ValidateRefreshToken(legacyRefreshToken(t, m)); err == nil {
		t.Error("legacy refresh token accepted with RejectLegacyUntyped set")
	}
}

// TestTokenUse_LegacyCrossTypeMatrix: inside the window an untyped token is
// accepted only by the validator its shape belongs to, never cross-type, and
// an untyped ID token (aud set) by none.
func TestTokenUse_LegacyCrossTypeMatrix(t *testing.T) {
	m := newWindowManager(t)
	cases := map[string]struct {
		tok  string
		want string
	}{
		"access":      {legacyAccessToken(t, m), "ValidateAccessToken"},
		"refresh":     {legacyRefreshToken(t, m), "ValidateRefreshToken"},
		"short_lived": {legacyShortLivedToken(t, m), "ValidateShortLivedToken"},
		"id":          {legacyIDToken(t, m), ""},
	}
	for name, c := range cases {
		for vname, validate := range validators {
			want := c.want == vname
			if got := validate(m, c.tok); got != want {
				t.Errorf("legacy %s token: %s accepted=%v, want %v", name, vname, got, want)
			}
		}
	}
}

// TestTokenUse_UnknownValueRejected: a token_use value this package does not
// mint is rejected even inside the window.
func TestTokenUse_UnknownValueRejected(t *testing.T) {
	m := newWindowManager(t)
	now := time.Now()
	tok := signRawClaims(t, m, map[string]any{
		"sub": "user-1", "uid": "user-1", "token_use": "admin",
		"exp": now.Add(time.Minute).Unix(), "iat": now.Unix(),
	})
	for vname, validate := range validators {
		if validate(m, tok) {
			t.Errorf("token_use=admin accepted by %s", vname)
		}
	}
}

// TestTokenUse_CompactLegacyWindow: a compact (HS256) state minted before #80
// has no token_use. It is accepted in the window and rejected after it.
func TestTokenUse_CompactLegacyWindow(t *testing.T) {
	m := newWindowManager(t)
	key, err := m.stateHMACKey()
	if err != nil {
		t.Fatalf("stateHMACKey: %v", err)
	}
	now := time.Now()
	tok, err := jwt.NewWithClaims(jwt.SigningMethodHS256, jwt.MapClaims{
		"sub": "company|google|https://app.test/cb", "iss": "test",
		"exp": now.Add(10 * time.Minute).Unix(), "iat": now.Unix(),
	}).SignedString(key)
	if err != nil {
		t.Fatalf("sign: %v", err)
	}
	if _, err := m.ValidateCompactShortLivedToken(tok); err != nil {
		t.Errorf("legacy compact token rejected inside the window: %v", err)
	}
	m.now = func() time.Time { return m.config.LegacyUntypedCutoff }
	if _, err := m.ValidateCompactShortLivedToken(tok); err == nil {
		t.Error("legacy compact token accepted after the cutoff")
	}
}
