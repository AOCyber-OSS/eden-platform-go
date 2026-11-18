package auth

// Hand-built token fixtures for the token-use tests (issue #80).
//
// Every fixture is minted from a test JWTManager's ephemeral ML-DSA-65 key, so
// nothing here depends on real keys or the network. The raw builders sign a
// MapClaims body directly, which lets a test produce the exact wire shape of a
// token that an older build of this package issued (no token_use claim).

import (
	"testing"
	"time"

	"github.com/golang-jwt/jwt/v5"
)

// tokenKind names one token type a JWTManager (or the AO ID issuer, for "id")
// can mint.
type tokenKind string

const (
	kindAccess            tokenKind = "access"
	kindHousehold         tokenKind = "household_access"
	kindRefresh           tokenKind = "refresh"
	kindShortLived        tokenKind = "short_lived"
	kindCompactShortLived tokenKind = "compact_short_lived"
	kindID                tokenKind = "id"
)

var allTokenKinds = []tokenKind{
	kindAccess, kindHousehold, kindRefresh, kindShortLived, kindCompactShortLived, kindID,
}

// mintKind issues one token of the given kind from m through its public API.
// "id" is built the way internal/aoid/issuer signs ID tokens (same key, an
// aud and a nonce), since that package is not importable from here.
func mintKind(t *testing.T, m *JWTManager, k tokenKind) string {
	t.Helper()
	var (
		tok string
		err error
	)
	switch k {
	case kindAccess:
		tok, err = m.CreateAccessToken("user-1", "company-1", "admin", 80, []string{"company-1"})
	case kindHousehold:
		tok, err = m.CreateHouseholdAccessToken("user-1", "household-1", "", false)
	case kindRefresh:
		tok, err = m.CreateRefreshToken("user-1")
	case kindShortLived:
		tok, err = m.CreateShortLivedToken("google|https://app.test/cb|verifier|nonce", 10*time.Minute)
	case kindCompactShortLived:
		tok, err = m.CreateCompactShortLivedToken("company|google|https://app.test/cb", 10*time.Minute)
	case kindID:
		now := time.Now()
		tok = signRawClaims(t, m, jwt.MapClaims{
			"sub":       "user-1",
			"iss":       m.config.Issuer,
			"aud":       []string{"client-a"},
			"exp":       now.Add(time.Hour).Unix(),
			"iat":       now.Unix(),
			"nbf":       now.Unix(),
			"nonce":     "nonce-1",
			"token_use": "id",
		})
	default:
		t.Fatalf("mintKind: unknown kind %q", k)
	}
	if err != nil {
		t.Fatalf("mint %s: %v", k, err)
	}
	return tok
}

// signRawClaims signs an arbitrary claim body with m's active ML-DSA-65 key
// and kid, exactly as JWTManager does for its own tokens.
func signRawClaims(t *testing.T, m *JWTManager, claims jwt.MapClaims) string {
	t.Helper()
	tok := jwt.NewWithClaims(signingMethodMLDSA65, claims)
	tok.Header["kid"] = m.activeKID
	s, err := tok.SignedString(m.keys[m.activeKID].PrivateKey)
	if err != nil {
		t.Fatalf("sign raw claims: %v", err)
	}
	return s
}

// Legacy (pre-#80) wire shapes: identical to what the previous release minted,
// so they carry no token_use claim.

func legacyAccessToken(t *testing.T, m *JWTManager) string {
	t.Helper()
	now := time.Now()
	return signRawClaims(t, m, jwt.MapClaims{
		"sub": "user-1", "iss": m.config.Issuer, "jti": "legacy-access",
		"exp": now.Add(15 * time.Minute).Unix(), "iat": now.Unix(),
		"uid": "user-1", "cid": "company-1", "role": "admin", "rlvl": 80,
	})
}

func legacyRefreshToken(t *testing.T, m *JWTManager) string {
	t.Helper()
	now := time.Now()
	return signRawClaims(t, m, jwt.MapClaims{
		"sub": "user-1", "iss": m.config.Issuer, "jti": "legacy-refresh",
		"exp": now.Add(7 * 24 * time.Hour).Unix(), "iat": now.Unix(),
	})
}

func legacyShortLivedToken(t *testing.T, m *JWTManager) string {
	t.Helper()
	now := time.Now()
	return signRawClaims(t, m, jwt.MapClaims{
		"sub": "google|https://app.test/cb|verifier|nonce", "iss": m.config.Issuer, "jti": "legacy-state",
		"exp": now.Add(10 * time.Minute).Unix(), "iat": now.Unix(),
	})
}

func legacyIDToken(t *testing.T, m *JWTManager) string {
	t.Helper()
	now := time.Now()
	return signRawClaims(t, m, jwt.MapClaims{
		"sub": "user-1", "iss": m.config.Issuer, "aud": []string{"client-a"}, "nonce": "n",
		"exp": now.Add(time.Hour).Unix(), "iat": now.Unix(), "nbf": now.Unix(),
	})
}

// validators runs each public Validate* method; ok reports acceptance.
var validators = map[string]func(m *JWTManager, tok string) bool{
	"ValidateAccessToken": func(m *JWTManager, tok string) bool {
		_, err := m.ValidateAccessToken(tok)
		return err == nil
	},
	"ValidateRefreshToken": func(m *JWTManager, tok string) bool {
		_, err := m.ValidateRefreshToken(tok)
		return err == nil
	},
	"ValidateShortLivedToken": func(m *JWTManager, tok string) bool {
		_, err := m.ValidateShortLivedToken(tok)
		return err == nil
	},
	"ValidateCompactShortLivedToken": func(m *JWTManager, tok string) bool {
		_, err := m.ValidateCompactShortLivedToken(tok)
		return err == nil
	},
}

// acceptedBy is the one validator that must accept each kind ("" = none of
// JWTManager's validators: ID tokens are for relying parties, not for us).
var acceptedBy = map[tokenKind]string{
	kindAccess:            "ValidateAccessToken",
	kindHousehold:         "ValidateAccessToken",
	kindRefresh:           "ValidateRefreshToken",
	kindShortLived:        "ValidateShortLivedToken",
	kindCompactShortLived: "ValidateCompactShortLivedToken",
	kindID:                "",
}
