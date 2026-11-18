package composition

// Issue #80: AOID_JWT_REJECT_LEGACY_UNTYPED closes the untyped-token
// migration window for AO ID before its dated cutoff.

import (
	"testing"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"go.aocyber.ai/eden-platform-go/internal/aoid/config"
	"go.aocyber.ai/eden-platform-go/platform/auth"
)

// legacyAccess signs a pre-#80 access token (uid, no token_use) with the
// manager's own active key.
func legacyAccess(t *testing.T, svcs *Services) string {
	t.Helper()
	now := time.Now()
	tok := jwt.NewWithClaims(jwt.GetSigningMethod("ML-DSA-65"), jwt.MapClaims{
		"sub": "u", "uid": "u", "iss": "http://localhost:8090",
		"exp": now.Add(time.Minute).Unix(), "iat": now.Unix(),
	})
	tok.Header["kid"] = svcs.JWTManager.ActiveKID()
	s, err := tok.SignedString(svcs.JWTManager.ActivePrivateKey())
	if err != nil {
		t.Fatalf("sign: %v", err)
	}
	return s
}

func TestBuildInMemory_RejectLegacyUntypedFlag(t *testing.T) {
	for _, reject := range []bool{false, true} {
		cfg := &config.Config{
			Issuer:                 "http://localhost:8090",
			Environment:            "dev",
			AccessTokenExpiry:      15 * time.Minute,
			RefreshTokenExpiry:     time.Hour,
			JWTRejectLegacyUntyped: reject,
		}
		svcs, err := BuildInMemory(cfg)
		if err != nil {
			t.Fatalf("BuildInMemory: %v", err)
		}
		_, verr := svcs.JWTManager.ValidateAccessToken(legacyAccess(t, svcs))
		_ = svcs.Close()
		if reject && verr == nil {
			t.Error("flag set: legacy untyped access token accepted")
		}
		if !reject && verr != nil && time.Now().Before(auth.DefaultLegacyUntypedCutoff) {
			t.Errorf("flag unset, window open: legacy access token rejected: %v", verr)
		}
	}
}
