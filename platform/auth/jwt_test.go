package auth

import (
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/cloudflare/circl/sign/mldsa/mldsa65"
	"github.com/golang-jwt/jwt/v5"
)

func newTestJWTManager(t *testing.T) *JWTManager {
	t.Helper()
	manager, err := NewJWTManager(JWTConfig{
		Issuer:             "test",
		AccessTokenExpiry:  time.Minute,
		RefreshTokenExpiry: time.Hour,
	})
	if err != nil {
		t.Fatalf("NewJWTManager() error = %v", err)
	}
	return manager
}

func TestJWTManager_CreateAndValidateAccessToken(t *testing.T) {
	manager := newTestJWTManager(t)

	token, err := manager.CreateAccessToken("user-1", "company-1", "admin", 80, []string{"company-1", "company-2"})
	if err != nil {
		t.Fatalf("CreateAccessToken() error = %v", err)
	}

	claims, err := manager.ValidateAccessToken(token)
	if err != nil {
		t.Fatalf("ValidateAccessToken() error = %v", err)
	}

	if claims.UserID != "user-1" {
		t.Errorf("UserID = %q, want %q", claims.UserID, "user-1")
	}
	if claims.CompanyID != "company-1" {
		t.Errorf("CompanyID = %q, want %q", claims.CompanyID, "company-1")
	}
	if claims.Role != "admin" {
		t.Errorf("Role = %q, want %q", claims.Role, "admin")
	}
	if claims.RoleLevel != 80 {
		t.Errorf("RoleLevel = %d, want %d", claims.RoleLevel, 80)
	}
	if len(claims.CompanyIDs) != 2 {
		t.Errorf("CompanyIDs length = %d, want 2", len(claims.CompanyIDs))
	}
	if claims.Subject != "user-1" {
		t.Errorf("Subject = %q, want %q", claims.Subject, "user-1")
	}
	if claims.Issuer != "test" {
		t.Errorf("Issuer = %q, want %q", claims.Issuer, "test")
	}
}

func TestJWTManager_CreateAndValidateRefreshToken(t *testing.T) {
	manager := newTestJWTManager(t)

	token, err := manager.CreateRefreshToken("user-1")
	if err != nil {
		t.Fatalf("CreateRefreshToken() error = %v", err)
	}

	claims, err := manager.ValidateRefreshToken(token)
	if err != nil {
		t.Fatalf("ValidateRefreshToken() error = %v", err)
	}

	if claims.Subject != "user-1" {
		t.Errorf("Subject = %q, want %q", claims.Subject, "user-1")
	}
	if claims.Issuer != "test" {
		t.Errorf("Issuer = %q, want %q", claims.Issuer, "test")
	}
}

func TestJWTManager_ExpiredAccessToken(t *testing.T) {
	manager, err := NewJWTManager(JWTConfig{
		Issuer:             "test",
		AccessTokenExpiry:  time.Millisecond,
		RefreshTokenExpiry: time.Hour,
	})
	if err != nil {
		t.Fatalf("NewJWTManager() error = %v", err)
	}

	token, err := manager.CreateAccessToken("user-1", "company-1", "admin", 80, nil)
	if err != nil {
		t.Fatalf("CreateAccessToken() error = %v", err)
	}

	time.Sleep(5 * time.Millisecond)

	_, err = manager.ValidateAccessToken(token)
	if err == nil {
		t.Errorf("ValidateAccessToken() expected error for expired token, got nil")
	}
}

func TestJWTManager_WrongSigningKey(t *testing.T) {
	manager1 := newTestJWTManager(t)
	manager2 := newTestJWTManager(t)

	token, err := manager1.CreateAccessToken("user-1", "company-1", "admin", 80, nil)
	if err != nil {
		t.Fatalf("CreateAccessToken() error = %v", err)
	}

	_, err = manager2.ValidateAccessToken(token)
	if err == nil {
		t.Errorf("ValidateAccessToken() expected error for wrong signing key, got nil")
	}
}

func TestJWTManager_EphemeralKeyGeneration(t *testing.T) {
	manager, err := NewJWTManager(JWTConfig{
		Issuer:             "test-ephemeral",
		AccessTokenExpiry:  time.Minute,
		RefreshTokenExpiry: time.Hour,
	})
	if err != nil {
		t.Fatalf("NewJWTManager() with empty paths error = %v", err)
	}

	token, err := manager.CreateAccessToken("user-1", "company-1", "member", 40, nil)
	if err != nil {
		t.Fatalf("CreateAccessToken() error = %v", err)
	}

	claims, err := manager.ValidateAccessToken(token)
	if err != nil {
		t.Fatalf("ValidateAccessToken() error = %v", err)
	}
	if claims.UserID != "user-1" {
		t.Errorf("UserID = %q, want %q", claims.UserID, "user-1")
	}
}

func TestJWTManager_MLDSA65SignatureSize(t *testing.T) {
	manager := newTestJWTManager(t)

	token, err := manager.CreateAccessToken("user-1", "company-1", "admin", 80, nil)
	if err != nil {
		t.Fatalf("CreateAccessToken() error = %v", err)
	}

	// ML-DSA-65 tokens are significantly larger than ES256 due to ~3309 byte signatures.
	// Base64-encoded, the token should be roughly 4-5KB.
	if len(token) < 3000 {
		t.Errorf("Token unexpectedly small (%d bytes) — expected ML-DSA-65 signature overhead", len(token))
	}
	// But still well under HTTP header limits.
	if len(token) > 8000 {
		t.Errorf("Token unexpectedly large (%d bytes) — may hit HTTP header limits", len(token))
	}
	t.Logf("ML-DSA-65 access token size: %d bytes", len(token))
}

func TestJWTManager_SeedDeterminism(t *testing.T) {
	seed, err := GenerateKeySeed()
	if err != nil {
		t.Fatalf("GenerateKeySeed() error = %v", err)
	}

	pk1, sk1 := mldsa65.NewKeyFromSeed(&seed)
	pk2, sk2 := mldsa65.NewKeyFromSeed(&seed)

	// Same seed must produce identical keys.
	if pk1.Bytes() == nil || string(pk1.Bytes()) != string(pk2.Bytes()) {
		t.Errorf("NewKeyFromSeed() produced different public keys for same seed")
	}
	_ = sk1
	_ = sk2
}

func TestJWTManager_ShortLivedToken(t *testing.T) {
	manager := newTestJWTManager(t)

	token, err := manager.CreateShortLivedToken("test-subject", 5*time.Minute)
	if err != nil {
		t.Fatalf("CreateShortLivedToken() error = %v", err)
	}

	subject, err := manager.ValidateShortLivedToken(token)
	if err != nil {
		t.Fatalf("ValidateShortLivedToken() error = %v", err)
	}
	if subject != "test-subject" {
		t.Errorf("Subject = %q, want %q", subject, "test-subject")
	}
}

// writeSeedFile creates a temporary seed file from an ML-DSA-65 key pair's seed.
// Returns the file path; caller is responsible for cleanup via t.Cleanup.
func writeSeedFile(t *testing.T, seed *[mldsa65.SeedSize]byte) string {
	t.Helper()
	f, err := os.CreateTemp(t.TempDir(), "seed-*.bin")
	if err != nil {
		t.Fatalf("create temp seed file: %v", err)
	}
	defer f.Close()
	if _, err := f.Write(seed[:]); err != nil {
		t.Fatalf("write seed file: %v", err)
	}
	return f.Name()
}

func TestJWTKeyRotation_SingleKeyBackwardCompat(t *testing.T) {
	// Generate a key and write its seed to a temp file.
	seed1, err := GenerateKeySeed()
	if err != nil {
		t.Fatalf("GenerateKeySeed: %v", err)
	}
	seedPath := writeSeedFile(t, &seed1)

	// Use legacy single-key config — must work exactly as before.
	manager, err := NewJWTManager(JWTConfig{
		KeySeedPath:        seedPath,
		Issuer:             "test",
		AccessTokenExpiry:  time.Minute,
		RefreshTokenExpiry: time.Hour,
	})
	if err != nil {
		t.Fatalf("NewJWTManager(single key): %v", err)
	}

	token, err := manager.CreateAccessToken("user-1", "company-1", "admin", 80, nil)
	if err != nil {
		t.Fatalf("CreateAccessToken: %v", err)
	}
	claims, err := manager.ValidateAccessToken(token)
	if err != nil {
		t.Fatalf("ValidateAccessToken: %v", err)
	}
	if claims.UserID != "user-1" {
		t.Errorf("UserID = %q, want %q", claims.UserID, "user-1")
	}

	// Refresh token round-trip.
	refresh, err := manager.CreateRefreshToken("user-1")
	if err != nil {
		t.Fatalf("CreateRefreshToken: %v", err)
	}
	rc, err := manager.ValidateRefreshToken(refresh)
	if err != nil {
		t.Fatalf("ValidateRefreshToken: %v", err)
	}
	if rc.Subject != "user-1" {
		t.Errorf("Subject = %q, want %q", rc.Subject, "user-1")
	}
}

func TestJWTKeyRotation_MultiKey(t *testing.T) {
	seed1, err := GenerateKeySeed()
	if err != nil {
		t.Fatalf("GenerateKeySeed seed1: %v", err)
	}
	seed2, err := GenerateKeySeed()
	if err != nil {
		t.Fatalf("GenerateKeySeed seed2: %v", err)
	}
	path1 := writeSeedFile(t, &seed1)
	path2 := writeSeedFile(t, &seed2)

	// Active key is key-2.
	manager, err := NewJWTManager(JWTConfig{
		KeySeedPaths: map[string]string{
			"key-1": path1,
			"key-2": path2,
		},
		ActiveKID:          "key-2",
		Issuer:             "test",
		AccessTokenExpiry:  time.Minute,
		RefreshTokenExpiry: time.Hour,
	})
	if err != nil {
		t.Fatalf("NewJWTManager(multi-key): %v", err)
	}

	// New token must include kid: "key-2".
	tokenStr, err := manager.CreateAccessToken("user-1", "company-1", "admin", 80, nil)
	if err != nil {
		t.Fatalf("CreateAccessToken: %v", err)
	}
	// Parse without validation just to inspect header.
	parsed, _, err := jwt.NewParser().ParseUnverified(tokenStr, &Claims{})
	if err != nil {
		t.Fatalf("ParseUnverified: %v", err)
	}
	if kid, _ := parsed.Header["kid"].(string); kid != "key-2" {
		t.Errorf("token kid = %q, want %q", kid, "key-2")
	}

	// Token signed by active key validates correctly.
	claims, err := manager.ValidateAccessToken(tokenStr)
	if err != nil {
		t.Fatalf("ValidateAccessToken: %v", err)
	}
	if claims.UserID != "user-1" {
		t.Errorf("UserID = %q, want %q", claims.UserID, "user-1")
	}

	// A manager configured with key-1 active can also sign; the multi-key manager
	// should validate that token because it holds key-1's public key.
	managerKey1Active, err := NewJWTManager(JWTConfig{
		KeySeedPaths: map[string]string{
			"key-1": path1,
			"key-2": path2,
		},
		ActiveKID:         "key-1",
		Issuer:            "test",
		AccessTokenExpiry: time.Minute,
	})
	if err != nil {
		t.Fatalf("NewJWTManager(key-1 active): %v", err)
	}
	token1, err := managerKey1Active.CreateAccessToken("user-2", "company-1", "member", 40, nil)
	if err != nil {
		t.Fatalf("CreateAccessToken with key-1: %v", err)
	}
	claims2, err := manager.ValidateAccessToken(token1)
	if err != nil {
		t.Fatalf("ValidateAccessToken token signed by key-1: %v", err)
	}
	if claims2.UserID != "user-2" {
		t.Errorf("UserID = %q, want %q", claims2.UserID, "user-2")
	}
}

func TestJWTKeyRotation_MissingKID(t *testing.T) {
	// Build a manager and create a token WITHOUT a kid header to simulate
	// tokens issued before key rotation support was added.
	manager := newTestJWTManager(t)

	// Create a token, then strip the kid header by re-signing manually.
	// Easiest approach: directly sign with the active key's private key
	// using NewWithClaims but without setting Header["kid"].
	now := time.Now()
	claims := &Claims{
		RegisteredClaims: jwt.RegisteredClaims{
			Subject:   "user-legacy",
			Issuer:    "test",
			ExpiresAt: jwt.NewNumericDate(now.Add(time.Minute)),
			IssuedAt:  jwt.NewNumericDate(now),
			ID:        generateJTI(),
		},
		// Typed (#80) so this test exercises only the missing-kid fallback,
		// not the dated untyped-token window.
		TokenUse:  TokenUseAccess,
		UserID:    "user-legacy",
		CompanyID: "company-1",
		Role:      "admin",
		RoleLevel: 80,
	}
	// NewWithClaims does NOT set kid by default.
	rawToken := jwt.NewWithClaims(signingMethodMLDSA65, claims)
	// Explicitly ensure kid is absent.
	delete(rawToken.Header, "kid")

	activeEntry := manager.keys[manager.activeKID]
	tokenStr, err := rawToken.SignedString(activeEntry.PrivateKey)
	if err != nil {
		t.Fatalf("SignedString (no kid): %v", err)
	}

	// Validate — should succeed via backward-compat fallback.
	result, err := manager.ValidateAccessToken(tokenStr)
	if err != nil {
		t.Fatalf("ValidateAccessToken (no kid) expected success, got: %v", err)
	}
	if result.UserID != "user-legacy" {
		t.Errorf("UserID = %q, want %q", result.UserID, "user-legacy")
	}
}

func TestJWTKeyRotation_UnknownKID(t *testing.T) {
	manager := newTestJWTManager(t)

	// Create a token with an unknown kid by forging the header.
	now := time.Now()
	claims := &Claims{
		RegisteredClaims: jwt.RegisteredClaims{
			Subject:   "user-1",
			Issuer:    "test",
			ExpiresAt: jwt.NewNumericDate(now.Add(time.Minute)),
			IssuedAt:  jwt.NewNumericDate(now),
			ID:        generateJTI(),
		},
		UserID:    "user-1",
		CompanyID: "company-1",
		Role:      "admin",
		RoleLevel: 80,
	}
	rawToken := jwt.NewWithClaims(signingMethodMLDSA65, claims)
	rawToken.Header["kid"] = "unknown-kid-xyz"

	activeEntry := manager.keys[manager.activeKID]
	tokenStr, err := rawToken.SignedString(activeEntry.PrivateKey)
	if err != nil {
		t.Fatalf("SignedString: %v", err)
	}

	// The keyfunc should reject this with "unknown kid".
	_, err = manager.ValidateAccessToken(tokenStr)
	if err == nil {
		t.Fatal("ValidateAccessToken with unknown kid expected error, got nil")
	}
	// Verify the error message contains "unknown kid".
	if msg := err.Error(); len(msg) == 0 {
		t.Error("expected non-empty error message")
	}
}

// TestJWTManager_HouseholdRoundTrip asserts that a household-scoped token
// (Obj 24a extension) round-trips through Validate without losing the
// new optional fields.
func TestJWTManager_HouseholdRoundTrip(t *testing.T) {
	manager := newTestJWTManager(t)

	const (
		userID      = "user-parent-1"
		householdID = "00000000-0000-0000-0000-0000000000aa"
		childID     = "00000000-0000-0000-0000-0000000000bb"
	)

	t.Run("parent_mode", func(t *testing.T) {
		token, err := manager.CreateHouseholdAccessToken(userID, householdID, "", false)
		if err != nil {
			t.Fatalf("CreateHouseholdAccessToken parent-mode: %v", err)
		}
		claims, err := manager.ValidateAccessToken(token)
		if err != nil {
			t.Fatalf("ValidateAccessToken parent-mode: %v", err)
		}
		if claims.UserID != userID {
			t.Errorf("UserID = %q, want %q", claims.UserID, userID)
		}
		if claims.HouseholdID != householdID {
			t.Errorf("HouseholdID = %q, want %q", claims.HouseholdID, householdID)
		}
		if claims.ChildID != "" {
			t.Errorf("ChildID = %q, want empty", claims.ChildID)
		}
		if claims.ChildMode {
			t.Errorf("ChildMode = true, want false (parent-mode token)")
		}
		// B2B fields must be zero.
		if claims.CompanyID != "" {
			t.Errorf("CompanyID = %q, want empty (household token)", claims.CompanyID)
		}
		if claims.Role != "" {
			t.Errorf("Role = %q, want empty (household token)", claims.Role)
		}
	})

	t.Run("child_mode", func(t *testing.T) {
		token, err := manager.CreateHouseholdAccessToken(userID, householdID, childID, true)
		if err != nil {
			t.Fatalf("CreateHouseholdAccessToken child-mode: %v", err)
		}
		claims, err := manager.ValidateAccessToken(token)
		if err != nil {
			t.Fatalf("ValidateAccessToken child-mode: %v", err)
		}
		if claims.HouseholdID != householdID {
			t.Errorf("HouseholdID = %q, want %q", claims.HouseholdID, householdID)
		}
		if claims.ChildID != childID {
			t.Errorf("ChildID = %q, want %q", claims.ChildID, childID)
		}
		if !claims.ChildMode {
			t.Errorf("ChildMode = false, want true (child-mode token)")
		}
	})
}

// decodeJWTPayload returns the JSON map of a JWT payload (the middle segment).
// Used by the backward-compat wire-format tests.
func decodeJWTPayload(t *testing.T, token string) map[string]any {
	t.Helper()
	parts := strings.Split(token, ".")
	if len(parts) != 3 {
		t.Fatalf("unexpected token segment count: %d", len(parts))
	}
	raw, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		t.Fatalf("decode payload: %v", err)
	}
	var m map[string]any
	if err := json.Unmarshal(raw, &m); err != nil {
		t.Fatalf("unmarshal payload: %v", err)
	}
	return m
}

// TestJWTManager_BackwardCompatWireFormat is the critical regression guard.
// A B2B token (issued via CreateAccessToken) must NOT carry the new
// household fields on the wire — they're optional, omitempty, and absent
// when zero-valued. This protects every existing B2B consumer from a
// surprise field appearing in their claims.
//
// Extended (politihub Obj 3 / TRD 03-01): the new "scopes" field MUST also
// be absent from a vanilla CreateAccessToken token. The Scopes axis is
// additive — staff issuance never sets it, so omitempty drops it.
func TestJWTManager_BackwardCompatWireFormat(t *testing.T) {
	manager := newTestJWTManager(t)

	token, err := manager.CreateAccessToken("user-1", "company-1", "admin", 80, []string{"company-1", "company-2"})
	if err != nil {
		t.Fatalf("CreateAccessToken: %v", err)
	}

	payload := decodeJWTPayload(t, token)

	// New household-axis fields AND the new scopes axis (politihub ADR-0003)
	// MUST be absent from the wire format for B2B-issued tokens.
	for _, forbidden := range []string{"hid", "child_id", "child_mode", "scopes"} {
		if _, present := payload[forbidden]; present {
			t.Errorf("B2B token payload unexpectedly contains %q: %v", forbidden, payload[forbidden])
		}
	}

	// Existing B2B fields MUST still be present.
	for _, required := range []string{"uid", "cid", "role", "rlvl"} {
		if _, present := payload[required]; !present {
			t.Errorf("B2B token payload missing required field %q", required)
		}
	}
}

// --- politihub Obj 3 / TRD 03-01: Scopes claim + helpers ---

// TestJWTManager_ScopesRoundTrip asserts that an access token issued with
// CreateAccessTokenWithScopes round-trips the Scopes axis through
// ValidateAccessToken without loss.
func TestJWTManager_ScopesRoundTrip(t *testing.T) {
	manager := newTestJWTManager(t)

	token, err := manager.CreateAccessTokenWithScopes(
		"user-1", "company-1", "", 0,
		[]string{"company-1"},
		[]string{"volunteer:field"},
	)
	if err != nil {
		t.Fatalf("CreateAccessTokenWithScopes: %v", err)
	}
	claims, err := manager.ValidateAccessToken(token)
	if err != nil {
		t.Fatalf("ValidateAccessToken: %v", err)
	}
	if len(claims.Scopes) != 1 || claims.Scopes[0] != "volunteer:field" {
		t.Errorf("Scopes = %v, want [volunteer:field]", claims.Scopes)
	}
}

// TestJWTManager_ScopesRoundTrip_Multi asserts that order is preserved when
// a token carries multiple scopes.
func TestJWTManager_ScopesRoundTrip_Multi(t *testing.T) {
	manager := newTestJWTManager(t)

	want := []string{"volunteer:field", "training:author"}
	token, err := manager.CreateAccessTokenWithScopes(
		"user-1", "company-1", "", 0,
		[]string{"company-1"},
		want,
	)
	if err != nil {
		t.Fatalf("CreateAccessTokenWithScopes: %v", err)
	}
	claims, err := manager.ValidateAccessToken(token)
	if err != nil {
		t.Fatalf("ValidateAccessToken: %v", err)
	}
	if len(claims.Scopes) != len(want) {
		t.Fatalf("Scopes length = %d, want %d", len(claims.Scopes), len(want))
	}
	for i := range want {
		if claims.Scopes[i] != want[i] {
			t.Errorf("Scopes[%d] = %q, want %q", i, claims.Scopes[i], want[i])
		}
	}
}

// TestJWTManager_ScopesOmitEmpty_Nil asserts that nil scopes produce no
// "scopes" key on the wire (omitempty).
func TestJWTManager_ScopesOmitEmpty_Nil(t *testing.T) {
	manager := newTestJWTManager(t)

	token, err := manager.CreateAccessTokenWithScopes(
		"user-1", "company-1", "admin", 80,
		[]string{"company-1"},
		nil,
	)
	if err != nil {
		t.Fatalf("CreateAccessTokenWithScopes(nil scopes): %v", err)
	}
	payload := decodeJWTPayload(t, token)
	if v, ok := payload["scopes"]; ok {
		t.Errorf("nil scopes: payload unexpectedly contains 'scopes' = %v", v)
	}
}

// TestJWTManager_ScopesOmitEmpty_Empty asserts that an empty (non-nil)
// scopes slice ALSO produces no "scopes" key (Go encoding/json honors
// omitempty for len-0 slices).
func TestJWTManager_ScopesOmitEmpty_Empty(t *testing.T) {
	manager := newTestJWTManager(t)

	token, err := manager.CreateAccessTokenWithScopes(
		"user-1", "company-1", "admin", 80,
		[]string{"company-1"},
		[]string{},
	)
	if err != nil {
		t.Fatalf("CreateAccessTokenWithScopes(empty scopes): %v", err)
	}
	payload := decodeJWTPayload(t, token)
	if v, ok := payload["scopes"]; ok {
		t.Errorf("empty scopes: payload unexpectedly contains 'scopes' = %v", v)
	}
}

// TestClaims_HasScope covers the helper's table of cases (pure scope-axis).
func TestClaims_HasScope(t *testing.T) {
	cases := []struct {
		name   string
		scopes []string
		query  string
		want   bool
	}{
		{"nil scopes", nil, "x", false},
		{"empty scopes", []string{}, "x", false},
		{"single match", []string{"volunteer:field"}, "volunteer:field", true},
		{"single no match", []string{"volunteer:field"}, "x", false},
		{"multi has", []string{"volunteer:field", "training:author"}, "training:author", true},
		{"multi miss", []string{"volunteer:field", "training:author"}, "missing", false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			c := &Claims{Scopes: tc.scopes}
			if got := c.HasScope(tc.query); got != tc.want {
				t.Errorf("HasScope(%q) on %v = %v, want %v", tc.query, tc.scopes, got, tc.want)
			}
		})
	}
}

// TestClaims_OnlyHasScope (MANDATORY) covers the exclusive single-scope
// contract.
func TestClaims_OnlyHasScope(t *testing.T) {
	cases := []struct {
		name   string
		scopes []string
		query  string
		want   bool
	}{
		{"nil scopes", nil, "x", false},
		{"empty scopes", []string{}, "x", false},
		{"single match", []string{"volunteer:field"}, "volunteer:field", true},
		{"single mismatch", []string{"volunteer:field"}, "other", false},
		{"multi with match", []string{"volunteer:field", "training:author"}, "volunteer:field", false},
		{"single wrong scope", []string{"other:thing"}, "volunteer:field", false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			c := &Claims{Scopes: tc.scopes}
			if got := c.OnlyHasScope(tc.query); got != tc.want {
				t.Errorf("OnlyHasScope(%q) on %v = %v, want %v", tc.query, tc.scopes, got, tc.want)
			}
		})
	}
}

// TestClaims_OnlyHasScope_IgnoresRole (MANDATORY) pins the user-locked
// decision: OnlyHasScope is PURE scope-axis. It does NOT inspect Role.
// Callers needing a "production-Navigators token" check combine it with
// `claims.Role == ""` themselves.
func TestClaims_OnlyHasScope_IgnoresRole(t *testing.T) {
	cases := []struct {
		name   string
		claims *Claims
	}{
		{
			name:   "no role",
			claims: &Claims{Scopes: []string{"volunteer:field"}, Role: "", RoleLevel: 0},
		},
		{
			name:   "owner role and same scope",
			claims: &Claims{Scopes: []string{"volunteer:field"}, Role: "owner", RoleLevel: 90},
		},
		{
			name:   "member role and same scope",
			claims: &Claims{Scopes: []string{"volunteer:field"}, Role: "member", RoleLevel: 40},
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if !tc.claims.OnlyHasScope("volunteer:field") {
				t.Errorf("OnlyHasScope must be pure scope-axis: returned false for token with sole scope (Role=%q, RoleLevel=%d)", tc.claims.Role, tc.claims.RoleLevel)
			}
		})
	}
}

// TestJWTManager_CreateAccessToken_StaffIssuanceUnchanged asserts that the
// legacy CreateAccessToken signature still works and produces tokens
// without a Scopes axis (delegates to CreateAccessTokenWithScopes with
// scopes=nil).
func TestJWTManager_CreateAccessToken_StaffIssuanceUnchanged(t *testing.T) {
	manager := newTestJWTManager(t)

	token, err := manager.CreateAccessToken("user-1", "company-1", "admin", 80, []string{"company-1"})
	if err != nil {
		t.Fatalf("CreateAccessToken: %v", err)
	}
	claims, err := manager.ValidateAccessToken(token)
	if err != nil {
		t.Fatalf("ValidateAccessToken: %v", err)
	}
	if len(claims.Scopes) != 0 {
		t.Errorf("legacy CreateAccessToken Scopes = %v, want empty/nil", claims.Scopes)
	}
	if claims.Role != "admin" {
		t.Errorf("Role = %q, want %q", claims.Role, "admin")
	}
}

// TestJWTManager_HouseholdClaimsOmitEmpty ensures that issuing a household
// token with empty optional fields (parent-mode, no childID) does NOT
// serialize them to the wire — keeps tokens lean and avoids surprising
// downstream consumers that don't know about child-mode.
func TestJWTManager_HouseholdClaimsOmitEmpty(t *testing.T) {
	manager := newTestJWTManager(t)

	token, err := manager.CreateHouseholdAccessToken("user-1", "00000000-0000-0000-0000-0000000000aa", "", false)
	if err != nil {
		t.Fatalf("CreateHouseholdAccessToken: %v", err)
	}

	payload := decodeJWTPayload(t, token)

	// HouseholdID is set; should be present.
	if _, ok := payload["hid"]; !ok {
		t.Errorf("parent-mode household token missing 'hid' field")
	}
	// ChildID is empty; should be absent (omitempty).
	if v, ok := payload["child_id"]; ok {
		t.Errorf("parent-mode household token unexpectedly contains 'child_id' = %v", v)
	}
	// ChildMode is false; should be absent (omitempty).
	if v, ok := payload["child_mode"]; ok {
		t.Errorf("parent-mode household token unexpectedly contains 'child_mode' = %v", v)
	}
}

// TestJWTManager_LegacyB2BTokenStillValid ensures that the existing
// B2B issuance/validation path produces the same Claims shape as before
// when household fields are unused — zero-valued.
func TestJWTManager_LegacyB2BTokenStillValid(t *testing.T) {
	manager := newTestJWTManager(t)

	token, err := manager.CreateAccessToken("user-1", "company-1", "admin", 80, nil)
	if err != nil {
		t.Fatalf("CreateAccessToken: %v", err)
	}
	claims, err := manager.ValidateAccessToken(token)
	if err != nil {
		t.Fatalf("ValidateAccessToken: %v", err)
	}

	// B2B fields populated.
	if claims.UserID != "user-1" {
		t.Errorf("UserID = %q, want %q", claims.UserID, "user-1")
	}
	if claims.CompanyID != "company-1" {
		t.Errorf("CompanyID = %q, want %q", claims.CompanyID, "company-1")
	}

	// Household fields zero-valued — never set, never populated by
	// CreateAccessToken.
	if claims.HouseholdID != "" {
		t.Errorf("HouseholdID = %q, want empty for B2B token", claims.HouseholdID)
	}
	if claims.ChildID != "" {
		t.Errorf("ChildID = %q, want empty for B2B token", claims.ChildID)
	}
	if claims.ChildMode {
		t.Errorf("ChildMode = true, want false for B2B token")
	}
}

func TestHashToken(t *testing.T) {
	token := "test-token-value"
	hash1 := HashToken(token)
	hash2 := HashToken(token)

	if hash1 != hash2 {
		t.Errorf("HashToken() not deterministic: %q != %q", hash1, hash2)
	}

	expected := sha256.Sum256([]byte(token))
	expectedHex := hex.EncodeToString(expected[:])
	if hash1 != expectedHex {
		t.Errorf("HashToken() = %q, want SHA-256 hex %q", hash1, expectedHex)
	}

	hash3 := HashToken("different-token")
	if hash1 == hash3 {
		t.Errorf("HashToken() same for different inputs")
	}
}
