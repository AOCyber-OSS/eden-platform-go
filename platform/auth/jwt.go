package auth

import (
	"crypto/rand"
	"crypto/sha256"
	"fmt"
	"log/slog"
	"os"
	"sync"
	"time"

	"github.com/cloudflare/circl/sign/mldsa/mldsa65"
	"github.com/golang-jwt/jwt/v5"
)

// Claims represents the JWT claims included in access tokens.
//
// The Claims struct hosts two orthogonal identity axes:
//
//  1. B2B axis (UserID + CompanyID/CompanyIDs + Role + RoleLevel): used by
//     AODex / eden-biz / AOSentry-style consumers where principals belong to
//     companies and have role-based access levels.
//  2. Household axis (HouseholdID + ChildID + ChildMode): used by AOFamily /
//     Eden Family-style consumers where principals belong to households and
//     parental controls gate restricted-mode sessions.
//
// Household fields are tagged `omitempty` so B2B tokens carry an identical
// wire format to the pre-24a era — adding them did NOT break any existing
// consumer. Populate them only via JWTManager.CreateHouseholdAccessToken.
type Claims struct {
	jwt.RegisteredClaims

	// TokenUse is the token-type claim (issue #80): "access" on every token
	// from CreateAccessToken / CreateAccessTokenWithScopes /
	// CreateHouseholdAccessToken. ValidateAccessToken requires it, so a
	// refresh, state or ID token signed with the same key is not an access
	// token.
	TokenUse string `json:"token_use,omitempty"`

	UserID     string   `json:"uid"`
	CompanyID  string   `json:"cid"`
	CompanyIDs []string `json:"cids,omitempty"`
	Role       string   `json:"role"`
	RoleLevel  int      `json:"rlvl"`

	// Scopes lists capability scopes carried by this token. Used by per-product
	// consumers to gate route access along an axis orthogonal to Role. The
	// first consumer is politihub (ADR-0003 — "volunteer:field" gates /v1/me/*
	// and is rejected by staff endpoints when it is the SOLE scope; politihub
	// combines OnlyHasScope("volunteer:field") with claims.Role == "" to
	// distinguish production Navigators tokens from dual-axis dev tokens).
	//
	// omitempty preserves wire-format compatibility — staff issuance paths
	// (CreateAccessToken) leave Scopes nil, so existing tokens carry no
	// "scopes" key.
	Scopes []string `json:"scopes,omitempty"`

	// Household-aware claims (Obj 24a). All optional so B2B consumers see
	// no wire-format change. Populated only via CreateHouseholdAccessToken
	// when a household-shaped product (AOFamily, Eden Family) issues a
	// token. HouseholdID links to a row in platform/household;
	// ChildID/ChildMode together control parental-control middleware
	// enforcement via RequireParentMode / RequireChildMode.
	HouseholdID string `json:"hid,omitempty"`
	ChildID     string `json:"child_id,omitempty"`
	ChildMode   bool   `json:"child_mode,omitempty"`

	// Entitlements (`ent`) carries the plan/entitlement scope resolved at
	// issuance by the token minter (AOID under AOFamily Path B). Wire-identical
	// to AOID's `ent` tag so household-product backends unmarshal it directly
	// via idt.Claims(&claims) with no per-backend decode change — the same
	// capture-by-tag mechanism that already picks up hid/child_mode. omitempty
	// keeps B2B/tnt-only tokens byte-compatible. eden is a passive carrier: the
	// plan→entitlement policy lives in the issuing product's billing service,
	// never here (see HasEntitlement / RequirePlan in entitlements.go).
	Entitlements []string `json:"ent,omitempty"`
}

// HasScope returns true if the token's scope list contains the given scope.
// Pure scope-axis — does NOT inspect Role/RoleLevel. Callers that need a
// dual-axis check must combine HasScope with their own Role check.
func (c *Claims) HasScope(scope string) bool {
	for _, s := range c.Scopes {
		if s == scope {
			return true
		}
	}
	return false
}

// OnlyHasScope returns true iff the token's scope list is exactly [scope]
// (length 1, single value). Pure scope-axis — does NOT inspect Role/RoleLevel.
// Callers needing a "production-Navigators token" check combine OnlyHasScope
// with their own Role check (e.g. politihub: OnlyHasScope("volunteer:field")
// && claims.Role == "").
//
// This contract is locked: a dual-axis token (staff Role + volunteer:field
// scope) returns true from OnlyHasScope("volunteer:field") because the
// scope-list is still exactly one value. The Role check belongs to the
// caller's middleware, where the staff/volunteer model is known.
func (c *Claims) OnlyHasScope(scope string) bool {
	return len(c.Scopes) == 1 && c.Scopes[0] == scope
}

// Token-use claim values (issue #80). Every token this package mints carries
// exactly one of them in the "token_use" claim, and each Validate* method
// accepts only its own. All ML-DSA-65 tokens share one signing key, so without
// this claim the signature alone cannot tell an access token from a refresh,
// state or ID token.
const (
	TokenUseAccess     = "access"
	TokenUseRefresh    = "refresh"
	TokenUseShortLived = "short_lived"
	// TokenUseID marks an OIDC ID token minted by the AO ID issuer with this
	// package's key. No JWTManager validator accepts it.
	TokenUseID = "id"
)

// RefreshClaims are the claims of a refresh token. Audience, when set, is the
// OAuth client the refresh token was issued to (see CreateClientRefreshToken).
// CompanyID, when set, is the company the session was issued for (see
// CreateCompanyRefreshToken); a refresh re-mints for that company only.
type RefreshClaims struct {
	jwt.RegisteredClaims
	TokenUse  string `json:"token_use,omitempty"`
	CompanyID string `json:"cid,omitempty"`
}

// typedClaims is the parse target for refresh and short-lived tokens. UID is
// never minted on these types; it is read only so legacyUseOf can tell a
// pre-#80 access token apart.
type typedClaims struct {
	jwt.RegisteredClaims
	TokenUse  string `json:"token_use,omitempty"`
	UID       string `json:"uid,omitempty"`
	CompanyID string `json:"cid,omitempty"`
}

// legacyShortLivedMax is the longest lifetime a pre-#80 untyped token can have
// and still be classified as short-lived (state tokens were minted for 10
// minutes); anything longer is classified as a refresh token (7 days).
const legacyShortLivedMax = time.Hour

// legacyUseOf classifies a token minted before #80 (no token_use) by the only
// shapes the previous release produced:
//   - uid present                -> access (only access tokens carried uid)
//   - aud present                -> none (AO ID ID tokens; never accepted)
//   - lifetime > 1h              -> refresh
//   - lifetime <= 1h             -> short_lived
func legacyUseOf(c *typedClaims) string {
	if c.UID != "" {
		return TokenUseAccess
	}
	if len(c.Audience) > 0 || c.ExpiresAt == nil || c.IssuedAt == nil {
		return ""
	}
	if c.ExpiresAt.Sub(c.IssuedAt.Time) > legacyShortLivedMax {
		return TokenUseRefresh
	}
	return TokenUseShortLived
}

// KeyEntry holds an ML-DSA-65 key pair identified by a kid (Key ID).
type KeyEntry struct {
	PrivateKey *mldsa65.PrivateKey
	PublicKey  *mldsa65.PublicKey
}

// JWTConfig holds configuration for the JWT manager.
type JWTConfig struct {
	// KeySeedPath is the path to a 32-byte raw seed file. ML-DSA-65 derives
	// both the private and public key deterministically from this seed.
	// If empty, an ephemeral key pair is generated (dev only).
	// Single-key backward-compat mode — used when KeySeedPaths is empty.
	KeySeedPath string

	// KeySeedPaths is an optional map of kid -> seed file path for multi-key
	// rotation support. When non-empty, KeySeedPath is ignored.
	KeySeedPaths map[string]string

	// ActiveKID specifies which kid from KeySeedPaths to use when signing new
	// tokens. Required when KeySeedPaths is non-empty.
	ActiveKID string

	Issuer             string
	AccessTokenExpiry  time.Duration
	RefreshTokenExpiry time.Duration

	// LegacyUntypedCutoff ends the migration window for tokens minted before
	// the token_use claim existed (issue #80). Until this instant, a token
	// with NO token_use is accepted by the validator its claim shape belongs
	// to (see legacyUseOf); from it on, every untyped token is rejected.
	// Zero means DefaultLegacyUntypedCutoff.
	LegacyUntypedCutoff time.Time

	// RejectLegacyUntyped closes the migration window now, regardless of
	// LegacyUntypedCutoff. Consumers can drive it (and the cutoff) from their
	// env with ApplyLegacyUntypedEnv.
	RejectLegacyUntyped bool

	// OnLegacyUntyped, when set, is called once per legacy (untyped) token
	// accepted in the window, with its inferred token_use. Wire it to a
	// metric (observability.AuthMetrics.RecordLegacyUntypedToken) to see
	// when pre-#80 tokens stop arriving.
	OnLegacyUntyped func(inferredUse string)

	// Logger receives the rate-limited legacy-acceptance warning (one per
	// inferred type per minute). Nil means slog.Default().
	Logger *slog.Logger
}

// DefaultLegacyUntypedCutoff is the end of the #80 migration window. Access
// tokens live 15 minutes and state tokens 10, so only refresh tokens (7 days,
// rotated on use) need the window; it is set a few weeks out so a module bump
// that ships late still lets pre-#80 sessions rotate onto typed tokens. After
// it the legacy path is dead code and should be deleted.
var DefaultLegacyUntypedCutoff = time.Date(2026, time.December, 15, 0, 0, 0, 0, time.UTC)

// DefaultJWTConfig returns sensible defaults.
func DefaultJWTConfig() JWTConfig {
	return JWTConfig{
		Issuer:             "eden-platform",
		AccessTokenExpiry:  15 * time.Minute,
		RefreshTokenExpiry: 7 * 24 * time.Hour,
	}
}

// JWTManager handles creation and validation of ML-DSA-65 (post-quantum) JWT tokens.
// It supports multiple signing keys identified by kid (Key ID) headers for zero-downtime
// key rotation.
type JWTManager struct {
	keys      map[string]*KeyEntry // kid -> key pair
	activeKID string               // kid used for signing new tokens
	config    JWTConfig
	now       func() time.Time // clock for the legacy window; time.Now outside tests

	legacyLogMu    sync.Mutex
	legacyLoggedAt map[string]time.Time // inferred use -> last warning
}

// legacyLogInterval rate-limits the legacy-acceptance warning per type.
const legacyLogInterval = time.Minute

// noteLegacy reports one accepted legacy token: the hook every time, the log
// at most once per type per legacyLogInterval.
func (m *JWTManager) noteLegacy(use string) {
	if m.config.OnLegacyUntyped != nil {
		m.config.OnLegacyUntyped(use)
	}
	now := m.now()
	m.legacyLogMu.Lock()
	last, seen := m.legacyLoggedAt[use]
	due := !seen || now.Sub(last) >= legacyLogInterval
	if due {
		if m.legacyLoggedAt == nil {
			m.legacyLoggedAt = make(map[string]time.Time)
		}
		m.legacyLoggedAt[use] = now
	}
	m.legacyLogMu.Unlock()
	if due {
		logger := m.config.Logger
		if logger == nil {
			logger = slog.Default()
		}
		logger.Warn("legacy untyped token accepted (issue #80 migration window)",
			"inferred_token_use", use, "cutoff", m.config.LegacyUntypedCutoff)
	}
}

// NewJWTManager creates a JWTManager from key seed files or auto-generates for dev.
//
// Priority:
//  1. KeySeedPaths (multi-key mode) — loads each (kid, path) pair, uses ActiveKID for signing.
//  2. KeySeedPath (single-key backward-compat) — loads one key with kid "default".
//  3. No paths — generates an ephemeral key pair with kid "ephemeral" (dev only).
func NewJWTManager(cfg JWTConfig) (*JWTManager, error) {
	if cfg.Issuer == "" {
		cfg.Issuer = "eden-platform"
	}
	if cfg.AccessTokenExpiry == 0 {
		cfg.AccessTokenExpiry = 15 * time.Minute
	}
	if cfg.RefreshTokenExpiry == 0 {
		cfg.RefreshTokenExpiry = 7 * 24 * time.Hour
	}
	if cfg.LegacyUntypedCutoff.IsZero() {
		cfg.LegacyUntypedCutoff = DefaultLegacyUntypedCutoff
	}

	m := &JWTManager{
		keys:   make(map[string]*KeyEntry),
		config: cfg,
		now:    time.Now,
	}

	// Multi-key mode: KeySeedPaths takes priority.
	if len(cfg.KeySeedPaths) > 0 {
		for kid, path := range cfg.KeySeedPaths {
			pk, sk, err := loadKeySeed(path)
			if err != nil {
				return nil, fmt.Errorf("load key seed for kid %q: %w", kid, err)
			}
			m.keys[kid] = &KeyEntry{PrivateKey: sk, PublicKey: pk}
		}
		if cfg.ActiveKID == "" {
			return nil, fmt.Errorf("ActiveKID must be set when KeySeedPaths is non-empty")
		}
		if _, ok := m.keys[cfg.ActiveKID]; !ok {
			return nil, fmt.Errorf("ActiveKID %q not found in KeySeedPaths", cfg.ActiveKID)
		}
		m.activeKID = cfg.ActiveKID
		slog.Info("loaded ML-DSA-65 key pairs from seed files", "count", len(m.keys), "active_kid", m.activeKID)
		return m, nil
	}

	// Single-key backward-compat mode.
	if cfg.KeySeedPath != "" {
		pk, sk, err := loadKeySeed(cfg.KeySeedPath)
		if err == nil {
			slog.Info("loaded ML-DSA-65 key pair from seed file")
			m.keys["default"] = &KeyEntry{PrivateKey: sk, PublicKey: pk}
			m.activeKID = "default"
			return m, nil
		}
		slog.Warn("failed to load JWT key seed, generating ephemeral keys", "error", err)
	}

	// Ephemeral fallback (dev only).
	slog.Warn("using auto-generated ML-DSA-65 key pair (dev only)")
	pk, sk, err := GenerateKeyPair()
	if err != nil {
		return nil, fmt.Errorf("generate key pair: %w", err)
	}
	m.keys["ephemeral"] = &KeyEntry{PrivateKey: sk, PublicKey: pk}
	m.activeKID = "ephemeral"
	return m, nil
}

// keyfunc returns a jwt.Keyfunc that selects the correct public key by kid.
// Tokens without a kid header fall back to the active key for backward compatibility.
func (m *JWTManager) keyfunc(t *jwt.Token) (interface{}, error) {
	if t.Method.Alg() != "ML-DSA-65" {
		return nil, fmt.Errorf("unexpected signing method: %v", t.Header["alg"])
	}
	kid, ok := t.Header["kid"].(string)
	if !ok || kid == "" {
		// Backward compat: tokens issued before kid support fall back to active key.
		return m.keys[m.activeKID].PublicKey, nil
	}
	entry, ok := m.keys[kid]
	if !ok {
		return nil, fmt.Errorf("unknown kid: %s", kid)
	}
	return entry.PublicKey, nil
}

// CreateAccessTokenWithScopes is CreateAccessToken with an explicit scopes
// parameter. Used by issuance flows (e.g. SignInNavigators) that need to set
// per-product capability scopes alongside the standard B2B claims.
//
// Backward compat: the existing CreateAccessToken is preserved as a thin
// delegate that passes scopes=nil. Tokens issued via CreateAccessToken are
// wire-format identical to pre-Scopes-field behavior because the
// `omitempty` tag drops nil/empty slices from the JSON payload.
func (m *JWTManager) CreateAccessTokenWithScopes(
	userID, companyID, role string,
	roleLevel int,
	companyIDs, scopes []string,
) (string, error) {
	now := time.Now()
	claims := &Claims{
		RegisteredClaims: jwt.RegisteredClaims{
			Subject:   userID,
			Issuer:    m.config.Issuer,
			ExpiresAt: jwt.NewNumericDate(now.Add(m.config.AccessTokenExpiry)),
			IssuedAt:  jwt.NewNumericDate(now),
			ID:        generateJTI(),
		},
		TokenUse:   TokenUseAccess,
		UserID:     userID,
		CompanyID:  companyID,
		CompanyIDs: companyIDs,
		Role:       role,
		RoleLevel:  roleLevel,
		Scopes:     scopes,
	}
	token := jwt.NewWithClaims(signingMethodMLDSA65, claims)
	token.Header["kid"] = m.activeKID
	return token.SignedString(m.keys[m.activeKID].PrivateKey)
}

// CreateAccessToken creates a signed ML-DSA-65 access token with a kid header.
//
// This signature is preserved for backward compatibility — all existing
// staff issuance callers (auth.Service.Login, auth.Service.SignUp,
// sso.go) keep compiling. The body delegates to CreateAccessTokenWithScopes
// with scopes=nil; omitempty drops the field from the wire format.
func (m *JWTManager) CreateAccessToken(userID, companyID, role string, roleLevel int, companyIDs []string) (string, error) {
	return m.CreateAccessTokenWithScopes(userID, companyID, role, roleLevel, companyIDs, nil)
}

// CreateHouseholdAccessToken creates a signed ML-DSA-65 access token scoped
// to a household. childID and childMode are optional — pass "" / false for
// a parent-mode token.
//
// B2B claims (CompanyID, Role, RoleLevel, CompanyIDs) are left zero-valued
// — they are orthogonal axes. Consumers that need to mix the two axes (rare)
// can construct a *Claims directly and sign via the lower-level jwt library,
// but the supported path is one or the other.
//
// Use this method from AOFamily-AI / AOFamily-Browser / AOFamily-Connect /
// Eden Family backends when issuing tokens for a family session. Use
// CreateAccessToken for the existing B2B issuance path.
func (m *JWTManager) CreateHouseholdAccessToken(userID, householdID, childID string, childMode bool) (string, error) {
	now := time.Now()
	claims := &Claims{
		RegisteredClaims: jwt.RegisteredClaims{
			Subject:   userID,
			Issuer:    m.config.Issuer,
			ExpiresAt: jwt.NewNumericDate(now.Add(m.config.AccessTokenExpiry)),
			IssuedAt:  jwt.NewNumericDate(now),
			ID:        generateJTI(),
		},
		TokenUse:    TokenUseAccess,
		UserID:      userID,
		HouseholdID: householdID,
		ChildID:     childID,
		ChildMode:   childMode,
	}
	token := jwt.NewWithClaims(signingMethodMLDSA65, claims)
	token.Header["kid"] = m.activeKID
	return token.SignedString(m.keys[m.activeKID].PrivateKey)
}

// CreateRefreshToken creates a signed ML-DSA-65 refresh token with a kid
// header and token_use "refresh". It is bound to no company and no OAuth
// client, so Service.RefreshToken re-mints a company-less access token from
// it. Use CreateCompanyRefreshToken for a company-scoped session and
// CreateClientRefreshToken for tokens handed to an OAuth client.
func (m *JWTManager) CreateRefreshToken(userID string) (string, error) {
	return m.createRefreshToken(userID, "", "")
}

// CreateCompanyRefreshToken creates a refresh token bound to the company the
// session was issued for (cid claim). A refresh re-mints for that company
// only, with the role the user holds there at refresh time.
func (m *JWTManager) CreateCompanyRefreshToken(userID, companyID string) (string, error) {
	if companyID == "" {
		return "", fmt.Errorf("create company refresh token: empty company id")
	}
	return m.createRefreshToken(userID, "", companyID)
}

// CreateClientRefreshToken creates a refresh token bound to an OAuth client:
// its aud claim is clientID. Refresh grants must check the binding (see
// Service.RefreshTokenForClient).
func (m *JWTManager) CreateClientRefreshToken(userID, clientID string) (string, error) {
	if clientID == "" {
		return "", fmt.Errorf("create client refresh token: empty client id")
	}
	return m.createRefreshToken(userID, clientID, "")
}

// CreateClientCompanyRefreshToken is CreateClientRefreshToken that also binds
// the company (used when rotating a client-bound, company-bound token).
func (m *JWTManager) CreateClientCompanyRefreshToken(userID, clientID, companyID string) (string, error) {
	if clientID == "" {
		return "", fmt.Errorf("create client refresh token: empty client id")
	}
	return m.createRefreshToken(userID, clientID, companyID)
}

func (m *JWTManager) createRefreshToken(userID, clientID, companyID string) (string, error) {
	now := time.Now()
	claims := &typedClaims{
		RegisteredClaims: jwt.RegisteredClaims{
			Subject:   userID,
			Issuer:    m.config.Issuer,
			ExpiresAt: jwt.NewNumericDate(now.Add(m.config.RefreshTokenExpiry)),
			IssuedAt:  jwt.NewNumericDate(now),
			ID:        generateJTI(),
		},
		TokenUse:  TokenUseRefresh,
		CompanyID: companyID,
	}
	if clientID != "" {
		claims.Audience = jwt.ClaimStrings{clientID}
	}
	token := jwt.NewWithClaims(signingMethodMLDSA65, claims)
	token.Header["kid"] = m.activeKID
	return token.SignedString(m.keys[m.activeKID].PrivateKey)
}

// ValidateAccessToken parses and validates an access token, returning the
// claims. The token must carry token_use "access".
func (m *JWTManager) ValidateAccessToken(tokenStr string) (*Claims, error) {
	claims := &Claims{}
	token, err := jwt.ParseWithClaims(tokenStr, claims, m.keyfunc)
	if err != nil {
		return nil, fmt.Errorf("parse access token: %w", err)
	}
	if !token.Valid {
		return nil, fmt.Errorf("invalid access token")
	}
	use := claims.TokenUse
	if use == "" && m.legacyWindowOpen() && claims.UserID != "" && len(claims.Audience) == 0 {
		// Pre-#80 access token: only access tokens ever carried uid.
		use = TokenUseAccess
	}
	if use != TokenUseAccess {
		return nil, fmt.Errorf("invalid access token: token_use %q", claims.TokenUse)
	}
	if claims.TokenUse == "" {
		m.noteLegacy(TokenUseAccess)
	}
	return claims, nil
}

// ValidateRefreshToken parses and validates a refresh token. The token must
// carry token_use "refresh". Callers that need the client binding use
// ValidateRefreshTokenClaims.
func (m *JWTManager) ValidateRefreshToken(tokenStr string) (*jwt.RegisteredClaims, error) {
	c, err := m.ValidateRefreshTokenClaims(tokenStr)
	if err != nil {
		return nil, err
	}
	return &c.RegisteredClaims, nil
}

// ValidateRefreshTokenClaims is ValidateRefreshToken returning the full
// refresh claims, including the token_use and the client binding (aud).
func (m *JWTManager) ValidateRefreshTokenClaims(tokenStr string) (*RefreshClaims, error) {
	claims, err := m.parseTyped(tokenStr, TokenUseRefresh)
	if err != nil {
		return nil, fmt.Errorf("parse refresh token: %w", err)
	}
	return &RefreshClaims{RegisteredClaims: claims.RegisteredClaims, TokenUse: claims.TokenUse, CompanyID: claims.CompanyID}, nil
}

// legacyWindowOpen reports whether tokens without a token_use claim may still
// be classified by shape (the #80 migration window).
func (m *JWTManager) legacyWindowOpen() bool {
	return !m.config.RejectLegacyUntyped && m.now().Before(m.config.LegacyUntypedCutoff)
}

// parseTyped parses an ML-DSA-65 token into typedClaims and requires the
// given token_use.
func (m *JWTManager) parseTyped(tokenStr, use string) (*typedClaims, error) {
	claims := &typedClaims{}
	token, err := jwt.ParseWithClaims(tokenStr, claims, m.keyfunc)
	if err != nil {
		return nil, err
	}
	if !token.Valid {
		return nil, fmt.Errorf("invalid token")
	}
	got := claims.TokenUse
	if got == "" && m.legacyWindowOpen() {
		got = legacyUseOf(claims)
	}
	if got != use {
		return nil, fmt.Errorf("token_use %q, want %q", claims.TokenUse, use)
	}
	if claims.TokenUse == "" {
		m.noteLegacy(use)
	}
	return claims, nil
}

// CreateShortLivedToken creates a signed JWT with the given subject and expiry
// and token_use "short_lived". Used for SSO state parameters, email
// verification, etc.
func (m *JWTManager) CreateShortLivedToken(subject string, expiry time.Duration) (string, error) {
	now := time.Now()
	claims := &typedClaims{
		RegisteredClaims: jwt.RegisteredClaims{
			Subject:   subject,
			Issuer:    m.config.Issuer,
			ExpiresAt: jwt.NewNumericDate(now.Add(expiry)),
			IssuedAt:  jwt.NewNumericDate(now),
			ID:        generateJTI(),
		},
		TokenUse: TokenUseShortLived,
	}
	token := jwt.NewWithClaims(signingMethodMLDSA65, claims)
	token.Header["kid"] = m.activeKID
	return token.SignedString(m.keys[m.activeKID].PrivateKey)
}

// ValidateShortLivedToken parses and validates a short-lived token, returning
// the subject. The token must carry token_use "short_lived".
func (m *JWTManager) ValidateShortLivedToken(tokenStr string) (string, error) {
	claims, err := m.parseTyped(tokenStr, TokenUseShortLived)
	if err != nil {
		return "", fmt.Errorf("parse short-lived token: %w", err)
	}
	return claims.Subject, nil
}

// stateHMACKey derives a stable 32-byte HMAC key from the active ML-DSA-65
// signing key. It exists so short-lived, SELF-VERIFIED tokens (SSO state, email
// verification) can carry a COMPACT HS256 signature (~32 bytes) instead of the
// ~3.3KB ML-DSA-65 one. That size matters when an upstream party embeds the
// token somewhere bounded — e.g. AO ID stuffs the SSO `state` into a cookie
// whose TOTAL must stay under the browser's ~4KB per-cookie limit; an ML-DSA
// state overflows it and the browser silently drops the cookie.
//
// Derivation is deterministic from the active key material, so every replica
// computes the same key with NO extra config/secret. Domain-separated so it can
// never collide with any other use of the key bytes.
func (m *JWTManager) stateHMACKey() ([]byte, error) {
	entry, ok := m.keys[m.activeKID]
	if !ok || entry.PrivateKey == nil {
		return nil, fmt.Errorf("no active signing key")
	}
	h := sha256.New()
	h.Write([]byte("eden-platform/short-lived-hs256/v1\x00"))
	h.Write(entry.PrivateKey.Bytes())
	return h.Sum(nil), nil
}

// CreateCompactShortLivedToken mints a short-lived token like
// CreateShortLivedToken but with a compact HS256 signature (see stateHMACKey),
// so the token stays small. Use ONLY for tokens this same service both signs and
// verifies (SSO state, email/verify links) — NEVER for tokens verified by other
// parties through the ML-DSA JWKS.
func (m *JWTManager) CreateCompactShortLivedToken(subject string, expiry time.Duration) (string, error) {
	key, err := m.stateHMACKey()
	if err != nil {
		return "", err
	}
	now := time.Now()
	claims := &typedClaims{
		RegisteredClaims: jwt.RegisteredClaims{
			Subject:   subject,
			Issuer:    m.config.Issuer,
			ExpiresAt: jwt.NewNumericDate(now.Add(expiry)),
			IssuedAt:  jwt.NewNumericDate(now),
			ID:        generateJTI(),
		},
		TokenUse: TokenUseShortLived,
	}
	return jwt.NewWithClaims(jwt.SigningMethodHS256, claims).SignedString(key)
}

// ValidateCompactShortLivedToken parses and validates a token minted by
// CreateCompactShortLivedToken, returning the subject. Rejects any non-HS256 alg
// (defence against alg-confusion with the ML-DSA path).
func (m *JWTManager) ValidateCompactShortLivedToken(tokenStr string) (string, error) {
	key, err := m.stateHMACKey()
	if err != nil {
		return "", err
	}
	claims := &typedClaims{}
	token, err := jwt.ParseWithClaims(tokenStr, claims, func(t *jwt.Token) (interface{}, error) {
		if t.Method.Alg() != jwt.SigningMethodHS256.Alg() {
			return nil, fmt.Errorf("unexpected signing method: %v", t.Header["alg"])
		}
		return key, nil
	})
	if err != nil {
		return "", fmt.Errorf("parse compact short-lived token: %w", err)
	}
	if !token.Valid {
		return "", fmt.Errorf("invalid token")
	}
	// The HMAC key is used only for these tokens, so the key already separates
	// them from every ML-DSA-65 type; the claim keeps the rule uniform. An
	// untyped compact token is pre-#80 and accepted only in the window.
	if claims.TokenUse != TokenUseShortLived && !(claims.TokenUse == "" && m.legacyWindowOpen()) {
		return "", fmt.Errorf("invalid token: token_use %q", claims.TokenUse)
	}
	if claims.TokenUse == "" {
		m.noteLegacy("compact_" + TokenUseShortLived)
	}
	return claims.Subject, nil
}

// PublicKeys returns a snapshot of the kid → public-key map. The returned
// map is a fresh copy so callers can iterate it without holding internal
// JWTManager state. Used by the AO ID JWKS endpoint to enumerate keys
// for federation.
func (m *JWTManager) PublicKeys() map[string]*mldsa65.PublicKey {
	out := make(map[string]*mldsa65.PublicKey, len(m.keys))
	for kid, entry := range m.keys {
		out[kid] = entry.PublicKey
	}
	return out
}

// ActiveKID returns the kid currently used for signing new tokens. JWKS
// consumers may flag this kid as the "preferred" verification key.
func (m *JWTManager) ActiveKID() string {
	return m.activeKID
}

// ActivePrivateKey returns the private key currently used for signing
// new tokens. Used by the AO ID issuer to sign custom claim sets (ID
// tokens) without re-implementing the mldsa key plumbing. Returns nil
// when no active key is configured.
func (m *JWTManager) ActivePrivateKey() *mldsa65.PrivateKey {
	entry, ok := m.keys[m.activeKID]
	if !ok {
		return nil
	}
	return entry.PrivateKey
}

// GenerateKeyPair generates a new ML-DSA-65 key pair.
func GenerateKeyPair() (*mldsa65.PublicKey, *mldsa65.PrivateKey, error) {
	return mldsa65.GenerateKey(rand.Reader)
}

// GenerateKeySeed generates a 32-byte random seed suitable for ML-DSA-65 key
// derivation. Store this seed securely — it is equivalent to the private key.
func GenerateKeySeed() ([mldsa65.SeedSize]byte, error) {
	var seed [mldsa65.SeedSize]byte
	if _, err := rand.Read(seed[:]); err != nil {
		return seed, fmt.Errorf("generate seed: %w", err)
	}
	return seed, nil
}

func generateJTI() string {
	b := make([]byte, 16)
	_, _ = rand.Read(b)
	return fmt.Sprintf("%x", b)
}

// loadKeySeed reads a 32-byte seed file and derives the ML-DSA-65 key pair.
func loadKeySeed(path string) (*mldsa65.PublicKey, *mldsa65.PrivateKey, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, nil, fmt.Errorf("read key seed: %w", err)
	}
	if len(data) != mldsa65.SeedSize {
		return nil, nil, fmt.Errorf("key seed must be exactly %d bytes, got %d", mldsa65.SeedSize, len(data))
	}
	var seed [mldsa65.SeedSize]byte
	copy(seed[:], data)
	pk, sk := mldsa65.NewKeyFromSeed(&seed)
	return pk, sk, nil
}
