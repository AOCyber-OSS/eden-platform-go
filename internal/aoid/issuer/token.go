package issuer

import (
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"strings"
	"time"

	"github.com/cloudflare/circl/sign/mldsa/mldsa65"
	"github.com/golang-jwt/jwt/v5"
	"github.com/google/uuid"
	"go.aocyber.ai/eden-platform-go/internal/aoid/clients"
	"go.aocyber.ai/eden-platform-go/platform/auth"
)

// TokenHandler serves POST /oauth2/token. It dispatches by grant_type
// (authorization_code | refresh_token) and emits the standard JSON
// response shape with access_token, id_token, refresh_token, expires_in.
func (i *Issuer) TokenHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		writeTokenError(w, http.StatusMethodNotAllowed, "invalid_request", "POST required")
		return
	}
	if err := r.ParseForm(); err != nil {
		writeTokenError(w, http.StatusBadRequest, "invalid_request", "could not parse form")
		return
	}

	clientID, secret, ok := extractClientCreds(r)
	if !ok {
		writeTokenError(w, http.StatusUnauthorized, "invalid_client", "client credentials required")
		return
	}
	client, err := i.Clients.Authenticate(r.Context(), clientID, secret)
	if err != nil {
		writeTokenError(w, http.StatusUnauthorized, "invalid_client", "invalid client credentials")
		return
	}

	switch r.FormValue("grant_type") {
	case "authorization_code":
		i.handleCodeGrant(w, r, client)
	case "refresh_token":
		i.handleRefreshGrant(w, r, client)
	case "":
		writeTokenError(w, http.StatusBadRequest, "invalid_request", "grant_type required")
	default:
		writeTokenError(w, http.StatusBadRequest, "unsupported_grant_type", "grant_type not supported")
	}
}

// handleCodeGrant exchanges an authorization code for a token bundle.
func (i *Issuer) handleCodeGrant(w http.ResponseWriter, r *http.Request, client *clients.Client) {
	if !client.HasGrant("authorization_code") {
		writeTokenError(w, http.StatusBadRequest, "unauthorized_client", "client cannot use authorization_code grant")
		return
	}
	codeStr := r.FormValue("code")
	if codeStr == "" {
		writeTokenError(w, http.StatusBadRequest, "invalid_request", "code required")
		return
	}
	code, err := i.Codes.Consume(r.Context(), codeStr)
	if err != nil {
		writeTokenError(w, http.StatusBadRequest, "invalid_grant", "code invalid, expired, or already used")
		return
	}
	if code.ClientID != client.ID {
		writeTokenError(w, http.StatusBadRequest, "invalid_grant", "code was issued to a different client")
		return
	}
	if r.FormValue("redirect_uri") != code.RedirectURI {
		writeTokenError(w, http.StatusBadRequest, "invalid_grant", "redirect_uri does not match the one used at /authorize")
		return
	}

	// PKCE verification
	verifier := r.FormValue("code_verifier")
	if verifier == "" {
		writeTokenError(w, http.StatusBadRequest, "invalid_request", "code_verifier required")
		return
	}
	if !verifyPKCE(verifier, code.CodeChallenge) {
		writeTokenError(w, http.StatusBadRequest, "invalid_grant", "PKCE verification failed")
		return
	}

	// Resolve the user.
	uid, err := uuid.Parse(code.UserID)
	if err != nil {
		writeTokenError(w, http.StatusInternalServerError, "server_error", "bad user id")
		return
	}
	user, err := i.UserStore.GetUserByID(r.Context(), uid)
	if err != nil {
		writeTokenError(w, http.StatusInternalServerError, "server_error", "user lookup failed")
		return
	}

	bundle, err := i.mintTokens(user, client.ID, code.Nonce, code.Scope)
	if err != nil {
		slog.Error("aoid: mint tokens", "error", err)
		writeTokenError(w, http.StatusInternalServerError, "server_error", "could not mint tokens")
		return
	}

	// Persist refresh token hash.
	if err := i.persistRefresh(r, user.ID, bundle.RefreshToken); err != nil {
		slog.Error("aoid: persist refresh token", "error", err)
		// non-fatal — tokens still work, but no rotation tracking.
	}

	writeTokenResponse(w, bundle)
}

// handleRefreshGrant rotates a refresh token. The platform/auth.Service
// handles validation + revoke + issue; we wrap it to also re-mint the
// ID token alongside.
func (i *Issuer) handleRefreshGrant(w http.ResponseWriter, r *http.Request, client *clients.Client) {
	if !client.HasGrant("refresh_token") {
		writeTokenError(w, http.StatusBadRequest, "unauthorized_client", "client cannot use refresh_token grant")
		return
	}
	rt := r.FormValue("refresh_token")
	if rt == "" {
		writeTokenError(w, http.StatusBadRequest, "invalid_request", "refresh_token required")
		return
	}
	// Bound to the authenticated client (issue #80): a refresh token issued to
	// another client is invalid_grant, and the rotated token stays bound.
	authResp, err := i.Auth.RefreshTokenForClient(r.Context(), rt, client.ID)
	if err != nil {
		writeTokenError(w, http.StatusBadRequest, "invalid_grant", "invalid or already-used refresh_token")
		return
	}

	// Mint a fresh ID token alongside (no nonce — refresh requests
	// don't carry one; clients should ignore stale ID tokens).
	idTok, err := i.signIDToken(authResp.User, client.ID, "", []string{"openid", "profile", "email"})
	if err != nil {
		slog.Error("aoid: refresh: sign id token", "error", err)
		writeTokenError(w, http.StatusInternalServerError, "server_error", "could not mint id token")
		return
	}

	writeTokenResponse(w, tokenBundle{
		AccessToken:  authResp.AccessToken,
		IDToken:      idTok,
		RefreshToken: authResp.RefreshToken,
		ExpiresIn:    int(15 * time.Minute / time.Second), // platform/auth default
		Scope:        "openid profile email",
	})
}

// tokenBundle is the in-memory shape we marshal to JSON for the token
// endpoint response.
type tokenBundle struct {
	AccessToken  string `json:"access_token"`
	TokenType    string `json:"token_type"`
	ExpiresIn    int    `json:"expires_in"`
	IDToken      string `json:"id_token,omitempty"`
	RefreshToken string `json:"refresh_token,omitempty"`
	Scope        string `json:"scope,omitempty"`
}

func (i *Issuer) mintTokens(user auth.User, clientID, nonce string, scope []string) (tokenBundle, error) {
	// Access token — same shape platform/auth issues for its own
	// callers. Company is left blank; AODex / downstream services can
	// re-derive context after introspecting the user.
	at, err := i.JWT.CreateAccessToken(user.ID.String(), "", "user", 0, nil)
	if err != nil {
		return tokenBundle{}, fmt.Errorf("create access token: %w", err)
	}
	rt, err := i.JWT.CreateClientRefreshToken(user.ID.String(), clientID)
	if err != nil {
		return tokenBundle{}, fmt.Errorf("create refresh token: %w", err)
	}
	idt, err := i.signIDToken(user, clientID, nonce, scope)
	if err != nil {
		return tokenBundle{}, fmt.Errorf("sign id token: %w", err)
	}
	return tokenBundle{
		AccessToken:  at,
		TokenType:    "Bearer",
		ExpiresIn:    int(15 * time.Minute / time.Second),
		IDToken:      idt,
		RefreshToken: rt,
		Scope:        strings.Join(scope, " "),
	}, nil
}

// IDTokenClaims is the OIDC ID token claim set.
type IDTokenClaims struct {
	jwt.RegisteredClaims
	// TokenUse is always auth.TokenUseID (issue #80): the ID token shares the
	// access-token key, and no platform validator accepts this value.
	TokenUse          string `json:"token_use"`
	AuthTime          int64  `json:"auth_time,omitempty"`
	Nonce             string `json:"nonce,omitempty"`
	Email             string `json:"email,omitempty"`
	EmailVerified     bool   `json:"email_verified,omitempty"`
	Name              string `json:"name,omitempty"`
	PreferredUsername string `json:"preferred_username,omitempty"`
}

// signIDToken builds + signs the OIDC ID token using the same
// JWTManager (and key) the access token uses.
func (i *Issuer) signIDToken(user auth.User, audience, nonce string, scope []string) (string, error) {
	now := time.Now()
	claims := IDTokenClaims{
		RegisteredClaims: jwt.RegisteredClaims{
			Subject:   user.ID.String(),
			Issuer:    i.Config.Issuer,
			Audience:  jwt.ClaimStrings{audience},
			ExpiresAt: jwt.NewNumericDate(now.Add(time.Hour)),
			IssuedAt:  jwt.NewNumericDate(now),
			NotBefore: jwt.NewNumericDate(now),
			ID:        randomID(),
		},
		TokenUse: auth.TokenUseID,
		AuthTime: now.Unix(),
		Nonce:    nonce,
	}
	if containsString(scope, "email") {
		claims.Email = user.Email
		claims.EmailVerified = user.IsActive // Phase A heuristic
		claims.PreferredUsername = user.Email
	}
	if containsString(scope, "profile") {
		claims.Name = user.DisplayName
		claims.PreferredUsername = user.Email
	}

	// Use platform/auth's signing method, accessed via JWTManager's
	// PublicKeys + ActiveKID + the unexported signing pieces. Since the
	// JWTManager doesn't expose Sign() generically for ID tokens, we
	// re-implement here using mldsa65 directly. The kid + alg headers
	// match what platform/auth uses so JWKS verification works.
	tok := jwt.NewWithClaims(authMLDSA65SigningMethod, claims)
	tok.Header["kid"] = i.JWT.ActiveKID()
	priv, err := i.privateKeyForActive()
	if err != nil {
		return "", err
	}
	return tok.SignedString(priv)
}

// privateKeyForActive returns the active signing key. JWTManager only
// exposes PublicKeys() — but we need the private key here for ID-token
// signing. We rely on JWTManager.CreateShortLivedToken's behavior: it
// signs with the active key, so we can piggyback. Since we want full
// control over claims, the cleaner path is exposing a Sign helper. For
// Phase A, route signing through CreateShortLivedToken's parent helper
// by delegating to mldsa via the registered signing method.
func (i *Issuer) privateKeyForActive() (*mldsa65.PrivateKey, error) {
	// JWTManager keeps keys private. We expose a helper here that
	// uses CreateShortLivedToken's signing pathway by issuing a token
	// with claims we never inspect — but that doesn't help us if we
	// need different claims. For Phase A the pragmatic answer is to
	// add an accessor to JWTManager. We do so via auth.JWTManager's
	// existing internal API (added in this PR — see auth/jwt.go change).
	pk, err := authPrivateKey(i.JWT)
	if err != nil {
		return nil, err
	}
	return pk, nil
}

// authPrivateKey is wired through a small accessor on JWTManager
// (added in 30-03) so the issuer can sign custom claim sets without
// duplicating mldsa key plumbing.
func authPrivateKey(m *auth.JWTManager) (*mldsa65.PrivateKey, error) {
	pk := m.ActivePrivateKey()
	if pk == nil {
		return nil, errors.New("issuer: no active private key available")
	}
	return pk, nil
}

// authMLDSA65SigningMethod is the jwt.SigningMethod the platform/auth
// package registers for ML-DSA-65. We look it up by name to avoid
// depending on its private symbol.
var authMLDSA65SigningMethod = jwt.GetSigningMethod("ML-DSA-65")

// persistRefresh writes the rotation row for a freshly-issued refresh
// token into the platform/auth store via the same auth.Service API.
// Borrows the package-level HashToken to compute the hash.
func (i *Issuer) persistRefresh(r *http.Request, userID uuid.UUID, refresh string) error {
	// platform/auth.Service exposes RefreshToken (rotate) but not the
	// raw "remember this token" surface. The cleanest path is to call
	// the underlying auth store via a method we add to auth.Service.
	// For Phase A we delegate to auth.RememberRefreshToken which we
	// add in this PR (see auth/service.go change in 30-03).
	return i.Auth.RememberRefreshToken(r.Context(), userID, refresh, time.Now().Add(7*24*time.Hour))
}

// extractClientCreds reads the client_id + client_secret from either
// HTTP Basic or the form body.
func extractClientCreds(r *http.Request) (string, string, bool) {
	if cid, sec, ok := r.BasicAuth(); ok {
		return cid, sec, true
	}
	cid := r.FormValue("client_id")
	sec := r.FormValue("client_secret")
	if cid == "" || sec == "" {
		return "", "", false
	}
	return cid, sec, true
}

// verifyPKCE checks sha256(verifier) base64url-encoded == challenge.
// Method=S256 is the only one we support.
func verifyPKCE(verifier, challenge string) bool {
	h := sha256.Sum256([]byte(verifier))
	got := base64.RawURLEncoding.EncodeToString(h[:])
	return got == challenge
}

// writeTokenResponse marshals the bundle to JSON.
func writeTokenResponse(w http.ResponseWriter, b tokenBundle) {
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("Pragma", "no-cache")
	if b.TokenType == "" {
		b.TokenType = "Bearer"
	}
	_ = json.NewEncoder(w).Encode(b)
}

// writeTokenError emits an OAuth 2.0 error response.
func writeTokenError(w http.ResponseWriter, status int, code, desc string) {
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("Pragma", "no-cache")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(map[string]string{
		"error":             code,
		"error_description": desc,
	})
}

// randomID returns a hex-encoded 16-byte random string for the JWT JTI.
func randomID() string {
	b := make([]byte, 16)
	_, _ = randRead(b)
	return fmt.Sprintf("%x", b)
}

// indirection so the test package can stub if needed.
var randRead = func(p []byte) (int, error) {
	return cryptoRandRead(p)
}
