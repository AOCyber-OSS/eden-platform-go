package auth

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"math/big"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"

	"github.com/google/uuid"
	"go.aocyber.ai/eden-platform-go/platform/rbac"

	gooidc "github.com/coreos/go-oidc/v3/oidc"
	"github.com/crewjam/saml"
	"github.com/crewjam/saml/samlsp"
	"golang.org/x/oauth2"
)

// SSOService handles OIDC and SAML SSO flows.
type SSOService struct {
	store      AuthStore
	jwtManager *JWTManager
	baseURL    string

	// Cached providers
	oidcMu        sync.RWMutex
	oidcProviders map[string]*oidcCachedProvider

	// SAML SP certificate (auto-generated for dev)
	samlCert tls.Certificate

	// callback is the code+state → tokens completion used by the OIDC HTTP
	// callback handler. It defaults to HandleOIDCCallbackWithState; tests inject
	// a canned result so the redirect tail can be exercised without real OIDC
	// discovery. (Mirrors the seam SocialAuthService already uses.)
	callback func(ctx context.Context, code, stateJWT string) (*AuthResponse, string, error)

	// handoffStore backs the ?code= callback contract (AOID obj-50 SDK-08 / D6):
	// the token pair is parked here and the redirect carries only a reference.
	handoffStore HandoffStore

	// egress is the outbound policy for every tenant-controlled fetch
	// (OIDC discovery/JWKS/token, SAML metadata); see sso_egress.go (#85).
	egress *ssoEgress
}

// SetHandoffStore replaces the per-process handoff store.
//
// REQUIRED for any deployment with more than one replica unless the callback
// redirect and the subsequent /auth/oidc/exchange POST are pinned to the same
// pod by session affinity. The default store keeps both the token payload and
// the single-use marker in process memory, so a code minted on pod A is not
// redeemable on pod B — it fails closed (a failed login), never open.
func (s *SSOService) SetHandoffStore(store HandoffStore) {
	s.handoffStore = store
}

type oidcCachedProvider struct {
	provider *gooidc.Provider
	config   oauth2.Config
}

// NewSSOService creates a new SSO service.
func NewSSOService(store AuthStore, jwtManager *JWTManager, baseURL string) *SSOService {
	svc := &SSOService{
		store:         store,
		jwtManager:    jwtManager,
		baseURL:       strings.TrimRight(baseURL, "/"),
		oidcProviders: make(map[string]*oidcCachedProvider),
		handoffStore:  NewInMemoryHandoffStore(),
		egress:        defaultSSOEgress(),
	}
	svc.callback = svc.HandleOIDCCallbackWithState

	// Generate self-signed SAML SP certificate for development
	cert, err := generateSelfSignedCert()
	if err != nil {
		slog.Warn("failed to generate SAML SP certificate", "error", err)
	} else {
		svc.samlCert = cert
	}

	return svc
}

// ProviderPreset maps well-known provider names to their OIDC issuer URLs.
var ProviderPresets = map[string]struct {
	IssuerURL   string
	DisplayName string
}{
	"microsoft": {
		IssuerURL:   "https://login.microsoftonline.com/common/v2.0",
		DisplayName: "Microsoft",
	},
	"google": {
		IssuerURL:   "https://accounts.google.com",
		DisplayName: "Google",
	},
}

// InitiateOIDC starts an OIDC authorization code flow for the given company and provider.
// Provider can be "microsoft", "google", or "oidc" (custom).
// redirectURI is encoded into the state JWT so the callback knows where to send the user.
// Returns the authorization URL the client should redirect to, plus the state JWT.
func (s *SSOService) InitiateOIDC(ctx context.Context, companyID uuid.UUID, provider, redirectURI string) (authURL string, state string, err error) {
	if provider == "" {
		provider = "oidc"
	}

	ssoConfig, err := s.store.GetSSOConfig(ctx, companyID, provider)
	if err != nil {
		return "", "", fmt.Errorf("SSO provider %q not configured for this company", provider)
	}

	// Resolve issuer URL from preset if empty
	if ssoConfig.IssuerURL == "" {
		if preset, ok := ProviderPresets[provider]; ok {
			ssoConfig.IssuerURL = preset.IssuerURL
		} else {
			return "", "", fmt.Errorf("no issuer URL configured for provider %q", provider)
		}
	}

	cached, err := s.getOrCreateOIDCProvider(ctx, ssoConfig)
	if err != nil {
		return "", "", fmt.Errorf("create OIDC provider: %w", err)
	}

	// Generate a per-authorization PKCE verifier (RFC 7636, 32 octets). AOID is
	// OAuth 2.1 PKCE-mandatory, so the authorize URL MUST carry an S256
	// code_challenge; the verifier is threaded through the state JWT so it
	// survives the stateless redirect and can be replayed on Exchange. The
	// params are additive and transparent to IdPs (Google/Microsoft/customer
	// OIDC) that do not enforce PKCE.
	verifier := oauth2.GenerateVerifier()

	// Generate state as signed JWT (stateless, works across instances)
	state, err = s.createStateJWT(companyID, provider, redirectURI, verifier)
	if err != nil {
		return "", "", fmt.Errorf("create state: %w", err)
	}

	authURL = cached.config.AuthCodeURL(state, oauth2.S256ChallengeOption(verifier))
	return authURL, state, nil
}

// createStateJWT creates a short-lived signed JWT encoding the SSO flow context.
// The PKCE verifier is carried as a 4th "|"-delimited field so it survives the
// stateless redirect. Legacy states written before PKCE carried only the first
// three fields; parseStateJWT still accepts that shape (empty verifier).
func (s *SSOService) createStateJWT(companyID uuid.UUID, provider, redirectURI, verifier string) (string, error) {
	// Encode context as subject with a 10-minute expiry.
	// Format: "companyID|provider|redirectURI|pkceVerifier"
	subject := companyID.String() + "|" + provider + "|" + redirectURI + "|" + verifier
	// Sign with a COMPACT HS256 signature, not the ~3.3KB ML-DSA-65 one. The
	// state is a short-lived, self-verified CSRF/PKCE carrier, and an upstream
	// OIDC provider (AO ID) embeds it into a cookie whose total must stay under
	// the browser's ~4KB per-cookie limit — an ML-DSA state (~4.8KB) overflows it,
	// the browser drops the cookie, and the login dead-ends at "No pending login
	// request". See JWTManager.CreateCompactShortLivedToken.
	return s.jwtManager.CreateCompactShortLivedToken(subject, 10*time.Minute)
}

// parseStateJWT decodes and validates the state JWT, returning companyID,
// provider, redirectURI, and the PKCE verifier.
//
// Back-compat: a legacy 3-field state (companyID|provider|redirectURI, written
// before PKCE) parses cleanly and yields an empty verifier, so an in-flight
// redirect issued just before deploy does not 500. Fewer than 3 fields is still
// malformed. The PKCE addition does not weaken state validation.
func (s *SSOService) parseStateJWT(stateJWT string) (companyID uuid.UUID, provider, redirectURI, verifier string, err error) {
	subject, err := s.jwtManager.ValidateCompactShortLivedToken(stateJWT)
	if err != nil {
		// Back-compat: a state minted before the compact-signature switch (or by a
		// not-yet-rolled replica during a deploy) carries an ML-DSA-65 signature.
		// Fall back so in-flight logins across a rolling deploy don't 500.
		subject, err = s.jwtManager.ValidateShortLivedToken(stateJWT)
		if err != nil {
			return uuid.Nil, "", "", "", fmt.Errorf("invalid state: %w", err)
		}
	}

	parts := strings.SplitN(subject, "|", 4)
	if len(parts) < 3 {
		return uuid.Nil, "", "", "", fmt.Errorf("malformed state")
	}

	companyID, err = uuid.Parse(parts[0])
	if err != nil {
		return uuid.Nil, "", "", "", fmt.Errorf("invalid company_id in state")
	}

	if len(parts) == 4 {
		verifier = parts[3]
	}

	return companyID, parts[1], parts[2], verifier, nil
}

// HandleOIDCCallbackWithState handles the OIDC redirect callback using the state JWT.
// Extracts companyID and provider from state, exchanges code, provisions user, stores OAuth tokens.
// Returns AuthResponse and the redirectURI from state (so caller knows where to send the user).
func (s *SSOService) HandleOIDCCallbackWithState(ctx context.Context, code, stateJWT string) (*AuthResponse, string, error) {
	companyID, provider, redirectURI, verifier, err := s.parseStateJWT(stateJWT)
	if err != nil {
		return nil, "", fmt.Errorf("invalid state: %w", err)
	}

	resp, err := s.HandleOIDCCallbackWithVerifier(ctx, code, provider, companyID, verifier)
	if err != nil {
		return nil, "", err
	}

	return resp, redirectURI, nil
}

// HandleOIDCCallback handles the OIDC redirect callback with authorization code.
// Performs JIT provisioning: creates user if not found, links to company.
// Stores the OAuth access/refresh tokens for future API use.
//
// This public signature is preserved for backward compatibility. It delegates
// to HandleOIDCCallbackWithVerifier with an empty PKCE verifier, which is
// byte-for-byte the pre-PKCE Exchange behavior (no code_verifier posted).
func (s *SSOService) HandleOIDCCallback(ctx context.Context, code, provider string, companyID uuid.UUID) (*AuthResponse, error) {
	return s.HandleOIDCCallbackWithVerifier(ctx, code, provider, companyID, "")
}

// HandleOIDCCallbackWithVerifier is HandleOIDCCallback with an explicit PKCE
// verifier. When verifier is non-empty, the code exchange posts the matching
// code_verifier (required by AOID's OAuth 2.1 PKCE-mandatory /oauth/token).
// When verifier is empty, NO code_verifier is sent — keeping the exchange
// byte-for-byte identical to the pre-PKCE path so existing Google/Microsoft/
// customer OIDC SSO (and any in-flight legacy state) is unaffected.
func (s *SSOService) HandleOIDCCallbackWithVerifier(ctx context.Context, code, provider string, companyID uuid.UUID, verifier string) (*AuthResponse, error) {
	ssoConfig, err := s.store.GetSSOConfig(ctx, companyID, provider)
	if err != nil {
		return nil, fmt.Errorf("SSO provider %q not configured for this company", provider)
	}

	cached, err := s.getOrCreateOIDCProvider(ctx, ssoConfig)
	if err != nil {
		return nil, fmt.Errorf("create OIDC provider: %w", err)
	}

	// Exchange code for tokens. Only attach the PKCE verifier when present, so
	// the empty-verifier path is identical to the legacy/non-PKCE exchange.
	var exchangeOpts []oauth2.AuthCodeOption
	if verifier != "" {
		exchangeOpts = append(exchangeOpts, oauth2.VerifierOption(verifier))
	}
	// The token endpoint comes from the tenant-controlled discovery
	// document, so the exchange goes through the egress policy too (#85).
	oauth2Token, err := cached.config.Exchange(gooidc.ClientContext(ctx, s.egress.client), code, exchangeOpts...)
	if err != nil {
		return nil, fmt.Errorf("exchange authorization code: %w", err)
	}

	// Extract and verify ID token
	rawIDToken, ok := oauth2Token.Extra("id_token").(string)
	if !ok {
		return nil, fmt.Errorf("no id_token in token response")
	}

	// Named idTokenVerifier to avoid shadowing the PKCE code verifier parameter.
	idTokenVerifier := cached.provider.Verifier(&gooidc.Config{ClientID: ssoConfig.ClientID})
	idToken, err := idTokenVerifier.Verify(ctx, rawIDToken)
	if err != nil {
		return nil, fmt.Errorf("verify ID token: %w", err)
	}

	// Extract claims
	var claims struct {
		Email string `json:"email"`
		Name  string `json:"name"`
	}
	if err := idToken.Claims(&claims); err != nil {
		return nil, fmt.Errorf("extract ID token claims: %w", err)
	}

	if claims.Email == "" {
		return nil, fmt.Errorf("email claim not found in ID token")
	}

	authResp, err := s.jitProvision(ctx, claims.Email, claims.Name, companyID, provider)
	if err != nil {
		return nil, err
	}

	// Store the provider's OAuth tokens for future API use (email sync, calendar, etc.)
	if oauth2Token.AccessToken != "" {
		_ = s.store.UpsertOAuthCredential(ctx, OAuthCredential{
			CompanyID:    companyID,
			UserID:       authResp.User.ID,
			Provider:     provider,
			AccessToken:  oauth2Token.AccessToken,
			RefreshToken: oauth2Token.RefreshToken,
			TokenExpiry:  oauth2Token.Expiry,
			Scopes:       ssoConfig.ExtraScopes,
		})
	}

	return authResp, nil
}

// InitiateSAML starts a SAML authentication flow for the given company.
func (s *SSOService) InitiateSAML(ctx context.Context, companyID uuid.UUID) (string, error) {
	ssoConfig, err := s.store.GetSSOConfig(ctx, companyID, "saml")
	if err != nil {
		return "", fmt.Errorf("SAML not configured for this company")
	}

	sp, err := s.createSAMLSP(ctx, ssoConfig)
	if err != nil {
		return "", fmt.Errorf("create SAML SP: %w", err)
	}

	// Build AuthnRequest
	authnReq, err := sp.MakeAuthenticationRequest(sp.GetSSOBindingLocation(saml.HTTPRedirectBinding), saml.HTTPRedirectBinding, saml.HTTPPostBinding)
	if err != nil {
		return "", fmt.Errorf("create SAML authn request: %w", err)
	}

	redirectURL, err := authnReq.Redirect("", sp)
	if err != nil {
		return "", fmt.Errorf("build SAML redirect URL: %w", err)
	}

	return redirectURL.String(), nil
}

// HandleSAMLCallback processes a SAML assertion from an HTTP request.
func (s *SSOService) HandleSAMLCallback(r *http.Request, companyID uuid.UUID) (*AuthResponse, error) {
	ssoConfig, err := s.store.GetSSOConfig(r.Context(), companyID, "saml")
	if err != nil {
		return nil, fmt.Errorf("SAML not configured for this company")
	}

	sp, err := s.createSAMLSP(r.Context(), ssoConfig)
	if err != nil {
		return nil, fmt.Errorf("create SAML SP: %w", err)
	}

	assertion, err := sp.ParseResponse(r, []string{})
	if err != nil {
		return nil, fmt.Errorf("validate SAML assertion: %w", err)
	}

	// Extract attributes
	email := getAssertionAttribute(assertion, "email", "http://schemas.xmlsoap.org/ws/2005/05/identity/claims/emailaddress")
	name := getAssertionAttribute(assertion, "displayName", "http://schemas.xmlsoap.org/ws/2005/05/identity/claims/name")

	if email == "" {
		return nil, fmt.Errorf("email attribute not found in SAML assertion")
	}

	return s.jitProvision(r.Context(), email, name, companyID, "saml")
}

// RegisterHTTPHandlers registers SSO callback HTTP handlers on the given mux.
func (s *SSOService) RegisterHTTPHandlers(mux *http.ServeMux) {
	mux.HandleFunc("GET /auth/oidc/callback", s.handleOIDCCallbackHTTP)
	// POST only: a GET would put the handoff code in the request line and return
	// the token pair in a cacheable response. ServeMux answers a GET with 405.
	mux.HandleFunc("POST /auth/oidc/exchange", s.handleOIDCExchangeHTTP)
	mux.HandleFunc("POST /auth/saml/acs", s.handleSAMLACSHTTP)
	mux.HandleFunc("GET /auth/saml/metadata", s.handleSAMLMetadataHTTP)

	slog.Info("registered SSO HTTP endpoints",
		"oidc_callback", "/auth/oidc/callback",
		"oidc_exchange", "/auth/oidc/exchange (POST)",
		"saml_acs", "/auth/saml/acs",
		"saml_metadata", "/auth/saml/metadata",
	)
}

func (s *SSOService) handleOIDCCallbackHTTP(w http.ResponseWriter, r *http.Request) {
	code := r.URL.Query().Get("code")
	stateJWT := r.URL.Query().Get("state")

	if code == "" || stateJWT == "" {
		http.Error(w, "missing code or state parameter", http.StatusBadRequest)
		return
	}

	resp, redirectURI, err := s.callback(r.Context(), code, stateJWT)
	if err != nil {
		slog.Error("OIDC callback failed", "error", err)
		http.Error(w, "authentication failed", ssoFailureStatus(err))
		return
	}

	// Redirect based on the redirectURI encoded in the state JWT, appending a
	// short-lived AUTHORIZATION CODE — never the tokens.
	//
	// This used to append "access_token=…&refresh_token=…" directly, which put a
	// ~9.6KB ML-DSA token pair into a URL: browser history, Referer headers,
	// every proxy access log on the path. The fragment note below dates from
	// that era; it survives because a hash-routed consumer may still pass a
	// fragment-shaped redirectURI and the ?code= tail must compose with it. A
	// ~200-byte code no longer needs the workaround to dodge a 414.
	//
	// Callers targeting a HASH-routed SPA point redirectURI at the in-app route
	// in the URL fragment (e.g. "https://host/#/auth/complete"); the code then
	// lands INSIDE the fragment ("…/#/auth/complete?code=…"), which the SPA
	// router parses as the route's query. A path-routed SPA passes a plain path
	// and reads window.location.search.
	//
	// The pair is obtainable only by POSTing the code to /auth/oidc/exchange,
	// which returns it in a JSON response BODY. (AOID obj-50 SDK-08 / D6.)
	if redirectURI != "" && redirectURI != "json" {
		handoffCode, err := MintHandoff(r.Context(), s.jwtManager, s.handoffStore, redirectURI, resp)
		if err != nil {
			slog.Error("mint OIDC handoff failed", "error", err)
			http.Error(w, "authentication failed", http.StatusInternalServerError)
			return
		}
		target := appendSSOQuery(redirectURI, "code", handoffCode)
		target = appendSSOQuery(target, "state", stateJWT)
		http.Redirect(w, r, target, http.StatusFound)
		return
	}

	// Default: return JSON (for API clients or testing). This branch was always
	// safe — tokens in a BODY, not a URL — and is the shape the exchange
	// endpoint mimics.
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "no-store")
	fmt.Fprintf(w, `{"access_token":"%s","refresh_token":"%s"}`, resp.AccessToken, resp.RefreshToken)
}

// ssoFailureStatus maps an SSO completion error to its HTTP status: a refused
// login is 403, anything else stays 500. The body is the same either way.
func ssoFailureStatus(err error) int {
	if errors.Is(err, ErrSSOEmailNotMember) {
		return http.StatusForbidden
	}
	return http.StatusInternalServerError
}

// appendSSOQuery appends key=value to a URL, choosing ? or & based on whether
// the URL already carries a query string. A fragment-shaped redirectURI
// ("https://host/#/route") gets the query appended INSIDE the fragment, which is
// what a hash-routed SPA parses.
func appendSSOQuery(rawURL, key, value string) string {
	sep := "?"
	if strings.Contains(rawURL, "?") {
		sep = "&"
	}
	return fmt.Sprintf("%s%s%s=%s", rawURL, sep, key, url.QueryEscape(value))
}

// handleOIDCExchangeHTTP trades an SSO handoff code for the token pair.
//
//	POST /auth/oidc/exchange
//	Content-Type: application/x-www-form-urlencoded
//	code=<handoff>&redirect_uri=<the exact target the code was delivered to>
//
//	200 OK
//	Content-Type: application/json
//	{"access_token":"...","refresh_token":"..."}
//
// POST only, and the parameters are read from the POST BODY specifically
// (PostFormValue, not FormValue) so the code cannot be smuggled back into the
// request line. Every failure is reported identically so the endpoint is not an
// oracle.
func (s *SSOService) handleOIDCExchangeHTTP(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		w.Header().Set("Allow", http.MethodPost)
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	if err := r.ParseForm(); err != nil {
		http.Error(w, "invalid request", http.StatusBadRequest)
		return
	}

	handoffCode := r.PostFormValue("code")
	redirectURI := r.PostFormValue("redirect_uri")
	if handoffCode == "" || redirectURI == "" {
		http.Error(w, "invalid request", http.StatusBadRequest)
		return
	}

	resp, err := RedeemHandoff(r.Context(), s.jwtManager, s.handoffStore, redirectURI, handoffCode)
	if err != nil {
		slog.Warn("OIDC handoff exchange refused", "error", err)
		http.Error(w, "invalid request", http.StatusBadRequest)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("Pragma", "no-cache")
	w.WriteHeader(http.StatusOK)
	_ = json.NewEncoder(w).Encode(map[string]string{
		"access_token":  resp.AccessToken,
		"refresh_token": resp.RefreshToken,
	})
}

func (s *SSOService) handleSAMLACSHTTP(w http.ResponseWriter, r *http.Request) {
	if err := r.ParseForm(); err != nil {
		http.Error(w, "failed to parse form", http.StatusBadRequest)
		return
	}

	companyIDStr := r.FormValue("RelayState") // We encode company_id in RelayState
	companyID, err := uuid.Parse(companyIDStr)
	if err != nil {
		http.Error(w, "invalid company_id in RelayState", http.StatusBadRequest)
		return
	}

	resp, err := s.HandleSAMLCallback(r, companyID)
	if err != nil {
		slog.Error("SAML ACS callback failed", "error", err)
		http.Error(w, "authentication failed", ssoFailureStatus(err))
		return
	}

	w.Header().Set("Content-Type", "application/json")
	fmt.Fprintf(w, `{"access_token":"%s","refresh_token":"%s"}`, resp.AccessToken, resp.RefreshToken)
}

func (s *SSOService) handleSAMLMetadataHTTP(w http.ResponseWriter, r *http.Request) {
	// Return basic SP metadata XML
	spURL := s.baseURL
	metadata := fmt.Sprintf(`<?xml version="1.0" encoding="UTF-8"?>
<md:EntityDescriptor xmlns:md="urn:oasis:names:tc:SAML:2.0:metadata"
    entityID="%s/auth/saml/metadata">
  <md:SPSSODescriptor AuthnRequestsSigned="true"
      protocolSupportEnumeration="urn:oasis:names:tc:SAML:2.0:protocol">
    <md:AssertionConsumerService
        Binding="urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST"
        Location="%s/auth/saml/acs"
        index="0" isDefault="true"/>
  </md:SPSSODescriptor>
</md:EntityDescriptor>`, spURL, spURL)

	w.Header().Set("Content-Type", "application/xml")
	w.WriteHeader(http.StatusOK)
	fmt.Fprint(w, metadata)
}

// ErrSSOEmailNotMember is returned when an SSO login asserts the email of an
// existing account that is not a member of the company whose IdP made the
// assertion. The login is refused: no membership is created and no token is
// issued (#74).
var ErrSSOEmailNotMember = errors.New("auth: SSO email belongs to an account that is not a member of this company")

// jitProvision resolves an SSO login to a user of companyID and issues tokens.
//
// A company's SSOConfig (its IdP) is trusted to vouch for that company's
// people, never for anyone else's. The email in the assertion therefore only
// selects an account; it does not authorize joining the company:
//
//   - email matches an existing MEMBER of companyID: sign them in with their
//     existing role.
//   - email matches an existing account that is NOT a member of companyID:
//     refuse with ErrSSOEmailNotMember. The account may belong to another
//     tenant, and that tenant's IdP is the only one allowed to speak for it.
//     Joining this company takes an explicit membership (an invite), never an
//     email match.
//   - email matches no account: create one and make it a member of companyID.
//     No other tenant has a claim on an address with no account.
func (s *SSOService) jitProvision(ctx context.Context, email, name string, companyID uuid.UUID, provider string) (*AuthResponse, error) {
	email = strings.ToLower(strings.TrimSpace(email))
	if name == "" {
		name = strings.Split(email, "@")[0]
	}

	if user, err := s.store.GetUserByEmail(ctx, email); err == nil {
		return s.signInExistingSSOUser(ctx, user, companyID, provider, email)
	}

	// No account for this email: create one (no password for SSO users) and
	// make it a member of the asserting company.
	user, err := s.createSSOUser(ctx, email, name, companyID)
	if err != nil {
		// A concurrent first login may have created the account between the
		// lookup and this insert (unique email). Resolve the winner under the
		// same member-or-refuse rule instead of failing with a 500.
		if existing, lookupErr := s.store.GetUserByEmail(ctx, email); lookupErr == nil {
			return s.signInExistingSSOUser(ctx, existing, companyID, provider, email)
		}
		return nil, fmt.Errorf("create SSO user: %w", err)
	}
	roleName, roleLevel := "member", 40
	if role, err := s.store.GetUserRole(ctx, companyID, user.ID); err == nil {
		roleName, roleLevel = role.Name, role.RoleLevel
	}
	return s.issueSSOTokens(ctx, user, companyID, roleName, roleLevel)
}

// createSSOUser creates a passwordless SSO user and their member-role
// membership in companyID. When the store is transactional (pgstore and
// devstore both are), the two writes commit together, so a failed membership
// never strands a user row that the refuse rule would lock out for good.
// A non-transactional AuthStore has no delete-user primitive to compensate
// with, so it keeps the two sequential writes and reports the error.
func (s *SSOService) createSSOUser(ctx context.Context, email, name string, companyID uuid.UUID) (User, error) {
	if txStore, ok := s.store.(TxAuthStore); ok {
		return createUserWithMembership(ctx, txStore, email, "", name, companyID, rbac.MemberRoleID)
	}
	user, err := s.store.CreateUser(ctx, email, "", name)
	if err != nil {
		return User{}, err
	}
	if err := s.store.CreateCompanyMembership(ctx, companyID, user.ID, rbac.MemberRoleID); err != nil {
		return User{}, fmt.Errorf("create SSO company membership: %w", err)
	}
	return user, nil
}

// signInExistingSSOUser signs in an existing account that is a member of
// companyID, and refuses (audited) one that is not.
func (s *SSOService) signInExistingSSOUser(ctx context.Context, user User, companyID uuid.UUID, provider, email string) (*AuthResponse, error) {
	role, err := s.store.GetUserRole(ctx, companyID, user.ID)
	if err != nil {
		s.auditSSORefusal(ctx, companyID, provider, email)
		return nil, ErrSSOEmailNotMember
	}
	return s.issueSSOTokens(ctx, user, companyID, role.Name, role.RoleLevel)
}

// auditSSORefusal records a refused login against the asserting company. The
// row has no actor (nobody signed in) and deliberately omits the matched
// account's id: that account may belong to another tenant, and this audit log
// is the asserting tenant's. The email, which the asserting IdP already knows,
// goes to the operator log only.
func (s *SSOService) auditSSORefusal(ctx context.Context, companyID uuid.UUID, provider, email string) {
	slog.Warn("SSO login refused: email belongs to an account that is not a member of the asserting company",
		"company_id", companyID, "provider", provider, "email", email)
	details, _ := json.Marshal(map[string]string{
		"reason":   "email_not_member",
		"provider": provider,
	})
	if err := s.store.CreateAuditLog(ctx, companyID, uuid.Nil, "auth.sso.login_refused", "sso_config", provider, "", details); err != nil {
		slog.Warn("audit SSO refusal failed", "company_id", companyID, "error", err)
	}
}

// issueSSOTokens mints the access/refresh pair for a user of companyID and
// stores the refresh token.
func (s *SSOService) issueSSOTokens(ctx context.Context, user User, companyID uuid.UUID, roleName string, roleLevel int) (*AuthResponse, error) {
	companyIDStr := companyID.String()
	accessToken, err := s.jwtManager.CreateAccessToken(user.ID.String(), companyIDStr, roleName, roleLevel, []string{companyIDStr})
	if err != nil {
		return nil, fmt.Errorf("create access token: %w", err)
	}

	refreshToken, err := s.jwtManager.CreateCompanyRefreshToken(user.ID.String(), companyIDStr)
	if err != nil {
		return nil, fmt.Errorf("create refresh token: %w", err)
	}

	tokenHash := HashToken(refreshToken)
	if err := s.store.CreateRefreshToken(ctx, user.ID, tokenHash, time.Now().Add(s.jwtManager.config.RefreshTokenExpiry)); err != nil {
		return nil, fmt.Errorf("store refresh token: %w", err)
	}

	return &AuthResponse{
		AccessToken:  accessToken,
		RefreshToken: refreshToken,
		User:         user,
	}, nil
}

func (s *SSOService) getOrCreateOIDCProvider(ctx context.Context, cfg SSOConfig) (*oidcCachedProvider, error) {
	key := cfg.CompanyID.String() + ":" + cfg.Provider

	s.oidcMu.RLock()
	if cached, ok := s.oidcProviders[key]; ok {
		s.oidcMu.RUnlock()
		return cached, nil
	}
	s.oidcMu.RUnlock()

	s.oidcMu.Lock()
	defer s.oidcMu.Unlock()

	// Double-check
	if cached, ok := s.oidcProviders[key]; ok {
		return cached, nil
	}

	// Resolve issuer URL from preset if needed
	issuerURL := cfg.IssuerURL
	if issuerURL == "" {
		if preset, ok := ProviderPresets[cfg.Provider]; ok {
			issuerURL = preset.IssuerURL
		}
	}

	// issuerURL is tenant-controlled: check it before any DNS, then discover
	// through the guarded client. go-oidc keeps that client for the JWKS
	// fetches of this provider as well (#85).
	if _, err := s.egress.checkRawURL(issuerURL); err != nil {
		return nil, fmt.Errorf("OIDC issuer URL: %w", err)
	}
	provider, err := gooidc.NewProvider(gooidc.ClientContext(ctx, s.egress.client), issuerURL)
	if err != nil {
		return nil, fmt.Errorf("discover OIDC provider at %s: %w", issuerURL, err)
	}

	// Base scopes + any extra scopes configured
	scopes := []string{gooidc.ScopeOpenID, "profile", "email"}
	scopes = append(scopes, cfg.ExtraScopes...)

	oauthConfig := oauth2.Config{
		ClientID:     cfg.ClientID,
		ClientSecret: cfg.ClientSecret,
		Endpoint:     provider.Endpoint(),
		RedirectURL:  s.baseURL + "/auth/oidc/callback",
		Scopes:       scopes,
	}

	cached := &oidcCachedProvider{provider: provider, config: oauthConfig}
	s.oidcProviders[key] = cached
	return cached, nil
}

func (s *SSOService) createSAMLSP(ctx context.Context, cfg SSOConfig) (*saml.ServiceProvider, error) {
	if cfg.MetadataURL == "" {
		return nil, fmt.Errorf("SAML metadata URL not configured")
	}

	// MetadataURL is tenant-controlled: check it before any DNS, then fetch
	// through the guarded client (#85).
	metadataURL, err := s.egress.checkRawURL(cfg.MetadataURL)
	if err != nil {
		return nil, fmt.Errorf("SAML metadata URL: %w", err)
	}

	rootURL, err := url.Parse(s.baseURL)
	if err != nil {
		return nil, fmt.Errorf("parse base URL: %w", err)
	}

	idpMetadata, err := samlsp.FetchMetadata(ctx, s.egress.client, *metadataURL)
	if err != nil {
		return nil, fmt.Errorf("fetch IdP metadata: %w", err)
	}

	sp := saml.ServiceProvider{
		Key:         s.samlCert.PrivateKey.(*rsa.PrivateKey),
		Certificate: s.samlCert.Leaf,
		MetadataURL: *rootURL,
		AcsURL:      *rootURL,
		IDPMetadata: idpMetadata,
	}
	sp.AcsURL.Path = "/auth/saml/acs"
	sp.MetadataURL.Path = "/auth/saml/metadata"

	return &sp, nil
}

func getAssertionAttribute(assertion *saml.Assertion, names ...string) string {
	if assertion == nil {
		return ""
	}
	for _, stmt := range assertion.AttributeStatements {
		for _, attr := range stmt.Attributes {
			for _, name := range names {
				if attr.Name == name || attr.FriendlyName == name {
					if len(attr.Values) > 0 {
						return attr.Values[0].Value
					}
				}
			}
		}
	}
	return ""
}

func generateSelfSignedCert() (tls.Certificate, error) {
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return tls.Certificate{}, fmt.Errorf("generate RSA key: %w", err)
	}

	template := x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject: pkix.Name{
			CommonName: "Eden Platform SAML SP",
		},
		NotBefore:             time.Now(),
		NotAfter:              time.Now().Add(365 * 24 * time.Hour),
		KeyUsage:              x509.KeyUsageDigitalSignature,
		BasicConstraintsValid: true,
	}

	certDER, err := x509.CreateCertificate(rand.Reader, &template, &template, &key.PublicKey, key)
	if err != nil {
		return tls.Certificate{}, fmt.Errorf("create certificate: %w", err)
	}

	leaf, err := x509.ParseCertificate(certDER)
	if err != nil {
		return tls.Certificate{}, fmt.Errorf("parse certificate: %w", err)
	}

	return tls.Certificate{
		Certificate: [][]byte{certDER},
		PrivateKey:  key,
		Leaf:        leaf,
	}, nil
}
