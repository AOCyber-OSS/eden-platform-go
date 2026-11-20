package auth_test

// TRD 27-01 (Objective 27 — eden-biz AOID SSO): additive S256 PKCE in the
// shared eden-platform SSO framework.
//
// AOID (auth.aocyber.ai) is OAuth 2.1 PKCE-mandatory on EVERY authorization-code
// flow, confidential clients included. eden's SSOService historically called
// oauth2's plain AuthCodeURL(state) + Exchange(ctx, code) — no PKCE — so a
// data-only AOID SSOConfig failed at /oauth/authorize with "code_challenge
// required". These tests pin the additive fix:
//
//   1. InitiateOIDC emits an S256 code_challenge on the authorize URL.
//   2. The PKCE verifier survives the stateless redirect inside the state JWT.
//   3. HandleOIDCCallbackWithState posts the matching code_verifier on Exchange.
//   4. REGRESSION: a plain OIDC IdP that ignores PKCE still authenticates — the
//      additive params are transparent, so existing Google/Microsoft/customer
//      OIDC SSO keeps working (THE mandatory non-PKCE-IdP guard).
//   5. Empty/tampered state is still rejected (state validation not weakened).
//   6. A legacy 3-field state (companyID|provider|redirectURI, no verifier)
//      still parses with an empty verifier (in-flight redirect across deploy).
//
// Fixtures are hand-built (no generated test data): a real in-memory AuthStore
// via devstore.NewMemoryBackend, and a from-scratch fake OIDC provider
// (discovery + JWKS + token) that hand-rolls an RS256 id_token — mirroring the
// established platform/oidcrp/flow_test.go pattern so no JWT lib leaks into the
// test.

import (
	"context"
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/base64"
	"encoding/binary"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"sync"
	"testing"
	"time"

	"go.aocyber.ai/eden-platform-go/platform/auth"
	"go.aocyber.ai/eden-platform-go/platform/devstore"

	"github.com/google/uuid"
)

// hashSHA256PKCE is the hash identifier used with rsa.SignPKCS1v15 when the
// fake OP signs the id_token. Held as a package var so signIDToken doesn't
// repeat the crypto.Hash reference.
var hashSHA256PKCE = crypto.SHA256

// fakePKCEOP is a complete OIDC provider for the SSO PKCE round-trip tests:
// discovery doc, JWKS, and a /token endpoint that (a) captures the posted form
// so the test can assert the code_verifier, and (b) issues an RS256-signed
// id_token whose aud equals the configured client_id (required by
// SSOService — the id_token verifier rejects a mismatched aud).
//
// It deliberately does NOT require code_challenge/code_verifier — modelling a
// plain Google/Microsoft/customer IdP — which is exactly what makes the case-4
// regression proof meaningful: the additive PKCE params must be transparent.
type fakePKCEOP struct {
	t        *testing.T
	srv      *httptest.Server
	rsaKey   *rsa.PrivateKey
	kid      string
	clientID string
	email    string
	name     string
	// emailVerified is the id_token's email_verified claim. nil omits the
	// claim; newFakePKCEOP defaults it to true (#96).
	emailVerified any

	mu             sync.Mutex
	lastTokenForm  url.Values // the form posted to /token by the most recent Exchange
	tokenCallCount int
}

func newFakePKCEOP(t *testing.T, clientID, email, name string) *fakePKCEOP {
	t.Helper()
	rsaKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("rsa gen: %v", err)
	}
	op := &fakePKCEOP{
		t:        t,
		rsaKey:   rsaKey,
		kid:      "sso-pkce-test-kid-1",
		clientID: clientID,
		email:    email,
		name:     name,

		emailVerified: true,
	}
	mux := http.NewServeMux()
	mux.HandleFunc("/.well-known/openid-configuration", op.handleDiscovery)
	mux.HandleFunc("/jwks", op.handleJWKS)
	mux.HandleFunc("/token", op.handleToken)
	op.srv = httptest.NewServer(mux)
	t.Cleanup(op.srv.Close)
	return op
}

func (op *fakePKCEOP) handleDiscovery(w http.ResponseWriter, r *http.Request) {
	resp := map[string]any{
		"issuer":                                op.srv.URL,
		"authorization_endpoint":                op.srv.URL + "/auth",
		"token_endpoint":                        op.srv.URL + "/token",
		"jwks_uri":                              op.srv.URL + "/jwks",
		"id_token_signing_alg_values_supported": []string{"RS256"},
		"response_types_supported":              []string{"code"},
		"subject_types_supported":               []string{"public"},
		// Note: no code_challenge_methods_supported advertised — this OP does
		// NOT require PKCE. The additive params must be ignored gracefully.
	}
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(resp)
}

func (op *fakePKCEOP) handleJWKS(w http.ResponseWriter, r *http.Request) {
	pub := &op.rsaKey.PublicKey
	nBytes := pub.N.Bytes()
	eBytes := make([]byte, 8)
	binary.BigEndian.PutUint64(eBytes, uint64(pub.E))
	// Trim leading zero bytes from E.
	i := 0
	for i < len(eBytes)-1 && eBytes[i] == 0 {
		i++
	}
	eBytes = eBytes[i:]
	jwks := map[string]any{
		"keys": []map[string]any{{
			"kty": "RSA",
			"alg": "RS256",
			"use": "sig",
			"kid": op.kid,
			"n":   base64.RawURLEncoding.EncodeToString(nBytes),
			"e":   base64.RawURLEncoding.EncodeToString(eBytes),
		}},
	}
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(jwks)
}

func (op *fakePKCEOP) handleToken(w http.ResponseWriter, r *http.Request) {
	if err := r.ParseForm(); err != nil {
		http.Error(w, "bad form", http.StatusBadRequest)
		return
	}
	op.mu.Lock()
	// Copy the posted form so the test can assert code_verifier after Exchange.
	op.lastTokenForm = make(url.Values, len(r.Form))
	for k, v := range r.Form {
		op.lastTokenForm[k] = append([]string(nil), v...)
	}
	op.tokenCallCount++
	op.mu.Unlock()

	resp := map[string]any{
		"access_token": "fake-provider-access-token",
		"token_type":   "Bearer",
		"expires_in":   3600,
		"id_token":     op.signIDToken(),
	}
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(resp)
}

// postedVerifier returns the code_verifier captured from the most recent
// /token POST (empty string if none was sent).
func (op *fakePKCEOP) postedVerifier() string {
	op.mu.Lock()
	defer op.mu.Unlock()
	if op.lastTokenForm == nil {
		return ""
	}
	return op.lastTokenForm.Get("code_verifier")
}

// signIDToken issues a minimal RS256 ID token with aud == op.clientID (the
// SSOService id_token verifier rejects a mismatched aud). Hand-rolled JWS so
// no JWT lib enters the test.
func (op *fakePKCEOP) signIDToken() string {
	header := map[string]string{
		"alg": "RS256",
		"typ": "JWT",
		"kid": op.kid,
	}
	now := time.Now()
	payload := map[string]any{
		"iss":   op.srv.URL,
		"sub":   "sso-pkce-user-sub-1",
		"aud":   op.clientID,
		"exp":   now.Add(5 * time.Minute).Unix(),
		"iat":   now.Unix(),
		"email": op.email,
		"name":  op.name,
	}
	if op.emailVerified != nil {
		payload["email_verified"] = op.emailVerified
	}
	hb, _ := json.Marshal(header)
	pb, _ := json.Marshal(payload)
	enc := base64.RawURLEncoding
	signingInput := enc.EncodeToString(hb) + "." + enc.EncodeToString(pb)
	sum := sha256.Sum256([]byte(signingInput))
	sig, err := rsa.SignPKCS1v15(rand.Reader, op.rsaKey, hashSHA256PKCE, sum[:])
	if err != nil {
		op.t.Fatalf("sign id_token: %v", err)
	}
	return signingInput + "." + enc.EncodeToString(sig)
}

// newSSOTestService builds an SSOService backed by a real in-memory AuthStore
// and a real JWTManager (ephemeral key), then upserts an OIDC SSOConfig for a
// freshly-created "AOCyber" company pointing at the fake OP. Returns the
// service and the company id.
func newSSOTestService(t *testing.T, op *fakePKCEOP, clientID string) (*auth.SSOService, uuid.UUID) {
	t.Helper()
	backend := devstore.NewMemoryBackend()
	store := backend.AuthStore()

	jwtManager, err := auth.NewJWTManager(auth.JWTConfig{
		Issuer:             "eden-platform-test",
		AccessTokenExpiry:  time.Minute,
		RefreshTokenExpiry: time.Hour,
	})
	if err != nil {
		t.Fatalf("NewJWTManager: %v", err)
	}

	ctx := context.Background()
	companyID, err := store.CreateCompany(ctx, "AOCyber", "aocyber", "standalone")
	if err != nil {
		t.Fatalf("CreateCompany: %v", err)
	}

	if err := store.UpsertSSOConfig(ctx, auth.SSOConfig{
		CompanyID: companyID,
		Provider:  "oidc",
		IssuerURL: op.srv.URL,
		ClientID:  clientID,
		// A confidential client secret — the fake OP does not enforce it, but
		// the SSOService always supplies one (confidential client mode).
		ClientSecret: "test-client-secret",
		IsActive:     true,
		// These tests JIT-provision first logins; the policy must allow it (#89).
		JITEnabled:           true,
		EmailDomainAllowlist: []string{"aocyber.ai", "example.com"},
	}); err != nil {
		t.Fatalf("UpsertSSOConfig: %v", err)
	}

	svc := auth.NewSSOService(store, jwtManager, "https://api.aocyber.ai")
	allowLoopbackIdPForTest(svc)
	return svc, companyID
}

func TestSSO_PKCE(t *testing.T) {
	const clientID = "eden-biz-client"

	// case 1 — the authorize URL carries an S256 code_challenge.
	t.Run("authorize URL carries S256 code_challenge", func(t *testing.T) {
		op := newFakePKCEOP(t, clientID, "staff@aocyber.ai", "AOCyber Staff")
		svc, companyID := newSSOTestService(t, op, clientID)

		authURL, _, err := svc.InitiateOIDC(context.Background(), companyID, "oidc", "/dashboard")
		if err != nil {
			t.Fatalf("InitiateOIDC: %v", err)
		}
		u, err := url.Parse(authURL)
		if err != nil {
			t.Fatalf("parse authURL: %v", err)
		}
		q := u.Query()
		if got := q.Get("code_challenge_method"); got != "S256" {
			t.Errorf("code_challenge_method = %q, want S256", got)
		}
		if q.Get("code_challenge") == "" {
			t.Error("missing code_challenge on authorize URL")
		}
	})

	// case 2 — the state JWT carries a 32-byte verifier matching the challenge.
	t.Run("state JWT carries a 32-byte verifier matching the challenge", func(t *testing.T) {
		op := newFakePKCEOP(t, clientID, "staff@aocyber.ai", "AOCyber Staff")
		svc, companyID := newSSOTestService(t, op, clientID)

		authURL, state, err := svc.InitiateOIDC(context.Background(), companyID, "oidc", "/dashboard")
		if err != nil {
			t.Fatalf("InitiateOIDC: %v", err)
		}
		u, err := url.Parse(authURL)
		if err != nil {
			t.Fatalf("parse authURL: %v", err)
		}
		challenge := u.Query().Get("code_challenge")

		verifier := svc.StateVerifierForTest(t, state)
		if verifier == "" {
			t.Fatal("state JWT carried an empty PKCE verifier")
		}
		// oauth2.GenerateVerifier uses 32 octets of randomness, base64url (no
		// padding) encoded. Decode and assert exactly 32 bytes.
		raw, err := base64.RawURLEncoding.DecodeString(verifier)
		if err != nil {
			t.Fatalf("verifier is not base64url: %v", err)
		}
		if len(raw) != 32 {
			t.Errorf("verifier decodes to %d bytes, want 32", len(raw))
		}
		// Recompute S256(verifier) the same way oauth2 does and compare.
		sum := sha256.Sum256([]byte(verifier))
		wantChallenge := base64.RawURLEncoding.EncodeToString(sum[:])
		if challenge != wantChallenge {
			t.Errorf("code_challenge = %q, want S256(verifier) = %q", challenge, wantChallenge)
		}
	})

	// case 3 — the exchange posts the matching code_verifier.
	t.Run("exchange posts the matching code_verifier", func(t *testing.T) {
		op := newFakePKCEOP(t, clientID, "staff@aocyber.ai", "AOCyber Staff")
		svc, companyID := newSSOTestService(t, op, clientID)

		_, state, err := svc.InitiateOIDC(context.Background(), companyID, "oidc", "/dashboard")
		if err != nil {
			t.Fatalf("InitiateOIDC: %v", err)
		}
		verifier := svc.StateVerifierForTest(t, state)
		if verifier == "" {
			t.Fatal("expected non-empty verifier in state")
		}

		_, _, err = svc.HandleOIDCCallbackWithState(context.Background(), "auth-code-xyz", state)
		if err != nil {
			t.Fatalf("HandleOIDCCallbackWithState: %v", err)
		}
		posted := op.postedVerifier()
		if posted == "" {
			t.Fatal("token endpoint received no code_verifier")
		}
		if posted != verifier {
			t.Errorf("posted code_verifier = %q, want %q (the verifier from state)", posted, verifier)
		}
	})

	// case 4 — THE regression guard: a non-PKCE-requiring IdP still authenticates.
	t.Run("non-PKCE-requiring IdP still authenticates (regression)", func(t *testing.T) {
		op := newFakePKCEOP(t, clientID, "customer@example.com", "Customer User")
		svc, companyID := newSSOTestService(t, op, clientID)

		_, state, err := svc.InitiateOIDC(context.Background(), companyID, "oidc", "/dashboard")
		if err != nil {
			t.Fatalf("InitiateOIDC: %v", err)
		}
		resp, redirectURI, err := svc.HandleOIDCCallbackWithState(context.Background(), "auth-code-regression", state)
		if err != nil {
			t.Fatalf("round-trip against non-PKCE IdP failed: %v", err)
		}
		if resp == nil || resp.AccessToken == "" {
			t.Fatal("expected a non-empty eden access token from the round-trip")
		}
		if resp.User.Email != "customer@example.com" {
			t.Errorf("provisioned user email = %q, want customer@example.com", resp.User.Email)
		}
		if redirectURI != "/dashboard" {
			t.Errorf("redirectURI = %q, want /dashboard", redirectURI)
		}
	})

	// case 5 — empty/tampered state is rejected (state validation not weakened).
	t.Run("empty/tampered state is rejected", func(t *testing.T) {
		op := newFakePKCEOP(t, clientID, "staff@aocyber.ai", "AOCyber Staff")
		svc, _ := newSSOTestService(t, op, clientID)

		if _, _, err := svc.HandleOIDCCallbackWithState(context.Background(), "code", ""); err == nil {
			t.Error("expected error for empty state, got nil")
		}
		if _, _, err := svc.HandleOIDCCallbackWithState(context.Background(), "code", "not-a-valid-jwt"); err == nil {
			t.Error("expected error for tampered state, got nil")
		}
	})

	// case 6 — a legacy 3-field state parses with an empty verifier.
	t.Run("legacy 3-field state parses with empty verifier", func(t *testing.T) {
		op := newFakePKCEOP(t, clientID, "legacy@example.com", "Legacy User")
		svc, companyID := newSSOTestService(t, op, clientID)

		// Hand-build a legacy state JWT in the OLD companyID|provider|redirectURI
		// format (no verifier field) via the test-only seam.
		legacyState := svc.LegacyStateForTest(t, companyID, "oidc", "/dashboard")

		gotCompany, gotProvider, gotRedirect, gotVerifier := svc.ParseStateForTest(t, legacyState)
		if gotCompany != companyID {
			t.Errorf("companyID = %v, want %v", gotCompany, companyID)
		}
		if gotProvider != "oidc" {
			t.Errorf("provider = %q, want oidc", gotProvider)
		}
		if gotRedirect != "/dashboard" {
			t.Errorf("redirectURI = %q, want /dashboard", gotRedirect)
		}
		if gotVerifier != "" {
			t.Errorf("legacy state verifier = %q, want empty", gotVerifier)
		}

		// And a full round-trip on a legacy state still authenticates (the
		// empty-verifier path must not send VerifierOption — additive/back-compat).
		resp, _, err := svc.HandleOIDCCallbackWithState(context.Background(), "legacy-code", legacyState)
		if err != nil {
			t.Fatalf("legacy-state round-trip failed: %v", err)
		}
		if resp == nil || resp.AccessToken == "" {
			t.Fatal("expected eden access token from legacy-state round-trip")
		}
		if op.postedVerifier() != "" {
			t.Errorf("legacy path posted a code_verifier %q, want none", op.postedVerifier())
		}
	})
}

// allowLoopbackIdPForTest lets an SSOService reach the plain-http loopback
// fake OPs these tests run. The production egress policy (#85) refuses
// loopback and http; see sso_egress_test.go for that policy's own tests.
func allowLoopbackIdPForTest(svc *auth.SSOService) {
	svc.SetEgressForTest(func(h string) bool { return h == "127.0.0.1" }, true, nil, nil)
}
