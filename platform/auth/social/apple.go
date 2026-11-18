package social

import (
	"context"
	"crypto/ecdsa"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"strings"
	"time"

	gooidc "github.com/coreos/go-oidc/v3/oidc"
	"github.com/golang-jwt/jwt/v5"
	"golang.org/x/oauth2"
)

// appleIssuer is Apple's OIDC issuer. It supports discovery, so the existing
// go-oidc provider can fetch Apple's JWKS (https://appleid.apple.com/auth/keys)
// and verify id_token signatures — UNLIKE the insecure decoder in the oauth/
// package which base64-decodes the id_token WITHOUT verifying its signature.
const appleIssuer = "https://appleid.apple.com"

// appleAuthURL / appleTokenURL are Apple's OAuth2 endpoints. Apple does not
// expose a userinfo endpoint — the id_token IS the identity, verified via JWKS.
const (
	appleAuthURL  = "https://appleid.apple.com/auth/authorize"
	appleTokenURL = "https://appleid.apple.com/auth/token"
)

// appleClientSecretMaxAge bounds the generated client-secret JWT lifetime. Apple
// caps it at 6 months; we use a comfortably-within-limit window (Pitfall 1). The
// .p8 key never expires, but the signed JWT does — regenerate within this window.
const appleClientSecretMaxAge = 150 * 24 * time.Hour

// GenerateAppleClientSecret hand-rolls Apple's "Sign in with Apple" client-secret
// JWT: an ES256-signed token with iss=teamID, sub=servicesID,
// aud=https://appleid.apple.com, and a header kid=keyID. This avoids a new
// dependency (golang-jwt/jwt/v5 is already vendored). The privateKeyPEM is the
// PKCS#8 EC key Apple issues as a .p8 file.
func GenerateAppleClientSecret(privateKeyPEM, teamID, servicesID, keyID string) (string, error) {
	key, err := parseECPrivateKey(privateKeyPEM)
	if err != nil {
		return "", fmt.Errorf("parse apple private key: %w", err)
	}

	now := time.Now()
	claims := jwt.RegisteredClaims{
		Issuer:    teamID,
		Subject:   servicesID,
		Audience:  jwt.ClaimStrings{appleIssuer},
		IssuedAt:  jwt.NewNumericDate(now),
		ExpiresAt: jwt.NewNumericDate(now.Add(appleClientSecretMaxAge)),
	}
	token := jwt.NewWithClaims(jwt.SigningMethodES256, claims)
	token.Header["kid"] = keyID

	signed, err := token.SignedString(key)
	if err != nil {
		return "", fmt.Errorf("sign apple client secret: %w", err)
	}
	return signed, nil
}

// parseECPrivateKey decodes a PEM-encoded EC private key. Apple .p8 files are
// PKCS#8; some keys are SEC1 ("EC PRIVATE KEY"). Both are tolerated.
func parseECPrivateKey(pemStr string) (*ecdsa.PrivateKey, error) {
	block, _ := pem.Decode([]byte(pemStr))
	if block == nil {
		return nil, fmt.Errorf("no PEM block found")
	}
	if k, err := x509.ParsePKCS8PrivateKey(block.Bytes); err == nil {
		ec, ok := k.(*ecdsa.PrivateKey)
		if !ok {
			return nil, fmt.Errorf("PKCS8 key is not an EC key")
		}
		return ec, nil
	}
	if ec, err := x509.ParseECPrivateKey(block.Bytes); err == nil {
		return ec, nil
	}
	return nil, fmt.Errorf("unsupported EC private key encoding")
}

// verifyAppleIDToken verifies an Apple id_token against Apple's JWKS via go-oidc
// discovery and returns its claims. The audience is the Services ID (Apple's
// client_id). This is the SECURE path — signature + issuer + audience + expiry
// are all checked, unlike the unverified decoder that platform/auth/oauth had
// (removed for issue #75).
func verifyAppleIDToken(ctx context.Context, rawIDToken, servicesID string) (map[string]any, error) {
	provider, err := gooidc.NewProvider(ctx, appleIssuer)
	if err != nil {
		return nil, fmt.Errorf("discover apple oidc provider: %w", err)
	}
	verifier := provider.Verifier(&gooidc.Config{ClientID: servicesID})
	idTok, err := verifier.Verify(ctx, rawIDToken)
	if err != nil {
		return nil, fmt.Errorf("verify apple id_token: %w", err)
	}
	var claims map[string]any
	if err := idTok.Claims(&claims); err != nil {
		return nil, fmt.Errorf("extract apple claims: %w", err)
	}
	return claims, nil
}

// appleFormUser models the one-time `user` form field Apple POSTs on the FIRST
// authorization only. The name is NOT present in the id_token, and Apple omits
// the field entirely on repeat sign-ins (Pitfall 2).
type appleFormUser struct {
	Name struct {
		FirstName string `json:"firstName"`
		LastName  string `json:"lastName"`
	} `json:"name"`
}

// appleClaimsToIdentity maps verified Apple id_token claims (+ the first-auth form
// `user` field, if present) into an Identity. EmailVerified is ALWAYS true: Apple
// verifies the address it returns, including its @privaterelay.appleid.com relay
// addresses, so Provision may safely link by email. DisplayName is populated ONLY
// when the first-auth form name is present; on repeat sign-ins it stays empty and
// Provision keeps the existing display_name.
func appleClaimsToIdentity(claims map[string]any, formUserField string) Identity {
	id := Identity{
		Provider:      "apple",
		ProviderSub:   claimString(claims, "sub"),
		Email:         strings.ToLower(strings.TrimSpace(claimString(claims, "email"))),
		EmailVerified: true, // Apple verifies the email it returns (incl. relay).
	}
	if dn := parseAppleFormName(formUserField); dn != "" {
		id.DisplayName = dn
	}
	return id
}

// parseAppleFormName extracts a display name from Apple's first-auth `user` form
// JSON. Returns "" for absent/malformed input (repeat sign-in or parse failure).
func parseAppleFormName(formUserField string) string {
	if strings.TrimSpace(formUserField) == "" {
		return ""
	}
	var fu appleFormUser
	if err := json.Unmarshal([]byte(formUserField), &fu); err != nil {
		return ""
	}
	name := strings.TrimSpace(fu.Name.FirstName + " " + fu.Name.LastName)
	return name
}

// appleOAuthConfig builds the oauth2.Config for Apple's token exchange. Apple
// uses a generated ES256 JWT as the client_secret (set by the caller before
// Exchange). The redirect URL is always the server's own callback.
func (s *SocialAuthService) appleOAuthConfig(clientSecret string) oauth2.Config {
	pc := s.providers["apple"]
	return oauth2.Config{
		ClientID:     pc.ClientID, // Services ID
		ClientSecret: clientSecret,
		Endpoint: oauth2.Endpoint{
			AuthURL:   appleAuthURL,
			TokenURL:  appleTokenURL,
			AuthStyle: oauth2.AuthStyleInParams,
		},
		RedirectURL: s.baseURL + "/auth/social/callback",
		Scopes:      []string{"name", "email"},
	}
}

// exchangeApple exchanges the authorization code for Apple's token response and
// returns the raw id_token (Apple's identity assertion). The client secret is the
// generated ES256 JWT.
func exchangeApple(ctx context.Context, cfg oauth2.Config, code string) (string, error) {
	token, err := cfg.Exchange(ctx, code)
	if err != nil {
		return "", fmt.Errorf("exchange apple code: %w", err)
	}
	rawIDToken, ok := token.Extra("id_token").(string)
	if !ok || rawIDToken == "" {
		return "", fmt.Errorf("apple token response missing id_token")
	}
	return rawIDToken, nil
}
