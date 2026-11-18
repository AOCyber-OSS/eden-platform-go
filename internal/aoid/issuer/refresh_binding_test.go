package issuer

// Issue #80: refresh grants are bound to the client the refresh token was
// issued to. These tests drive the real /oauth2/token endpoint over HTTP.

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"io"
	"net/http"
	"net/url"
	"strings"
	"testing"

	"go.aocyber.ai/eden-platform-go/internal/aoid/clients"
)

const (
	otherClientID     = "other-client"
	otherClientSecret = "other-secret"
)

// registerOtherClient adds a second confidential client allowed to use the
// refresh_token grant.
func (h *testHarness) registerOtherClient(t *testing.T) {
	t.Helper()
	err := h.svcs.Clients.Register(context.Background(), clients.Client{
		ID:            otherClientID,
		SecretHash:    clients.HashSecret(otherClientSecret),
		Name:          "Other client",
		Type:          clients.ClientTypeConfidential,
		RedirectURIs:  []string{"http://other.test/cb"},
		AllowedScopes: []string{"openid", "profile", "email", "offline_access"},
		AllowedGrants: []string{"authorization_code", "refresh_token"},
		AuthMethod:    "client_secret_basic",
	})
	if err != nil {
		t.Fatalf("register other client: %v", err)
	}
}

type tokenResp struct {
	AccessToken  string `json:"access_token"`
	IDToken      string `json:"id_token"`
	RefreshToken string `json:"refresh_token"`
	Error        string `json:"error"`
}

// postToken POSTs form to /oauth2/token with Basic client credentials.
func (h *testHarness) postToken(t *testing.T, form url.Values, clientID, secret string) (int, tokenResp) {
	t.Helper()
	req, _ := http.NewRequest(http.MethodPost, h.srv.URL+"/oauth2/token", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.SetBasicAuth(clientID, secret)
	res, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("token POST: %v", err)
	}
	defer res.Body.Close()
	body, _ := io.ReadAll(res.Body)
	var tr tokenResp
	_ = json.Unmarshal(body, &tr)
	return res.StatusCode, tr
}

// codeFlowTokens runs login + code exchange for the harness's AODex client.
func (h *testHarness) codeFlowTokens(t *testing.T) tokenResp {
	t.Helper()
	verifier, challenge := pkce(t)
	form := url.Values{}
	form.Set("aoid_login", "1")
	form.Set("response_type", "code")
	form.Set("client_id", h.client)
	form.Set("redirect_uri", h.rURI)
	form.Set("scope", "openid email profile offline_access")
	form.Set("state", "S")
	form.Set("nonce", "N")
	form.Set("code_challenge", challenge)
	form.Set("code_challenge_method", "S256")
	form.Set("email", h.fix.ParentEmail)
	form.Set("password", h.fix.ParentPassword)
	cli := &http.Client{CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
	res, err := cli.PostForm(h.srv.URL+"/oauth2/authorize", form)
	if err != nil {
		t.Fatalf("authorize POST: %v", err)
	}
	res.Body.Close()
	loc, _ := url.Parse(res.Header.Get("Location"))
	code := loc.Query().Get("code")
	if code == "" {
		t.Fatalf("no code (status %d)", res.StatusCode)
	}
	tf := url.Values{}
	tf.Set("grant_type", "authorization_code")
	tf.Set("code", code)
	tf.Set("redirect_uri", h.rURI)
	tf.Set("code_verifier", verifier)
	status, tr := h.postToken(t, tf, h.client, h.secret)
	if status != http.StatusOK || tr.RefreshToken == "" {
		t.Fatalf("code exchange status=%d resp=%+v", status, tr)
	}
	return tr
}

func refreshForm(rt string) url.Values {
	f := url.Values{}
	f.Set("grant_type", "refresh_token")
	f.Set("refresh_token", rt)
	return f
}

// TestRefresh_CrossClientRejected: a refresh token issued to AODex cannot be
// redeemed by another authenticated client.
func TestRefresh_CrossClientRejected(t *testing.T) {
	h := newHarness(t)
	h.registerOtherClient(t)
	tr := h.codeFlowTokens(t)

	status, resp := h.postToken(t, refreshForm(tr.RefreshToken), otherClientID, otherClientSecret)
	if status != http.StatusBadRequest || resp.Error != "invalid_grant" {
		t.Fatalf("cross-client refresh: status=%d error=%q, want 400 invalid_grant", status, resp.Error)
	}

	// Wrong-client attempt must not burn the owner's token.
	status, resp = h.postToken(t, refreshForm(tr.RefreshToken), h.client, h.secret)
	if status != http.StatusOK || resp.RefreshToken == "" {
		t.Fatalf("owner refresh after cross-client attempt: status=%d resp=%+v", status, resp)
	}
}

// TestIDToken_TypedAndNotAnAccessToken: the AO ID ID token is signed with the
// same key as access tokens. It must carry token_use "id" and be refused by
// ValidateAccessToken and by /oauth2/userinfo.
func TestIDToken_TypedAndNotAnAccessToken(t *testing.T) {
	h := newHarness(t)
	tr := h.codeFlowTokens(t)

	parts := strings.Split(tr.IDToken, ".")
	if len(parts) != 3 {
		t.Fatalf("id_token segments = %d", len(parts))
	}
	raw, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		t.Fatalf("decode id_token payload: %v", err)
	}
	var payload map[string]any
	_ = json.Unmarshal(raw, &payload)
	if payload["token_use"] != "id" {
		t.Errorf("id_token token_use = %v, want \"id\"", payload["token_use"])
	}

	if _, err := h.svcs.JWTManager.ValidateAccessToken(tr.IDToken); err == nil {
		t.Error("ValidateAccessToken accepted the ID token")
	}
	req, _ := http.NewRequest(http.MethodGet, h.srv.URL+"/oauth2/userinfo", nil)
	req.Header.Set("Authorization", "Bearer "+tr.IDToken)
	res, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("userinfo: %v", err)
	}
	res.Body.Close()
	if res.StatusCode != http.StatusUnauthorized {
		t.Errorf("userinfo with ID token: status=%d, want 401", res.StatusCode)
	}
}
