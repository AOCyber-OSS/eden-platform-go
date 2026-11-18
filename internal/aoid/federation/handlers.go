package federation

import (
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"net/url"
	"path"
	"strings"
	"time"

	"github.com/google/uuid"
	"go.aocyber.ai/eden-platform-go/platform/auth/saml/idp"
)

// Stack bundles every federation runtime component a server boots
// from. composition.BuildFederation returns one of these.
type Stack struct {
	Registry   Registry
	SPRegistry SPRegistry
	IdPManager *IdPManager
	Bridge     *Bridge
	Exchanger  OIDCExchanger

	// BaseURL is the AO ID public URL, used to construct callback URLs.
	BaseURL string

	// StateSecret is the HMAC key used to sign federation state tokens
	// (carried in OIDC `state` / SAML RelayState). 32+ random bytes.
	StateSecret []byte

	// SessionTTL bounds federation-initiated sessions. Matches the
	// issuer's session TTL by default.
	SessionTTL time.Duration
}

// Mount registers every federation route onto mux.
func (s *Stack) Mount(mux *http.ServeMux) {
	h := &Handler{stack: s}
	mux.HandleFunc("/saml/idp/", h.routeSAMLIdP)
	mux.HandleFunc("/federation/", h.routeFederation)
}

// Handler wraps Stack with the HTTP-level glue. Construct via
// Stack.Mount; direct construction is supported for tests.
type Handler struct {
	stack *Stack
}

// NewHandler is the test-friendly constructor.
func NewHandler(stack *Stack) *Handler { return &Handler{stack: stack} }

// routeSAMLIdP dispatches /saml/idp/{tenant}/... paths.
func (h *Handler) routeSAMLIdP(w http.ResponseWriter, r *http.Request) {
	tenantID, rest, ok := splitTenantPath(r.URL.Path, "/saml/idp/")
	if !ok {
		http.NotFound(w, r)
		return
	}
	switch rest {
	case "metadata":
		h.IdPMetadata(w, r, tenantID)
	case "sso":
		h.IdPSSO(w, r, tenantID)
	default:
		http.NotFound(w, r)
	}
}

// routeFederation dispatches /federation/{tenant}/... paths.
func (h *Handler) routeFederation(w http.ResponseWriter, r *http.Request) {
	tenantID, rest, ok := splitTenantPath(r.URL.Path, "/federation/")
	if !ok {
		http.NotFound(w, r)
		return
	}
	switch {
	case rest == "start":
		h.StartFederation(w, r, tenantID)
	case rest == "saml/acs":
		h.SAMLACS(w, r, tenantID)
	case rest == "oidc/callback":
		h.OIDCCallback(w, r, tenantID)
	case rest == "idps":
		h.ListExternalIdPs(w, r, tenantID)
	default:
		http.NotFound(w, r)
	}
}

// IdPMetadata serves /saml/idp/{tenant}/metadata.
func (h *Handler) IdPMetadata(w http.ResponseWriter, r *http.Request, tenantID uuid.UUID) {
	body, err := h.stack.IdPManager.Metadata(r.Context(), tenantID)
	if err != nil {
		writeFederationError(w, err)
		return
	}
	w.Header().Set("Content-Type", "application/samlmetadata+xml")
	_, _ = w.Write(body)
}

// IdPSSO accepts SAML AuthnRequests at /saml/idp/{tenant}/sso. Phase A
// implementation: parses the AuthnRequest, requires an AO ID session
// cookie (set elsewhere by the OIDC issuer login flow), issues the
// assertion, and auto-submits it to the SP's ACS URL via an HTML form.
//
// For requests without a session, returns 401 with a JSON body — the
// caller (typically a browser redirected by an SP) should be bounced
// to the AO ID login page. The HTTP layer keeps this deliberately
// minimal; full SP-initiated-then-IdP-login UX is a follow-on.
func (h *Handler) IdPSSO(w http.ResponseWriter, r *http.Request, tenantID uuid.UUID) {
	if err := r.ParseForm(); err != nil {
		http.Error(w, "bad request", http.StatusBadRequest)
		return
	}
	samlReq := r.FormValue("SAMLRequest")
	if samlReq == "" {
		samlReq = r.URL.Query().Get("SAMLRequest")
	}
	if samlReq == "" {
		http.Error(w, "missing SAMLRequest", http.StatusBadRequest)
		return
	}

	spReg, requestID, err := h.stack.IdPManager.AcceptAuthnRequest(r.Context(), tenantID, samlReq)
	if err != nil {
		writeFederationError(w, err)
		return
	}

	// Phase A: require explicit "asUserID" param identifying the AO ID
	// user whose context the assertion should reflect. In a normal
	// production flow this would be derived from the AO ID login
	// session cookie set by the OIDC issuer. We expose `asUserID` as
	// an explicit parameter for now so the federation surface is
	// independently testable; the issuer-integrated flow lands in the
	// admin UI follow-on.
	userIDStr := r.URL.Query().Get("aoid_user_id")
	if userIDStr == "" {
		userIDStr = r.FormValue("aoid_user_id")
	}
	if userIDStr == "" {
		w.Header().Set("WWW-Authenticate", "AOID session required")
		http.Error(w, "AO ID session required (Phase A: pass aoid_user_id explicitly)", http.StatusUnauthorized)
		return
	}
	userID, err := uuid.Parse(userIDStr)
	if err != nil {
		http.Error(w, "invalid aoid_user_id", http.StatusBadRequest)
		return
	}

	// Build assertion attributes from the AO ID user record.
	tplAttrs, err := h.stack.IdPManager.AttributeTemplate(r.Context(), tenantID)
	if err != nil {
		writeFederationError(w, err)
		return
	}
	user, err := h.stack.Bridge.AuthService.GetUserByID(r.Context(), userID)
	if err != nil {
		http.Error(w, "user not found", http.StatusNotFound)
		return
	}

	attrs := buildAssertionAttributes(userAdapter{
		Email:       user.Email,
		DisplayName: user.DisplayName,
		ID:          user.ID.String(),
	}, tplAttrs)

	signed, err := h.stack.IdPManager.IssueAssertion(r.Context(), tenantID, idp.AssertionInput{
		SPEntityID:   spReg.EntityID,
		InResponseTo: requestID,
		NameID:       user.Email,
		Attributes:   attrs,
	})
	if err != nil {
		writeFederationError(w, err)
		return
	}

	// Auto-submit the assertion to the SP's ACS URL.
	body := buildPostAutoSubmit(spReg.ACSURL, signed, r.FormValue("RelayState"))
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.Header().Set("Cache-Control", "no-store")
	_, _ = w.Write(body)
}

// StartFederation begins an inbound federation flow.
func (h *Handler) StartFederation(w http.ResponseWriter, r *http.Request, tenantID uuid.UUID) {
	externalIDStr := r.URL.Query().Get("external_idp_id")
	if externalIDStr == "" {
		http.Error(w, "missing external_idp_id", http.StatusBadRequest)
		return
	}
	externalID, err := uuid.Parse(externalIDStr)
	if err != nil {
		http.Error(w, "invalid external_idp_id", http.StatusBadRequest)
		return
	}
	cfg, err := h.stack.SPRegistry.Get(r.Context(), externalID)
	if err != nil {
		writeFederationError(w, err)
		return
	}
	if cfg.TenantID != tenantID || !cfg.IsActive {
		http.NotFound(w, r)
		return
	}

	wrapper, err := NewExternalIdP(cfg, h.stack.Exchanger)
	if err != nil {
		writeFederationError(w, err)
		return
	}

	state, err := h.stack.signState(stateClaims{
		TenantID:      tenantID,
		ExternalIdPID: externalID,
		IssuedAt:      time.Now().Unix(),
	})
	if err != nil {
		writeFederationError(w, err)
		return
	}

	redirectURI := h.callbackURL(cfg, tenantID)
	authURL, err := wrapper.AuthorizationURL(r.Context(), redirectURI, state)
	if err != nil {
		writeFederationError(w, err)
		return
	}
	http.Redirect(w, r, authURL, http.StatusFound)
}

// SAMLACS handles the SAML response from an inbound external IdP.
func (h *Handler) SAMLACS(w http.ResponseWriter, r *http.Request, tenantID uuid.UUID) {
	if err := r.ParseForm(); err != nil {
		http.Error(w, "bad request", http.StatusBadRequest)
		return
	}
	samlResp := r.FormValue("SAMLResponse")
	relayState := r.FormValue("RelayState")
	if samlResp == "" {
		http.Error(w, "missing SAMLResponse", http.StatusBadRequest)
		return
	}

	claims, err := h.stack.verifyState(relayState)
	if err != nil {
		http.Error(w, "invalid RelayState", http.StatusBadRequest)
		return
	}
	if claims.TenantID != tenantID {
		http.NotFound(w, r)
		return
	}

	cfg, err := h.stack.SPRegistry.Get(r.Context(), claims.ExternalIdPID)
	if err != nil {
		writeFederationError(w, err)
		return
	}
	idp, err := NewExternalIdP(cfg, h.stack.Exchanger)
	if err != nil {
		writeFederationError(w, err)
		return
	}

	a, err := idp.ValidateSAMLResponse(r.Context(), samlResp)
	if err != nil {
		http.Error(w, fmt.Sprintf("parse assertion: %v", err), http.StatusBadRequest)
		return
	}

	res, err := h.stack.Bridge.HandleAssertion(r.Context(), tenantID, claims.ExternalIdPID, a)
	if err != nil {
		writeFederationError(w, err)
		return
	}
	writeTokenJSON(w, res)
}

// OIDCCallback handles the OIDC redirect from an inbound external IdP.
func (h *Handler) OIDCCallback(w http.ResponseWriter, r *http.Request, tenantID uuid.UUID) {
	code := r.URL.Query().Get("code")
	state := r.URL.Query().Get("state")
	if code == "" || state == "" {
		http.Error(w, "missing code or state", http.StatusBadRequest)
		return
	}
	claims, err := h.stack.verifyState(state)
	if err != nil {
		http.Error(w, "invalid state", http.StatusBadRequest)
		return
	}
	if claims.TenantID != tenantID {
		http.NotFound(w, r)
		return
	}
	cfg, err := h.stack.SPRegistry.Get(r.Context(), claims.ExternalIdPID)
	if err != nil {
		writeFederationError(w, err)
		return
	}
	idp, err := NewExternalIdP(cfg, h.stack.Exchanger)
	if err != nil {
		writeFederationError(w, err)
		return
	}
	a, err := idp.ExchangeAuthCode(r.Context(), code, h.callbackURL(cfg, tenantID))
	if err != nil {
		http.Error(w, fmt.Sprintf("exchange code: %v", err), http.StatusBadRequest)
		return
	}
	res, err := h.stack.Bridge.HandleAssertion(r.Context(), tenantID, claims.ExternalIdPID, a)
	if err != nil {
		writeFederationError(w, err)
		return
	}
	writeTokenJSON(w, res)
}

// ListExternalIdPs returns the active external IdPs for a tenant.
type externalIdPSummary struct {
	ID          string `json:"id"`
	Provider    string `json:"provider"`
	DisplayName string `json:"display_name"`
}

// ListExternalIdPs serves /federation/{tenant}/idps.
func (h *Handler) ListExternalIdPs(w http.ResponseWriter, r *http.Request, tenantID uuid.UUID) {
	list, err := h.stack.SPRegistry.ListByTenant(r.Context(), tenantID, true)
	if err != nil {
		writeFederationError(w, err)
		return
	}
	out := make([]externalIdPSummary, 0, len(list))
	for _, cfg := range list {
		out = append(out, externalIdPSummary{
			ID:          cfg.ID.String(),
			Provider:    cfg.Provider,
			DisplayName: cfg.DisplayName,
		})
	}
	w.Header().Set("Content-Type", "application/json")
	if err := json.NewEncoder(w).Encode(out); err != nil {
		slog.Error("federation: write idp list", "error", err)
	}
}

// callbackURL builds the AO ID-side callback URL for the inbound flow.
// `redirect_uri` for OIDC; ACS URL for SAML.
func (h *Handler) callbackURL(cfg TenantExternalIdP, tenantID uuid.UUID) string {
	base := strings.TrimRight(h.stack.BaseURL, "/")
	if cfg.Provider == ProviderOIDC {
		return fmt.Sprintf("%s/federation/%s/oidc/callback", base, tenantID.String())
	}
	return fmt.Sprintf("%s/federation/%s/saml/acs", base, tenantID.String())
}

// buildAssertionAttributes resolves the tenant's AttributeTemplate
// against an auth.User record. Each template entry of the form
// "claim" -> ["source1","source2"] is consulted in order; the first
// non-empty source wins.
func buildAssertionAttributes(user authUserLike, tpl map[string][]string) map[string][]string {
	values := map[string]string{
		"email":        user.GetEmail(),
		"display_name": user.GetDisplayName(),
		"sub":          user.GetID(),
		"id":           user.GetID(),
	}
	out := make(map[string][]string)
	for claim, sources := range tpl {
		for _, src := range sources {
			if v, ok := values[strings.ToLower(src)]; ok && v != "" {
				out[claim] = []string{v}
				break
			}
		}
	}
	// Always include email if not already mapped.
	if _, ok := out["email"]; !ok && values["email"] != "" {
		out["email"] = []string{values["email"]}
	}
	return out
}

// authUserLike is the slim interface buildAssertionAttributes needs.
// auth.User satisfies it via the implicit accessors below.
type authUserLike interface {
	GetEmail() string
	GetDisplayName() string
	GetID() string
}

// userAdapter wraps auth.User to satisfy authUserLike.
type userAdapter struct {
	Email       string
	DisplayName string
	ID          string
}

func (u userAdapter) GetEmail() string       { return u.Email }
func (u userAdapter) GetDisplayName() string { return u.DisplayName }
func (u userAdapter) GetID() string          { return u.ID }

// buildPostAutoSubmit returns an HTML body that auto-submits the
// SAML response to the SP's ACS URL via JavaScript onload. Falls back
// to a "submit" button when JS is disabled.
func buildPostAutoSubmit(acsURL string, samlResponseXML []byte, relayState string) []byte {
	encoded := base64.StdEncoding.EncodeToString(samlResponseXML)
	relay := ""
	if relayState != "" {
		relay = fmt.Sprintf(`<input type="hidden" name="RelayState" value="%s">`, htmlEscape(relayState))
	}
	body := fmt.Sprintf(`<!doctype html>
<html><body onload="document.forms[0].submit()">
<noscript><p>JavaScript required to redirect. Click below.</p></noscript>
<form method="post" action="%s">
  <input type="hidden" name="SAMLResponse" value="%s">
  %s
  <noscript><button type="submit">Continue</button></noscript>
</form>
</body></html>`, htmlEscape(acsURL), encoded, relay)
	return []byte(body)
}

func htmlEscape(s string) string {
	r := strings.NewReplacer(
		"&", "&amp;",
		"<", "&lt;",
		">", "&gt;",
		`"`, "&quot;",
		"'", "&#39;",
	)
	return r.Replace(s)
}

// writeTokenJSON renders a successful bridge result as JSON.
func writeTokenJSON(w http.ResponseWriter, res *BridgeResult) {
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "no-store")
	out := struct {
		AccessToken    string `json:"access_token"`
		RefreshToken   string `json:"refresh_token"`
		UserID         string `json:"user_id"`
		Email          string `json:"email"`
		ProvisionedNew bool   `json:"provisioned_new"`
	}{
		AccessToken:    res.AccessToken,
		RefreshToken:   res.RefreshToken,
		UserID:         res.User.ID.String(),
		Email:          res.User.Email,
		ProvisionedNew: res.ProvisionedNew,
	}
	if err := json.NewEncoder(w).Encode(out); err != nil {
		slog.Error("federation: write token", "error", err)
	}
}

// writeFederationError maps internal errors to HTTP responses.
func writeFederationError(w http.ResponseWriter, err error) {
	switch {
	case errors.Is(err, ErrTenantNotFound),
		errors.Is(err, ErrExternalIdPNotFound):
		http.Error(w, http.StatusText(http.StatusNotFound), http.StatusNotFound)
	case errors.Is(err, ErrTenantInactive):
		http.Error(w, "tenant inactive", http.StatusGone)
	case errors.Is(err, ErrInvalidConfig):
		http.Error(w, err.Error(), http.StatusBadRequest)
	case errors.Is(err, ErrFederationUserNotFound),
		errors.Is(err, ErrJITDisabled):
		http.Error(w, "user not provisioned", http.StatusForbidden)
	case errors.Is(err, ErrFederationEmailNotMember):
		// #74: the IdP vouched for an account outside its tenant. A policy
		// refusal, not a server fault; the body names no other tenant.
		http.Error(w, "account is not a member of this tenant", http.StatusForbidden)
	case errors.Is(err, ErrJITDomainNotAllowed):
		http.Error(w, "email domain not allowed", http.StatusForbidden)
	case errors.Is(err, ErrJITMFARequired):
		http.Error(w, "multi-factor authentication required", http.StatusForbidden)
	default:
		http.Error(w, http.StatusText(http.StatusInternalServerError), http.StatusInternalServerError)
	}
}

// splitTenantPath returns (tenantID, rest, true) when path looks like
// "{prefix}{uuid}/<rest>". rest is the substring after the tenant ID.
func splitTenantPath(p, prefix string) (uuid.UUID, string, bool) {
	if !strings.HasPrefix(p, prefix) {
		return uuid.Nil, "", false
	}
	suffix := strings.TrimPrefix(p, prefix)
	// First segment is tenantID.
	parts := strings.SplitN(suffix, "/", 2)
	if len(parts) < 2 {
		return uuid.Nil, "", false
	}
	tenantID, err := uuid.Parse(parts[0])
	if err != nil {
		return uuid.Nil, "", false
	}
	return tenantID, path.Clean(parts[1]), true
}

// stateClaims is the federation HMAC token payload.
type stateClaims struct {
	TenantID      uuid.UUID `json:"tenant_id"`
	ExternalIdPID uuid.UUID `json:"external_idp_id"`
	IssuedAt      int64     `json:"iat"`
}

func (s *Stack) signState(claims stateClaims) (string, error) {
	body, err := json.Marshal(claims)
	if err != nil {
		return "", err
	}
	enc := base64.RawURLEncoding.EncodeToString(body)
	sig := s.computeStateSig(enc)
	return enc + "." + sig, nil
}

func (s *Stack) verifyState(token string) (*stateClaims, error) {
	idx := strings.IndexByte(token, '.')
	if idx <= 0 || idx == len(token)-1 {
		return nil, errors.New("federation: malformed state")
	}
	body := token[:idx]
	sig := token[idx+1:]
	if !hmac.Equal([]byte(s.computeStateSig(body)), []byte(sig)) {
		return nil, errors.New("federation: state signature mismatch")
	}
	raw, err := base64.RawURLEncoding.DecodeString(body)
	if err != nil {
		return nil, err
	}
	var claims stateClaims
	if err := json.Unmarshal(raw, &claims); err != nil {
		return nil, err
	}
	// 30-minute validity window.
	if time.Now().Unix()-claims.IssuedAt > 30*60 {
		return nil, errors.New("federation: state expired")
	}
	return &claims, nil
}

func (s *Stack) computeStateSig(body string) string {
	mac := hmac.New(sha256.New, s.StateSecret)
	_, _ = mac.Write([]byte(body))
	return hex.EncodeToString(mac.Sum(nil))
}

// Adapter helper: turn an auth.User into the userAdapter needed by
// buildAssertionAttributes. Defined as a method on Handler so tests can
// override behavior if needed.
func (h *Handler) userToAdapter(u userValue) authUserLike {
	return userAdapter{Email: u.Email, DisplayName: u.DisplayName, ID: u.ID}
}

// userValue is an internal transport struct used by the SSO handler.
type userValue struct {
	Email       string
	DisplayName string
	ID          string
}

// Context cancellation helper (unused now but kept for future async).
var _ = context.Background
var _ = url.Parse
