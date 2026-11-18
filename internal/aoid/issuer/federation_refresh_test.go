package issuer

// Federation-bridge refresh tokens must still be redeemable at
// /oauth2/token (AO ID's only refresh route) and stay in the tenant.

import (
	"context"
	"net/http"
	"testing"
	"time"

	"github.com/google/uuid"
	"go.aocyber.ai/eden-platform-go/internal/aoid/federation"
)

func TestFederationRefresh_RedeemableAndStaysInTenant(t *testing.T) {
	h := newHarness(t)
	ctx := context.Background()

	// A user who already exists and belongs to the tenant company.
	up, err := h.svcs.Auth.SignUp(ctx, "fed@acme.com", "password123", "Fed User")
	if err != nil {
		t.Fatalf("SignUp: %v", err)
	}
	upClaims, err := h.svcs.JWTManager.ValidateAccessToken(up.AccessToken)
	if err != nil {
		t.Fatalf("validate signup: %v", err)
	}
	tenantID := uuid.MustParse(upClaims.CompanyID)

	reg := federation.NewInMemorySPRegistry()
	cfg := federation.TenantExternalIdP{
		ID: uuid.New(), TenantID: tenantID, Provider: federation.ProviderSAML,
		DisplayName: "Acme", EntityID: "https://idp.acme.test", MetadataURL: "https://idp.acme.test/md",
		ClientID: "acme", ClientSecret: "shh",
		JITPolicy: federation.JITPolicy{Enabled: true, DefaultRole: "member", AllowedDomains: []string{"acme.com"}},
		IsActive:  true,
	}
	if err := reg.Register(ctx, cfg); err != nil {
		t.Fatalf("register idp: %v", err)
	}
	bridge, err := federation.NewBridge(h.svcs.Auth, reg, h.svcs.JWTManager, nil)
	if err != nil {
		t.Fatalf("NewBridge: %v", err)
	}
	res, err := bridge.HandleAssertion(ctx, tenantID, cfg.ID, &federation.Assertion{
		Email: "fed@acme.com", IssuedAt: time.Now(), ExpiresAt: time.Now().Add(5 * time.Minute),
		AuthnContext: "urn:oasis:names:tc:SAML:2.0:ac:classes:MultiFactorContract",
	})
	if err != nil {
		t.Fatalf("HandleAssertion: %v", err)
	}

	status, tr := h.postToken(t, refreshForm(res.RefreshToken), h.client, h.secret)
	if status != http.StatusOK {
		t.Fatalf("federation refresh at /oauth2/token: status=%d error=%q, want 200", status, tr.Error)
	}
	c, err := h.svcs.JWTManager.ValidateAccessToken(tr.AccessToken)
	if err != nil {
		t.Fatalf("validate refreshed: %v", err)
	}
	if c.CompanyID != tenantID.String() {
		t.Errorf("refreshed company=%q, want tenant %s", c.CompanyID, tenantID)
	}
}
