package federation

import (
	"context"
	"encoding/base64"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"
	platsaml "go.aocyber.ai/eden-platform-go/platform/auth/saml"
	"go.aocyber.ai/eden-platform-go/platform/auth/saml/idp"
)

// buildSignedSAMLResponse returns a base64-encoded signed SAML response
// for the supplied user. Uses the platform/auth/saml/idp package as a
// fixture "external IdP" so the federation parser can exercise its
// extraction logic against a realistic assertion.
func buildSignedSAMLResponse(t *testing.T, email, displayName, authnContext string) string {
	t.Helper()
	signingKey, err := platsaml.GenerateSigningKey("Fixture IdP", time.Hour)
	if err != nil {
		t.Fatalf("GenerateSigningKey: %v", err)
	}
	idpInstance, err := idp.New(idp.Config{
		EntityID:          "https://fixture.example.com/idp/metadata",
		SSOURL:            "https://fixture.example.com/idp/sso",
		CurrentKey:        signingKey,
		AssertionLifetime: 5 * time.Minute,
		AllowedSPs: map[string]idp.SPRegistration{
			"https://aoid.example.com/federation/test/saml/acs": {
				EntityID: "https://aoid.example.com/federation/test/saml/acs",
				ACSURL:   "https://aoid.example.com/federation/test/saml/acs",
			},
		},
	})
	if err != nil {
		t.Fatalf("idp.New: %v", err)
	}
	xmlBytes, err := idpInstance.IssueAssertion(idp.AssertionInput{
		SPEntityID:           "https://aoid.example.com/federation/test/saml/acs",
		NameID:               email,
		AuthnContextClassRef: authnContext,
		Attributes: map[string][]string{
			"email":        {email},
			"display_name": {displayName},
		},
	})
	if err != nil {
		t.Fatalf("IssueAssertion: %v", err)
	}
	return base64.StdEncoding.EncodeToString(xmlBytes)
}

// The inbound SAML path refuses even a correctly signed assertion while
// verification is unwired, and it says ErrInvalidConfig so the bridge
// treats it as a misconfiguration rather than as a user's bad credential.
//
// This test replaces the former happy path, which asserted that a
// response was accepted and its attributes returned. That test passed
// with NO SigningCertificatePEM in the fixture, so what it actually
// locked in was the authentication bypass: any assertion, signed by
// anyone or by nobody, became an identity. See the doc comment on
// ValidateSAMLResponse and aocyber-compliance#17.
func TestExternalIdP_ValidateSAMLResponse_RefusesWhileVerificationIsUnwired(t *testing.T) {
	cfg := newExternalIdPConfig(t, ProviderSAML, uuid.New())
	cfg.AttributeMapping = map[string]string{
		"email":        "email",
		"display_name": "display_name",
	}
	// Non-empty is all the current code requires to get past the
	// no-trust-anchor branch and reach the not-wired branch; it is not a
	// usable certificate, and nothing verifies against it yet.
	cfg.SigningCertificatePEM = "-----BEGIN CERTIFICATE-----\nnot-a-real-cert\n-----END CERTIFICATE-----"

	idpInstance, err := NewExternalIdP(cfg, nil)
	if err != nil {
		t.Fatalf("NewExternalIdP: %v", err)
	}

	encoded := buildSignedSAMLResponse(t, "alice@acme.com", "Alice Smith",
		"urn:oasis:names:tc:SAML:2.0:ac:classes:PasswordProtectedTransport")

	a, err := idpInstance.ValidateSAMLResponse(context.Background(), encoded)
	if err == nil {
		t.Fatalf("accepted an assertion although no verifying path is wired: subject=%q", a.Subject)
	}
	if !errors.Is(err, ErrInvalidConfig) {
		t.Errorf("want ErrInvalidConfig so the bridge reports a config fault, got %v", err)
	}
}

func TestExternalIdP_ValidateSAMLResponse_RejectsOIDCFlow(t *testing.T) {
	cfg := newExternalIdPConfig(t, ProviderOIDC, uuid.New())
	idp, _ := NewExternalIdP(cfg, &StubOIDCExchanger{})
	_, err := idp.ValidateSAMLResponse(context.Background(), "anything")
	if !errors.Is(err, ErrUnsupportedFlow) {
		t.Errorf("expected ErrUnsupportedFlow, got %v", err)
	}
}

func TestExternalIdP_ValidateSAMLResponse_EmptyInput(t *testing.T) {
	cfg := newExternalIdPConfig(t, ProviderSAML, uuid.New())
	idp, _ := NewExternalIdP(cfg, nil)
	if _, err := idp.ValidateSAMLResponse(context.Background(), ""); err == nil {
		t.Errorf("expected error on empty input")
	}
}

func TestExternalIdP_AuthorizationURL_SAML(t *testing.T) {
	cfg := newExternalIdPConfig(t, ProviderSAML, uuid.New())
	idp, _ := NewExternalIdP(cfg, nil)
	urlStr, err := idp.AuthorizationURL(context.Background(),
		"https://aoid.example.com/federation/test/saml/acs", "state-token")
	if err != nil {
		t.Fatalf("AuthorizationURL SAML: %v", err)
	}
	if !strings.Contains(urlStr, "SAMLRequest=") {
		t.Errorf("URL missing SAMLRequest param: %s", urlStr)
	}
	if !strings.Contains(urlStr, "RelayState=state-token") {
		t.Errorf("URL missing RelayState: %s", urlStr)
	}
}

func TestExternalIdP_AuthorizationURL_OIDC(t *testing.T) {
	cfg := newExternalIdPConfig(t, ProviderOIDC, uuid.New())
	cfg.ClientID = "client-abc"
	idp, _ := NewExternalIdP(cfg, &StubOIDCExchanger{})
	urlStr, err := idp.AuthorizationURL(context.Background(),
		"https://aoid.example.com/federation/test/oidc/callback", "state-xyz")
	if err != nil {
		t.Fatalf("AuthorizationURL OIDC: %v", err)
	}
	if !strings.Contains(urlStr, "client_id=client-abc") {
		t.Errorf("URL missing client_id: %s", urlStr)
	}
	if !strings.Contains(urlStr, "response_type=code") {
		t.Errorf("URL missing response_type=code: %s", urlStr)
	}
	if !strings.Contains(urlStr, "state=state-xyz") {
		t.Errorf("URL missing state: %s", urlStr)
	}
}

func TestExternalIdP_AuthorizationURL_OIDCWithoutExchanger(t *testing.T) {
	cfg := newExternalIdPConfig(t, ProviderOIDC, uuid.New())
	idp, _ := NewExternalIdP(cfg, nil)
	_, err := idp.AuthorizationURL(context.Background(), "https://x", "s")
	if !errors.Is(err, ErrUnsupportedFlow) {
		t.Errorf("expected ErrUnsupportedFlow, got %v", err)
	}
}

func TestExternalIdP_ExchangeAuthCode(t *testing.T) {
	cfg := newExternalIdPConfig(t, ProviderOIDC, uuid.New())
	idp, _ := NewExternalIdP(cfg, &StubOIDCExchanger{})
	a, err := idp.ExchangeAuthCode(context.Background(), "code-123", "https://x")
	if err != nil {
		t.Fatalf("ExchangeAuthCode: %v", err)
	}
	if a.Email == "" {
		t.Errorf("ExchangeAuthCode returned blank Email")
	}
}

func TestExternalIdP_ExchangeAuthCode_RejectsSAML(t *testing.T) {
	cfg := newExternalIdPConfig(t, ProviderSAML, uuid.New())
	idp, _ := NewExternalIdP(cfg, &StubOIDCExchanger{})
	if _, err := idp.ExchangeAuthCode(context.Background(), "x", "y"); !errors.Is(err, ErrUnsupportedFlow) {
		t.Errorf("expected ErrUnsupportedFlow, got %v", err)
	}
}

func TestExternalIdP_EnforceJITPolicy(t *testing.T) {
	cfg := newExternalIdPConfig(t, ProviderSAML, uuid.New())
	cfg.JITPolicy = JITPolicy{
		Enabled:        true,
		AllowedDomains: []string{"acme.com"},
		RequireMFA:     true,
	}
	idp, _ := NewExternalIdP(cfg, nil)

	t.Run("allowed", func(t *testing.T) {
		a := &Assertion{Email: "user@acme.com", AuthnContext: "urn:oasis:names:tc:SAML:2.0:ac:classes:MultiFactorContract"}
		if err := idp.EnforceJITPolicy(a); err != nil {
			t.Errorf("expected nil, got %v", err)
		}
	})
	t.Run("domain mismatch", func(t *testing.T) {
		a := &Assertion{Email: "user@evil.com", AuthnContext: "urn:oasis:names:tc:SAML:2.0:ac:classes:MultiFactorContract"}
		if err := idp.EnforceJITPolicy(a); !errors.Is(err, ErrJITDomainNotAllowed) {
			t.Errorf("expected ErrJITDomainNotAllowed, got %v", err)
		}
	})
	t.Run("mfa missing", func(t *testing.T) {
		a := &Assertion{Email: "user@acme.com", AuthnContext: "urn:oasis:names:tc:SAML:2.0:ac:classes:PasswordProtectedTransport"}
		if err := idp.EnforceJITPolicy(a); !errors.Is(err, ErrJITMFARequired) {
			t.Errorf("expected ErrJITMFARequired, got %v", err)
		}
	})
	t.Run("no domain restriction", func(t *testing.T) {
		cfg.JITPolicy.AllowedDomains = nil
		idp2, _ := NewExternalIdP(cfg, nil)
		a := &Assertion{Email: "user@somewhere.com", AuthnContext: "urn:oasis:names:tc:SAML:2.0:ac:classes:MultiFactorContract"}
		if err := idp2.EnforceJITPolicy(a); err != nil {
			t.Errorf("no allowlist should allow any domain, got %v", err)
		}
	})
}

func TestStubOIDCExchanger_BuildAuthURL(t *testing.T) {
	cfg := newExternalIdPConfig(t, ProviderOIDC, uuid.New())
	cfg.EntityID = "https://stub.example.com/"
	s := &StubOIDCExchanger{}
	urlStr, err := s.BuildAuthURL(context.Background(), cfg, "https://aoid/x", "state-1")
	if err != nil {
		t.Fatalf("BuildAuthURL: %v", err)
	}
	if !strings.HasPrefix(urlStr, "https://stub.example.com/authorize?") {
		t.Errorf("URL prefix: %s", urlStr)
	}
}

func TestStubOIDCExchanger_FixedAssertion(t *testing.T) {
	stub := &StubOIDCExchanger{
		FixedAssertion: &Assertion{Email: "fixed@example.com"},
	}
	a, err := stub.ExchangeCode(context.Background(), TenantExternalIdP{}, "any", "any")
	if err != nil {
		t.Fatalf("ExchangeCode: %v", err)
	}
	if a.Email != "fixed@example.com" {
		t.Errorf("FixedAssertion not returned")
	}
}

func TestAssertion_HasMFA(t *testing.T) {
	cases := []struct {
		ctx string
		mfa bool
	}{
		{"urn:oasis:names:tc:SAML:2.0:ac:classes:PasswordProtectedTransport", false},
		{"urn:oasis:names:tc:SAML:2.0:ac:classes:MultiFactorContract", true},
		{"urn:oasis:names:tc:SAML:2.0:ac:classes:Smartcard", true},
		{"", false},
	}
	for _, tc := range cases {
		a := &Assertion{AuthnContext: tc.ctx}
		if got := a.HasMFA(); got != tc.mfa {
			t.Errorf("HasMFA(%q): got %v, want %v", tc.ctx, got, tc.mfa)
		}
	}
}

// buildUnsignedSAMLResponse hand-writes a SAML Response carrying NO
// signature at all, with attacker-chosen identity. Nothing issued it and
// nothing signed it.
func buildUnsignedSAMLResponse(email, displayName string) string {
	raw := `<?xml version="1.0"?>
<Response xmlns="urn:oasis:names:tc:SAML:2.0:protocol" ID="_forged" Version="2.0" IssueInstant="2026-10-14T00:00:00Z">
  <Assertion xmlns="urn:oasis:names:tc:SAML:2.0:assertion" ID="_forged_a" Version="2.0" IssueInstant="2026-10-14T00:00:00Z">
    <Issuer>https://attacker.example.com/idp</Issuer>
    <Subject><NameID Format="urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress">` + email + `</NameID></Subject>
    <Conditions NotBefore="2026-10-14T00:00:00Z" NotOnOrAfter="2099-01-01T00:00:00Z"/>
    <AttributeStatement>
      <Attribute Name="email"><AttributeValue>` + email + `</AttributeValue></Attribute>
      <Attribute Name="display_name"><AttributeValue>` + displayName + `</AttributeValue></Attribute>
    </AttributeStatement>
    <AuthnStatement AuthnInstant="2026-10-14T00:00:00Z">
      <AuthnContext><AuthnContextClassRef>urn:oasis:names:tc:SAML:2.0:ac:classes:PasswordProtectedTransport</AuthnContextClassRef></AuthnContext>
    </AuthnStatement>
  </Assertion>
</Response>`
	return base64.StdEncoding.EncodeToString([]byte(raw))
}

// A SAML response is a claim about who someone is, so an assertion that no
// trusted IdP signed must never become an identity. This is the security
// property of the whole federation inbound path, which is why it is
// asserted on its own rather than folded into a happy-path test.
func TestExternalIdP_ValidateSAMLResponse_RejectsUnsignedAssertion(t *testing.T) {
	cfg := newExternalIdPConfig(t, ProviderSAML, uuid.New())
	cfg.AttributeMapping = map[string]string{"email": "email", "display_name": "display_name"}
	idpInstance, err := NewExternalIdP(cfg, nil)
	if err != nil {
		t.Fatalf("NewExternalIdP: %v", err)
	}

	forged := buildUnsignedSAMLResponse("attacker@evil.example", "Totally Legit")

	a, err := idpInstance.ValidateSAMLResponse(context.Background(), forged)
	if err == nil {
		t.Fatalf("an unsigned assertion was accepted and became an identity: "+
			"subject=%q email=%q (nothing signed this response)", a.Subject, a.Email)
	}
}

// The doc comment on ValidateSAMLResponse promises that a registry entry
// with no SigningCertificatePEM yields a CONFIG error rather than an
// authentication success. Nothing can be verified without a trust anchor,
// so the only safe answer is to refuse.
func TestExternalIdP_ValidateSAMLResponse_RefusesWithoutASigningCertificate(t *testing.T) {
	cfg := newExternalIdPConfig(t, ProviderSAML, uuid.New())
	if cfg.SigningCertificatePEM != "" {
		t.Fatalf("fixture precondition: expected no signing cert, got one")
	}
	idpInstance, err := NewExternalIdP(cfg, nil)
	if err != nil {
		t.Fatalf("NewExternalIdP: %v", err)
	}

	// Even a properly signed assertion must be refused when the registry
	// entry names no certificate: with no trust anchor there is nothing to
	// check the signature against.
	encoded := buildSignedSAMLResponse(t, "alice@acme.com", "Alice Smith",
		"urn:oasis:names:tc:SAML:2.0:ac:classes:PasswordProtectedTransport")

	if _, err := idpInstance.ValidateSAMLResponse(context.Background(), encoded); err == nil {
		t.Fatal("accepted an assertion although the registry entry configures no " +
			"SigningCertificatePEM — there was no trust anchor to verify against")
	}
}
