package saml_test

import (
	"context"
	"crypto/x509"
	"errors"
	"strings"
	"testing"
	"time"

	platsaml "go.aocyber.ai/eden-platform-go/platform/auth/saml"
	"go.aocyber.ai/eden-platform-go/platform/auth/saml/idp"
	replaysaml "go.aocyber.ai/eden-platform-go/platform/saml"
)

// Tests for the additive verifier API introduced with the gosaml2-backed SP
// (issue #87): request-ID binding, replay refusal, an injectable clock,
// multi-certificate trust (rotation), IdP metadata parsing, and the typed
// VerifiedAssertion that SSOService consumes.
//
// Test list:
//   - InResponseTo matching a tracked request ID → accepted
//   - InResponseTo not tracked → rejected; unsolicited with
//     RequireInResponseTo → rejected; an empty tracked ID never matches
//   - the same assertion presented twice with a replay cache → second refused;
//     a replay-cache error → refused (fail closed)
//   - injected clock past NotOnOrAfter → rejected
//   - rotation: either of two trusted certificates verifies; a third does not
//   - wrong-tenant: tenant A's response at tenant B's Verifier → rejected
//   - ParseIDPMetadata: entity ID, signing certs, SSO endpoints; wrapped in an
//     EntitiesDescriptor; no IDPSSODescriptor or garbage → error

func verifierFor(tn *spTenant, certs ...*x509.Certificate) platsaml.Verifier {
	if len(certs) == 0 {
		certs = []*x509.Certificate{tn.key.Certificate}
	}
	return platsaml.Verifier{
		IDPEntityID:     tn.idpEntity,
		IDPCertificates: certs,
		SPEntityID:      tn.spEntity,
		ACSURL:          tn.acs,
	}
}

func TestVerifier_InResponseToBinding(t *testing.T) {
	tn := newSPTenant(t, "acme")
	ctx := context.Background()
	solicited := tn.mint(t, "r@acme.example.com", idp.AssertionInput{InResponseTo: "_req-1"})
	unsolicited := tn.mint(t, "r@acme.example.com", idp.AssertionInput{})
	v := verifierFor(tn)

	t.Run("tracked request ID is accepted", func(t *testing.T) {
		got, err := v.Verify(ctx, solicited, platsaml.VerifyOptions{RequestIDs: []string{"_other", "_req-1"}})
		if err != nil {
			t.Fatalf("Verify: %v", err)
		}
		if got.InResponseTo != "_req-1" || got.NameID != "r@acme.example.com" {
			t.Fatalf("got %+v", got)
		}
	})
	t.Run("untracked request ID is refused", func(t *testing.T) {
		if _, err := v.Verify(ctx, solicited, platsaml.VerifyOptions{RequestIDs: []string{"_other"}}); err == nil {
			t.Fatal("want rejection")
		}
	})
	t.Run("unsolicited refused when a request is required", func(t *testing.T) {
		if _, err := v.Verify(ctx, unsolicited, platsaml.VerifyOptions{RequireInResponseTo: true, RequestIDs: []string{""}}); err == nil {
			t.Fatal("want rejection")
		}
	})
	t.Run("unsolicited accepted by default", func(t *testing.T) {
		if _, err := v.Verify(ctx, unsolicited, platsaml.VerifyOptions{}); err != nil {
			t.Fatalf("Verify: %v", err)
		}
	})
	t.Run("options form of VerifyResponse honours request IDs", func(t *testing.T) {
		attrs, err := platsaml.VerifyResponseWithOptions(ctx, solicited, tn.cfg(), platsaml.VerifyOptions{RequestIDs: []string{"_req-1"}})
		if err != nil || attrs["email"] != "r@acme.example.com" {
			t.Fatalf("attrs=%v err=%v", attrs, err)
		}
	})
}

type failingReplay struct{}

func (failingReplay) Seen(context.Context, string, time.Time) (bool, error) {
	return false, errors.New("replay store unavailable")
}

func TestVerifier_ReplayIsRefused(t *testing.T) {
	tn := newSPTenant(t, "acme")
	ctx := context.Background()
	resp := tn.mint(t, "p@acme.example.com", idp.AssertionInput{})
	store := replaysaml.NewInMemoryReplayStoreWithInterval(0)
	t.Cleanup(store.Close)
	opts := platsaml.VerifyOptions{Replay: store}

	if _, err := platsaml.VerifyResponseWithOptions(ctx, resp, tn.cfg(), opts); err != nil {
		t.Fatalf("first presentation must verify: %v", err)
	}
	_, err := platsaml.VerifyResponseWithOptions(ctx, resp, tn.cfg(), opts)
	if !errors.Is(err, platsaml.ErrAssertionReplayed) {
		t.Fatalf("second presentation: err = %v, want ErrAssertionReplayed", err)
	}

	t.Run("a replay-cache error fails closed", func(t *testing.T) {
		fresh := tn.mint(t, "p@acme.example.com", idp.AssertionInput{})
		if _, err := platsaml.VerifyResponseWithOptions(ctx, fresh, tn.cfg(), platsaml.VerifyOptions{Replay: failingReplay{}}); err == nil {
			t.Fatal("want rejection when the replay cache cannot answer")
		}
	})
	t.Run("a rejected response is not recorded", func(t *testing.T) {
		other := newSPTenant(t, "other")
		fresh := tn.mint(t, "p@acme.example.com", idp.AssertionInput{})
		if _, err := platsaml.VerifyResponseWithOptions(ctx, fresh, other.cfg(), opts); err == nil {
			t.Fatal("wrong tenant must be rejected")
		}
		if _, err := platsaml.VerifyResponseWithOptions(ctx, fresh, tn.cfg(), opts); err != nil {
			t.Fatalf("a response refused elsewhere must not be burned: %v", err)
		}
	})
}

func TestVerifier_InjectedClock(t *testing.T) {
	tn := newSPTenant(t, "acme")
	resp := tn.mint(t, "c@acme.example.com", idp.AssertionInput{})
	later := func() time.Time { return time.Now().Add(30 * time.Minute) }
	if _, err := verifierFor(tn).Verify(context.Background(), resp, platsaml.VerifyOptions{Now: later}); err == nil {
		t.Fatal("an assertion past NotOnOrAfter at the injected time must be rejected")
	}
}

func TestVerifier_CertificateRotation(t *testing.T) {
	tn := newSPTenant(t, "acme")
	previous := newSigningKey(t, "acme-idp-previous")
	stranger := newSigningKey(t, "stranger")
	resp := tn.mint(t, "k@acme.example.com", idp.AssertionInput{})
	ctx := context.Background()

	if _, err := verifierFor(tn, previous.Certificate, tn.key.Certificate).Verify(ctx, resp, platsaml.VerifyOptions{}); err != nil {
		t.Fatalf("current cert among trusted certs must verify: %v", err)
	}
	if _, err := verifierFor(tn, previous.Certificate, stranger.Certificate).Verify(ctx, resp, platsaml.VerifyOptions{}); err == nil {
		t.Fatal("no trusted cert signed it; want rejection")
	}
	if _, err := verifierFor(tn, nil).Verify(ctx, resp, platsaml.VerifyOptions{}); err == nil {
		t.Fatal("a nil trusted cert must not verify-skip")
	}
	empty := verifierFor(tn)
	empty.IDPCertificates = nil
	if _, err := empty.Verify(ctx, resp, platsaml.VerifyOptions{}); err == nil {
		t.Fatal("no trusted certs must reject, not verify-skip")
	}
}

func TestVerifier_WrongTenantIsRejected(t *testing.T) {
	a := newSPTenant(t, "tenant-a")
	b := newSPTenant(t, "tenant-b")
	resp := a.mint(t, "alice@tenant-a.example.com", idp.AssertionInput{})
	ctx := context.Background()
	if _, err := verifierFor(a).Verify(ctx, resp, platsaml.VerifyOptions{}); err != nil {
		t.Fatalf("tenant A must accept its own response: %v", err)
	}
	if got, err := verifierFor(b).Verify(ctx, resp, platsaml.VerifyOptions{}); err == nil {
		t.Fatalf("tenant B accepted tenant A's response: %+v", got)
	}
	// Same IdP key and entity trusted by B (one IdP org serving both): the SP
	// binding (audience, recipient, destination) still keeps them apart.
	shared := verifierFor(b, a.key.Certificate)
	shared.IDPEntityID = a.idpEntity
	if got, err := shared.Verify(ctx, resp, platsaml.VerifyOptions{}); err == nil {
		t.Fatalf("tenant B (shared IdP) accepted tenant A's response: %+v", got)
	}
}

func TestVerifiedAssertion_AttributeLookup(t *testing.T) {
	tn := newSPTenant(t, "acme")
	resp := tn.mint(t, "f@acme.example.com", idp.AssertionInput{Attributes: map[string][]string{
		"http://schemas.xmlsoap.org/ws/2005/05/identity/claims/emailaddress": {"f@acme.example.com"},
		"displayName": {"Fay"},
	}})
	got, err := verifierFor(tn).Verify(context.Background(), resp, platsaml.VerifyOptions{})
	if err != nil {
		t.Fatalf("Verify: %v", err)
	}
	if v := got.Attribute("email", "http://schemas.xmlsoap.org/ws/2005/05/identity/claims/emailaddress"); v != "f@acme.example.com" {
		t.Errorf("email = %q", v)
	}
	if v := got.Attribute("displayName"); v != "Fay" {
		t.Errorf("displayName = %q", v)
	}
	if v := got.Attribute("missing"); v != "" {
		t.Errorf("missing = %q", v)
	}
	if got.Issuer != tn.idpEntity || got.ID == "" || got.NotOnOrAfter.IsZero() {
		t.Errorf("assertion metadata = %+v", got)
	}
}

func TestParseIDPMetadata(t *testing.T) {
	tn := newSPTenant(t, "acme")
	raw, err := tn.issuer(t).Metadata()
	if err != nil {
		t.Fatalf("Metadata: %v", err)
	}

	t.Run("entity descriptor", func(t *testing.T) {
		md, err := platsaml.ParseIDPMetadata(raw)
		if err != nil {
			t.Fatalf("ParseIDPMetadata: %v", err)
		}
		if md.EntityID != tn.idpEntity {
			t.Errorf("EntityID = %q", md.EntityID)
		}
		if len(md.SigningCertificates) != 1 || !md.SigningCertificates[0].Equal(tn.key.Certificate) {
			t.Errorf("SigningCertificates = %v", md.SigningCertificates)
		}
		if md.SSOLocation(platsaml.BindingHTTPRedirect) == "" && md.SSOLocation(platsaml.BindingHTTPPost) == "" {
			t.Errorf("no SSO endpoint parsed: %+v", md.SSOServices)
		}
	})
	t.Run("wrapped in EntitiesDescriptor", func(t *testing.T) {
		body := string(raw)
		if i := strings.Index(body, "?>"); i >= 0 {
			body = body[i+2:]
		}
		wrapped := `<EntitiesDescriptor xmlns="urn:oasis:names:tc:SAML:2.0:metadata">` + body + `</EntitiesDescriptor>`
		md, err := platsaml.ParseIDPMetadata([]byte(wrapped))
		if err != nil || md.EntityID != tn.idpEntity {
			t.Fatalf("md=%+v err=%v", md, err)
		}
	})
	t.Run("errors", func(t *testing.T) {
		for name, in := range map[string]string{
			"garbage":             "not xml",
			"no IDPSSODescriptor": `<EntityDescriptor xmlns="urn:oasis:names:tc:SAML:2.0:metadata" entityID="https://x"/>`,
			"no entityID":         `<EntityDescriptor xmlns="urn:oasis:names:tc:SAML:2.0:metadata"><IDPSSODescriptor protocolSupportEnumeration="urn:oasis:names:tc:SAML:2.0:protocol"/></EntityDescriptor>`,
		} {
			if _, err := platsaml.ParseIDPMetadata([]byte(in)); err == nil {
				t.Errorf("%s: want error", name)
			}
		}
	})
}
