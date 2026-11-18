package saml_test

import (
	"crypto/tls"
	"encoding/base64"
	"testing"

	"github.com/beevik/etree"
	dsig "github.com/russellhaering/goxmldsig"
	platsaml "go.aocyber.ai/eden-platform-go/platform/auth/saml"
	"go.aocyber.ai/eden-platform-go/platform/auth/saml/idp"
)

// GO-2026-6909 (crewjam/saml through v0.5.1), issue #73.
//
//  1. A SIGNED assertion that omits an optional element (Subject, Conditions)
//     made ServiceProvider.validateAssertion dereference nil AFTER the signature
//     check: a panic reachable by anyone holding a trusted IdP's signing key.
//  2. Subject.NameID carried the bare xml:"NameID" tag, so a <NameID> in a
//     foreign namespace populated Subject.NameID when the real saml:NameID was
//     absent — and VerifyResponse's NameID→email fallback turned that into the
//     login email.
//
// Every fixture here is GENUINELY signed: resign() takes a response minted by
// the saml/idp toolkit, strips its signature, applies one deterministic etree
// transform, and signs the result again with the same trusted IdP key. The
// signature therefore verifies, which is the precondition for both flaws.

// resign applies mutate to the decoded response and re-signs it (enveloped,
// RSA-SHA256, exclusive C14N — the toolkit's own signing profile) with key.
func resign(t *testing.T, key *platsaml.SigningKey, b64 string, mutate func(resp *etree.Element)) string {
	t.Helper()
	doc := decodeDoc(t, b64)
	for _, sig := range doc.FindElements("//Signature") {
		if p := sig.Parent(); p != nil {
			p.RemoveChild(sig)
		}
	}
	mutate(doc.Root())

	ctx := dsig.NewDefaultSigningContext(dsig.TLSCertKeyStore(tls.Certificate{
		PrivateKey:  key.PrivateKey,
		Certificate: [][]byte{key.Certificate.Raw},
	}))
	ctx.Canonicalizer = dsig.MakeC14N10ExclusiveCanonicalizerWithPrefixList("")
	if err := ctx.SetSignatureMethod(dsig.RSASHA256SignatureMethod); err != nil {
		t.Fatalf("SetSignatureMethod: %v", err)
	}
	signed, err := ctx.SignEnveloped(doc.Root())
	if err != nil {
		t.Fatalf("SignEnveloped: %v", err)
	}
	out := etree.NewDocument()
	out.SetRoot(signed)
	raw, err := out.WriteToBytes()
	if err != nil {
		t.Fatalf("write signed xml: %v", err)
	}
	return base64.StdEncoding.EncodeToString(raw)
}

// removeAssertionChild deletes every <tag> directly under the Assertion.
func removeAssertionChild(tag string) func(*etree.Element) {
	return func(resp *etree.Element) {
		a := resp.FindElement("./Assertion")
		for _, el := range a.SelectElements(tag) {
			a.RemoveChild(el)
		}
	}
}

// removeEmailAttribute deletes the "email" Attribute so VerifyResponse has to
// decide whether to fall back to the NameID.
func removeEmailAttribute(resp *etree.Element) {
	for _, stmt := range resp.FindElements("./Assertion/AttributeStatement") {
		for _, attr := range stmt.SelectElements("Attribute") {
			if attr.SelectAttrValue("Name", "") == "email" {
				stmt.RemoveChild(attr)
			}
		}
	}
}

// verifyNoPanic calls VerifyResponse and converts a panic into a test failure,
// so a RED run reports the flaw instead of killing the test binary.
func verifyNoPanic(t *testing.T, resp string, cfg platsaml.Config) (attrs map[string]string, err error) {
	t.Helper()
	defer func() {
		if r := recover(); r != nil {
			t.Fatalf("GO-2026-6909: VerifyResponse panicked on a signed assertion: %v", r)
		}
	}()
	return platsaml.VerifyResponse(resp, cfg)
}

// Control: the resign fixture itself produces a response that verifies, so the
// failures below are caused by the mutation, not by a broken re-signature.
func TestVerifyResponse_6909_ResignedControlVerifies(t *testing.T) {
	key := newSigningKey(t, "tenant-idp")
	resp := resign(t, key, mintSigned(t, newIDP(t, key), "ctl@tenant.example.com"), func(*etree.Element) {})

	attrs, err := verifyNoPanic(t, resp, verifyCfg(certPEM(t, key)))
	if err != nil {
		t.Fatalf("an untouched, re-signed response must verify: %v", err)
	}
	if attrs["email"] != "ctl@tenant.example.com" {
		t.Errorf("email = %q", attrs["email"])
	}
}

func TestVerifyResponse_6909_SignedAssertionWithoutSubjectIsRejected(t *testing.T) {
	key := newSigningKey(t, "tenant-idp")
	resp := resign(t, key, mintSigned(t, newIDP(t, key), "s@tenant.example.com"), removeAssertionChild("Subject"))

	if _, err := verifyNoPanic(t, resp, verifyCfg(certPEM(t, key))); err == nil {
		t.Fatal("a signed assertion with no Subject must be rejected")
	}
}

func TestVerifyResponse_6909_SignedAssertionWithoutConditionsIsRejected(t *testing.T) {
	key := newSigningKey(t, "tenant-idp")
	resp := resign(t, key, mintSigned(t, newIDP(t, key), "c@tenant.example.com"), removeAssertionChild("Conditions"))

	if _, err := verifyNoPanic(t, resp, verifyCfg(certPEM(t, key))); err == nil {
		t.Fatal("a signed assertion with no Conditions must be rejected")
	}
}

// The spoof: the real saml:NameID is replaced by a foreign-namespace NameID
// carrying another user's address, and the email attribute is removed. The
// victim's address must never come back as the login email.
func TestVerifyResponse_6909_ForeignNamespaceNameIDIsNotTheEmail(t *testing.T) {
	const victim = "victim@other-tenant.example.com"
	key := newSigningKey(t, "tenant-idp")
	resp := resign(t, key, mintSigned(t, newIDP(t, key), "attacker@tenant.example.com"), func(r *etree.Element) {
		removeEmailAttribute(r)
		subject := r.FindElement("./Assertion/Subject")
		real := subject.SelectElement("NameID")
		format := real.SelectAttrValue("Format", "")
		subject.RemoveChild(real)
		foreign := etree.NewElement("x:NameID")
		foreign.CreateAttr("xmlns:x", "urn:example:not-saml")
		foreign.CreateAttr("Format", format)
		foreign.SetText(victim)
		subject.InsertChildAt(0, foreign)
	})

	attrs, err := verifyNoPanic(t, resp, verifyCfg(certPEM(t, key)))
	if err == nil && attrs["email"] == victim {
		t.Fatalf("GO-2026-6909: a foreign-namespace NameID became the login email %q", attrs["email"])
	}
}

// mintWithoutEmailAttr mints a natively signed response whose only identity
// is the NameID (value + format): no "email" attribute at all.
func mintWithoutEmailAttr(t *testing.T, key *platsaml.SigningKey, nameID, format string) string {
	t.Helper()
	signed, err := newIDP(t, key).IssueAssertion(idp.AssertionInput{
		SPEntityID:   vSPEntityID,
		NameID:       nameID,
		NameIDFormat: format,
		Attributes:   map[string][]string{"first_name": {"Test"}},
	})
	if err != nil {
		t.Fatalf("IssueAssertion: %v", err)
	}
	return base64.StdEncoding.EncodeToString(signed)
}

const (
	nameIDFormatEmail      = "urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress"
	nameIDFormatPersistent = "urn:oasis:names:tc:SAML:2.0:nameid-format:persistent"
)

// The NameID -> email fallback is kept only where it is justified: the IdP
// signed a saml:NameID whose Format says it IS an email address, and the value
// parses as one. Each case below is a signed response with no email attribute.
func TestVerifyResponse_NameIDEmailFallback(t *testing.T) {
	cases := []struct {
		name      string
		nameID    string
		format    string
		wantEmail string
	}{
		{"emailAddress format with an address falls back", "nina@tenant.example.com", nameIDFormatEmail, "nina@tenant.example.com"},
		{"persistent opaque id is never an email", "a1b2c3-opaque-subject", nameIDFormatPersistent, ""},
		{"persistent id shaped like an address is still not an email", "victim@other-tenant.example.com", nameIDFormatPersistent, ""},
		{"emailAddress format with a non-address is rejected", "not-an-address", nameIDFormatEmail, ""},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			key := newSigningKey(t, "tenant-idp")
			resp := mintWithoutEmailAttr(t, key, tc.nameID, tc.format)

			attrs, err := verifyNoPanic(t, resp, verifyCfg(certPEM(t, key)))
			if err != nil {
				t.Fatalf("a genuinely signed response must verify: %v", err)
			}
			if got := attrs["email"]; got != tc.wantEmail {
				t.Errorf("email = %q, want %q", got, tc.wantEmail)
			}
		})
	}
}
