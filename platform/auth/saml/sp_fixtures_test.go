package saml_test

import (
	"crypto/tls"
	"encoding/base64"
	"testing"
	"time"

	"github.com/beevik/etree"
	dsig "github.com/russellhaering/goxmldsig"
	platsaml "go.aocyber.ai/eden-platform-go/platform/auth/saml"
	"go.aocyber.ai/eden-platform-go/platform/auth/saml/idp"
)

// Fixture generators for the SP verifier suite (issue #87).
//
// Every response is minted by this module's own signing IdP (saml/idp) and
// then changed with a deterministic etree transform. Where a transform must
// leave the result validly signed, the fixture re-signs it with the tenant's
// real key, so a rejection is caused by the transform and never by a broken
// signature. There is no hand-written SAML XML.

// spTenant is one tenant's SAML trust pair: its upstream IdP (entity ID +
// signing key) and the SP entity ID / ACS URL the platform serves for it.
type spTenant struct {
	name      string
	key       *platsaml.SigningKey
	idpEntity string
	spEntity  string
	acs       string
}

// newSPTenant builds a tenant with its own IdP key and URLs derived from name.
func newSPTenant(t *testing.T, name string) *spTenant {
	t.Helper()
	return &spTenant{
		name:      name,
		key:       newSigningKey(t, name+"-idp"),
		idpEntity: "https://idp." + name + ".example.com/metadata",
		spEntity:  "https://app.platform.local/auth/saml/" + name + "/metadata",
		acs:       "https://app.platform.local/auth/saml/" + name + "/callback",
	}
}

// cfg is the SP Config the platform stores for this tenant.
func (tn *spTenant) cfg() platsaml.Config {
	return platsaml.Config{
		IDPCert:     string(tn.key.CertificatePEM()),
		IDPEntityID: tn.idpEntity,
		SPEntityID:  tn.spEntity,
		ACSURL:      tn.acs,
	}
}

// issuer returns the tenant's IdP with its own SP registered.
func (tn *spTenant) issuer(t *testing.T) *idp.IdentityProvider {
	t.Helper()
	p, err := idp.New(idp.Config{
		EntityID:          tn.idpEntity,
		SSOURL:            tn.idpEntity + "/sso",
		CurrentKey:        tn.key,
		AssertionLifetime: 5 * time.Minute,
		AllowedSPs: map[string]idp.SPRegistration{
			tn.spEntity: {EntityID: tn.spEntity, ACSURL: tn.acs},
		},
	})
	if err != nil {
		t.Fatalf("idp.New(%s): %v", tn.name, err)
	}
	return p
}

// mint returns a base64 Response, signed on the Response element only (the
// toolkit's native profile), for email with default attributes. in may
// override InResponseTo / IssueInstant / NameID fields.
func (tn *spTenant) mint(t *testing.T, email string, in idp.AssertionInput) string {
	t.Helper()
	in.SPEntityID = tn.spEntity
	if in.NameID == "" {
		in.NameID = email
	}
	if in.Attributes == nil {
		in.Attributes = map[string][]string{
			"email":      {email},
			"first_name": {"Test"},
			"last_name":  {"User"},
		}
	}
	signed, err := tn.issuer(t).IssueAssertion(in)
	if err != nil {
		t.Fatalf("IssueAssertion(%s): %v", tn.name, err)
	}
	return base64.StdEncoding.EncodeToString(signed)
}

// signMode says which elements a re-signed fixture carries a signature on.
type signMode int

const (
	signNone signMode = iota
	signResponseOnly
	signAssertionOnly
	signBoth
)

// resignAs strips every signature from b64, applies mutate (may be nil), and
// signs the result per mode with key.
func resignAs(t *testing.T, key *platsaml.SigningKey, b64 string, mode signMode, mutate func(resp *etree.Element)) string {
	t.Helper()
	doc := decodeDoc(t, b64)
	stripAllSignatures(doc.Root())
	if mutate != nil {
		mutate(doc.Root())
	}
	root := doc.Root()
	if mode == signAssertionOnly || mode == signBoth {
		for _, a := range root.SelectElements("Assertion") {
			signed := signElement(t, key, a)
			replaceChild(root, a, signed)
		}
	}
	if mode == signResponseOnly || mode == signBoth {
		root = signElement(t, key, root)
	}
	out := etree.NewDocument()
	out.SetRoot(root)
	raw, err := out.WriteToBytes()
	if err != nil {
		t.Fatalf("write xml: %v", err)
	}
	return base64.StdEncoding.EncodeToString(raw)
}

func stripAllSignatures(el *etree.Element) {
	for _, sig := range el.FindElements(".//Signature") {
		if p := sig.Parent(); p != nil {
			p.RemoveChild(sig)
		}
	}
}

// signElement returns an enveloped-signed copy of el (RSA-SHA256, exclusive
// C14N: the toolkit's own signing profile).
func signElement(t *testing.T, key *platsaml.SigningKey, el *etree.Element) *etree.Element {
	t.Helper()
	ctx := dsig.NewDefaultSigningContext(dsig.TLSCertKeyStore(tls.Certificate{
		PrivateKey:  key.PrivateKey,
		Certificate: [][]byte{key.Certificate.Raw},
	}))
	ctx.Canonicalizer = dsig.MakeC14N10ExclusiveCanonicalizerWithPrefixList("")
	if err := ctx.SetSignatureMethod(dsig.RSASHA256SignatureMethod); err != nil {
		t.Fatalf("SetSignatureMethod: %v", err)
	}
	signed, err := ctx.SignEnveloped(el)
	if err != nil {
		t.Fatalf("SignEnveloped: %v", err)
	}
	return signed
}

func replaceChild(parent, old, repl *etree.Element) {
	idx := old.Index()
	parent.RemoveChild(old)
	parent.InsertChildAt(idx, repl)
}

// mutateDoc applies mutate to b64 WITHOUT re-signing.
func mutateDoc(t *testing.T, b64 string, mutate func(resp *etree.Element)) string {
	t.Helper()
	doc := decodeDoc(t, b64)
	mutate(doc.Root())
	return encodeDoc(t, doc)
}

// setEmail rewrites the NameID and the email attribute value of a.
func setEmail(a *etree.Element, email string) {
	for _, el := range a.FindElements(".//NameID") {
		el.SetText(email)
	}
	for _, attr := range a.FindElements(".//Attribute") {
		if attr.SelectAttrValue("Name", "") == "email" {
			if v := attr.SelectElement("AttributeValue"); v != nil {
				v.SetText(email)
			}
		}
	}
}
