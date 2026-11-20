package saml_test

import (
	"encoding/base64"
	"strings"
	"testing"
	"time"

	"github.com/beevik/etree"
	platsaml "go.aocyber.ai/eden-platform-go/platform/auth/saml"
	"go.aocyber.ai/eden-platform-go/platform/auth/saml/idp"
)

// Behaviour lock for VerifyResponse (issue #87). These cases go through the
// existing public API only, so the same file runs against the crewjam-backed
// verifier (before) and the gosaml2-backed one (after). Every rejection case
// also asserts that the attacker-chosen identity never comes back.
//
// Test list:
//   - accept: response-signed, assertion-signed, both signed, IssueInstant
//     inside the clock-skew window
//   - reject: unsigned, signed by the wrong key, assertion re-signed by an
//     attacker under a trusted response signature
//   - reject: signature wrapping (duplicated assertion, wrapped assertion,
//     signed response nested under an unsigned one, assertion appended after
//     signing); comment injection yields the signed value or an error
//   - reject: wrong Audience, Recipient, Destination, Issuer; non-success
//     Status; expired; not yet valid
//   - reject: an InResponseTo the stateless verifier never issued
//   - reject: tenant A's response at tenant B's SP (own key, and shared key)
//   - error, no panic: malformed base64, non-XML, deep nesting, huge input

const lockEvil = "attacker@evil.example.com"

// mustVerify verifies resp for tn and fails the test on error.
func mustVerify(t *testing.T, resp string, cfg platsaml.Config) map[string]string {
	t.Helper()
	attrs, err := verifyNoPanic(t, resp, cfg)
	if err != nil {
		t.Fatalf("want a verified response, got: %v", err)
	}
	return attrs
}

// mustReject asserts resp is refused and never yields forbidden as the email.
func mustReject(t *testing.T, resp string, cfg platsaml.Config, forbidden ...string) {
	t.Helper()
	attrs, err := verifyNoPanic(t, resp, cfg)
	for _, f := range forbidden {
		if attrs["email"] == f {
			t.Fatalf("verifier returned forbidden identity %q", f)
		}
	}
	if err == nil {
		t.Fatalf("want rejection, got attributes %v", attrs)
	}
}

func TestSPVerify_AcceptsEachSigningProfile(t *testing.T) {
	tn := newSPTenant(t, "acme")
	const email = "alice@acme.example.com"
	base := tn.mint(t, email, idp.AssertionInput{})
	for name, resp := range map[string]string{
		"response signed (native)": base,
		"response signed":          resignAs(t, tn.key, base, signResponseOnly, nil),
		"assertion signed":         resignAs(t, tn.key, base, signAssertionOnly, nil),
		"both signed":              resignAs(t, tn.key, base, signBoth, nil),
	} {
		t.Run(name, func(t *testing.T) {
			attrs := mustVerify(t, resp, tn.cfg())
			if attrs["email"] != email || attrs["first_name"] != "Test" {
				t.Fatalf("attrs = %v", attrs)
			}
		})
	}
}

func TestSPVerify_AcceptsIssueInstantInsideSkew(t *testing.T) {
	tn := newSPTenant(t, "acme")
	resp := tn.mint(t, "skew@acme.example.com", idp.AssertionInput{IssueInstant: time.Now().UTC().Add(30 * time.Second)})
	mustVerify(t, resp, tn.cfg())
}

func TestSPVerify_RejectsUnsignedAssertion(t *testing.T) {
	tn := newSPTenant(t, "acme")
	base := tn.mint(t, "u@acme.example.com", idp.AssertionInput{})
	t.Run("nothing signed", func(t *testing.T) {
		mustReject(t, resignAs(t, tn.key, base, signNone, nil), tn.cfg())
	})
	t.Run("nothing signed, identity swapped", func(t *testing.T) {
		resp := resignAs(t, tn.key, base, signNone, func(r *etree.Element) { setEmail(r.SelectElement("Assertion"), lockEvil) })
		mustReject(t, resp, tn.cfg(), lockEvil)
	})
}

func TestSPVerify_RejectsUntrustedSigner(t *testing.T) {
	tn := newSPTenant(t, "acme")
	attacker := newSigningKey(t, "attacker")
	base := tn.mint(t, "real@acme.example.com", idp.AssertionInput{})
	for name, mode := range map[string]signMode{
		"response":  signResponseOnly,
		"assertion": signAssertionOnly,
		"both":      signBoth,
	} {
		t.Run(name, func(t *testing.T) {
			resp := resignAs(t, attacker, base, mode, func(r *etree.Element) { setEmail(r.SelectElement("Assertion"), lockEvil) })
			mustReject(t, resp, tn.cfg(), lockEvil)
		})
	}
	t.Run("attacker-signed assertion inside a trusted response signature", func(t *testing.T) {
		// Attacker-signed assertion, then the trusted key signs the envelope:
		// an assertion signature that does not verify must fail the response.
		inner := resignAs(t, attacker, base, signAssertionOnly, func(r *etree.Element) { setEmail(r.SelectElement("Assertion"), lockEvil) })
		doc := decodeDoc(t, inner)
		root := signElement(t, tn.key, doc.Root())
		out := etree.NewDocument()
		out.SetRoot(root)
		raw, err := out.WriteToBytes()
		if err != nil {
			t.Fatal(err)
		}
		mustReject(t, base64.StdEncoding.EncodeToString(raw), tn.cfg(), lockEvil)
	})
}

// Signature-wrapping variants: the signed content stays intact and verifies,
// while an unsigned, attacker-controlled assertion is placed where a naive
// parser would read it.
func TestSPVerify_RejectsSignatureWrapping(t *testing.T) {
	tn := newSPTenant(t, "acme")
	const real = "real@acme.example.com"
	base := tn.mint(t, real, idp.AssertionInput{})
	assertionSigned := resignAs(t, tn.key, base, signAssertionOnly, nil)

	evilCopy := func(a *etree.Element) *etree.Element {
		e := a.Copy()
		stripAllSignatures(e)
		e.CreateAttr("ID", "_evil")
		setEmail(e, lockEvil)
		return e
	}

	cases := map[string]string{
		"unsigned evil assertion before the signed one": mutateDoc(t, assertionSigned, func(r *etree.Element) {
			a := r.SelectElement("Assertion")
			r.InsertChildAt(a.Index(), evilCopy(a))
		}),
		"unsigned evil assertion after the signed one": mutateDoc(t, assertionSigned, func(r *etree.Element) {
			r.AddChild(evilCopy(r.SelectElement("Assertion")))
		}),
		"signed assertion wrapped inside the evil one": mutateDoc(t, assertionSigned, func(r *etree.Element) {
			a := r.SelectElement("Assertion")
			e := evilCopy(a)
			r.RemoveChild(a)
			e.SelectElement("Subject").AddChild(a)
			r.AddChild(e)
		}),
		"signed response nested under an unsigned evil response": mutateDoc(t, base, func(r *etree.Element) {
			signed := r.Copy()
			for _, a := range r.SelectElements("Assertion") {
				setEmail(a, lockEvil)
			}
			stripAllSignatures(r)
			r.CreateAttr("ID", "_evil-response")
			ext := r.CreateElement("samlp:Extensions")
			ext.AddChild(signed)
		}),
		"evil assertion appended to a signed response": mutateDoc(t, base, func(r *etree.Element) {
			r.AddChild(evilCopy(r.SelectElement("Assertion")))
		}),
	}
	for name, resp := range cases {
		t.Run(name, func(t *testing.T) {
			mustReject(t, resp, tn.cfg(), lockEvil)
		})
	}
}

// A comment inside a signed text node is dropped by exclusive C14N, so the
// signature still verifies. The verifier must use the whole signed value (or
// refuse), never the text before the comment.
func TestSPVerify_CommentInjectionYieldsSignedValue(t *testing.T) {
	tn := newSPTenant(t, "acme")
	const prefix = "victim@acme.example.com"
	const signedValue = prefix + ".attacker.test"
	base := tn.mint(t, signedValue, idp.AssertionInput{})
	resp := mutateDoc(t, base, func(r *etree.Element) {
		a := r.SelectElement("Assertion")
		split := func(el *etree.Element) {
			el.SetText(prefix)
			el.CreateComment("x")
			el.CreateText(".attacker.test")
		}
		for _, el := range a.FindElements(".//NameID") {
			split(el)
		}
		for _, attr := range a.FindElements(".//Attribute") {
			if attr.SelectAttrValue("Name", "") == "email" {
				split(attr.SelectElement("AttributeValue"))
			}
		}
	})
	attrs, err := verifyNoPanic(t, resp, tn.cfg())
	if err == nil && attrs["email"] != signedValue {
		t.Fatalf("email = %q; want the signed value %q or a rejection", attrs["email"], signedValue)
	}
}

func TestSPVerify_RejectsWrongBinding(t *testing.T) {
	tn := newSPTenant(t, "acme")
	base := tn.mint(t, "b@acme.example.com", idp.AssertionInput{})
	setAttr := func(path, attr, val string) func(*etree.Element) {
		return func(r *etree.Element) {
			for _, el := range r.FindElements(path) {
				el.CreateAttr(attr, val)
			}
		}
	}
	setText := func(path, val string) func(*etree.Element) {
		return func(r *etree.Element) {
			for _, el := range r.FindElements(path) {
				el.SetText(val)
			}
		}
	}
	cases := map[string]func(*etree.Element){
		"wrong audience":    setText("./Assertion/Conditions/AudienceRestriction/Audience", "https://other-sp.example.com/metadata"),
		"wrong recipient":   setAttr("./Assertion/Subject/SubjectConfirmation/SubjectConfirmationData", "Recipient", "https://other-sp.example.com/acs"),
		"wrong destination": setAttr(".", "Destination", "https://other-sp.example.com/acs"),
		"wrong issuer": func(r *etree.Element) {
			setText("./Issuer", "https://idp.evil.example.com")(r)
			setText("./Assertion/Issuer", "https://idp.evil.example.com")(r)
		},
		"non-success status": setAttr("./Status/StatusCode", "Value", "urn:oasis:names:tc:SAML:2.0:status:Requester"),
	}
	for name, mutate := range cases {
		for mname, mode := range map[string]signMode{"response signed": signResponseOnly, "assertion signed": signAssertionOnly} {
			t.Run(name+"/"+mname, func(t *testing.T) {
				if name == "wrong destination" || name == "non-success status" {
					if mode == signAssertionOnly {
						t.Skip("Response-level field: unsigned in an assertion-only profile")
					}
				}
				mustReject(t, resignAs(t, tn.key, base, mode, mutate), tn.cfg())
			})
		}
	}
	t.Run("config pins another IdP entity", func(t *testing.T) {
		cfg := tn.cfg()
		cfg.IDPEntityID = "https://idp.other.example.com/metadata"
		mustReject(t, base, cfg)
	})
}

func TestSPVerify_RejectsOutsideValidityWindow(t *testing.T) {
	tn := newSPTenant(t, "acme")
	for name, at := range map[string]time.Time{
		"expired an hour ago":   time.Now().UTC().Add(-time.Hour),
		"expired beyond skew":   time.Now().UTC().Add(-9 * time.Minute),
		"not valid for an hour": time.Now().UTC().Add(time.Hour),
		"beyond skew in future": time.Now().UTC().Add(10 * time.Minute),
	} {
		t.Run(name, func(t *testing.T) {
			mustReject(t, tn.mint(t, "w@acme.example.com", idp.AssertionInput{IssueInstant: at}), tn.cfg())
		})
	}
}

// VerifyResponse is stateless: it never issued an AuthnRequest, so any
// InResponseTo is unknown to it and must be refused.
func TestSPVerify_RejectsUnknownInResponseTo(t *testing.T) {
	tn := newSPTenant(t, "acme")
	mustReject(t, tn.mint(t, "i@acme.example.com", idp.AssertionInput{InResponseTo: "_never-issued"}), tn.cfg())
}

// Wrong-tenant isolation: a response that is valid for tenant A is refused at
// tenant B's SP, whether B trusts a different IdP key or the same one.
func TestSPVerify_WrongTenantIsRejected(t *testing.T) {
	a := newSPTenant(t, "tenant-a")
	b := newSPTenant(t, "tenant-b")
	const email = "alice@tenant-a.example.com"
	respA := a.mint(t, email, idp.AssertionInput{})
	mustVerify(t, respA, a.cfg())

	t.Run("tenant B trusts its own IdP", func(t *testing.T) {
		mustReject(t, respA, b.cfg(), email)
	})
	t.Run("tenant B trusts the same IdP key and entity", func(t *testing.T) {
		shared := b.cfg()
		shared.IDPCert = a.cfg().IDPCert
		shared.IDPEntityID = a.idpEntity
		mustReject(t, respA, shared, email)
	})
}

func TestSPVerify_MalformedInputErrorsWithoutPanic(t *testing.T) {
	tn := newSPTenant(t, "acme")
	b64 := func(s string) string { return base64.StdEncoding.EncodeToString([]byte(s)) }
	deep := `<samlp:Response xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol">` + strings.Repeat("<a>", 50000) + strings.Repeat("</a>", 50000) + `</samlp:Response>`
	huge := `<samlp:Response xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol">` + strings.Repeat("<x/>", 2_000_000) + `</samlp:Response>`
	for name, resp := range map[string]string{
		"empty":        "",
		"not base64":   "%%%not-base64%%%",
		"not xml":      b64("this is not xml"),
		"empty xml":    b64("<?xml version=\"1.0\"?>"),
		"deep nesting": b64(deep),
		"huge input":   b64(huge),
	} {
		t.Run(name, func(t *testing.T) {
			mustReject(t, resp, tn.cfg())
		})
	}
}
