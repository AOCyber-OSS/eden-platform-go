package saml

import (
	"context"
	"crypto/x509"
	"errors"
	"fmt"
	"slices"
	"strings"
	"time"

	saml2 "github.com/russellhaering/gosaml2"
	"github.com/russellhaering/gosaml2/types"
	dsig "github.com/russellhaering/goxmldsig"
)

// DefaultClockSkew is the clock drift tolerated between the IdP and this SP
// when checking NotBefore, NotOnOrAfter and IssueInstant.
const DefaultClockSkew = 180 * time.Second

// maxResponseIssueDelay is how long after its IssueInstant a Response is still
// accepted, on top of the clock skew.
const maxResponseIssueDelay = 90 * time.Second

// maxEncodedResponseBytes bounds the base64 SAMLResponse accepted for
// verification. Real responses, including ones carrying large group claims,
// are far smaller.
const maxEncodedResponseBytes = 2 << 20

// ErrAssertionReplayed is returned when VerifyOptions.Replay reports that the
// assertion ID was already accepted.
var ErrAssertionReplayed = errors.New("saml: assertion already used")

// ReplayCache records accepted assertion IDs. Seen must record assertionID and
// report whether it was already recorded, atomically. platform/saml's
// ReplayStore implementations satisfy it.
type ReplayCache interface {
	Seen(ctx context.Context, assertionID string, expiresAt time.Time) (alreadySeen bool, err error)
}

// VerifyOptions tunes one verification.
type VerifyOptions struct {
	// RequestIDs are the AuthnRequest IDs this SP issued and still accepts.
	// A response or assertion carrying an InResponseTo must name one of them.
	// Empty entries never match.
	RequestIDs []string
	// RequireInResponseTo refuses unsolicited (IdP-initiated) responses: a
	// signed InResponseTo naming one of RequestIDs is then mandatory.
	RequireInResponseTo bool
	// Replay, when set, refuses an assertion whose ID was already accepted.
	// Only responses that pass every other check are recorded.
	Replay ReplayCache
	// Now overrides the verification clock (tests).
	Now func() time.Time
}

// Verifier verifies SAML 2.0 Responses for one SP / IdP trust pair. Every
// field is required; a Verifier missing one rejects every response.
type Verifier struct {
	// IDPEntityID is the IdP entity ID; Response and Assertion Issuer must
	// equal it.
	IDPEntityID string
	// IDPCertificates are the IdP signing certificates trusted for this
	// tenant (more than one during rotation).
	IDPCertificates []*x509.Certificate
	// SPEntityID is this SP's entity ID; the assertion audience must be it.
	SPEntityID string
	// ACSURL is this SP's assertion consumer URL; Destination (when present)
	// and the bearer Recipient must equal it.
	ACSURL string
	// ClockSkew overrides DefaultClockSkew when positive.
	ClockSkew time.Duration
}

// VerifiedAssertion is the cryptographically verified content of a SAML
// assertion. It is only ever produced by Verifier.Verify.
type VerifiedAssertion struct {
	ID           string
	Issuer       string
	NameID       string
	NameIDFormat string
	InResponseTo string
	SessionIndex string
	NotOnOrAfter time.Time
	Attributes   []Attribute
}

// Attribute is one verified SAML attribute.
type Attribute struct {
	Name         string
	FriendlyName string
	Values       []string
}

// Attribute returns the first value of the first attribute whose Name or
// FriendlyName equals one of names, in the order names are given.
func (a *VerifiedAssertion) Attribute(names ...string) string {
	if a == nil {
		return ""
	}
	for _, name := range names {
		for _, attr := range a.Attributes {
			if (attr.Name == name || attr.FriendlyName == name) && len(attr.Values) > 0 {
				return attr.Values[0]
			}
		}
	}
	return ""
}

// Verify decodes the base64 SAMLResponse and returns its assertion only if
// all of the following hold:
//
//   - the Response or the Assertion carries an XML signature by one of
//     IDPCertificates (an assertion signature, when present, must verify
//     even under a signed Response), and the values returned are read from
//     the signed element;
//   - the Response contains exactly one assertion;
//   - Response and Assertion Issuer equal IDPEntityID; Status is Success;
//   - Destination, when present, equals ACSURL; a bearer
//     SubjectConfirmation names ACSURL as Recipient and is not expired;
//   - Conditions carry at least one AudienceRestriction, each naming
//     SPEntityID; NotBefore/NotOnOrAfter hold within ClockSkew; the Response
//     IssueInstant is recent and no IssueInstant is in the future;
//   - InResponseTo satisfies opts (see VerifyOptions);
//   - opts.Replay, when set, has not seen the assertion ID.
//
// Parsing and signature validation are delegated to russellhaering/gosaml2
// and goxmldsig; the remaining checks are done here because gosaml2 reports
// audience and validity-window failures only as warnings.
func (v Verifier) Verify(ctx context.Context, samlResponse string, opts VerifyOptions) (*VerifiedAssertion, error) {
	certs := make([]*x509.Certificate, 0, len(v.IDPCertificates))
	for _, c := range v.IDPCertificates {
		if c != nil {
			certs = append(certs, c)
		}
	}
	switch {
	case len(certs) == 0:
		return nil, errors.New("saml: no trusted IdP signing certificate")
	case v.IDPEntityID == "":
		return nil, errors.New("saml: IdP entity ID is not configured")
	case v.SPEntityID == "":
		return nil, errors.New("saml: SP entity ID is not configured")
	case v.ACSURL == "":
		return nil, errors.New("saml: ACS URL is not configured")
	case samlResponse == "":
		return nil, errors.New("saml: empty SAMLResponse")
	case len(samlResponse) > maxEncodedResponseBytes:
		return nil, errors.New("saml: SAMLResponse too large")
	}

	now := time.Now()
	if opts.Now != nil {
		now = opts.Now()
	}
	skew := v.ClockSkew
	if skew <= 0 {
		skew = DefaultClockSkew
	}

	sp := &saml2.SAMLServiceProvider{
		IdentityProviderIssuer:      v.IDPEntityID,
		AssertionConsumerServiceURL: v.ACSURL,
		ServiceProviderIssuer:       v.SPEntityID,
		AudienceURI:                 v.SPEntityID,
		IDPCertificateStore:         &dsig.MemoryX509CertificateStore{Roots: certs},
		AllowMissingAttributes:      true,
		Clock:                       dsig.NewFakeClockAt(now),
	}

	resp, err := sp.ValidateEncodedResponse(strings.TrimSpace(samlResponse))
	if err != nil {
		return nil, fmt.Errorf("saml: response rejected: %w", err)
	}
	if len(resp.Assertions) != 1 {
		return nil, fmt.Errorf("saml: response rejected: want exactly one assertion, got %d", len(resp.Assertions))
	}
	a := resp.Assertions[0]

	warn, err := sp.VerifyAssertionConditions(&a)
	if err != nil {
		return nil, fmt.Errorf("saml: assertion conditions: %w", err)
	}
	if warn.NotInAudience || len(a.Conditions.AudienceRestrictions) == 0 {
		return nil, fmt.Errorf("saml: assertion audience is not %q", v.SPEntityID)
	}
	notOnOrAfter, err := checkValidityWindow(resp, &a, now, skew)
	if err != nil {
		return nil, err
	}
	if a.Subject == nil || a.Subject.NameID == nil {
		return nil, errors.New("saml: assertion has no NameID")
	}
	inResponseTo, err := checkInResponseTo(resp, &a, opts)
	if err != nil {
		return nil, err
	}

	if opts.Replay != nil {
		if a.ID == "" {
			return nil, errors.New("saml: assertion has no ID")
		}
		seen, err := opts.Replay.Seen(ctx, a.ID, notOnOrAfter.Add(skew))
		if err != nil {
			return nil, fmt.Errorf("saml: replay check: %w", err)
		}
		if seen {
			return nil, ErrAssertionReplayed
		}
	}

	return toVerifiedAssertion(&a, inResponseTo, notOnOrAfter), nil
}

// checkValidityWindow enforces NotBefore/NotOnOrAfter (with skew) and the
// IssueInstants, and returns the assertion's NotOnOrAfter.
func checkValidityWindow(resp *types.Response, a *types.Assertion, now time.Time, skew time.Duration) (time.Time, error) {
	notBefore, err := time.Parse(time.RFC3339, a.Conditions.NotBefore)
	if err != nil {
		return time.Time{}, fmt.Errorf("saml: Conditions NotBefore: %w", err)
	}
	notOnOrAfter, err := time.Parse(time.RFC3339, a.Conditions.NotOnOrAfter)
	if err != nil {
		return time.Time{}, fmt.Errorf("saml: Conditions NotOnOrAfter: %w", err)
	}
	if notBefore.Add(-skew).After(now) {
		return time.Time{}, errors.New("saml: assertion is not yet valid")
	}
	if !now.Before(notOnOrAfter.Add(skew)) {
		return time.Time{}, errors.New("saml: assertion has expired")
	}
	if a.IssueInstant.Add(-skew).After(now) {
		return time.Time{}, errors.New("saml: assertion IssueInstant is in the future")
	}
	if !resp.IssueInstant.IsZero() {
		if resp.IssueInstant.Add(-skew).After(now) {
			return time.Time{}, errors.New("saml: response IssueInstant is in the future")
		}
		if resp.IssueInstant.Add(maxResponseIssueDelay + skew).Before(now) {
			return time.Time{}, errors.New("saml: response is too old")
		}
	}
	return notOnOrAfter, nil
}

// checkInResponseTo applies VerifyOptions' request-ID policy and returns the
// effective InResponseTo. A value on an unsigned Response envelope is never
// trusted to satisfy RequireInResponseTo, but any value present must match.
func checkInResponseTo(resp *types.Response, a *types.Assertion, opts VerifyOptions) (string, error) {
	var signedIRT string
	if sc := a.Subject.SubjectConfirmation; sc != nil && sc.SubjectConfirmationData != nil {
		signedIRT = sc.SubjectConfirmationData.InResponseTo
	}
	envelopeIRT := resp.InResponseTo
	if signedIRT != "" && envelopeIRT != "" && signedIRT != envelopeIRT {
		return "", errors.New("saml: InResponseTo differs between response and assertion")
	}
	for _, irt := range []string{signedIRT, envelopeIRT} {
		if irt != "" && !slices.Contains(opts.RequestIDs, irt) {
			return "", errors.New("saml: InResponseTo does not match a request issued by this SP")
		}
	}
	if resp.SignatureValidated && signedIRT == "" {
		signedIRT = envelopeIRT
	}
	if opts.RequireInResponseTo && signedIRT == "" {
		return "", errors.New("saml: unsolicited response refused")
	}
	if signedIRT == "" {
		return envelopeIRT, nil
	}
	return signedIRT, nil
}

func toVerifiedAssertion(a *types.Assertion, inResponseTo string, notOnOrAfter time.Time) *VerifiedAssertion {
	out := &VerifiedAssertion{
		ID:           a.ID,
		NameID:       strings.TrimSpace(a.Subject.NameID.Value),
		NameIDFormat: a.Subject.NameID.Format,
		InResponseTo: inResponseTo,
		NotOnOrAfter: notOnOrAfter,
	}
	if a.Issuer != nil {
		out.Issuer = a.Issuer.Value
	}
	if a.AuthnStatement != nil {
		out.SessionIndex = a.AuthnStatement.SessionIndex
	}
	if a.AttributeStatement != nil {
		for _, attr := range a.AttributeStatement.Attributes {
			vals := make([]string, 0, len(attr.Values))
			for _, v := range attr.Values {
				vals = append(vals, v.Value)
			}
			out.Attributes = append(out.Attributes, Attribute{Name: attr.Name, FriendlyName: attr.FriendlyName, Values: vals})
		}
	}
	return out
}
