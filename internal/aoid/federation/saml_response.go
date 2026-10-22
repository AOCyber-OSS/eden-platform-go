package federation

import (
	"context"
	"fmt"
	"strings"
)

// ValidateSAMLResponse refuses every inbound SAML response on this path.
//
// It previously decoded the response and returned an Assertion built from
// the Subject NameID, attributes, AuthnContext and Conditions in the XML
// without the signature ever being checked against the registry entry's
// SigningCertificatePEM. An assertion is a claim about who someone is, so
// a path that derives an identity from an unverified one is not an
// authentication step at all. The RelayState check in Handler.SAMLACS is
// CSRF protection for a value this service issued; it establishes nothing
// about the IdP.
//
// The old implementation also documented behaviour it did not have: the
// doc comment promised ErrInvalidConfig when SigningCertificatePEM was
// missing, an inline comment forty lines down said verification was "the
// caller's responsibility", and the code did neither. The accompanying
// test asserted the accepting behaviour as correct with no certificate in
// the fixture, so the suite locked it in.
//
// REFUSING IS DELIBERATE — PLEASE DO NOT RESTORE THE ACCEPTING PATH.
// The way forward is platform/auth/saml.VerifyResponse, the verifying
// primitive for this module: it delegates to crewjam/saml's ParseResponse
// for XML-DSig validation, XSW-safe canonicalization and
// Conditions/audience checks in one call, and it returns an error rather
// than verify-skipping when IDPCert is empty or unparseable. It cannot be
// dropped in here as-is, because it needs the SP-side ACSURL and
// SPEntityID and TenantExternalIdP carries neither — only EntityID,
// MetadataURL and SigningCertificatePEM. Supplying them means threading SP
// identity through the registry or Stack, which is a design decision for
// whoever owns this surface rather than something to settle in a fix.
//
// Until that is wired this returns an error, which is the honest answer:
// the alternative is a route that half-works and reports success. Nothing
// usable is lost. This path is not reachable by any consumer of the module
// — internal/aoid sits under internal/, so Go makes it unimportable
// externally — and no workflow publishes a cmd/aoid image; the deployed
// identity service is built from the standalone aoid repo.
//
// Background and rationale: AO-Cyber-Systems/aocyber-compliance#17 (private).
func (e *ExternalIdP) ValidateSAMLResponse(ctx context.Context, samlResponseB64 string) (*Assertion, error) {
	if e.cfg.Provider != ProviderSAML {
		return nil, ErrUnsupportedFlow
	}
	if strings.TrimSpace(samlResponseB64) == "" {
		return nil, fmt.Errorf("federation: empty SAMLResponse")
	}

	// No certificate means no trust anchor, so nothing can be checked.
	// This is the config error the previous doc comment always claimed.
	if strings.TrimSpace(e.cfg.SigningCertificatePEM) == "" {
		return nil, fmt.Errorf(
			"%w: external IdP %s configures no SigningCertificatePEM, so an inbound "+
				"SAML assertion has no trust anchor and cannot be authenticated",
			ErrInvalidConfig, e.cfg.ID)
	}

	// A certificate is configured, but no verifying code path consumes it
	// yet. Returning an identity anyway is precisely what was wrong here.
	return nil, fmt.Errorf(
		"%w: inbound SAML assertion verification is not wired for external IdP %s "+
			"(platform/auth/saml.VerifyResponse needs an SP ACSURL and SPEntityID that "+
			"TenantExternalIdP does not carry); refusing to derive an identity from an "+
			"unverified assertion",
		ErrInvalidConfig, e.cfg.ID)
}
