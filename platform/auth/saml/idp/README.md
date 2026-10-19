# platform/auth/saml/idp

SAML 2.0 **Identity Provider** support. Together with `platform/auth/saml`
(SP), this package gives the platform both halves of SAML federation:

- **SP** — when an AOC app authenticates users via Okta, Azure AD, or any
  upstream IdP. Live since Obj 22.
- **IdP** — when AOC apps **issue** SAML assertions to downstream
  Service Providers (e.g. partner apps that have integrated AOC ID as
  their corporate IdP). Added in Obj 23.

## Quickstart

```go
import (
    "go.aocyber.ai/eden-platform-go/platform/auth/saml"
    "go.aocyber.ai/eden-platform-go/platform/auth/saml/idp"
)

// 1. Generate (or load) the IdP signing key.
key, err := saml.GenerateSigningKey("AOC ID Production", 365*24*time.Hour)
if err != nil { return err }

// 2. Configure the IdP — the entity ID is the metadata URL.
idp, err := idp.New(idp.Config{
    EntityID:          "https://id.aocyber.com/saml/metadata",
    SSOURL:            "https://id.aocyber.com/saml/sso",
    CurrentKey:        key,
    AssertionLifetime: 5 * time.Minute,
    AllowedSPs: map[string]idp.SPRegistration{
        "https://partner.example.com/saml/metadata": {
            EntityID: "https://partner.example.com/saml/metadata",
            ACSURL:   "https://partner.example.com/saml/acs",
            // SigningCertificate optional — if nil, signed AuthnRequests
            // are accepted without IdP-side signature verification.
        },
    },
})

// 3. Mount the metadata endpoint.
http.Handle("/saml/metadata", idp.MetadataHandler())

// 4. On a successful login, issue a signed assertion.
signed, err := idp.IssueAssertion(idp.AssertionInput{
    SPEntityID:   "https://partner.example.com/saml/metadata",
    InResponseTo: incomingRequestID,
    NameID:       user.Email,
    Attributes: map[string][]string{
        "email":      {user.Email},
        "first_name": {user.FirstName},
        "last_name":  {user.LastName},
    },
})
// signed is a Base64-decoded XML <Response> document. Wrap it as a form
// auto-post to sp.ACSURL to complete the SP-Initiated SSO flow.
```

## Key rotation (R33.4)

Configure both `CurrentKey` and `PreviousKey` during the rotation window:

```go
idp, _ := idp.New(idp.Config{
    CurrentKey:  newKey,   // signs new assertions
    PreviousKey: oldKey,   // still published in metadata so SPs that
                           // haven't refreshed metadata can validate
                           // the assertion that was just signed by
                           // newKey AND any in-flight assertion still
                           // signed by oldKey.
})
```

Rotation procedure:
1. Generate `newKey`. Persist it (consumer's responsibility).
2. Set `CurrentKey = newKey`, `PreviousKey = oldKey`.
3. Refresh metadata in all SPs (most do this automatically every 24h).
4. After 7 days (typical), set `PreviousKey = nil` and retire `oldKey`.

## Conformance (R33.6)

The package's unit tests round-trip a signed assertion through goxmldsig's
validation context — which is the same library every SP-side library
(crewjam/saml, gosaml2, etc.) uses to validate inbound responses. A
passing test means the assertion would be accepted by any compliant SP
that trusts the IdP's published certificate.

Tested against:
- **goxmldsig** (RSA-SHA256 + xml-exc-c14n10) — round-trip in
  `idp_test.go::TestIssueAssertion_ProducesSignedResponse`.
- **crewjam/saml** primitives — the IdP exposes its
  `ServiceProviderProvider` so crewjam middleware can drive the IdP for
  HTTP-POST acceptance tests.

For external interop testing (Okta-as-SP, SimpleSAMLphp), point the SP at
the IdP's metadata endpoint and post a signed assertion through. Test
artifacts are stored under `platform/auth/saml/idp/testdata/` for
regression.

## Security considerations (R33.7)

- **Replay protection.** SPs are responsible for tracking
  `Response.ID` + `Assertion.ID` and rejecting duplicates. The IdP
  generates fresh random IDs per assertion.
- **Audience restriction.** Every assertion includes a single
  `<Audience>` element matching the registered SP's EntityID. SPs MUST
  enforce this (the standard SAML libraries do).
- **Time skew.** `NotBefore` is set to the IssueInstant; `NotOnOrAfter`
  is `IssueInstant + AssertionLifetime` (default 5 min). Bump
  `AssertionLifetime` if you see clock-skew rejections, but do not
  exceed 60 minutes — longer windows broaden the replay window.
- **NameID privacy.** Default format is
  `nameid-format:emailAddress`. For high-privacy deployments consider
  `nameid-format:transient` and persist the IdP-side mapping yourself.
- **Signing certificates.** Use the package's `GenerateSigningKey` only
  for development. In production, mint certificates from your PKI and
  load them via `saml.LoadSigningKey(privPEM, certPEM)`.
