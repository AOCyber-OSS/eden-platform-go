# platform/auth/saml

SAML 2.0 primitives for the AOC platform — covers both the **Service Provider**
(SP) side (consume assertions from upstream IdPs) and the **Identity
Provider** (IdP) side (issue signed assertions to downstream SPs).

## Layout

```
platform/auth/saml/
├── saml.go      Service Provider primitives (AuthnRequest, response parsing,
│                  SP metadata, IdP-cert parsing)
├── crypto.go    Shared signing key + certificate helpers (used by both
│                  SP and IdP)
└── idp/         Identity Provider package (metadata, AuthnRequest
                   acceptance, signed assertion issuance, key rotation)
```

For the high-level orchestrated SP flow (tenant-configured SAML SSO with
attribute mapping, JIT user provisioning, refresh-token issuance), use
`platform/auth.SSOService` — it wraps this package's gosaml2-backed
`Verifier` with company-aware
configuration and is the recommended entry point for most callers.

For the lower-level primitives in this package, see:
- `BuildAuthnRequestRedirectURL` / `ParseResponse` / `BuildSPMetadata` for
  SP flows that need direct XML control.
- `idp.IdentityProvider` for IdP issuance — covered in
  [`idp/README.md`](./idp/README.md).

## Configuring an SP-Initiated flow against this IdP

When AO ID acts as the IdP for partner apps:

1. **Provision the SP**. Add the partner's EntityID + ACS URL to your
   `idp.Config.AllowedSPs` map. Optionally pin the SP's signing
   certificate to require signed AuthnRequests.

2. **Publish metadata.** Point the SP at
   `https://<your-idp>/saml/metadata`. The endpoint emits the IdP's
   current (and previous, during rotation) signing certificate plus the
   SSO endpoint binding/location.

3. **Handle SSO requests.** The SP redirects users to your
   `idp.Config.SSOURL` with a `SAMLRequest` query parameter. Decode +
   validate it via `idp.AcceptAuthnRequest`, run the user through the
   platform's existing auth (e.g. `platform/auth.SSOService` or your own
   login flow), then call `idp.IssueAssertion` and post the signed
   assertion to the SP's ACS URL via an auto-submit HTML form.

## Federating an external IdP into AO ID

Going the other way — an enterprise customer wants to federate their Okta
into AOC apps:

1. Configure the SSOConfig row for the company (issuer URL, client ID,
   secret, attribute mapping). See `platform/auth.SSOService.InitiateSAML`.

2. The platform service constructs an AuthnRequest, redirects the user to
   the customer's IdP, validates the returned assertion (using
   this package's signature-verifying `Verifier`), and JIT-provisions the user
   into the company.

This direction is fully covered by `platform/auth.SSOService` — you do
not need to call into this package directly for a tenant-configured SP
flow.

## Troubleshooting clock-skew errors

Most SAML errors during integration testing are clock-skew related. The
IdP defaults to a 5-minute assertion lifetime
(`Conditions.NotBefore` .. `Conditions.NotOnOrAfter`). Symptoms:

- "Assertion is not yet valid" → IdP clock is ahead of SP clock by more
  than the skew tolerance. Sync NTP on both sides.
- "Assertion has expired" → IdP clock behind, or assertion was held in
  transit too long, or `AssertionLifetime` is too short.

Mitigations: increase `idp.Config.AssertionLifetime` (do not exceed 60
minutes); ensure NTP is healthy on both endpoints; verify the SP's clock
skew tolerance is at least 60 seconds (most SPs default to 60 or 180s).

## Security considerations

See [`idp/README.md`](./idp/README.md) for the full IdP security
checklist (replay protection, audience restriction, time skew, NameID
privacy, signing cert provisioning). For SP-side security, the
`Verifier` (gosaml2 + goxmldsig) provides signature verification, issuer,
audience, destination/recipient and validity-window checks, request-ID
binding and, when given a `ReplayCache`, replay refusal. `VerifyResponse`
and `SSOService` both use it. Treat `ParseResponseUnverified` as a primitive
that does NOT verify signatures — see its docstring.
