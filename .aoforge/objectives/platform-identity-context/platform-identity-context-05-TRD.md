---
objective: platform-identity-context
trd: 05
type: tdd
wave: 4
depends_on: [01, 02, 03, 04]
files_modified:
  - platform/identity/identity_test.go
  - platform/identity/doc.go
  - platform/identity/README.md
autonomous: true
requirements: [IC-05]
must_haves:
  truths:
    - "Round-trip: mint -> publish via platform/auth/jwks -> serve over httptest -> RemoteJWKS -> Verify returns the ORIGINAL claim values"
    - "The round trip goes through platform/auth/jwks.Set (AddSigningKey + MarshalJSON), proving this package's minter and this platform's key publication interoperate"
    - "Multi-issuer end-to-end: two independent issuers, each with its own signer and key source, both verified by ONE verifier"
    - "Version negotiation end-to-end: one token, two verifiers with different accepted sets, opposite outcomes"
    - "Wire-compatibility fixture: a token built from a HAND-WRITTEN claims JSON (not via the minter) verifies, proving the contract is the wire format and not just self-consistency"
    - "README documents the claim table, the emitted vs accepted version distinction, and adoption without a wire-format change"
    - "Hygiene sweep is CLEAN across platform/identity and this objective's commits and planning docs"
  artifacts:
    - platform/identity/identity_test.go
    - platform/identity/doc.go
    - platform/identity/README.md
  key_links:
    - "This TRD proves the acceptance criteria as a whole; TRDs 01-04 each proved their own unit"
    - "The hand-written-claims fixture is the only test that can catch a JSON-tag rename, since minter and verifier share the struct"
---

<objective>
Prove the package's acceptance criteria end to end, document it, and run the
public-repository hygiene sweep.

The unit TRDs each verified their own layer. The gap they cannot close by
construction: minter and verifier share one `Claims` struct, so a renamed JSON
tag round-trips perfectly between them while breaking every other consumer on
the wire. This TRD closes that gap with a fixture built from raw JSON.
</objective>

<file_tree>
platform/identity/
├── claims.go            (TRD 01)
├── minter.go            (TRD 02)
├── keysource.go         (TRD 03)
├── verifier.go          (TRD 04)
├── identity_test.go     ← CREATE (end-to-end: round-trip, multi-issuer, versions, wire fixture)
├── doc.go               ← CREATE (package doc)
└── README.md            ← CREATE
</file_tree>

<execution_context>
@~/.claude/devflow/workflows/execute-trd.md
@~/.claude/devflow/templates/summary.md
</execution_context>

<embedded_context>

<the_wire_compatibility_fixture>
This is the load-bearing test of the whole objective.

Every other test mints with this package and verifies with this package. Both
sides share the `Claims` struct, so renaming `tnt` to `tenant` keeps all of them
green — while silently breaking every independent consumer in the field. That is
precisely the failure this package exists to prevent, and it is invisible to a
symmetric test.

So: construct a token whose payload comes from a HAND-WRITTEN JSON literal using
the raw wire keys, sign it with a test key, and assert the verifier accepts it
and surfaces the expected values.

```go
payload := `{
  "iss":"https://issuer.example/",
  "sub":"subject-1",
  "iat":<now>, "exp":<now+900>,
  "tnt":"acme",
  "ent":["admin"],
  "aal":"AAL2",
  "ctx_ver":1,
  "tok_ref":"0123456789abcdef"
}`
```

Build the compact JWS from a hand-assembled header (`{"alg":"ES256",
"typ":"identity-context+jwt","kid":"..."}`) and this payload so no struct tag
participates in producing the bytes. If a tag is ever renamed, THIS test fails
and nothing else does.
</the_wire_compatibility_fixture>

<the_full_round_trip>
Prove the minter and this platform's existing key-publication surface
interoperate, rather than assuming it:

1. Mint with a test ES256 signer through the TRD 02 minter.
2. Publish that signer's public half with `platform/auth/jwks`:
   `(&jwks.Set{}).AddSigningKey(signer, kid)` then `MarshalJSON`.
3. Serve those bytes from an `httptest` server (OS-assigned port; never 8080).
4. Point a `RemoteJWKS` key source at that URL.
5. Verify, and assert the ORIGINAL sub / tnt / ent / aal / ctx_ver come back.

Step 2 is the part worth having: it proves a key set published by this platform
is readable by this package's consumer, which is what a real deployment does.
</the_full_round_trip>

<documentation>
doc.go carries the package doc. README.md covers:
- the claim table: wire key, Go field, meaning, and whether it is required
- EMITTED version vs ACCEPTED set — that the minter emits 1, that the default
  accepted set is {1}, and that widening is explicit and deliberate
- that trusted issuers are configuration and nothing is compiled in
- the single-sentinel-error property and why per-reason errors are not offered
- how a consumer adopts WITHOUT a wire-format change: the claim shape and typ
  are unchanged, so an existing verifier and this one accept the same tokens

Write it as documentation for this contract on its own terms. Do not narrate the
migration of any particular service.
</documentation>

<hygiene_sweep>
This repository is PUBLIC and the planning documents are tracked in it, so the
sweep covers code, tests, docs AND .planning for this objective.

Run a case-insensitive search across `platform/identity/`, this objective's
`.planning` directory, and the branch's commit messages for:
- absolute local filesystem paths (`/Users/`, `/home/`)
- internal ticket / design-doc reference patterns (`TRD <digit>-`, `Obj <digit>`,
  `Pitfall <digit>`, `identity-context-v<digit>.md`)
- private repo or service identifiers

Report the sweep OUTPUT as evidence, not a bare assertion that it passed. A hit
inside this objective's own TRD filenames (`platform-identity-context-0N-TRD.md`)
is a filename, not a leak — judge hits on content.

Note the intended exception: the tracking issue number for THIS repository's own
public issue is fine; references to OTHER repositories' internal numbering are not.
</hygiene_sweep>

<constraints>
- PUBLIC REPO — see TRD 01 constraints.
- No new module dependencies.
- httptest only; never a hardcoded port; port 8080 is unavailable in this environment.
</constraints>

</embedded_context>

<verify>
go test ./platform/identity/... -race -count=1 -v
go vet ./platform/identity/...
go build ./...
git diff --exit-code go.mod go.sum
</verify>
