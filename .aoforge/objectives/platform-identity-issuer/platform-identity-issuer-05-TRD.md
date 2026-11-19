---
objective: platform-identity-issuer
trd: 05
type: tdd
wave: 5
depends_on: [01, 02, 03, 04]
files_modified:
  - platform/identity/issuer_e2e_test.go
  - platform/identity/README.md
autonomous: true
requirements: [IS-05]
must_haves:
  truths:
    - "End to end: a credential is verified, a context minted, the key set served, fetched, and the context verified — with the ORIGINAL subject, tenant, entitlements and derived assurance returned"
    - "The end-to-end path uses NO test doubles for the identity package's own types — only the two consumer seams are faked, because a consumer supplies them"
    - "A rejected credential produces no token and reaches neither the key set nor the verifier"
    - "Each assurance rung survives the full round trip intact — a single-factor login verifies as single-factor at the far end"
    - "A context minted by the issuer is accepted by a verifier configured with the DEFAULT accepted-version set, proving the issuer emits the version deployed consumers already take"
    - "README documents the two seams, the assurance ladder, why the key id is not a parameter, and the start-up signing proof"
    - "Hygiene sweep is CLEAN across the package, this objective's planning directory, and the branch's commit messages"
  artifacts:
    - platform/identity/issuer_e2e_test.go
    - platform/identity/README.md
  key_links:
    - "This is the acceptance proof for the objective; TRDs 01-04 each proved their own unit"
    - "Extends the existing README rather than replacing it — the contract half stays as it is"
---

<objective>
Prove the issuer end to end, and document it.

The unit TRDs each verified one layer against its own construction. This
assembles them the way a deployment does — a login on one side, a published key
set in between, a verifier on the other — and asserts on what comes out.
</objective>

<file_tree>
platform/identity/
├── issuer.go              (TRD 03)
├── keyset.go              (TRD 04)
├── issuer_e2e_test.go     ← CREATE
└── README.md              ← EXTEND (do not rewrite the existing contract sections)
</file_tree>

<execution_context>
@~/.claude/devflow/workflows/execute-trd.md
@~/.claude/devflow/templates/summary.md
</execution_context>

<embedded_context>

<what_may_be_faked>
Only the two consumer seams — credential verification and claims resolution —
because a consumer supplies those and this package genuinely has no
implementation of them.

Everything else on the path must be the real thing: the real issuer, the real
minter, the real key-set handler over a test server, the real remote key source,
the real verifier. A round trip that substitutes any of those proves only that
the substitutes agree with each other.
</what_may_be_faked>

<the_version_assertion>
Verify the issuer's output with a verifier built on the DEFAULT accepted-version
set, not a widened one.

That is the assertion that the issuer emits a version already-deployed consumers
accept. Widening the verifier for this test would hide exactly the mismatch that
motivated this package: emitting a version outside what the strictest deployed
consumer takes strands it in the field, and turns a library change into a
coordinated multi-service deploy.
</the_version_assertion>

<readme_additions>
Extend the existing README; the contract, version-negotiation, error-opacity and
key-set sections stay as they are. Add:

- **Acting as an issuer** — the two seams a consumer implements, and what each is
  responsible for. State plainly that no storage interface is required, and that
  the credential primitives it will build on are pure functions.
- **The assurance ladder** — the table of rungs and what reaches each, including
  that two knowledge factors are one category, and that the top rung needs
  asserted properties no factor name implies.
- **Why the key id is not a parameter** — derived from the key so a constant one
  is unrepresentable, and what goes wrong when a deployment pins one.
- **The start-up signing proof** — what it catches and why it fails construction
  rather than the first login.
- A short worked example: implement the two seams, construct an issuer, serve the
  key set, issue a context.
</readme_additions>

<hygiene_sweep>
This repository is PUBLIC and `.planning/` is tracked in it, so the sweep covers
package source, tests, docs, this objective's planning directory AND the branch's
commit messages.

Search case-insensitively for absolute local filesystem paths, internal ticket
and design-document reference patterns, and private repository or service
identifiers. REPORT THE SWEEP OUTPUT as evidence, not a bare assertion. Judge
hits on content: a match inside this objective's own TRD filenames is a filename,
and a reference to this repository's own tracking issue is fine.
</hygiene_sweep>

<constraints>
- PUBLIC REPO — as above, for code, comments, test names, docs and commits.
- No new module dependencies.
- httptest only; never a hardcoded port; 8080 is permanently occupied here.
- The 225 tests already in the package must stay green.
</constraints>

</embedded_context>

<verify>
go test ./platform/identity/... -race -count=1 -v
go vet ./platform/identity/...
gofmt -l platform/identity/
go build ./...
git diff --exit-code go.mod go.sum
</verify>
