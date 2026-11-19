---
objective: platform-identity-issuer
trd: 02
subsystem: platform/identity
tags: [identity, assurance, aal, purity]
requires:
  - platform-identity-issuer-01 (Authentication.Kinds, Authentication.Validate)
provides:
  - DeriveAssurance(*Authentication) (string, error)
affects: []
tech-stack:
  added: []
  patterns:
    - pure derivation returning an existing contract constant, never a newly invented value
key-files:
  created:
    - platform/identity/assurance.go
    - platform/identity/assurance_test.go
  modified: []
decisions:
  - DeriveAssurance validates before deriving, so a malformed authentication yields an error rather than a guess — an unrecognised category is rejected, never counted as an independent one
  - The multi-factor test is written "categories < 2" rather than "== 1" so any future path with no countable category lands on the bottom rung instead of falling through to a higher one
  - AAL3 requires both asserted properties AND two categories; the properties qualify a multi-factor authentication and never substitute for one
metrics:
  tasks: 1
  tests-added: 30
completed: 2026-08-19
---

# Objective platform-identity-issuer TRD 02: Assurance Derivation Summary

`DeriveAssurance` turns what actually happened during authentication into an
AAL1/AAL2/AAL3 rung of the existing claim contract, counting distinct factor
categories rather than prompts and resolving every gap downward.

## What Was Built

`platform/identity/assurance.go` — one exported function, no state:

| Input | Result | Reasoning |
|---|---|---|
| no factors | **error**, no level | Nothing was established. The lowest rung would read as "authenticated weakly" when the truth is "not authenticated". |
| one distinct category | AAL1 | However many methods were used within it. A password plus a security question is two prompts and one line of defence — whatever compromises the first tends to compromise the second. |
| two or more categories | AAL2 | The multi-factor rung. What earns it is independence: a knowledge factor and a possession factor fail to different attacks. |
| two or more categories **and** both `HardwareBacked` **and** `PhishingResistant` | AAL3 | Both properties are read from what the verifier asserted, never inferred from a method name — "webauthn" may or may not be hardware backed depending on deployment. |
| both properties, one category | AAL1 | The properties qualify a multi-factor authentication; they do not substitute for one. |
| unrecognised category | **error**, no level | Rejected rather than counted, so a typo cannot promote a single-factor authentication to AAL2. |

Every rejection returns `""` alongside the error, so a caller who mishandles the
error cannot pick up a rung that was never reached. The function reuses the
`AAL1`/`AAL2`/`AAL3` constants from the existing claim contract and does not
redeclare them; a test asserts every derived level is one the mint contract
already accepts.

## Deviations from Plan

None — TRD executed exactly as written.

## Task Evidence

| Task | Verify Command | Exit Code | Status |
|---|---|---|---|
| 1 (RED) | `go test ./platform/identity/ -count=1` | 1 | FAIL as intended (build failed: undefined DeriveAssurance) |
| 1 (GREEN) | `go test ./platform/identity/ -race -count=1` | 0 | PASS |
| 1 | `go vet ./platform/identity/` | 0 | PASS |
| 1 | `gofmt -l platform/identity/` | 0 | PASS (empty) |
| 1 | `git diff --exit-code go.mod go.sum` | 0 | PASS (unchanged) |

## TDD Evidence

| Phase | Command | Exit Code | Expected |
|---|---|---|---|
| RED | `go test ./platform/identity/ -count=1` | 1 | FAIL (correct) |
| GREEN | `go test ./platform/identity/ -race -count=1` | 0 | PASS (correct) |
| REFACTOR | not needed | — | — |

Test count moved 252 → 282 PASS, 0 SKIP, 0 FAIL.

## Mutation Check

`categories := len(auth.Kinds())` was replaced with `len(auth.Factors)` — the
"count prompts, not categories" mistake this TRD exists to prevent. Two rows
died and nothing else:

```
--- FAIL: TestDeriveAssurance/two_knowledge_factors_are_one_category,_so_AAL1
--- FAIL: TestDeriveAssurance/three_methods_within_one_category_are_still_AAL1
    assurance_test.go:165: DeriveAssurance() returned "AAL2", want "AAL1"
```

Both AAL3 rows and every AAL2 row still passed under the mutant, confirming the
two failing rows are the ones carrying the rule rather than incidental
coverage. The file was restored with `git checkout` (working tree reported
clean, so the restore was byte-identical) and the suite re-ran green.

## Post-TRD Verification

- Auto-fix cycles used: 0
- Must-haves verified: 8/8
- Gate failures: None
- Mutation check: killed as designed

## Commits

- `5d96b42` test(platform-identity-issuer-02): specify the assurance ladder and every way of stopping short
- `355fe1d` feat(platform-identity-issuer-02): derive assurance from distinct factor categories

## Self-Check: PASSED
