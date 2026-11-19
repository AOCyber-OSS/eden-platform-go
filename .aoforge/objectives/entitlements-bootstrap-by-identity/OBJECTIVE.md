# Objective: entitlements-bootstrap-by-identity (C1 — client by AOID identity)

**Repo:** eden-platform-go. **Branch:** `feat/entitlements-bootstrap-by-identity` off origin/main.
**Work:** feature. **TDD:** strict.

## Goal

Add the by-AOID-**subject** methods to `EntitlementClient` + middleware so aodex (A1) can resolve a SaaS buyer's entitlements from their AOID subject (the biz B1/#418 + B2/#420 endpoint) instead of `company_id`. Client half of the arc.

## Scope (IN)

`platform/entitlements/client.go` + `platform/entitlements/middleware.go` + new contract tests:
1. `BootstrapByIdentity(ctx, subject, email) (*BootstrapResponse, error)` — `GET /api/v1/entitlements/bootstrap?aoid_subject=<subject>` + `Bearer` + `X-AOID-Email` header (only when email!=""); **subject-keyed cache** (new, distinct from the companyID `bootstrapCache`); non-2xx→error. `InvalidateIdentity(subject)`.
2. `CanUseFeatureByIdentity(ctx, subject, email, featureKey) (bool, error)` — deny-by-default (mirror `CanUseFeature`).
3. `InjectEntitlementsByIdentity(client, subjectFromCtx, emailFromCtx)` — **fail-open** exactly like `InjectEntitlements` (empty/err→pass; success→inject into the SAME `bootstrapContextKey`).
4. `RequireEntitlementByIdentity(client, featureKey, subjectFromCtx, emailFromCtx)` — **fail-closed** exactly like `RequireEntitlement` (empty→401; err/not-allowed→403).

Keep all existing methods byte-behavior-identical.

## Out of scope

Biz change; aodex change (A1 consumes these, provides the subject/email ctx extractors + sends the header). No new deps.

## Requirements (each in a TRD)

- **C1-01** — `BootstrapByIdentity` wire contract (path/`?aoid_subject=`/`Bearer`/`X-AOID-Email` present-when-set + ABSENT-when-empty) + `BootstrapResponse` parse + subject-keyed cache (distinct from companyID cache) + non-2xx→error + `InvalidateIdentity`.
- **C1-02** — `CanUseFeatureByIdentity` deny-by-default.
- **C1-03** — `InjectEntitlementsByIdentity` fail-open (inject on success into `bootstrapContextKey`; empty subject→pass; error→warn+pass).
- **C1-04** — `RequireEntitlementByIdentity` fail-closed (empty→401; error→403; not-allowed→403; allowed→next).

## Verification

`go test ./platform/entitlements/ -race -count=1 -v` — real PASS counts, SKIP==0, never a bare `ok`. httptest contract tests mirroring the #34 `client_contract_test.go` pattern (assert emitted request + parse biz-shaped responses). No secrets, no new deps.

## Coordination

Independent repo/PR. #34 (contract test for existing methods) is a sibling — create a NEW `*_by_identity_test.go` (no file conflict). Consumed by A1 (aodex). Full design: `scratchpad/OBJECTIVE_C1_client_by_identity.md`.
