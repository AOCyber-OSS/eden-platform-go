# Roadmap — eden-platform-go

> **Canonical roadmap:** `eden-libs/.planning/ROADMAP.md` covers Objectives
> 1–33 spanning every sibling repo in the workspace. This file is a
> **repo-scoped projection**: only the objectives whose code (or substantial
> code) ships in eden-platform-go are listed here, with status as of the
> head of `main`.

**M9 milestone reached 2026-05-11** — Eden Family launch-ready.
Portfolio standardization plan §1–§11 complete. Post-M9 work is
maintenance + AO ID hardening (see "Post-M9" section below).

---

## Workstream W1 — Platform package consolidation

### Phase 1A — Foundation hygiene (M1)

- [x] **Obj 16: Platform Foundation Hygiene Consolidation** — `platform/{audit,observability,encryption,config}` promoted to beta; READMEs + public-API test coverage. **PR #2 merged 2026-05-10.** Local TRDs: `.planning/objectives/16-foundation-hygiene/16-{01..04}-TRD.md`.
- [x] **Obj 17: RBAC + Webhook Consolidation** — `platform/rbac` policy/role-name shim, `platform/webhook` retry queue + options, README HMAC scheme, rbac→audit→webhook integration test. **PR #3 merged 2026-05-10.**

### Phase 1B — Tier-B platform extension (M2)

- [x] **Obj 18: Tier-B Core** — `platform/{jobs,ratelimit,realtime,email}` promoted. **Part of PR #10 merged 2026-05-10.**
- [x] **Obj 19: Tier-B Storage Stack** — `platform/{storage,attachments,statemachine}`. **Part of PR #10.**
- [x] **Obj 20: Tier-B Remainder** — `platform/{scheduler,webfetch}`. **Part of PR #10.**
- [x] **Obj 26: platform/aigateway** — consolidates 7 historical AOSentry-client forks. **PR #4 merged 2026-05-10.**

### Phase D10 closure (M3)

- [x] **Obj 21: Eden-Biz Receives Platform Migration** — verification + cross-repo integration smoke test. eden-biz-go now a pure platform consumer for 14 packages. **PR #15 merged 2026-05-10.** Local TRDs: `.planning/objectives/21-eden-biz-package-migration/21-{01..03}-TRD.md`.

### AOSentry pkg/* promotion (W1.1A)

- [x] **Obj 10 / W1.1A: AOSentry pkg/{crypto,apierror,httputil} → platform** — **PR #6 merged 2026-05-10.**

---

## Workstream W2 — Auth absorption (M4)

- [x] **Obj 22: Absorb AODex `internal/auth` into `platform/auth`** — full absorption: sessions, apikey, email-OTP, breach, TOTP, WebAuthn, OIDC, OAuth, JWKS, KMS signer, secret-hasher. **PR #9 merged 2026-05-10.**
- [x] **Obj 23: SAML IdP** — `platform/auth/saml/idp` adds IdP issuance to the existing SP. **PR #12 merged 2026-05-10.**

---

## Workstream W3 — Net-new platform packages

- [x] **Obj 24: platform/household** — net-new family / POR / child-account package backing AOFamily-AI and Eden Family. **PR #8 merged 2026-05-10.**
- [x] **Obj 24a: platform/auth household-aware claims extension** — `Claims` extended with HouseholdID / ChildID / ChildMode (all `omitempty`); `CreateHouseholdAccessToken` + `RequireHousehold` / `RequireParentMode` / `RequireChildMode`. **PR #16 merged 2026-05-10.**
- [x] **Obj 25: platform/consent** — append-only COPPA / GDPR-K consent ledger. **PR #11 merged 2026-05-10.**
- [x] **Obj 27: platform/{feature-flags,billing-rail}** — entitlements + billing primitives. **PR #7 merged 2026-05-10.**
- [x] **Obj 28: eden-livekit extraction → platform/livekit** — WebRTC realtime primitive. **PR #5 merged 2026-05-10.**

---

## Workstream W6 — AO ID extraction

- [x] **Obj 29: AO ID Service Scaffolding** — `cmd/aoid` + `internal/aoid`; OIDC discovery 200; JWKS rotation-ready against ML-DSA-65 keys. **PR #13 merged 2026-05-10.**
- [x] **Obj 30 Phase A: AO ID OIDC Issuer Activation + AODex Pilot** — issuer flipped active; AODex registered as first OIDC client. **PR #14 merged 2026-05-10.**
- [x] **Obj 31: AO ID Federation Surface + Per-Product Decommission Plan** — federation imports/exports; per-product decommission plan. **PR #17 merged 2026-05-10. M8 milestone.**

---

## M9 milestone — Eden Family launch-ready

- [x] **Obj 33: AOFamily Eden Family Platform Integration** — cross-package integration test (12 scenarios) + architecture doc + launch-readiness checklist. All 47 platform packages green; `platform/integration` package 12/12. **PR #18 merged 2026-05-11. M9 milestone reached.**

---

## Post-M9 — Maintenance & continued hardening (in flight)

### Shipped post-M9

- [x] **politihub Scopes claim (ADR-0003)** — `platform/auth.Claims` gains scopes + Navigators issuance. **PR #19 merged 2026-05-12.**
- [x] **Audit pipeline hardening** — OTLP log sink with synchronous error propagation; aoedge_audit.proto schema + Go bindings; AuditService.IngestBreakGlassEvent RPC and connectapi handler. **Direct commits to main (`db54c37`, `189e1eb`, `ce2e1a8`, `7210de4`, `2ebb094`).**
- [x] **KMS — softkey signer + OpenWithOptions registry extension** — `platform/kms/softkey` software-resident signer; `kms.OpenWithOptions` + `RegisterOptions`. **Direct commits (`6c1afa0`, `85683f5`).**
- [x] **Streaming-interceptor security fix** — `Auth`/`RBAC`/`Audit` interceptors now wrap server-streaming handlers (previously bypassed → unauthenticated streams). **PR #21 merged 2026-05-21.**
- [x] **Issue #20 closure — platform_households rename** — three platform tables renamed away from un-prefixed names to avoid downstream collision with app-domain `households` tables (e.g. justinforme CRM). **PR #22 merged 2026-05-21.**
- [x] **CI infrastructure repair** — `DATABASE_URL` scheme fix (pgx5://), aoid-smoke assertions refreshed for active-issuer state, sqlc pinned to v1.30.0. First green main CI in 11 days. **Bundled in PR #22.**
- [x] **.gitignore + working-tree noise cleanup** — `/aoid`, `/eden-platform-dev`, `*.srl`, `.planning/.awareness-cache.json`, `.planning/.skill-active`. **PR #23 merged 2026-05-21.**

### In flight — not yet on main

- [x] **platform/identity — application as first-party issuer** — an application
  authenticates its own users through two narrow seams (credential verification,
  claims resolution), derives an honest assurance level from the factors actually
  exercised, mints a context, and publishes its key set. No storage interface
  required and no second key path: the issuer takes a platform signing key, reads
  its key id off it, and proves it can sign at start-up. 356 tests,
  mutation-verified. Tracking issue #52. Branch `feat/platform-identity-issuer`.

- [x] **platform/identity — the shared identity-context contract** — new package:
  the frozen claim type with a configurable accepted-version set, a minter over
  the existing signing seam, static and remote key sources, and a verifier that
  trusts a configured **set** of issuers. 225 tests, mutation-verified. Tracking
  issue #49; the first-party-issuer follow-on is #52. Merged to main. TRDs and verification
  at `.planning/objectives/platform-identity-context/`.

### Active work streams (tracked via commit prefixes; canonical plan TBD)

These are not yet stood up as portfolio-level objectives. The work lives
in main via incremental commits with internal phase numbering (`aoid-NN-MM`,
`NN-MM`). When ready to plan formally, run
`/devflow:plan-objective <num>` against the parent eden-libs and import
TRDs back here.

- **AO ID identity-service buildout** — recent commit prefixes
  `aoid-08-*`, `aoid-09-*`, `aoid-11-*` (account-admin RPCs,
  recertification, MFA clear, AC2 / AuditQuery / SelfRecovery extensions,
  BreakGlass event ingestion).
- **Policy cache infrastructure** — prefix `10-0*` (PolicyCache
  combinator + Cache + PostgresListener + IntervalPoller; risk evaluator;
  signed audit forwarder; canonical JSON; GeoIP wrapper).
- **KMS deepening** — prefix `13-0*` (currently softkey; AWS KMS / GCP KMS
  drivers expected to follow).
- **Entitlements bootstrap-by-AOID-identity** — `platform/entitlements`
  client + middleware `*ByIdentity` methods (subject-keyed bootstrap +
  `X-AOID-Email` first-call self-heal). TRDs at
  `.planning/objectives/entitlements-bootstrap-by-identity/` (C1-01..04);
  branch `feat/entitlements-bootstrap-by-identity`. Client half of the biz
  #412/#418/#420 arc; consumed by aodex (A1).

---

## Out of scope for this repo

Objectives 1–15, 32, 32a live in sibling repos. See
`eden-libs/.planning/ROADMAP.md` for the canonical list including:

- Obj 1: Eden CLI (`eden-cli`)
- Obj 2: Token-refresh interceptor (`eden-platform-api-dart`)
- Obj 3: SSO + RBAC wiring into Flutter (`eden-platform-flutter`)
- Obj 4–8: Quality + test-coverage objectives across the workspace
- Obj 9–15: DevX / dev-server / UI library / upgrade-command objectives
- Obj 32, 32a: AOFamily backend auth + aigateway migrations (in `aofamily-dev`)

## Cross-references

- Portfolio canonical: [`../../eden-libs/.planning/ROADMAP.md`](../../eden-libs/.planning/ROADMAP.md)
- Source plan: [`../../eden-libs/PORTFOLIO_STANDARDIZATION_PLAN.md`](../../eden-libs/PORTFOLIO_STANDARDIZATION_PLAN.md)
- Capability reference: [`../../eden-libs/CAPABILITIES.md`](../../eden-libs/CAPABILITIES.md)
