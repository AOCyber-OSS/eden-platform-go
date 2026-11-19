# Project State — eden-platform-go

## Project

- **Name:** eden-platform-go (Go backend platform for the Eden portfolio)
- **Type:** Library + two binaries (`cmd/eden-platform-dev`, `cmd/aoid`) — child of the `eden-libs/` workspace
- **Status:** M9 reached; post-M9 maintenance + AO ID hardening

## Current Position

- **Last objective complete:** Obj 33 — AOFamily Eden Family Platform Integration (M9 milestone) — merged 2026-05-11 (PR #18).
- **Portfolio status:** Standardization plan §1–§11 complete. The platform's six-workstream consolidation finished at M9; remaining work is consumer migrations (owned by their own repos) plus AO ID hardening.
- **Active local work:** post-M9 maintenance and AO ID buildout via incremental commits to `main`.

## Progress

```
W1 Platform package consolidation  ██████████ 100%   (Obj 16, 17, 18, 19, 20, 21, 26)
W2 Auth absorption                 ██████████ 100%   (Obj 22, 23)
W3 Net-new platform packages       ██████████ 100%   (Obj 24, 24a, 25, 27, 28)
W6 AO ID extraction                ██████████ 100%   (Obj 29, 30A, 31)  ◄ M8
M9 Eden Family launch-ready        ██████████ 100%   (Obj 33)            ◄ M9 reached 2026-05-11
─────────────────────────────────────────────────────────────────
Post-M9 maintenance                ████░░░░░░ ~40%   (commit-prefix work, no formal objective yet)
```

Last activity: 2026-05-21 — issue #20 closed + PR #21/#22/#23 merged. First green main CI in 11 days.

## In Flight

- **platform/identity first-party issuer (issue #52)** — the two consumer seams,
  assurance derivation, the issuer, key-set publication, end-to-end proof and
  README. Five TRDs, all executed and verified; 356 tests green, `go.mod`
  unchanged. On `feat/platform-identity-issuer`.
  - The key id is deliberately not a constructor parameter: it is read off the
    signing key, so a deployment cannot pin a constant one and strand every
    consumer behind an unchanging identifier.
  - Construction runs the signing key's health check, so a key service that
    permits reading a public key but denies signing fails at start-up rather
    than at the first login.


- **platform/identity (issue #49)** — the shared identity-context contract:
  claim type + configurable version set, minter, key sources, multi-issuer
  verifier, end-to-end proof and README. Five TRDs, all executed and verified;
  225 tests green, `go.mod` unchanged. On `feat/platform-identity-context`,
  **PR not yet opened**.
  - Found and fixed during verification: the minter's constructor was overriding
    the JWT library's global ES256/RS256 signing methods process-wide and
    irreversibly. Now selects the method value directly.
  - Follow-on: issue #52 (application as first-party issuer) builds on the minter.
  - Noted, out of scope: `platform/auth/jwt.go` and `platform/auth/entitlements.go`
    carry private product names and an internal design-doc reference in doc
    comments, on a public repo's default branch.

## Just Merged

- **PR #23: `chore: gitignore cmd/* build outputs, .srl, and DevFlow runtime dotfiles`** — merged 2026-05-21 at `39d74ad`. `.gitignore` adds for cmd/* build outputs, `*.srl`, and the two `.planning/` runtime dotfiles. Deletes three stale untracked files. Closes status-review item #4.
- **PR #22: `fix(migrations): rename household tables to platform_* (closes #20) + green-CI driver fix`** — merged 2026-05-21 at `e4bc0e2`. Four atomic commits:
  1. Rename platform `households` / `household_members` / `parent_of_record` → `platform_*` (3 tables + 5 indexes + FK refs in migration 013 + 14 sqlc statements + regenerated `db.Platform*` structs + pgstore mapper signatures + new "Database tables" section in `platform/household/README.md` with one-time ALTER recipe for installs that did apply 012 cleanly). **Closes GitHub issue #20.**
  2. `DATABASE_URL: postgres://` → `pgx5://` in CI (matches the pgx/v5 driver imported in `migrate.go`).
  3. Refresh stale `aoid-smoke` assertions: `"scaffold"` → `"active"` and expected `/oauth2/token` status `503` → `405` (issuer flipped active in PR #14 but assertions were never updated).
  4. Pin `sqlc@latest` → `sqlc@v1.30.0` so `sqlc diff` doesn't drift on the version-comment header.
- **PR #21: `fix(server): wrap streaming handlers in Auth + RBAC + Audit interceptors`** — merged 2026-05-21 at `b32ed31`. `NewAuth/RBAC/AuditInterceptor` now return `connect.Interceptor` (not `UnaryInterceptorFunc`) so `WrapStreamingHandler` carries the same logic. Pinned by a new streaming-interceptor integration test that drives an end-to-end server-streaming RPC through the full chain. Discovered during downstream CMS AI wizard UAT.

## Recent Decisions

- **Platform tables stay un-prefixed except where collision is documented.** The first known collision (household domain in downstream apps) was resolved with `platform_*` rename on those three tables specifically. Not a portfolio-wide adoption of the prefix. See PR #22 + `platform/household/README.md`.
- **Edit-in-place over fix-forward for `012_households` migration.** Justified because no external consumer had applied 012 cleanly (justinforme failed → rolled back; the rest is internal CI). A fix-forward 014 would not have unblocked justinforme. Documented in PR #22 description.
- **Streaming-aware interceptor return type.** `connect.Interceptor` (was `UnaryInterceptorFunc`). `UnaryInterceptorFunc` already satisfies `Interceptor`, so the change is source-compatible for callers using `connect.WithInterceptors(...)`.
- **CI infrastructure pinned in PR #22.** sqlc pinned to v1.30.0; `DATABASE_URL` standardized on `pgx5://`. Bumping sqlc now requires deliberately bumping the pin and regenerating.

## Pending Todos

None tracked locally; portfolio-level pending items live in
`eden-libs/.planning/STATE.md`.

## Blockers / Concerns

- **AO ID phase-level work uses an ad-hoc objective numbering scheme** (commit prefixes `aoid-NN-MM`, `NN-MM`) that doesn't map cleanly to the portfolio roadmap. Eventually these should be rolled up into formal objectives (32-aofamily-auth-migration succeeds, then AO ID hardening becomes the next workstream). Not blocking ship; blocks high-fidelity ROADMAP rendering.
- **Dependabot reports 3 vulnerabilities on default branch** (1 high, 1 moderate, 1 low). Visible in every push warning. Not investigated this session.
- **The downstream `justinforme` consumer** is awaiting a vendor bump to pick up both the AuthData proto fix and the `platform_households` migration. Once they bump, the eden-platform-flutter#10 chain unblocks.

## Quick Tasks Completed

| # | Description | Date | Commit | Directory |
|---|-------------|------|--------|-----------|
| 1 | Rename platform household tables to platform_households (issue #20) | 2026-05-21 | ee3ad0c | [1-rename-platform-household-tables-to-plat](./quick/1-rename-platform-household-tables-to-plat/) |
| 2 | test: memstore membership resolves the oldest company, like pgstore | 2026-10-02 | ed01402 | eden-platform-pr38-wt |
| 3 | fix: memstore membership keeps creation order, matching pgstore | 2026-10-02 | 657886d | eden-platform-pr38-wt |

## Session Continuity

- **Last session:** 2026-05-21 — Status review → PR #22 (closes #20) → PR #21 rebase + merge → PR #23 noise cleanup → planning reconstruction (this file + PROJECT.md + ROADMAP.md).
- **Stopped at:** Planning reconstruction committed.
- **No resume file** — clean stop. Next `/devflow:status` should now render against the full state.

## See also

- `eden-libs/.planning/STATE.md` — portfolio-wide state (canonical)
- `.planning/PROJECT.md` — what eden-platform-go is, requirements, constraints
- `.planning/ROADMAP.md` — repo-scoped objective list (projection of parent roadmap)
- `.planning/objectives/16-foundation-hygiene/` and `21-eden-biz-package-migration/` — local TRDs for the two objectives whose TRDs were captured in this repo's `.planning/`
- `.planning/quick/` — quick-task SUMMARYs and JOBs
