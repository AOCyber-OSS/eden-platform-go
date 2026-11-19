# Objective 21 — Platform Receives Eden-Biz Migration

**Maps to roadmap requirement:** R31 (D10 closure on platform side)
**Source:** `PORTFOLIO_STANDARDIZATION_PLAN.md` §11 milestones (M3)
**Milestone:** M3 — Tier-B + Eden-Biz migration done
**Implementation:** eden-platform-go (verification + integration); eden-biz-go side already shipped under Obj 36-41

## Scope

Verification + integration objective on the platform side of D10. This is the eden-libs/eden-platform-go counterpart to the six eden-biz D10 migrations (Obj 36-41). The package promotions themselves landed in earlier waves (Obj 16-20). This objective:

1. **Validates** all 14 platform packages eden-biz now consumes are stable and well-tested at current `origin/main` HEAD.
2. **Cross-repo integration test:** clone (or worktree) eden-biz-go at its post-D10 main and run its tests against current eden-platform-go HEAD; confirm clean build + test for D10-affected internal packages.
3. **Consolidates** the deferred backlog from D10 — items that cross-reference platform work (apikeys cutover, audit/webhooks Connect upstreaming, attachments multi-tenancy, server-extension middleware).
4. **Updates** `CAPABILITIES.md` (eden-libs root) so the section about Eden-Biz reflects "pure platform consumer post-D10."
5. **Closes** M3 milestone once all of the above are green.

## Detailed Requirements

### R31.1: Platform Package Stability (eden-libs side)
- All platform packages eden-biz consumes (`platform/{audit,webhook,storage,attachments,jobs,scheduler,statemachine,encryption,server,auth/apikey}`) build clean (`go build ./platform/...`) and pass tests (`go test -short ./platform/...`) at current `origin/main` HEAD.
- `go vet ./platform/...` is clean.

### R31.2: Cross-Repo Integration Smoke Test
- eden-biz-go at its post-D10 main HEAD (Obj 41 merged, commit `d8efc3a`) must build cleanly against eden-platform-go's current `origin/main` HEAD when go.mod replace points at the eden-platform-go worktree.
- D10-affected internal packages (`internal/{audit,audithelper,webhooks,events,eventhelper,storage,attachments,jobs,cron,crypto,sso,apikeys,middleware}`) compile clean.
- D10-affected packages with test files (`internal/{webhooks,attachments,crypto,middleware}`) pass `go test -short`.
- Pre-existing baseline failures (24+ bizv1 proto-dependent packages noted in Obj 36-41 reports) are unchanged from origin/main and explicitly excluded from gating.

### R31.3: Backlog Consolidation
- Confirm eden-biz-go's `PLATFORM_BACKLOG.md` (filed in Obj 41) is comprehensive and link-correct.
- Document in this objective's SUMMARY which deferred items map to future eden-libs/eden-platform-go work (versus eden-biz-side or ops-side work).

### R31.4: CAPABILITIES.md Reflects Post-D10 Reality
- `CAPABILITIES.md` updated to note Eden-Biz is now a pure platform consumer for the 14 D10 packages (with the listed exceptions for biz-specific shapes that stay authoritative).

### R31.5: M3 Milestone Closure
- `PORTFOLIO_STANDARDIZATION_PLAN.md` §11 M3 row confirmed met.
- `STATE.md`, `ROADMAP.md` (Obj 21 checkbox), `.planning/workstreams/STATUS.md` updated to reflect closure.

## Test Coverage Gates
- All 47 platform packages pass `go test -short` on origin/main.
- D10-affected eden-biz internal packages with tests pass against current platform HEAD.
- No new code in this objective; verification artifacts only (TRDs + SUMMARY).

## Dependencies
- All of Objectives 16, 17, 18, 19, 20, 22, 23 (platform package promotions feeding D10) — all MERGED.
- All of Objectives 36, 37, 38, 39, 40, 41 (eden-biz-side D10 migrations) — all MERGED on eden-biz-go origin/main.

## Out of Scope
- Modifying eden-biz-go consumer code (D10 closed; further changes belong to follow-on objectives per `PLATFORM_BACKLOG.md`).
- New platform package work (apikeys cutover, audit-Connect upstreaming, attachments-tenancy, server-extension middleware) — these have their own future workstreams.
- DNS / customer data / external creds / repo archive operations.

## Exit Criteria
- All five R31.x requirements met.
- M3 milestone marked complete in `PORTFOLIO_STANDARDIZATION_PLAN.md`.
- This objective's planning closeout (REQUIREMENTS + 3 TRDs + SUMMARY + STATE/ROADMAP updates) committed and merged.
