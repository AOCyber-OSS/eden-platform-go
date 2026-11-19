---
status: complete
mode: quick
issue: 20
date: 2026-05-21
---

# Quick Task 1 — Summary

## What shipped

Renamed the platform household-domain tables from un-prefixed to `platform_*`
to eliminate the collision documented in GitHub issue #20 (downstream apps
with their own `households` table — notably `justinforme` — could not apply
migration 012).

- `households` → `platform_households`
- `household_members` → `platform_household_members`
- `parent_of_record` → `platform_parent_of_record`
- All 5 associated indexes renamed for hygiene.

## Strategy

Edited migrations 012/013 in place rather than fix-forward with a 014. Safe
in this case because no external consumer had ever applied 012 cleanly:
justinforme failed on first attempt and rolled back; all other Obj 24/24a/31/33
consumers are internal platform code running ephemeral CI databases. A
fix-forward 014 would not have unblocked justinforme — the collision on 012
itself would still fail.

For the (unlikely) install that did apply 012 cleanly before this PR, a
one-time `ALTER TABLE … RENAME TO …` block is documented in
`platform/household/README.md`.

## Files changed

| File | Change |
|------|--------|
| `migrations/platform/012_households.up.sql` | Rename 3 tables + 5 indexes, updated header comment with rationale |
| `migrations/platform/012_households.down.sql` | Drop `platform_*` names in reverse FK order |
| `migrations/platform/013_consent_ledger.up.sql` | FK refs → `platform_households(id)`, `platform_household_members(id)` |
| `queries/platform/households.sql` | All 14 query statements updated to reference `platform_*` |
| `internal/db/households.sql.go` | Regenerated via `sqlc generate` (sqlc v1.30.0); 41 lines changed |
| `internal/db/models.go` | sqlc-regenerated struct types now `PlatformHousehold` / `PlatformHouseholdMember` / `PlatformParentOfRecord` |
| `platform/pgstore/household_store.go` | 3 mapper signatures updated to consume the renamed `db.Platform*` structs |
| `platform/pgstore/pgstore_test.go` | Teardown list uses `platform_*` table names |
| `platform/household/README.md` | New "Database tables" section + one-time `ALTER` recipe |

`013_consent_ledger.down.sql` only drops `consent_ledger` itself — no
reference to the renamed tables, no change needed.

## Verification

- `go build ./...` clean.
- `go vet ./...` clean.
- `go test -short ./platform/household/... ./platform/integration/...` green.
- `go test ./platform/pgstore/...` against a fresh local Postgres
  (`pgx5://justin@localhost/eden_platform_test_rename`) — green (migrations
  apply cleanly from 001 → 013).
- Final grep for SQL strings referencing the bare names: clean (remaining
  matches are error-message strings and domain-concept names, not SQL).

## Out of scope (intentional)

- Go package `platform/household` keeps its name — this was a DB-table
  rename, not a code rename.
- Other platform tables (`users`, `companies`, …) stay un-prefixed; this is a
  one-off resolution for the one collision, not a portfolio-wide
  `platform_*` adoption.
- Moving to a Postgres schema (`platform.*`) — heavier refactor; deferred.
- `consent_ledger` keeps its bare name (no known collision).

## Closes

GitHub issue #20.
