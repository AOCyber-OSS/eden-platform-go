---
status: planned
mode: quick
issue: 20
date: 2026-05-21
---

# Quick Task 1 — Rename platform `households` → `platform_households`

## Why

GitHub issue #20: platform migration `012_households.up.sql` collides with
downstream apps (e.g. `justinforme`) that already own a domain `households`
table with a completely different shape. `CREATE TABLE IF NOT EXISTS` silently
skips the create, then `CREATE INDEX idx_households_primary_contact` fails
with `column "primary_contact_user_id" does not exist`, leaving migrations
dirty. Migration 013 (`consent_ledger`) then can never apply because its FK
target (`household_members`) was never created. Downstream is forced to roll
back the vendor bump and cannot pick up unrelated proto fixes that landed in
the same release.

## Decisions

- **Name:** `platform_households` (also `platform_household_members`,
  `platform_parent_of_record`). One-off rename for this specific collision —
  not a portfolio-wide adoption of `platform_*` prefix on every table.
- **Strategy:** Edit migrations 012/013 in place. Safe here: no external
  consumer has successfully applied 012 (justinforme failed → rolled back; all
  other Obj 24/24a/31/33 consumers are internal platform code on ephemeral CI
  DBs). Honors fix-forward over migration-immutability convention because
  fix-forward (a new 014_rename) cannot actually unblock justinforme — the
  collision on 012 itself would still fail.
- **Go package name stays `household`** — this is a DB-table rename only.

## Must-haves

- All references to bare `households` / `household_members` / `parent_of_record`
  table names in the platform schema are replaced with `platform_*`.
- `sqlc generate` succeeds; `sqlc diff` clean against the new sources.
- `go build ./...`, `go vet ./...` clean.
- `go test ./platform/pgstore/... ./platform/household/... ./platform/integration/...` clean.
- Release note documents the in-place edit + the one-time ALTER recipe for
  any install that already applied 012 cleanly.

## Files touched

| File | Change |
|------|--------|
| `migrations/platform/012_households.up.sql` | Rename 3 tables + 5 indexes |
| `migrations/platform/012_households.down.sql` | Match `.up` |
| `migrations/platform/013_consent_ledger.up.sql` | FK refs → `platform_households(id)`, `platform_household_members(id)` |
| `migrations/platform/013_consent_ledger.down.sql` | Check (the down only drops `consent_ledger` itself; should be unaffected) |
| `queries/platform/households.sql` | 5 statements: INSERT/Get/Update/Delete/ListForUser |
| `internal/db/households.sql.go` | Regenerated via `sqlc generate` (DO NOT hand-edit) |
| `platform/pgstore/pgstore_test.go:52` | Teardown list |
| `README.md` or `AGENTS.md` | Release note + ALTER recipe |

## Out of scope

- Renaming the Go package `platform/household`.
- Renaming `consent_ledger` (no collision known).
- Renaming any other platform tables (`users`, `companies`, etc.).
- Adopting a Postgres schema (`platform.*`) — heavier refactor; deferred.
