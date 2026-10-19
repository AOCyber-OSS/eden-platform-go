# platform/household

Net-new platform package providing the Eden Family household / parent-of-record
/ child model. Backs AOFamily-AI today and Eden Family at launch (per
`PORTFOLIO_STANDARDIZATION_PLAN.md` §6 N1).

## Model

Household membership is **re-homed onto AOID identity** (Eden Family ADR,
Option B). It models three things:

1. **Household** — a family / billable / governable group, keyed on a
   `primary_contact_identity_id`. Eden Family uses households as the
   family-plan billable entity; AOFamily-AI uses them as the COPPA / GDPR-K
   compliance anchor.
2. **Member** — an individual associated with a household, keyed on a logical
   `identity_id`, described by two independent axes (see below).
3. **Parent-of-record** — the legally-responsible guardian for a child member.
   Multiple parents-of-record per child are supported (split households). Only
   members whose role can grant consent (guardians) should be established as
   parent-of-record.

### Identity keying

Members and the household primary contact key on a **logical `identity_id` =
`aoid.identities(id)`**, not on `platform.users(id)`. It is **not** an enforced
cross-DB foreign key — the platform (`eden_platform`) and AOID (`aoid`)
databases are separate. `identity_id` is validated at **provisioning time
(Phase 0.4)**, not by the DB.

### Two axes

A member is described by a relationship axis and a capability axis, which are
independent:

- **Role** (relationship): `guardian | adult | child`
  - `guardian` — legally-responsible adult; the only role eligible to grant
    COPPA / GDPR-K consent.
  - `adult` — an adult who is not a guardian of a child in the household
    (e.g. extended family on a shared family plan).
  - `child` — a minor; `Birthdate` is required. A child can hold no capability.
- **Capabilities**:
  - `is_manager` — `0..n` per household; may administer the household.
  - `is_account_owner` — **at most one** per household; holds the AOcyber
    subscription / card.

### Invariants (what is actually enforced, and where)

- **DB** (migration 016): role domain (`guardian|adult|child`);
  a child is never a manager and never an account_owner (CHECK constraints);
  **at-most-one** account_owner per household (partial unique index over
  non-removed members).
- **Service** (`Service`): the account_owner must be an adult (non-child);
  the account_owner cannot be removed without first transferring it; the last
  manager cannot be removed.
- **Not enforced in this phase**: any *lower* bound. `CreateHousehold` makes an
  **empty** household, so zero managers / zero owners is reachable through the
  store/service alone. The atomic existence guarantee — create a household and
  seed its first manager + account_owner together — is built at the **Phase 0.4
  provisioning seam**, not here. Do not rely on ">=1 manager" or "exactly one
  owner" holding at this layer.

All mutations route through `household.Service`, which wraps a `household.Store`
and emits a `platform/audit` event for every change.

## Quickstart

```go
import (
    "encoding/json"
    "time"

    "go.aocyber.ai/eden-platform-go/platform/audit"
    "go.aocyber.ai/eden-platform-go/platform/household"
    "go.aocyber.ai/eden-platform-go/platform/pgstore"
    "github.com/google/uuid"
)

backend, _ := pgstore.NewBackend(ctx, dbURL, migrationsFS)
auditLogger := audit.NewLogger(backend.AuditStore())
auditLogger.Start()
defer auditLogger.Stop()

svc := household.NewService(backend.HouseholdStore(), auditLogger)

// ActorID is the acting AOID identity (aoid.identities(id)), NOT a users row.
ac := household.AuditContext{
    CompanyID: tenantCompanyID, // billable company for the family
    ActorID:   actingIdentityID,
    IPAddress: clientIP,
}

// Create the household; the actor identity becomes its primary contact.
hh, err := svc.CreateHousehold(ctx, ac, "Smith Family", json.RawMessage(`{}`))

// Add a guardian who is both the household manager and the account owner.
guardian, err := svc.AddMember(ctx, ac, household.Member{
    HouseholdID:    hh.ID,
    IdentityID:     guardianIdentityID,
    Role:           household.RoleGuardian,
    IsManager:      true,
    IsAccountOwner: true,
})

// Add a child (birthdate is required for COPPA logic).
bday := time.Date(2018, 6, 1, 0, 0, 0, 0, time.UTC)
child, err := svc.AddMember(ctx, ac, household.Member{
    HouseholdID: hh.ID,
    IdentityID:  childIdentityID,
    Role:        household.RoleChild,
    Birthdate:   &bday,
})

// Establish the legal parent-of-record link (guardian over child).
por, err := svc.EstablishParentOfRecord(ctx, ac, child.ID, guardian.ID)
```

## Audit semantics

Every mutating call emits an audit event with `Resource = "household"`. The
action constants are exported (`ActionHouseholdCreated`, `ActionMemberAdded`,
etc.) so callers can filter or assert on them.

The audit actor (`AuditContext.ActorID`) is the acting **AOID identity**, not a
platform user. Migration 017 dropped the `audit_logs.actor_id -> users(id)` FK
so `actor_id` is a logical actor UUID that may be a platform user (auth events)
or an AOID identity (household / consent events). Before 017 an identity actor
would FK-fail on insert and be silently dropped by the audit logger.

`AuditContext.CompanyID` is required because the platform `audit_logs` table
FK-references `companies(id)`. For Eden Family use the family's billable
company; for AOFamily-AI use the per-tenant company id.

## Roles & capabilities

| Role       | CanGrantConsent | CanBeManager | CanBeAccountOwner |
|------------|-----------------|--------------|-------------------|
| `guardian` | yes             | yes          | yes               |
| `adult`    | no              | yes          | yes               |
| `child`    | no              | no           | no                |

`is_manager` / `is_account_owner` are the enforced capability columns.
`Member.Capabilities` is a forward-compatible JSONB bag for future, non-enforced
per-member flags — adding fields there does not require a migration.

## Integration with platform/consent (Objective 25)

`platform/consent` keys consent records on household members. The eligibility
gate uses `household.Role.CanGrantConsent()` — under the re-homed role model
only **guardians** may grant consent on behalf of a child member (the old
`parent` role no longer exists). The package also exports
`ActionParentOfRecordEstablished` so consent flows can audit-correlate.

## Database tables

This package's PostgreSQL backing tables are prefixed `platform_` to avoid
colliding with downstream apps that already own a domain `households` table
with a different shape (e.g. CRM voter-household tracking). The platform
schema owns:

- `platform_households`
- `platform_household_members`
- `platform_parent_of_record`

### Note for installs that applied migration 012 before 2026-05-21

Migration `012_households.up.sql` originally created un-prefixed tables. The
file was rewritten in place (GitHub issue #20) because no external consumer
had successfully applied the original — its un-prefixed shape collided with
existing `households` tables in downstream apps and the migration went dirty.

If your install **did** apply the original 012 cleanly (un-prefixed tables
exist with platform shape) and you are now pulling the rewritten 012, run
this one-time rename in a transaction before `migrate up`:

```sql
BEGIN;
ALTER TABLE households            RENAME TO platform_households;
ALTER TABLE household_members     RENAME TO platform_household_members;
ALTER TABLE parent_of_record      RENAME TO platform_parent_of_record;
ALTER INDEX idx_households_primary_contact      RENAME TO idx_platform_households_primary_contact;
ALTER INDEX idx_household_members_household     RENAME TO idx_platform_household_members_household;
ALTER INDEX idx_household_members_user          RENAME TO idx_platform_household_members_user;
ALTER INDEX idx_parent_of_record_child          RENAME TO idx_platform_parent_of_record_child;
ALTER INDEX idx_parent_of_record_parent         RENAME TO idx_platform_parent_of_record_parent;
COMMIT;
```

Then mark migration 012 as applied at its new content hash (consult your
migrate tool's docs — for `golang-migrate`, the version row in
`schema_migrations` already records `12`; no force needed).

Migrations 016 (re-home onto identity + two-axis model) and 017 (drop the
audit actor FK) build on top of 012.

## Test surface

- `service_test.go` covers all Service-layer business rules with an in-memory
  store (no DB needed).
- `memstore_test.go` provides the in-memory `Store` twin used by the service
  tests (mirrors pg semantics, including the at-most-one-account-owner guard).
- `pgstore/household_test.go` covers the PostgreSQL-backed store and an
  end-to-end service + audit-emission integration test (proves an AOID-identity
  audit actor persists after migration 017).

## Out of scope

- **Provisioning / atomic household bootstrap** — Phase 0.4 provisioning seam.
- **Consent ledger** — Objective 25 / `platform/consent`.
- **Billing rail / feature flags** — Objective 27 / `platform/entitlements`.
- **AO ID composition** — `internal/aoid/composition`.
