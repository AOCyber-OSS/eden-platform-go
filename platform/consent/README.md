# platform/consent

Net-new platform package providing an append-only COPPA / GDPR-K consent
ledger keyed to household members. Required for any under-13 user flow
(AOFamily-AI today, Eden Family at launch). Per `PORTFOLIO_STANDARDIZATION_PLAN.md`
§6 Workstream 3 N2 / Objective 25.

## Why this exists

COPPA (US) and GDPR Article 8 (EU/UK) require **verifiable parental consent
(VPC)** before processing personal data of a child under 13 (COPPA) or 16
(GDPR-K). The legally-relevant artifact is not just "did the parent click
yes" but **a durable record of which version of the consent text was
accepted, who accepted it, on whose behalf, with what evidence, and when**.

`platform/consent` provides that record. It does NOT run the VPC method
(no credit-card check, no signed PDF generation); it stores the **evidence**
that the caller produces.

## Architecture

```
[child onboarding flow]
        │  (parent clicks "I consent")
        ▼
[caller code: VPC method]
        │  produces evidence: e.g. card-auth webhook payload
        ▼
[platform/consent.Service.Grant]
        ├──► consent_ledger INSERT (append-only row)
        └──► platform/audit Logger.Log("consent.granted")

[any later code path that needs to act on behalf of child]
        ▼
[platform/consent.Service.IsValid(principal, purpose, T)]
        ├──► consent_ledger SELECT (latest for purpose)
        └──► platform/audit Logger.Log("consent.read")  ◄── R35.3 read-audit
```

## Append-only invariant

The `consent_ledger` table has `BEFORE UPDATE` and `BEFORE DELETE` row-level
triggers that raise an exception. The `Service` API has no UPDATE / DELETE
methods. **Revocations are new rows** whose `RevokesID` points at the
original grant. The history of every grant + revocation is preserved
forever; auditors can replay it.

`TRUNCATE consent_ledger CASCADE` bypasses row-level triggers and is the
only way to clean the table (used by test cleanup; never in production).

## Quickstart

```go
import (
    "go.aocyber.ai/eden-platform-go/platform/audit"
    "go.aocyber.ai/eden-platform-go/platform/consent"
    "go.aocyber.ai/eden-platform-go/platform/household"
    "go.aocyber.ai/eden-platform-go/platform/pgstore"
)

backend, _ := pgstore.NewBackend(ctx, dbURL, migrationsFS)
auditLogger := audit.NewLogger(backend.AuditStore())
auditLogger.Start()
defer auditLogger.Stop()

consentSvc := consent.NewService(backend.ConsentStore(), auditLogger)
hhSvc := household.NewService(backend.HouseholdStore(), auditLogger)

ac := consent.AuditContext{
    CompanyID: tenantCompanyID,
    ActorID:   currentUserID,
    IPAddress: clientIP,
}

// Eligibility check: only parent or guardian may grant consent.
parent, err := hhSvc.GetMember(ctx, parentMemberID)
if err != nil { return err }
if !parent.Role.CanGrantConsent() {
    return errors.New("not eligible to grant consent")
}

evidence, _ := consent.Evidence{
    Method:    "click_through",
    Recorded:  time.Now().UTC(),
    IPAddress: clientIP,
    UserAgent: req.UserAgent(),
    Reference: "consent_v1.0_modal",
}.JSON()

entry, err := consentSvc.Grant(ctx, ac, consent.GrantRequest{
    HouseholdID:        hhID,
    PrincipalMemberID:  childMemberID,
    ConsenterMemberID:  parentMemberID,
    Purpose:            consent.PurposeAITutorInteraction,
    ConsentTextVersion: "v1.0",
    Evidence:           evidence,
})

// Later — gate any child-account action on:
v, err := consentSvc.IsValid(ctx, ac, childMemberID, consent.PurposeAITutorInteraction, time.Now())
if !v.Valid { return errors.New("consent not granted or revoked") }

// Revoke: insert a new row referring to the original.
_, err = consentSvc.Revoke(ctx, ac, entry.ID, parentMemberID, evidence)
```

## VPC methods accepted today

The package is **method-agnostic** — it stores whatever evidence the caller
produces. Documented patterns:

| Method            | Evidence shape                                                                |
|-------------------|--------------------------------------------------------------------------------|
| `click_through`   | `{method, recorded_at, ip_address, user_agent, reference: "modal_v1.0"}`       |
| `credit_card`     | `{method, recorded_at, ip_address, reference: "<provider_txn_id>"}`            |
| `signed_pdf`      | `{method, recorded_at, reference: "<pdf_storage_id>", custom: {hash}}`         |
| `webhook`         | `{method, recorded_at, reference: "<provider_callback_id>"}`                   |

The package does NOT validate evidence shape. Compliance teams should
review the evidence patterns against the FTC's COPPA Rule §312.5(b)
acceptable methods.

## Consent text versioning

`ConsentTextVersion` is a free-form string. The package stores the version
string but does NOT store the consent text content (the actual paragraphs
the parent clicked through) — that lives in `platform/cms` or your CMS of
choice. When you ship a new consent text version:

1. Bump the version string (e.g., `v1.0` → `v1.1`).
2. Old consents remain `Valid: true` until your application re-prompts.
3. After re-prompt, call `Grant` again with the new version. Both rows
   persist in history; `LatestForPurpose` returns the renewal.

## Read-auditing (R35.3)

Every call to `IsValid`, `ListForPrincipal`, or `GetEntry` emits a
`consent.read` audit event. Auditors can prove who looked up which
principal's consent state and when. This is required for compliance —
"who saw the data" is as important as "who granted consent".

## Privacy considerations

The `evidence` and `scope` columns are JSONB and may contain PII (IP
address, user-agent, signed payloads). Recommend pairing with
`platform/encryption` for column-level encryption at rest if your
deployment requires it. The package does NOT auto-encrypt.

## Composition with platform/household

`platform/consent` does NOT import `platform/household`. Eligibility
checks are the caller's responsibility — typically composed via
`household.Member.Role.CanGrantConsent()`. This keeps each package
independently testable and avoids any future circular dependency.

The two packages share `AuditContext` shape (CompanyID + ActorID + IPAddress)
for symmetry; callers can pass the same struct.

## Test surface

- `service_test.go` — grant / revoke / validity / read-audit / as-of-time
  with an in-memory store (no DB needed).
- `pgstore/consent_test.go` — append-only invariant via UPDATE/DELETE
  trigger assertions, end-to-end grant→IsValid→revoke→IsValid flow with
  audit events flushed to `audit_logs`, and consent-text renewal.

## Out of scope

- Active VPC method implementations (credit-card check, etc.) — this
  package stores the evidence the caller's chosen VPC method produces.
- Consent text content management — see `platform/cms`.
- AO ID composition — Objective 29 / `ao-id` service composes household +
  consent into a unified identity API.
