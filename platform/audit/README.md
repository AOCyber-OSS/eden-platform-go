# platform/audit

Canonical audit-log surface for the Eden portfolio. Beta.

## Purpose

One implementation of audit logging across `aosentry`, `aodex`, `eden-biz`,
`aofamily`, and any future product. Async by default for hot paths, sync
fallback for security-critical audits and tests.

## Quickstart

```go
import "go.aocyber.ai/eden-platform-go/platform/audit"

logger := audit.NewLogger(store) // store implements audit.AuditStore
logger.Start()
defer logger.Stop()

// Async — never blocks; drops if the buffer is full.
logger.Log(audit.Event{
    CompanyID:  companyID.String(),
    ActorID:    actorID.String(),
    Action:     audit.ActionUserLogin.String(),
    Resource:   "user",
    ResourceID: userID.String(),
}.WithRequestID(requestID).WithReason("password"))

// Sync — returns an error on failure. Use for must-not-drop audits.
if err := logger.LogSync(ctx, e); err != nil {
    return fmt.Errorf("audit: %w", err)
}

// HTTP-derived metadata (IP, user-agent, X-Request-ID).
e := audit.EventFromHTTP(r).WithAction(audit.ActionUserLogin)
e.CompanyID = companyID.String()
e.ActorID = actorID.String()
e.Resource = "user"
e.ResourceID = userID.String()
logger.Log(e)
```

## Event schema

| Field        | Type                | Notes                                       |
|--------------|---------------------|---------------------------------------------|
| CompanyID    | string (UUID)       | Required. Tenant scope.                     |
| ActorID      | string (UUID)       | Required. The user (or service) acting.     |
| Action       | string              | See action conventions below.               |
| Resource     | string              | Logical type ("user", "apikey", "voter").   |
| ResourceID   | string              | Stable identifier (UUID, slug, etc.).       |
| Details      | map[string]any      | Free-form. See standard keys below.         |
| IPAddress    | string              | Client IP. `EventFromHTTP` derives this.    |

`Details` is JSON-marshaled before being passed to the store. Non-marshalable
values surface as a sync-write error or a logged warning on the async path.

## Action naming convention

`domain.entity.verb`, lower-case, dot-separated. Examples:

- `auth.user.login`
- `auth.user.signup`
- `auth.token.refresh`
- `auth.apikey.create`
- `rbac.role.grant`
- `generic.create`, `generic.update`, `generic.delete`

Constants are exported under `audit.Action*`. Prefer constants to magic strings;
add new constants here when a new domain joins the portfolio.

## Standard detail keys

Use these so cross-product queries on `details` work without schema drift:

- `before` — pre-change snapshot for update events
- `after` — post-change snapshot for update events
- `reason` — human-readable explanation (revoke/delete events)
- `request_id` — correlation id matching the structured log line
- `user_agent` — UA string from the originating HTTP request

Helpers:

- `Event.WithDetail(key, value) Event`
- `Event.WithBeforeAfter(before, after any) Event`
- `Event.WithRequestID(id) Event`
- `Event.WithReason(reason) Event`
- `Event.WithAction(audit.Action) Event`

## Sync vs async

- **`Logger.Log(e)`** — async, drops on full buffer (10k slots). Default.
- **`Logger.LogSync(ctx, e)`** — synchronous, returns error. Use for
  security-relevant audits (key rotation, role grants, deletions of records
  under retention) and tests that must observe the row.

The async path uses 100ms batched flushes with a max batch of 50 events. On
`Stop()` the buffer drains before return.

## Stability

This package is **beta**. Public API is stable; additions are non-breaking.
Field additions to `Event` would be additive and non-breaking. The
`AuditStore` interface is the integration contract — any store implementing
`CreateAuditLog` works.

## Migration notes

Consumers under `aosentry/audit`, `eden-biz/audit`, and `audithelper` should
move to this package package-by-package in their own PRs. This objective is
**platform-side only** — no consumer migration here.
