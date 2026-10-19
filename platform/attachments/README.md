# platform/attachments

Polymorphic file-attachment abstraction. Beta.

## Donor

`eden-biz/attachments` (handler.go, service.go, store_pg.go).

## Concept

Any record (any table) can have files via `(attachment_owner_type, attachment_owner_id)`.
The metadata lives in Postgres; the blob lives in `platform/storage`.

```go
import (
    "go.aocyber.ai/eden-platform-go/platform/attachments"
    "go.aocyber.ai/eden-platform-go/platform/storage"
)

storeClient := storage.NewS3Client(s3Cfg, storage.Policy{MaxBytes: 25*1024*1024})
attStore := attachments.NewPostgresStore(pgPool)
svc := attachments.NewService(attStore, storeClient, "attachments/")

// Attach a file to ANY domain object
att, _ := svc.Attach(ctx,
    attachments.Owner{Type: "invoice", ID: invoiceID.String()},
    body, "receipt.pdf", "application/pdf", size, currentUserID)

// List
files, _ := svc.List(ctx, attachments.Owner{Type: "invoice", ID: invoiceID.String()})

// Presigned download URL for the browser
url, _ := svc.PresignedDownload(ctx, att.ID, 5*time.Minute)

// Browser-direct upload flow:
//   1) caller asks platform/storage for PresignedPut URL
//   2) browser PUTs directly
//   3) caller calls AttachFromKey to record the metadata
att, _ = svc.AttachFromKey(ctx, owner, storageKey, filename, contentType, size, userID)

// Remove
_ = svc.Remove(ctx, att.ID)  // deletes blob + metadata
```

## Schema

```sql
CREATE TABLE attachments (
    id                       UUID PRIMARY KEY,
    attachment_owner_type    TEXT NOT NULL,
    attachment_owner_id      TEXT NOT NULL,
    storage_key              TEXT NOT NULL UNIQUE,
    filename                 TEXT NOT NULL,
    content_type             TEXT NOT NULL,
    size                     BIGINT NOT NULL,
    uploaded_by              TEXT NOT NULL,
    metadata                 JSONB NOT NULL DEFAULT '{}'::jsonb,
    created_at               TIMESTAMPTZ NOT NULL DEFAULT now()
);
CREATE INDEX attachments_owner_idx
    ON attachments (attachment_owner_type, attachment_owner_id);
```

## What this package is not

- **Not** an upload-flow orchestrator with pending state — see `platform/upload` for that pattern.
- **Not** an authoritative virus scanner — out of scope (deferred per Obj 19 requirements).

## When to use which package

| Use case | Package |
| --- | --- |
| Object-store IO + presigned URLs only | `platform/storage` |
| Pending → confirmed upload flow with company/user scoping | `platform/upload` |
| Polymorphic attach-anything-to-anything | `platform/attachments` |
