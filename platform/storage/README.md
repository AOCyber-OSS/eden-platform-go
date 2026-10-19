# platform/storage

S3-compatible object storage with presigned URLs and per-bucket policy
enforcement. Beta.

## Donor

`eden-biz/storage` (s3.go + presigned.go). The platform package promotes
the **lower-level storage primitive** while leaving `platform/upload`
(which already handles the pending-attachment + DB-backed upload workflow)
in place. Consumers needing only object IO use `platform/storage` directly;
consumers needing DB-tracked attachment lifecycles use `platform/upload`
or `platform/attachments`.

## Quickstart

```go
import "go.aocyber.ai/eden-platform-go/platform/storage"

policy := storage.Policy{
    MaxBytes:      50 * 1024 * 1024,                // 50 MB
    AllowedTypes:  []string{"image/*", "application/pdf"},
    DefaultExpiry: 15 * time.Minute,
}

// Production
client, _ := storage.NewS3Client(storage.Config{
    Endpoint: "s3.amazonaws.com", AccessKey: "...", SecretKey: "...",
    UseSSL: true, Region: "us-east-1", Bucket: "my-bucket",
}, policy)

// Tests / dev
client := storage.NewMemoryClient("test", policy)

// Direct upload
obj, _ := client.Put(ctx, "users/123/avatar.png", body, "image/png", size, nil)

// Browser uploads via presigned URL
url, _ := client.PresignedPut(ctx, "users/123/upload.jpg", "image/jpeg", size, 0)
// caller hands URL to browser; browser PUTs to it directly

// Browser downloads via presigned URL
durl, _ := client.PresignedGet(ctx, "users/123/avatar.png", 5*time.Minute)
```

## Backends

- **AWS S3** — set `UseSSL: true`, `UsePathStyle: false`, regional endpoint.
- **MinIO** — set `UsePathStyle: true`, endpoint = "minio:9000".
- **Cloudflare R2** — `UsePathStyle: true`, endpoint = "<account>.r2.cloudflarestorage.com".
- **DigitalOcean Spaces** — `UsePathStyle: false`, endpoint = "<region>.digitaloceanspaces.com".

## Policy enforcement

`Policy.MaxBytes` defaults to 100 MB (consumers can override per-bucket).
`Policy.AllowedTypes` accepts exact types and prefix wildcards (`image/*`).
Presigned PUT URLs also enforce policy at issuance time — your pre-flight
check rejects oversized / wrong-MIME requests before handing back a URL,
which means the browser never gets a valid URL for an invalid request.

## Integration testing

A live S3/MinIO integration test is documented in the package but gated
behind the `STORAGE_TEST_S3_ENDPOINT` env var so it doesn't run on bare
`go test ./...`. To run locally:

```bash
docker run -d -p 9000:9000 -p 9001:9001 \
  -e MINIO_ROOT_USER=admin -e MINIO_ROOT_PASSWORD=admin12345 \
  minio/minio server /data --console-address ":9001"

STORAGE_TEST_S3_ENDPOINT=localhost:9000 \
STORAGE_TEST_S3_ACCESS=admin \
STORAGE_TEST_S3_SECRET=admin12345 \
STORAGE_TEST_S3_BUCKET=test \
go test ./platform/storage/ -tags=integration
```
