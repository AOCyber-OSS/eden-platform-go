# platform/config

Canonical environment configuration loader for the Eden portfolio. Beta.

## Quickstart

```go
import "go.aocyber.ai/eden-platform-go/platform/config"

cfg := config.Load()
if err := cfg.Validate(); err != nil {
    log.Fatalf("config: %v", err)
}
```

For multi-environment loading (e.g. one binary, three deploys):

```go
cfg := config.LoadFor(os.Getenv("EDEN_ENV")) // "production" / "staging" / ""
if err := cfg.Validate(); err != nil {
    log.Fatalf("config: %v", err)
}
```

## Resolution order

For every config field, values are resolved in this order, highest precedence first:

1. `<KEY>__<env>` — environment-specific override (only when `env` is set,
   either via `LoadFor(env)` or `EDEN_ENV` env var).
2. `<KEY>` — plain env var.
3. `<KEY>_FILE` — Docker-secrets convention (file path; trimmed contents).
4. `<KEY>_BASE64` — base64-encoded value (std, URL-safe, padded or raw).
5. Compiled-in default.

The `_FILE` and `_BASE64` strategies are only consulted by **secret** loaders
(`GetSecret`, `GetSecretFor`, and the secret fields of `LoadFor`). Non-secret
loaders skip steps 3-4.

## Public API

### Loaders

- `Load() *PlatformConfig` — read all platform fields with no environment context.
- `LoadFor(env string) *PlatformConfig` — same, with `<KEY>__<env>` overrides.
- `(*PlatformConfig).Validate() error` — aggregated check of required fields.

### Typed env helpers

- `GetEnv(key, fallback string) string`
- `GetSecret(key, fallback string) string`
- `GetInt(key string, fallback int) int`
- `GetBool(key string, fallback bool) bool`
- `GetDuration(key string, fallback time.Duration) time.Duration`
- `MustGet(key string) string` — panic-on-missing (boot-time only).
- `Required(keys ...string) error` — multi-key aggregated check.

Each has an `*For(..., env string)` sibling that applies the `__<env>`
override.

## Required fields

| Field         | Env var          | Default                                                       |
|---------------|------------------|---------------------------------------------------------------|
| DatabaseURL   | `DATABASE_URL`   | `postgres://localhost:5432/eden_dev?sslmode=disable` (dev only) |
| PlatformMode  | `PLATFORM_MODE`  | `b2b` (or `b2c`)                                              |

`Validate()` errors if `DATABASE_URL` is empty or `PLATFORM_MODE` is set to
anything other than `b2b` or `b2c`.

## Optional fields with defaults

| Field          | Env var               | Default                          |
|----------------|-----------------------|----------------------------------|
| ServerAddr     | `SERVER_ADDR`         | `:8080`                          |
| NatsURL        | `NATS_URL`            | `nats://localhost:4222`          |
| MinIOEndpoint  | `MINIO_ENDPOINT`      | `localhost:9000`                 |
| MinIOAccessKey | `MINIO_ACCESS_KEY`    | `minioadmin` (secret loader)     |
| MinIOSecretKey | `MINIO_SECRET_KEY`    | `minioadmin` (secret loader)     |
| MinIOBucket    | `MINIO_BUCKET`        | `eden-platform`                  |
| MinIORegion    | `MINIO_REGION`        | `us-east-1`                      |
| MinIOUseSSL    | `MINIO_USE_SSL`       | `false`                          |
| RedisURL       | `REDIS_URL`           | `localhost:6379`                 |
| RedisPassword  | `REDIS_PASSWORD`      | `""` (secret loader)             |
| JWTKeySeedPath | `JWT_KEY_SEED_PATH`   | `""`                             |

## Secrets handling

Three ways to deliver a secret in production, in increasing preference:

1. **`<KEY>` env var** — fine for development; do not use in CI logs.
2. **`<KEY>_BASE64`** — opaque opaque-to-shell-history; decoded at boot.
3. **`<KEY>_FILE`** — Docker secrets / Kubernetes secret-mounted file. Most secure.

Order of resolution above means a `_FILE` value wins over a `_BASE64` value
when both are set, which matches Docker-secrets-first deployments.

## Multi-environment overrides

Set `EDEN_ENV=prod` in the deployment, then suffix any env var with `__prod`
to override:

```bash
EDEN_ENV=prod
DATABASE_URL=postgres://localhost/dev_db        # dev fallback
DATABASE_URL__prod=postgres://prod-host/eden    # used when EDEN_ENV=prod
```

## Stability

This package is **beta**. All exports are stable. New fields on
`PlatformConfig` and new helpers are added non-breakingly.
