# platform/aigateway

Canonical Go client for the AOSentry AI gateway.

This package consolidates seven prior forks of an AOSentry HTTP client that
grew up independently across the AOC portfolio. It is the union of those
forks' real surface area; new capabilities (function calling / tool use) are
intentionally out of scope until a real consumer needs them.

## Status

Beta. Public API is stable for the surfaces below; backwards-incompatible
changes will be flagged in `CHANGELOG.md` (per `eden-platform-go` policy).

## Quick start

```go
import "go.aocyber.ai/eden-platform-go/platform/aigateway"

cfg, err := aigateway.ConfigFromEnv()
if err != nil { /* AOSentry not configured — degrade gracefully */ }

c, err := aigateway.NewClient(cfg)
if err != nil { /* same — ErrNotConfigured */ }

resp, err := c.ChatCompletion(ctx, aigateway.ChatRequest{
    Messages: []aigateway.ChatMessage{
        {Role: "system", Content: "You are helpful."},
        {Role: "user",   Content: "Hi"},
    },
    Temperature: aigateway.Float64Ptr(0.7),
    MaxTokens:   aigateway.IntPtr(200),
    User:        userID, // forwarded for per-user spend attribution
})
if err != nil { /* handle */ }
fmt.Println(resp.FirstContent())
```

## Configuration

| Env var                   | Required | Default                   | Notes                          |
|---------------------------|----------|---------------------------|--------------------------------|
| `AOSENTRY_BASE_URL`       | Yes      | _none_                    | Trailing slashes trimmed       |
| `AOSENTRY_API_KEY`        | No\*     | _none_                    | Sent as `Authorization: Bearer`|
| `AOSENTRY_DEFAULT_MODEL`  | No       | `gpt-4o-mini`             | Used when request omits model  |
| `AOSENTRY_TIMEOUT`        | No       | `30s`                     | Go duration string             |
| `AOSENTRY_MAX_RETRIES`    | No       | `3`                       | Retries on 429 / 5xx           |

\*Empty `BaseURL` returns `ErrNotConfigured` from `NewClient` so callers can
degrade gracefully ("AI unavailable") in environments where AOSentry is
intentionally not provisioned.

## Endpoints

| Method                     | Path                                  | Notes                                         |
|----------------------------|---------------------------------------|-----------------------------------------------|
| `ChatCompletion`           | `POST /v1/chat/completions`           | Text + vision + JSON-mode                     |
| `ChatCompletionStream`     | `POST /v1/chat/completions` (SSE)     | Returns `<-chan string, <-chan error`         |
| `Embeddings`, `EmbedText`  | `POST /v1/embeddings`                 | `[]float32` shape via `EmbedText`             |
| `Moderate`                 | `POST /v1/moderations`                | Open-ended category maps                      |
| `CheckGuardrails`          | `POST /v1/guardrails/check`           | Policy-aware classifier                       |
| `RedactPII`, `RehydratePII`| `POST /v1/guardrails/pii/{redact,rehydrate}` | Round-trip PII handling           |
| `GenerateImage`            | `POST /v1/images/generations`         | OpenAI-compatible images.generations          |
| `TranscribeAudio`          | `POST /v1/audio/transcriptions`       | Multipart upload                              |
| `RefinePrompt`             | `POST /v1/prompts/refine`             | Domain + intent prompt polishing              |
| `SummarizeDocument`        | `POST /v1/documents/summarize`        | Eden-Biz docprocessing surface                |
| `ExtractText`              | `POST /v1/documents/extract`          | Multipart PDF -> text                         |
| `Generate`                 | `POST /v1/generate`                   | Legacy system+user prompt surface (justinforme)|

## Errors

Sentinel errors compared via `errors.Is`:

- `ErrNotConfigured` — `BaseURL` empty
- `ErrUnauthorized` — upstream HTTP 401
- `ErrBudgetExceeded` — upstream HTTP 402

Other non-retryable failures return `*HTTPError{Status, Body, Path}`.
Transient failures (HTTP 429 and 5xx) are retried with exponential backoff
up to `Config.MaxRetries`.

## Observability

```go
type myObs struct{ /* prometheus or otel handles */ }
func (m *myObs) Observe(ctx context.Context, ev aigateway.Event) { /* record */ }

c, _ := aigateway.NewClient(cfg, aigateway.WithObserver(&myObs{}))
```

Every endpoint dispatches a single `Event` per call (success or failure)
with operation, model, prompt/completion/total tokens (when present),
duration, success flag, and error (if any). The interface deliberately
keeps this package free of a hard dependency on any specific metrics or
tracing library.

## Testing

The package is self-contained — every endpoint is exercised against
`httptest.NewServer`. Run:

```sh
go test ./platform/aigateway/...
```

## Migration

See [`MIGRATION.md`](./MIGRATION.md) for per-fork mapping tables and a
step-by-step playbook for retiring each existing AOSentry fork.
