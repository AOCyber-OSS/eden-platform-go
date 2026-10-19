# Migration playbook — replacing your AOSentry fork

This package consolidates seven historical forks of an AOSentry HTTP client.
Each fork was correct for its consumer at the time it was written, but the
duplication has cost: bugs fixed in one fork didn't propagate to the others,
auth/headers drifted, and observability was inconsistent. This playbook
walks each consumer through retiring its fork.

> **Scope clarifier.** Objective 26 ships the platform package. Each
> consumer migration is its own PR in its own repo and is owned by that
> consumer's DevFlow setup. Don't bundle migrations with this PR.

## 1. Find your fork

| Repo                                | Fork location                                                           |
|-------------------------------------|-------------------------------------------------------------------------|
| eden-circle                         | `internal/ai/gateway_aosentry.go` (+ `gateway.go` interface)            |
| eden-biz-go                         | `internal/docprocessing/aosentry_client.go`                             |
| aohealth-go                         | `internal/aosentry/client.go` + `models.go` + `refine.go` + `spend.go`  |
| justinforme                         | `app/ai/aosentry.go`                                                    |
| smartWellness                       | `internal/aosentry/client.go`                                           |
| aofamily-ai                         | `go/internal/aosentry/client.go`                                        |
| aofamily-browser                    | `go/internal/aosentry/client.go`                                        |

Note: `eden-biz-dev/eden-biz-go/internal/aitools/` is a service-layer for
conversation/template/usage persistence — it does **not** contain an AOSentry
HTTP client today. When that service grows one, it should consume
`platform/aigateway` from day one rather than fork.

## 2. Generic migration steps

For every consumer:

1. Add the dependency: `go get go.aocyber.ai/eden-platform-go@<pinned-version>`
   (or rely on the existing `replace` directive if your repo already pins
   eden-platform-go via local path; see `eden-biz-go/go.mod` for an example).
2. Replace your fork's import with `platform/aigateway`.
3. Map call sites using the per-fork tables below.
4. Run `go test ./...` and `go vet ./...` in your repo.
5. Delete the fork directory (`internal/aosentry/`, `app/ai/aosentry.go`, etc.).
6. Update CI to drop fork-specific env vars if any (most use the same
   `AOSENTRY_*` env names — see the README).
7. Open a PR titled `chore(aosentry): migrate to platform/aigateway` with a
   link back to Objective 26.

## 3. Per-fork mapping tables

### 3.1 eden-circle (`internal/ai/`)

| Fork API                                         | Platform replacement                                             |
|--------------------------------------------------|------------------------------------------------------------------|
| `ai.AIGateway.ChatCompletion(ctx, req)`          | `c.ChatCompletion(ctx, req)` — same shape; map fork's `ChatRequest` to platform's |
| `ai.AIGateway.GenerateEmbedding(ctx, text)`      | `c.EmbedText(ctx, text, "")`                                     |
| `ai.AIGateway.TranscribeAudio(ctx, audio, fmt)`  | `c.TranscribeAudio(ctx, audio, filename, "")`                    |
| `ai.AOSentryGateway` constructor + rate limiter  | Drop the rate limiter (AOSentry enforces RPS server-side); use `aigateway.NewClient(cfg)` |
| `audit.Log` glue                                  | Replace with `aigateway.WithObserver(yourAuditObserver)`         |

### 3.2 eden-biz-go (`internal/docprocessing/`)

| Fork API                                         | Platform replacement                                             |
|--------------------------------------------------|------------------------------------------------------------------|
| `AOSentryClient.Summarize(ctx, text, docID)`     | `c.SummarizeDocument(ctx, text, docID.String())`                 |
| `AOSentryClient.ExtractText(ctx, pdf, docID)`    | `c.ExtractText(ctx, pdf, "document.pdf", docID.String())`        |
| `ErrAOSentryNotConfigured`                       | `aigateway.ErrNotConfigured` (same semantics)                    |

### 3.3 aohealth-go (`internal/aosentry/`)

| Fork API                                         | Platform replacement                                             |
|--------------------------------------------------|------------------------------------------------------------------|
| `Client.ChatCompletion(ctx, userID, req)`        | `c.ChatCompletion(ctx, req)` — set `req.User = strconv.FormatInt(userID, 10)` (matches fork behavior) |
| `Client.ChatCompletionVision(ctx, userID, req)`  | Same `c.ChatCompletion`; build `Messages[i].Content` as `[]ContentPart` |
| `Client.RefinePrompt(ctx, req)`                  | `c.RefinePrompt(ctx, req)`                                       |
| `ErrNotConfigured` / `ErrBudgetExceeded`         | Identical sentinels in `platform/aigateway`                      |
| Per-user spend tracking                          | Already preserved — `User` field is forwarded verbatim           |

### 3.4 justinforme (`app/ai/aosentry.go`)

| Fork API                                         | Platform replacement                                             |
|--------------------------------------------------|------------------------------------------------------------------|
| `AOSentryClient.Generate(ctx, req)`              | `c.Generate(ctx, req)` — `GenerateRequest` shape preserved (Model, SystemPrompt, UserPrompt, MaxTokens) |
| 5s timeout (`generateTimeout`)                   | Pass `Config{Timeout: 5*time.Second}` — TRD-08 fallback detector still keys on `context.DeadlineExceeded` |
| TRD-08 graceful fallback                         | Errors from the platform client preserve `errors.Is(err, context.DeadlineExceeded)` (transport errors wrapped with `%w`) |
| "AI service" naming requirement                  | Caller-side — slog.Log calls stay in justinforme                 |

### 3.5 smartWellness (`internal/aosentry/`)

| Fork API                                         | Platform replacement                                             |
|--------------------------------------------------|------------------------------------------------------------------|
| `Client.Chat(ctx, req)` returning `(string, string, ChatUsage, error)` | `resp, err := c.ChatCompletion(ctx, req); resp.FirstContent()`, `resp.Model`, `resp.Usage` |
| `Client.AnalyzeImage(ctx, req)`                  | `c.ChatCompletion(ctx, req)` with `ContentPart{Type:"image_url"}` (the fork already wraps this; keep app-level helper if helpful) |
| `Client.GenerateImage(ctx, req)`                 | `c.GenerateImage(ctx, req)` — same shape                         |
| `ErrDisabled`                                     | `aigateway.ErrNotConfigured`                                     |
| `MessagePart` / `MessageImage`                   | `ContentPart` / `ImageURLPart`                                   |

### 3.6 aofamily-ai (`go/internal/aosentry/`)

| Fork API                                         | Platform replacement                                             |
|--------------------------------------------------|------------------------------------------------------------------|
| `Client.ChatCompletion(ctx, req)`                | `c.ChatCompletion(ctx, req)`                                     |
| `Client.ChatCompletionStream(ctx, req)`          | `c.ChatCompletionStream(ctx, req)` — returns `<-chan string, <-chan error` |
| `Client.Moderate(ctx, input)`                    | `c.Moderate(ctx, input)` — categories now `map[string]bool`      |
| `Client.CheckGuardrails(ctx, input, policy, md)` | `c.CheckGuardrails(ctx, input, policy, md)`                      |
| `Client.RedactPII` / `RehydratePII`              | Identical names on platform client                               |
| `Client.Embeddings(ctx, input, model)`           | `c.Embeddings(ctx, EmbeddingRequest{Input: input, Model: model})`|
| `Client.ModelForAge(age)`                        | App-level helper — keep in `aofamily-ai` (not platform concern)  |
| `BuildPersonaMessages(...)`                      | App-level helper — keep in `aofamily-ai`                         |

### 3.7 aofamily-browser (`go/internal/aosentry/`)

| Fork API                                         | Platform replacement                                             |
|--------------------------------------------------|------------------------------------------------------------------|
| `Client.ChatCompletion(ctx, *req)`               | `c.ChatCompletion(ctx, req)` (drop pointer)                      |
| `Client.Moderate(ctx, input)`                    | `c.Moderate(ctx, input)`                                         |
| `Client.Embed(ctx, input, model)`                | `c.EmbedText(ctx, input, model)` (returns `[]float32`)           |
| `Client.CheckGuardrails(ctx, content)`           | App-level helper around `c.ChatCompletion` — the fork's impl is a chat-completion-with-classifier-prompt, not a server endpoint. Keep a thin caller-side helper or migrate to `c.CheckGuardrails(ctx, ..., "family-safe", nil)` server-side. |
| `ConfigFromEnv()`                                 | `aigateway.ConfigFromEnv()` (env names match)                    |

## 4. Verification checklist

After your migration PR:

- [ ] `go vet ./...` clean
- [ ] `go test ./...` green
- [ ] Fork directory deleted (`git diff --stat` shows the removed files)
- [ ] Production AI calls verified end-to-end against AOSentry (manual smoke or integration test)
- [ ] Spend logs in AOSentry show traffic from your service post-migration
- [ ] `eden status --all` (run from eden-libs) reports your repo as no
      longer carrying an AOSentry fork

## 5. Out of scope for migrations

Don't expand the surface during migration. If your fork shipped extra
helpers (rate limiters, caches, retry-aware spend recorders), keep them
in your app and consume `platform/aigateway` underneath them. New
helpers that prove useful across two or more consumers are candidates
for promotion in a follow-up objective.
