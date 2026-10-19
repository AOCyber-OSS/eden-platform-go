# platform/httputil

Minimal HTTP response/request helpers for handlers in the Eden portfolio.
Promoted from `aosentry/pkg/httputil` per the standardization plan §3
Hidden Gems and Objective 10 (AOSentry pkg/ Promotion).

Pairs with [`platform/apierror`](../apierror/README.md): `WriteError`
takes an `*apierror.APIError` and renders the OpenAI-shaped envelope
with the right status code in one call.

## Surface

### Response

| Function | What it does |
|---|---|
| `WriteJSON(w, status, data)` | `Content-Type: application/json`, `WriteHeader(status)`, JSON body. `nil` data means body-less response (for 204). |
| `WriteError(w, *apierror.APIError)` | Writes status from `err.StatusCode`, body shape `{"error": {...}}`. |
| `WriteSSEEvent(w, event, data)` | Writes a single `data: <bytes>\n\n` SSE line and flushes. |
| `WriteSSEDone(w)` | Writes the OpenAI stream terminator `data: [DONE]\n\n`. |

### Request

| Function | What it does |
|---|---|
| `DecodeJSON(r, dst)` | Reads body (capped at `MaxBodySize` = 100 MiB), unmarshals into `dst`. Returns `*apierror.ValidationError` on failure ready to hand to `WriteError`. |
| `ReadBody(r)` | Same body cap, returns raw bytes. Use when shape is opaque (SSE proxy). |
| `GetClientIP(r)` | `X-Forwarded-For` → `X-Real-IP` → `r.RemoteAddr`. Trust headers only when you control the upstream proxy. |

### Pagination

| Function | What it does |
|---|---|
| `ParsePagination(r)` | Reads `?limit=&offset=`. Clamps: `limit ≤ 0 → DefaultLimit`, `limit > MaxLimit → MaxLimit`, `offset < 0 → 0`. |
| `ParsePage(r)` | Reads `?page=&page_size=` (1-indexed page). Same clamping. |

`Pagination` returns `int32` to align with sqlc-generated query parameter
types so the value can be passed straight into a generated query.

## Quickstart

```go
import (
    "go.aocyber.ai/eden-platform-go/platform/apierror"
    "go.aocyber.ai/eden-platform-go/platform/httputil"
)

func (h *Handler) Create(w http.ResponseWriter, r *http.Request) {
    var body CreateRequest
    if apiErr := httputil.DecodeJSON(r, &body); apiErr != nil {
        httputil.WriteError(w, apiErr)
        return
    }
    obj, err := h.svc.Create(r.Context(), body)
    if err != nil {
        httputil.WriteError(w, apierror.InternalError(err.Error()))
        return
    }
    httputil.WriteJSON(w, http.StatusCreated, obj)
}
```

## Stability

Beta. The function set and signatures are stable; `MaxBodySize` is exported
so callers can switch to a different limit via `http.MaxBytesReader`
directly when they outgrow the default.
