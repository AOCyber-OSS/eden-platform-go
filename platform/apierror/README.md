# platform/apierror

Typed HTTP API error structures shaped to match the OpenAI error wire
format. Promoted from `aosentry/pkg/apierror` per the portfolio
standardization plan §3 Hidden Gems and Objective 10 (AOSentry pkg/
Promotion).

## Wire format

```json
{
  "error": {
    "message": "Invalid API key",
    "type": "authentication_error",
    "code": "invalid_api_key"
  }
}
```

`code` is `omitempty`. The HTTP status code lives on the Go struct
(`*APIError.StatusCode`) and is **not** rendered into the JSON body —
pair with `platform/httputil.WriteError` to write status code and body
in one call.

## Constructors

| Constructor | HTTP | type | code |
|---|---|---|---|
| `AuthenticationError` | 401 | `authentication_error` | `invalid_api_key` |
| `BudgetExceeded` | 402 | `budget_exceeded` | `budget_exceeded` |
| `Forbidden` | 403 | `permission_error` | `forbidden` |
| `NotFound` | 404 | `not_found` | `not_found` |
| `Conflict` | 409 | `conflict` | `conflict` |
| `ValidationError` | 400 | `invalid_request_error` | `invalid_request` |
| `GuardrailBlocked` | 400 | `guardrail_blocked` | `content_policy_violation` |
| `RateLimitExceeded` | 429 | `rate_limit_exceeded` | `rate_limit_exceeded` |
| `InternalError` | 500 | `internal_error` | `internal_error` |
| `ProviderError(msg, status)` | caller-supplied | `provider_error` | `provider_error` |

`ProviderError` propagates the upstream status code unchanged so a 503
from an LLM provider stays a 503 to the caller.

## Quickstart

```go
import (
    "go.aocyber.ai/eden-platform-go/platform/apierror"
    "go.aocyber.ai/eden-platform-go/platform/httputil"
)

func (h *Handler) GetThing(w http.ResponseWriter, r *http.Request) {
    thing, err := h.svc.Get(r.Context(), id)
    if errors.Is(err, ErrMissing) {
        httputil.WriteError(w, apierror.NotFound("thing not found"))
        return
    }
    if err != nil {
        httputil.WriteError(w, apierror.InternalError(err.Error()))
        return
    }
    httputil.WriteJSON(w, http.StatusOK, thing)
}
```

## Stability

Beta. The constructor list and wire shape are stable; new
constructors are additive.
