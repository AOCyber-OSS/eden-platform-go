# platform/webfetch

Hardened outbound HTTP client with safe-by-default SSRF / size / redirect
controls. Beta.

## Donor

`aosentry/internal/webfetch` (URLValidator + Fetcher). The Bright Data
integration is consumer-specific and stays in AOSentry; the platform
package promotes only the **safe-by-default outbound HTTP** primitive.

## Use this everywhere a product fetches user-supplied URLs.

That includes: web search snippets, link previews, OAuth discovery doc
fetches, webhook delivery (consumers that don't want full retry semantics —
otherwise see `platform/webhook`), document import, AI tool calls.

## Quickstart

```go
import "go.aocyber.ai/eden-platform-go/platform/webfetch"

c, _ := webfetch.NewClient(webfetch.SafeDefault())

res, err := c.Fetch(ctx, userSuppliedURL)
if err != nil {
    // ErrPolicyViolation -> SSRF / scheme / size attempt
    // ErrTooManyRedirects -> exceeded redirect cap
    return err
}
fmt.Println(res.StatusCode, res.ContentType, res.Truncated)
```

## Safe defaults

| Control | Default |
| --- | --- |
| Allowed schemes | `http`, `https` |
| Private IPs | denied (RFC 1918, link-local, loopback, multicast, unspecified) |
| `localhost` / `metadata.google.internal` / 169.254.169.254 | denied (cloud IMDS) |
| Max response bytes | 10 MB |
| Max redirects | 5 |
| Redirect schemes | `http`, `https` only |
| Connect timeout | 10s |
| Read timeout | 60s |
| User-Agent | `aocyber-webfetch/1.0` |

## Overrides for trusted use cases

```go
p := webfetch.SafeDefault()
p.MaxResponseBytes = 50 * 1024 * 1024     // accept bigger documents
p.MaxRedirects     = 10
p.UserAgent        = "myapp/1.0"
p.AdditionalHeaders = map[string]string{"X-Tenant": tenantID}

// Allow specific internal hostnames for an integration test loop:
p.AllowHostsRegexp = []string{`^trusted-internal\.example\.com$`}

// Add additional deny patterns:
p.DenyHostsRegexp = []string{`\.internal$`, `\.cluster\.local$`}

c, _ := webfetch.NewClient(p)
```

## Security review notes

- **AllowHostsRegexp short-circuits everything.** When a host matches the
  allow pattern, all other policy checks (private IP, deny patterns) are
  skipped. Only use AllowHosts for explicit integration tests or trusted
  internal services.
- **Hostname resolution is part of policy enforcement.** `denyPrivateIP`
  resolves the hostname and rejects any IP in a private range. This means
  an attacker can't just send `http://attacker-controlled.example.com`
  with a DNS A-record pointing to 169.254.169.254 — the resolved IP is
  checked.
- **Redirect-time policy is re-evaluated.** Each redirect re-checks
  scheme + host. A 200 → 301 → file:// chain is blocked at hop 2, not at
  hop 1.
- **Truncated responses are flagged but not errored.** Callers see
  `res.Truncated == true`. If your context wants strict denial, wrap the
  call and convert to `ErrResponseTooLarge`.

## Migration

AOSentry's `internal/webfetch.URLValidator` and `Fetcher` retire in their
own consumer-side PR (out of scope for this objective).
