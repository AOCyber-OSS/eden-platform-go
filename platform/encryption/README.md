# platform/encryption

AES-256-GCM field-level encryption with HMAC-SHA256 blind indexing — the
canonical implementation across the Eden portfolio. Beta (production-grade).

## What this package provides

- **AES-256-GCM** — `Encrypt(plaintext) []byte`, `Decrypt(ciphertext) []byte`.
  Random nonce per call; tamper-detection via the GCM authentication tag.
- **String envelopes** — `EncryptString` (base64 wrapper) and `EncryptStringV1`
  (versioned `v1:` prefix). `DecryptString` accepts both forms.
- **HMAC blind index** — `BlindIndex(s)` for case-sensitive lookups,
  `BlindIndexLower(s)` for case-insensitive (emails, usernames).
- **Key loaders** — `GenerateKey`, `KeyFromHex`, `KeyFromBase64`, `KeyFromEnv`.

## Quickstart

```go
import "go.aocyber.ai/eden-platform-go/platform/encryption"

encKey, err := encryption.KeyFromEnv("ENC_KEY")
if err != nil { return err }
indexKey, err := encryption.KeyFromEnv("BLIND_INDEX_KEY")
if err != nil { return err }

enc, err := encryption.New(encKey, indexKey)
if err != nil { return err }

// Field-level
ct, _ := enc.EncryptStringV1("user@example.com")
pt, _ := enc.DecryptString(ct)

// Searchable lookup
idx := enc.BlindIndexLower("user@example.com")
// store `ct` and `idx` side-by-side; query by idx
```

## Key formats

`KeyFromEnv` accepts either:

- **Hex** — exactly 64 hex characters (`[0-9a-fA-F]`), case-insensitive.
- **Base64** — std, URL-safe, with or without padding.

Both encode 32 bytes (AES-256). `KeyFromHex` and `KeyFromBase64` are exported
for callers that already know which format they have.

Example (generate fresh keys for an environment):

```bash
openssl rand -hex 32   # → ENC_KEY=...
openssl rand -hex 32   # → BLIND_INDEX_KEY=...
```

## Versioned envelope (`v1:` prefix)

`EncryptStringV1` adds a `v1:` prefix to the base64 output. `DecryptString`
accepts both prefixed and unprefixed forms transparently. Future key rotations
or algorithm bumps can introduce `v2:` without breaking existing data.

**Migration:** existing AES-GCM payloads continue to decrypt unchanged. Move
new writes to `EncryptStringV1` at any point; reads use `DecryptString`.

## Blind index — case-insensitive

`BlindIndexLower("Test@Example.com")` lower-cases the input before hashing so
inserts and lookups using the same canonicalization match. **Always pick one
side and stick with it** — mixing `BlindIndex` and `BlindIndexLower` for the
same column produces non-matching indexes.

## What this package does NOT do

- **Key management / rotation** — call sites own key sourcing.
- **Database integration** — hand the ciphertext bytes (or string envelope)
  to your storage layer; nothing in this package touches a DB.
- **Streaming** — values must fit in memory. The `Encrypt`/`Decrypt` shape is
  intentionally batch-shaped for field-level use.

## Stability

This package is **beta (production-grade)**. All exports are stable. New
helpers are added non-breakingly.
