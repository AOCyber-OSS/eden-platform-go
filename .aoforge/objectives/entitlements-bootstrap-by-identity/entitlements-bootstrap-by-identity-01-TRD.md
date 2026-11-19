---
objective: entitlements-bootstrap-by-identity
trd: 01
type: tdd
wave: 1
depends_on: []
files_modified:
  - platform/entitlements/client.go
  - platform/entitlements/client_by_identity_test.go
autonomous: true
requirements: [C1-01, C1-02]
must_haves:
  truths:
    - "BootstrapByIdentity emits GET /api/v1/entitlements/bootstrap?aoid_subject=<subject> with Authorization: Bearer <serviceToken>"
    - "X-AOID-Email header is present with the email value only when email != \"\", and ABSENT when email == \"\""
    - "BootstrapResponse is parsed from the biz-shaped JSON body"
    - "Repeated calls for the same subject hit the server exactly once (subject-keyed cache); distinct subjects never share cached entries; the by-identity cache is distinct from the companyID bootstrapCache"
    - "Non-2xx status returns an error (no cache write); InvalidateIdentity(subject) evicts so the next call re-fetches"
    - "CanUseFeatureByIdentity returns the matching entry's Allowed, and false (deny-by-default) for an unknown feature"
    - "Existing Bootstrap / CanUseFeature behavior is byte-behavior-identical (companyID path unchanged)"
  artifacts:
    - platform/entitlements/client.go
    - platform/entitlements/client_by_identity_test.go
  key_links:
    - "BootstrapByIdentity reuses setAuth for the Bearer token and adds X-AOID-Email via a header-carrying GET path"
    - "bootstrapByIdentityCache is a NEW *Cache[string, *BootstrapResponse] keyed by subject, separate from bootstrapCache"
    - "CanUseFeatureByIdentity delegates to BootstrapByIdentity (same deny-by-default loop as CanUseFeature)"
---

<objective>
Add the by-AOID-identity client methods to `EntitlementClient` so A1 (aodex) can resolve a SaaS buyer's entitlements from their AOID **subject** (+ `X-AOID-Email` for first-call self-heal) against the biz B1/#418 + B2/#420 endpoint, instead of by `company_id`.

Purpose: Client half of the entitlements-by-identity arc (#412 company → #418 subject → #420 self-heal → **C1 client** → A1 aodex). This TRD covers the client layer only (`client.go`).
Output: `BootstrapByIdentity`, `CanUseFeatureByIdentity`, `InvalidateIdentity`, a subject-keyed cache, and a header-carrying GET path — all TDD, all mirroring the existing companyID methods without altering them.
</objective>

<file_tree>
platform/entitlements/
├── client.go                      ← MODIFY (add by-identity methods + cache + header GET)
├── client_by_identity_test.go     ← CREATE (httptest contract tests + hand-built fixtures)
├── middleware.go                  (untouched here — TRD 02)
├── models.go                      (unchanged — reuse BootstrapResponse/EntitlementEntry)
└── cache.go                       (unchanged — reuse NewCache/Get/Set/Invalidate)
</file_tree>

<execution_context>
@~/.claude/devflow/workflows/execute-trd.md
@~/.claude/devflow/templates/summary.md
</execution_context>

<embedded_context>

<codebase_examples>
Mirror the existing companyID `Bootstrap` exactly — same cache-first, doGet, json.Unmarshal, cache-set shape (client.go:63-81):

```go
func (c *EntitlementClient) Bootstrap(ctx context.Context, companyID string) (*BootstrapResponse, error) {
	if resp, ok := c.bootstrapCache.Get(companyID); ok {
		return resp, nil
	}
	u := c.baseURL + "/api/v1/entitlements/bootstrap?company_id=" + url.QueryEscape(companyID)
	resp, err := c.doGet(ctx, u)
	if err != nil {
		return nil, fmt.Errorf("entitlements bootstrap: %w", err)
	}
	var result BootstrapResponse
	if err := json.Unmarshal(resp, &result); err != nil {
		return nil, fmt.Errorf("entitlements bootstrap: parse: %w", err)
	}
	c.bootstrapCache.Set(companyID, &result)
	return &result, nil
}
```

Existing `doGet` sets auth only (client.go:168-191). The by-identity path needs an extra header, so extend with a header-carrying sibling. Keep `doGet` and `setAuth` reuse:

```go
func (c *EntitlementClient) doGet(ctx context.Context, rawURL string) ([]byte, error) {
	req, err := http.NewRequestWithContext(ctx, "GET", rawURL, nil)
	// ...
	c.setAuth(req)   // Authorization: Bearer <serviceToken>
	// ... read body, LimitReader 1<<20, status>=300 -> error ...
}
```

Deny-by-default loop to mirror (client.go:108-122):
```go
for _, e := range bootstrap.Entitlements {
	if e.FeatureKey == featureKey {
		return e.Allowed, nil
	}
}
return false, nil // not in plan -> deny by default
```

Cache construction pattern (client.go:57-58, cache.go): `NewCache[string, *BootstrapResponse](c.cacheTTL)`, with `.Get(k) (V, bool)`, `.Set(k, v)`, `.Invalidate(k)`.

InvalidateCompany pattern to mirror (client.go:161-166): `c.bootstrapCache.Invalidate(companyID)`.
</codebase_examples>

<anti_patterns>
- DO NOT modify `doGet`'s existing signature call sites so that the companyID `Bootstrap` behavior changes. If you extend `doGet`, keep an overload/sibling so the existing call `c.doGet(ctx, u)` remains byte-identical, OR add a `doGetWithHeaders(ctx, url, headers)` and leave `doGet` untouched (preferred — smallest blast radius).
- DO NOT reuse `bootstrapCache` for subjects — a subject string could collide with a companyID string. Use a NEW `bootstrapByIdentityCache`.
- DO NOT set `X-AOID-Email` to an empty string when email == "" — the header must be entirely ABSENT (biz #420 distinguishes "no email provided" from "empty email").
- DO NOT use LLM-generated JSON blobs as test fixtures. Use the hand-built `newBootstrapResponse(...)` factory (constraint: no_llm_test_data).
- DO NOT add any external test dependency — stdlib `net/http/httptest` only (no testify, no gopter/rapid).
</anti_patterns>

<error_recovery>
- If `-race` flags a data race on the cache: the shared `Cache` is already mutex-guarded (cache.go). A race almost certainly means you introduced an unguarded field on `EntitlementClient` — revert to using `*Cache` only.
- If a repeated-subject test sees >1 server hit: the cache Set/Get key is wrong (using email or a composite key instead of bare subject), or you wrote to the wrong cache. Assert the key is exactly `subject`.
- If `X-AOID-Email` shows up when email=="": you unconditionally called `req.Header.Set`. Guard with `if email != ""`.
</error_recovery>

</embedded_context>

<context>
@.planning/PROJECT.md
@.planning/objectives/entitlements-bootstrap-by-identity/OBJECTIVE.md
@platform/entitlements/client.go
@platform/entitlements/models.go
@platform/entitlements/cache.go

User CLAUDE.md TDD Playbook applies: test-list-first, one test at a time (RED→GREEN→REFACTOR), hand-built fixture generators (no LLM test data), outside-in. This TRD is the INNER (client) layer of the outside-in stack — TRD 02 (middleware) is the outer HTTP layer and depends on the methods created here.
</context>

## Test list (write these RED, one at a time, before implementation)

C1-01 — `BootstrapByIdentity` wire contract + parse + cache:
- [ ] emits method GET, path `/api/v1/entitlements/bootstrap`, query `aoid_subject=<subject>` (URL-escaped)
- [ ] emits `Authorization: Bearer <serviceToken>` (client built `WithServiceToken`)
- [ ] emits `X-AOID-Email: <email>` header when email is set
- [ ] does NOT emit `X-AOID-Email` at all when email == "" (server asserts header absent)
- [ ] parses a biz-shaped `BootstrapResponse` (Entitlements populated) from the 200 body
- [ ] subject-keyed cache: 3 sequential calls for the same subject → server handler invoked exactly once
- [ ] subject isolation: calls for subject "sub-a" and "sub-b" return their own distinct responses (2 server hits, no cross-bleed)
- [ ] by-identity cache is distinct from companyID cache: a `Bootstrap(companyID)` call and a `BootstrapByIdentity(subject)` call where companyID==subject string do NOT share a cached entry (both hit the server)
- [ ] non-2xx (401) → returns error, nothing cached (next call re-hits server)
- [ ] `InvalidateIdentity(subject)` evicts → subsequent call re-fetches (server hit count increments)

C1-02 — `CanUseFeatureByIdentity` deny-by-default:
- [ ] known feature with Allowed=true → returns (true, nil)
- [ ] known feature with Allowed=false → returns (false, nil)
- [ ] unknown feature (not in Entitlements) → returns (false, nil) deny-by-default
- [ ] BootstrapByIdentity error (server 500) → returns (false, err)

Regression guard:
- [ ] existing `Bootstrap(companyID)` still emits `?company_id=` and caches by companyID (unchanged) — a short assertion confirming the companyID path is untouched by the doGet refactor

<tasks>

<task type="auto">
  <name>Task 1: Hand-built fixtures + asserting httptest harness</name>
  <files>platform/entitlements/client_by_identity_test.go</files>
  <action>
Create the test file with the shared, hand-built (NOT LLM-generated) test support — this is the fixture-generator task, ahead of any behavior test (fixture_strategy=generators, constraint no_llm_test_data).

Add:
1. `newBootstrapResponse(entries ...EntitlementEntry) *BootstrapResponse` — factory returning a BootstrapResponse with the given Entitlements (and a minimal Subscription/Plan). No literal JSON blobs.
2. `entitled(featureKey string, allowed bool) EntitlementEntry` — small entry factory.
3. `newAssertingServer(t *testing.T, want requestExpectations) (*httptest.Server, *int32)` — an `httptest.NewServer` whose handler:
   - asserts `r.Method == GET`, `r.URL.Path == "/api/v1/entitlements/bootstrap"`, `r.URL.Query().Get("aoid_subject")` equals the expected subject
   - asserts `r.Header.Get("Authorization") == "Bearer <token>"`
   - asserts `X-AOID-Email` present==want.emailPresent (use `_, ok := r.Header["X-Aoid-Email"]` for the absent case — canonical MIME key)
   - increments an atomic hit counter (returned so tests can assert hit counts)
   - writes `json.NewEncoder(w).Encode(<a *BootstrapResponse fixture>)`
4. `newTestClient(t, serverURL string) *EntitlementClient` — `NewClient(serverURL, WithServiceToken("svc-token"), WithHTTPClient(server.Client()))`.

Keep the harness generic enough to serve every C1-01/C1-02 case in Tasks 2-3. Do not implement production methods yet.
  </action>
  <verify>`go build ./platform/entitlements/` compiles; `go vet ./platform/entitlements/` clean. (Test file compiles against existing exported symbols only.)</verify>
  <done>client_by_identity_test.go exists with the fixture factories + asserting httptest harness; package builds; no production code added yet.</done>
  <recovery>If the file references not-yet-existing methods and won't compile, comment out the harness's call to those methods until Task 2 — but keep the fixtures/server compiling.</recovery>
</task>

<task type="auto" tdd="true">
  <name>Task 2: BootstrapByIdentity + subject cache + InvalidateIdentity + header GET (C1-01)</name>
  <files>platform/entitlements/client.go, platform/entitlements/client_by_identity_test.go</files>
  <action>
RED → GREEN, one behavior at a time, for the full C1-01 test list above.

RED: write the failing contract tests (wire method/path/query, Bearer, X-AOID-Email present-when-set and ABSENT-when-empty, parse, subject-cache single-hit, subject isolation, distinct-from-companyID-cache, 401→error, InvalidateIdentity re-fetch).

GREEN: implement in client.go:

Approach:
1. Add field `bootstrapByIdentityCache *Cache[string, *BootstrapResponse]` to EntitlementClient; initialize it in NewClient next to bootstrapCache: `c.bootstrapByIdentityCache = NewCache[string, *BootstrapResponse](c.cacheTTL)`.
2. Add a header-carrying GET WITHOUT touching existing doGet call sites. Preferred: new sibling
   `func (c *EntitlementClient) doGetWithHeaders(ctx, rawURL string, headers map[string]string) ([]byte, error)` — identical body to doGet (setAuth reuse, LimitReader 1<<20, status>=300→error) plus `for k,v := range headers { req.Header.Set(k,v) }` before Do. Leave doGet byte-identical.
3. Implement BootstrapByIdentity:
   # cache-first on bare subject key
   if resp, ok := c.bootstrapByIdentityCache.Get(subject); ok { return resp, nil }
   u := c.baseURL + "/api/v1/entitlements/bootstrap?aoid_subject=" + url.QueryEscape(subject)
   headers := map[string]string{}
   # GOTCHA: header ABSENT when email=="" — only set inside the guard
   if email != "" { headers["X-AOID-Email"] = email }
   resp, err := c.doGetWithHeaders(ctx, u, headers)  // Bearer via setAuth inside
   ... json.Unmarshal into BootstrapResponse, wrap errors "entitlements bootstrap by identity: ..." ...
   c.bootstrapByIdentityCache.Set(subject, &result)
   return &result, nil
4. Implement InvalidateIdentity(subject string) { c.bootstrapByIdentityCache.Invalidate(subject) }

# CRITICAL: subject cache MUST be separate from bootstrapCache (key collision risk).
# CRITICAL: existing Bootstrap/doGet must remain byte-behavior-identical.
  </action>
  <verify>`go test ./platform/entitlements/ -race -count=1 -v -run 'ByIdentity|Bootstrap'` — all C1-01 tests PASS, SKIP==0. Confirm the repeated-subject test asserts exactly 1 server hit and InvalidateIdentity forces a 2nd.</verify>
  <done>BootstrapByIdentity, InvalidateIdentity, doGetWithHeaders, and bootstrapByIdentityCache exist; every C1-01 test passes under -race; companyID Bootstrap regression assertion passes.</done>
  <recovery>If refactoring doGet broke the companyID path, revert doGet and add doGetWithHeaders as a pure sibling instead of extending in place.</recovery>
</task>

<task type="auto" tdd="true">
  <name>Task 3: CanUseFeatureByIdentity deny-by-default (C1-02)</name>
  <files>platform/entitlements/client.go, platform/entitlements/client_by_identity_test.go</files>
  <action>
RED → GREEN for the C1-02 test list (allowed=true→true, allowed=false→false, unknown feature→false deny-by-default, bootstrap error→(false, err)).

GREEN: implement, mirroring CanUseFeature exactly:
```go
func (c *EntitlementClient) CanUseFeatureByIdentity(ctx context.Context, subject, email, featureKey string) (bool, error) {
	bootstrap, err := c.BootstrapByIdentity(ctx, subject, email)
	if err != nil {
		return false, err
	}
	for _, e := range bootstrap.Entitlements {
		if e.FeatureKey == featureKey {
			return e.Allowed, nil
		}
	}
	return false, nil // deny by default
}
```
Reuse Task 1 fixtures (`newBootstrapResponse(entitled("feat.x", true), ...)`).
  </action>
  <verify>`go test ./platform/entitlements/ -race -count=1 -v` — full package PASS, SKIP==0, real PASS count printed (not a bare "ok"). `go vet ./platform/entitlements/` clean.</verify>
  <done>CanUseFeatureByIdentity exists with deny-by-default; all C1-02 tests pass under -race; whole package green.</done>
  <recovery>If deny-by-default returns an error instead of (false,nil) for unknown feature, remove the extra error branch — mirror CanUseFeature's silent fall-through.</recovery>
</task>

</tasks>

<validation_gates>
<test>go test ./platform/entitlements/ -race -count=1 -v</test>
<lint>go vet ./platform/entitlements/</lint>
<build>go build ./platform/entitlements/</build>
</validation_gates>

<verification>
- `go test ./platform/entitlements/ -race -count=1 -v` reports real PASS counts, SKIP==0, never a bare "ok".
- Wire contract asserted by httptest: GET, path `/api/v1/entitlements/bootstrap`, `?aoid_subject=`, `Authorization: Bearer`, `X-AOID-Email` present-when-set / absent-when-empty.
- Subject-keyed cache proven (3 calls → 1 hit), distinct from companyID cache, InvalidateIdentity re-fetches.
- Deny-by-default proven for unknown feature.
- Existing Bootstrap/CanUseFeature untouched (regression assertion + no diff to their bodies).
- No new external deps; stdlib httptest only.

Atomic commits: `test:` (RED tests + fixtures) → `feat:` (BootstrapByIdentity/CanUseFeatureByIdentity/InvalidateIdentity) → optional `refactor:` (doGetWithHeaders extraction).
</verification>

<success_criteria>
- BootstrapByIdentity, CanUseFeatureByIdentity, InvalidateIdentity, doGetWithHeaders, bootstrapByIdentityCache all present in client.go.
- Every C1-01 and C1-02 test passes under -race with SKIP==0.
- companyID methods byte-behavior-identical.
- Package builds, `go vet` clean, no new deps.
</success_criteria>

<output>
After completion, create `.planning/objectives/entitlements-bootstrap-by-identity/entitlements-bootstrap-by-identity-01-SUMMARY.md`
</output>
