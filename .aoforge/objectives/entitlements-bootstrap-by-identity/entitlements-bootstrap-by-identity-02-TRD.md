---
objective: entitlements-bootstrap-by-identity
trd: 02
type: tdd
wave: 2
depends_on: [entitlements-bootstrap-by-identity-01]
files_modified:
  - platform/entitlements/middleware.go
  - platform/entitlements/middleware_by_identity_test.go
autonomous: true
requirements: [C1-03, C1-04]
must_haves:
  truths:
    - "InjectEntitlementsByIdentity is FAIL-OPEN: empty subject → pass through (no context injection); BootstrapByIdentity error → slog.Warn + pass through; success → inject into bootstrapContextKey so EntitlementsFromContext returns it"
    - "RequireEntitlementByIdentity is FAIL-CLOSED: empty subject → 401; CanUseFeatureByIdentity error → 403; not allowed → 403; allowed → next handler runs (200)"
    - "Both middlewares inject/read the SAME bootstrapContextKey used by the companyID variants, so EntitlementsFromContext works unchanged"
    - "subject and email are pulled from request context via caller-supplied extractor funcs (subjectFromCtx, emailFromCtx)"
    - "Existing InjectEntitlements / RequireEntitlement behavior is byte-behavior-identical"
  artifacts:
    - platform/entitlements/middleware.go
    - platform/entitlements/middleware_by_identity_test.go
  key_links:
    - "InjectEntitlementsByIdentity → client.BootstrapByIdentity(ctx, subject, email) → context.WithValue(bootstrapContextKey, bootstrap)"
    - "RequireEntitlementByIdentity → client.CanUseFeatureByIdentity(ctx, subject, email, featureKey) → writeErr(401/403) or next.ServeHTTP"
    - "emailFromCtx(ctx) supplies X-AOID-Email so the middleware carries first-call self-heal into the client"
---

<objective>
Add the by-AOID-identity HTTP middlewares to `middleware.go` so services (A1/aodex) can gate features by AOID **subject** instead of `company_id`, reusing the client methods from TRD 01. This is the OUTERMOST (HTTP boundary) layer of the outside-in stack.

Purpose: Complete the client half of the entitlements-by-identity arc with drop-in middleware mirroring `InjectEntitlements` (fail-open) and `RequireEntitlement` (fail-closed).
Output: `InjectEntitlementsByIdentity`, `RequireEntitlementByIdentity` — both TDD via httptest, both mirroring their companyID twins exactly and reusing the same `bootstrapContextKey`.
</objective>

<file_tree>
platform/entitlements/
├── middleware.go                      ← MODIFY (add two by-identity middlewares)
├── middleware_by_identity_test.go     ← CREATE (httptest handler-chain tests)
├── client.go                          (from TRD 01 — provides BootstrapByIdentity/CanUseFeatureByIdentity)
└── models.go                          (unchanged)
</file_tree>

<execution_context>
@~/.claude/devflow/workflows/execute-trd.md
@~/.claude/devflow/templates/summary.md
</execution_context>

<embedded_context>

<codebase_examples>
Mirror `InjectEntitlements` EXACTLY (middleware.go:84-104) — same fail-open shape:
```go
func InjectEntitlements(client *EntitlementClient, companyIDFromCtx func(context.Context) string) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			companyID := companyIDFromCtx(r.Context())
			if companyID == "" { next.ServeHTTP(w, r); return }           // empty -> pass
			bootstrap, err := client.Bootstrap(r.Context(), companyID)
			if err != nil {                                                // err -> warn + pass
				slog.Warn("[Entitlements] bootstrap prefetch failed", "company_id", companyID, "error", err)
				next.ServeHTTP(w, r); return
			}
			ctx := context.WithValue(r.Context(), bootstrapContextKey, bootstrap)  // success -> inject
			next.ServeHTTP(w, r.WithContext(ctx))
		})
	}
}
```

Mirror `RequireEntitlement` EXACTLY (middleware.go:19-47) — same fail-closed shape:
```go
companyID := companyIDFromCtx(r.Context())
if companyID == "" { writeErr(w, http.StatusUnauthorized, "missing company context"); return }   // 401
allowed, err := client.CanUseFeature(r.Context(), companyID, featureKey)
if err != nil { slog.Warn(...); writeErr(w, http.StatusForbidden, "feature not available"); return }  // 403
if !allowed { writeErr(w, http.StatusForbidden, "feature '"+featureKey+"' is not included in your plan"); return }  // 403
next.ServeHTTP(w, r)  // allowed
```

`bootstrapContextKey` and `EntitlementsFromContext` (middleware.go:12, 109-112) — reuse the SAME key; `writeErr` (middleware.go:114-118) — reuse for 401/403.
</codebase_examples>

<anti_patterns>
- DO NOT introduce a new context key. Inject into the SAME `bootstrapContextKey` so `EntitlementsFromContext` is unchanged for downstream handlers.
- DO NOT make the Require variant fail-open, or the Inject variant fail-closed — they are opposite by design (Inject=fail-open prefetch, Require=fail-closed gate).
- DO NOT change `InjectEntitlements` / `RequireEntitlement` bodies. Add new functions beside them.
- DO NOT hard-code X-AOID-Email extraction inside the middleware — take `emailFromCtx func(context.Context) string` so the caller (aodex) supplies it, exactly as `companyIDFromCtx` is supplied today.
- Stdlib `net/http/httptest` only — no test framework deps.
</anti_patterns>

<error_recovery>
- If the fail-open server-500 test sees a non-200 status: the Inject variant is treating a Bootstrap error as a gate (returning early with an error status) instead of warn+pass. Copy InjectEntitlements' error branch verbatim.
- If the empty-subject Require test returns 403 instead of 401: you checked entitlement before the empty guard — the empty-subject 401 branch must come first, before any client call.
- If EntitlementsFromContext is nil after a successful inject: you injected under a different key. Use `bootstrapContextKey`.
</error_recovery>

</embedded_context>

<context>
@.planning/PROJECT.md
@.planning/objectives/entitlements-bootstrap-by-identity/OBJECTIVE.md
@platform/entitlements/middleware.go
@platform/entitlements/client.go

Depends on TRD 01 (BootstrapByIdentity / CanUseFeatureByIdentity must exist to compile). Outside-in ordering: this HTTP-boundary middleware is the outermost user-observable layer; tests drive a real handler chain (httptest server as biz backend + real EntitlementClient). One test at a time, RED→GREEN. Fixtures hand-built (no LLM test data).
</context>

## Test list (write these RED, one at a time, before implementation)

C1-03 — `InjectEntitlementsByIdentity` fail-open:
- [ ] success path: extractor returns subject → middleware calls client → BootstrapByIdentity 200 → downstream handler reads `EntitlementsFromContext(r.Context())` and it is non-nil with the expected Entitlements; response 200
- [ ] empty subject: subjectFromCtx returns "" → next handler runs, `EntitlementsFromContext` is nil, response 200 (pass-through, no server call)
- [ ] error path (server 500): BootstrapByIdentity errors → next handler runs (fail-open), `EntitlementsFromContext` is nil, response 200
- [ ] email carried: when emailFromCtx returns an email, the biz server receives `X-AOID-Email` (assert on the httptest handler)

C1-04 — `RequireEntitlementByIdentity` fail-closed:
- [ ] allowed: subject present + feature Allowed=true → next handler runs, response 200
- [ ] not allowed: feature Allowed=false (or absent → deny-by-default) → response 403, next NOT called
- [ ] empty subject: subjectFromCtx returns "" → response 401, no client call, next NOT called
- [ ] server error: BootstrapByIdentity/CanUseFeatureByIdentity errors (server 500) → response 403, next NOT called

Regression guard:
- [ ] existing InjectEntitlements + RequireEntitlement still pass their own behavior (companyID path) — confirm no diff to their bodies

<tasks>

<task type="auto">
  <name>Task 1: httptest handler-chain harness + context extractors + fixtures</name>
  <files>platform/entitlements/middleware_by_identity_test.go</files>
  <action>
Create the middleware test file with hand-built support (fixture-generator task; no LLM test data):
1. `ctxWith(subject, email string) func(context.Context) string` helpers — or a small pair `staticSubject(s)` / `staticEmail(e)` returning extractor funcs; plus an `emptyExtractor` returning "".
2. `newBizServer(t, opts) *httptest.Server` — an httptest server standing in for eden-biz that returns a hand-built BootstrapResponse (reuse the `newBootstrapResponse`/`entitled` idea; if sharing across files in-package, define package-level test helpers once — check TRD 01's client_by_identity_test.go and avoid redeclaring; if already defined there, reuse them, since both test files are in package `entitlements`).
3. A `spyHandler` recording whether `next` was invoked, and (for Inject tests) capturing `EntitlementsFromContext(r.Context())`.
4. Client built with `NewClient(bizServer.URL, WithServiceToken("svc-token"), WithHTTPClient(bizServer.Client()))`.

NOTE (in-package helper collision): client_by_identity_test.go (TRD 01) already defines `newBootstrapResponse`/`entitled`/`newTestClient` in package `entitlements`. REUSE them here — do NOT redeclare. Only add middleware-specific helpers (extractors, spyHandler, biz server variants that toggle 200/500).

Do not implement production middleware yet.
  </action>
  <verify>`go build ./platform/entitlements/` and `go vet ./platform/entitlements/` clean; no duplicate-symbol errors with client_by_identity_test.go.</verify>
  <done>middleware_by_identity_test.go compiles, reuses TRD 01's in-package fixtures without redeclaration, provides extractors + spyHandler + toggleable biz server.</done>
  <recovery>If duplicate-declaration errors appear, delete the redeclared helper here and import from the existing test file (same package — just reference the symbol).</recovery>
</task>

<task type="auto" tdd="true">
  <name>Task 2: InjectEntitlementsByIdentity fail-open (C1-03)</name>
  <files>platform/entitlements/middleware.go, platform/entitlements/middleware_by_identity_test.go</files>
  <action>
RED → GREEN for the full C1-03 test list (success injects into bootstrapContextKey; empty subject passes; server-500 warn+passes; X-AOID-Email carried to biz server).

GREEN: implement mirroring InjectEntitlements exactly, swapping companyID→subject and adding email:
```go
func InjectEntitlementsByIdentity(client *EntitlementClient, subjectFromCtx, emailFromCtx func(context.Context) string) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			subject := subjectFromCtx(r.Context())
			if subject == "" { next.ServeHTTP(w, r); return }              // fail-open: empty -> pass
			email := emailFromCtx(r.Context())
			bootstrap, err := client.BootstrapByIdentity(r.Context(), subject, email)
			if err != nil {                                                // fail-open: err -> warn + pass
				slog.Warn("[Entitlements] bootstrap-by-identity prefetch failed", "subject", subject, "error", err)
				next.ServeHTTP(w, r); return
			}
			ctx := context.WithValue(r.Context(), bootstrapContextKey, bootstrap)   // SAME key
			next.ServeHTTP(w, r.WithContext(ctx))
		})
	}
}
```
# CRITICAL: inject into bootstrapContextKey (not a new key) so EntitlementsFromContext works.
  </action>
  <verify>`go test ./platform/entitlements/ -race -count=1 -v -run 'InjectEntitlementsByIdentity'` — all C1-03 tests PASS, SKIP==0. Confirm success case asserts EntitlementsFromContext non-nil and error case asserts nil + 200.</verify>
  <done>InjectEntitlementsByIdentity exists, fail-open, injects into bootstrapContextKey; all C1-03 tests pass under -race.</done>
  <recovery>If success case leaves context nil, verify context.WithValue result is passed via r.WithContext(ctx) to next (not the original r).</recovery>
</task>

<task type="auto" tdd="true">
  <name>Task 3: RequireEntitlementByIdentity fail-closed (C1-04)</name>
  <files>platform/entitlements/middleware.go, platform/entitlements/middleware_by_identity_test.go</files>
  <action>
RED → GREEN for the full C1-04 test list (allowed→200 next; not-allowed→403; empty subject→401; server-error→403).

GREEN: implement mirroring RequireEntitlement exactly:
```go
func RequireEntitlementByIdentity(client *EntitlementClient, featureKey string, subjectFromCtx, emailFromCtx func(context.Context) string) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			subject := subjectFromCtx(r.Context())
			if subject == "" { writeErr(w, http.StatusUnauthorized, "missing identity context"); return }  // 401 FIRST
			email := emailFromCtx(r.Context())
			allowed, err := client.CanUseFeatureByIdentity(r.Context(), subject, email, featureKey)
			if err != nil {
				slog.Warn("[Entitlements] identity check failed, denying by default", "feature", featureKey, "subject", subject, "error", err)
				writeErr(w, http.StatusForbidden, "feature not available"); return                          // 403
			}
			if !allowed { writeErr(w, http.StatusForbidden, "feature '"+featureKey+"' is not included in your plan"); return }  // 403
			next.ServeHTTP(w, r)                                                                              // allowed
		})
	}
}
```
# CRITICAL: empty-subject 401 branch comes BEFORE any client call (fail-closed ordering).
  </action>
  <verify>`go test ./platform/entitlements/ -race -count=1 -v` — whole package PASS, SKIP==0, real PASS count printed (never a bare "ok"). `go vet ./platform/entitlements/` clean.</verify>
  <done>RequireEntitlementByIdentity exists, fail-closed (401/403/next); all C1-04 tests pass; whole entitlements package green under -race.</done>
  <recovery>If empty-subject returns 403, move the empty-subject guard above the CanUseFeatureByIdentity call.</recovery>
</task>

</tasks>

<validation_gates>
<test>go test ./platform/entitlements/ -race -count=1 -v</test>
<lint>go vet ./platform/entitlements/</lint>
<build>go build ./platform/entitlements/</build>
</validation_gates>

<verification>
- `go test ./platform/entitlements/ -race -count=1 -v` reports real PASS counts, SKIP==0, never a bare "ok".
- Fail-open proven (Inject): success injects into bootstrapContextKey (EntitlementsFromContext non-nil); empty subject and server-500 both pass through with nil context + 200.
- Fail-closed proven (Require): empty→401, error→403, not-allowed→403, allowed→next 200; next NOT called on any deny.
- X-AOID-Email carried from emailFromCtx through to the biz httptest server.
- Existing InjectEntitlements/RequireEntitlement untouched.
- No new external deps; stdlib httptest only.

Atomic commits: `test:` (RED tests + middleware fixtures) → `feat:` (both by-identity middlewares).
</verification>

<success_criteria>
- InjectEntitlementsByIdentity (fail-open) and RequireEntitlementByIdentity (fail-closed) present in middleware.go, reusing bootstrapContextKey + writeErr.
- Every C1-03 and C1-04 test passes under -race with SKIP==0.
- companyID middlewares byte-behavior-identical.
- Package builds, `go vet` clean, no new deps.
</success_criteria>

<output>
After completion, create `.planning/objectives/entitlements-bootstrap-by-identity/entitlements-bootstrap-by-identity-02-SUMMARY.md`
</output>
