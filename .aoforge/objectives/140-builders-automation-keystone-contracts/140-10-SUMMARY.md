---
objective: 140-builders-automation-keystone-contracts
trd: "10"
subsystem: platform/experience (tool dispatch runtime)
tags: [stub-dispatcher, tool-binding, tenant-scope, swap-seam, tdd]
requires: ["140-07 (ToolDefinition/AgentNode/SideEffect/ValidateTooling + adapter allowlist)", "140-04 (ScopedContext/AoidIdentity/ErrScopeDenied)"]
provides: ["experience.Dispatcher port", "experience.StubDispatcher", "experience.StubResult/GateClass/DispatchStatus", "ErrDispatchDenied/ErrDispatchExternalDeferred/ErrDispatchInvalidInput", "experience.ExternalClient seam"]
affects: ["obj 144 (real LLM loop swaps in behind Dispatcher port)"]
tech-stack:
  added: []   # NO new deps — lightweight structural JSON validation, encoding/json only
  patterns: ["StepDispatcher port (swap-stable seam)", "single non-leaking denial sentinel (no existence oracle)", "tenant-scoped curated adapter allowlist FK"]
key-files:
  created:
    - platform/experience/dispatcher.go
    - platform/experience/dispatcher_test.go
  modified:
    - platform/experience/fixtures/tool_factory.go
decisions:
  - "Tool->adapter binding is tenant-scoped via a per-ScopeID adapter registry; wrong-tenant + off-allowlist + tool-not-bound + nil all collapse to ONE ErrDispatchDenied (adapter_id never echoed) — no existence oracle"
  - "Stub does lightweight structural JSON-Schema validation (type/required) — NO new schema-validator dependency on the frozen-contract package; obj 144 can plug a full validator behind the same Dispatch signature"
  - "ExternalClient seam is held by the stub but NEVER invoked; recording spy asserts zero calls on every path (no-LLM/no-execution proof)"
metrics:
  duration: ~25m
  completed: 2026-06-29
---

# Objective 140 TRD 10: Stub Tool Dispatcher + Wrong-Tenant Tool->Adapter Binding Summary

A STUB tool dispatcher (`experience.StubDispatcher`) behind a swap-stable `Dispatcher` port: it validates the typed io-envelope, enforces the tenant-scoped curated adapter allowlist, classifies the side_effect gate, and returns a typed `StubResult` — WITHOUT calling any LLM or executing the real adapter. The locked 140 decision ("ship a stub dispatcher, defer the real loop to obj 144") is realized: obj 144 replaces the stub body behind the SAME interface with no contract change.

## What was built

- **`Dispatcher` port** — `Dispatch(ctx, *AgentNode, *ToolDefinition, ScopedContext, input []byte) (StubResult, error)`. Mirrors biz `internal/workflows` StepDispatcher. The envelope-preserving swap seam.
- **`StubDispatcher`** — validates, in fail-closed order: tool/node present -> AgentNode binds the tool's adapter -> adapter in the DISPATCHING SCOPE's curated allowlist -> io-envelope present -> side_effect gate (external deferred, unspecified fail-closed) -> input structurally satisfies input_schema -> returns a `StubResult` with an echoed output envelope. Never executes; never calls the external client.
- **`StubResult`** — `{Status, GateClass, WriteGated, Executed(=false for stub), OutputEnvelope}`. The shape obj 144 must preserve.
- **Non-leaking sentinels** — `ErrDispatchDenied` (wrong-tenant == off-allowlist == tool-not-bound == nil, byte-identical, adapter_id never echoed), `ErrDispatchExternalDeferred` (webhooks out of scope, distinct from a denial), `ErrDispatchInvalidInput` (schema violation, distinct from a denial).
- **`ExternalClient`** seam — held but never invoked by the stub (the swap target for obj 144).
- **Fixtures** — per-scope adapter registry (`ScopedAdapters`/`AllowedAdaptersForScope`) with `WrongTenantID`'s set DISJOINT from the default adapters, plus `NewAgentNodeForTool`.

## Security model honored

- Tool binds ONLY to the curated allowlist (adapter_id is an FK) — NO arbitrary RPC/SQL.
- Allowlist is TENANT-SCOPED (resolved per `ScopedContext.ScopeID`) — a tool bound under tenant X is absent from tenant Y's set, collapsing to the SAME denial as an unknown adapter (no cross-tenant existence oracle; the `feedback_allowlist_by_stored_value_injection` / `feedback_rest_authority_field_body_binding` lesson).
- Args format-validated at write (input checked against input_schema before any notional dispatch).
- External side-effect rejected/deferred — never wired, never executed.

## Deviations from Plan

**None affecting contract.** One in-test fixture bug fixed during GREEN (Rule 1 — Bug): the read-vs-write distinctness assertion reused the write-tool's AgentNode, which (correctly) does not bind the read adapter, so the impl denied it; the test now builds a node that binds the read tool. The impl was correct; only the test fixture was wrong. Committed in the GREEN commit `5429c28`.

The planned `files_modified` named `dispatcher.go`, `dispatcher_test.go`, and `tool_factory.go` — all three delivered, no extra files.

## TDD Evidence

| Phase | Command | Exit Code | Expected |
|---|---|---|---|
| RED | `go test -count=1 ./platform/experience/` | 1 | FAIL (dispatcher symbols undefined — correct) |
| GREEN | `go test -count=1 ./platform/experience/...` | 0 | PASS (correct) |

RED commit `0ae6a2f`, GREEN commit `5429c28` (both committed incrementally per the prior-executor-died-after-RED guard).

## Task Evidence

| Task | Verify Command | Exit Code | Status |
|---|---|---|---|
| 1: Extend tool factory + RED tests | `go test -count=1 ./platform/experience/` | 1 (RED) | PASS (failed for the right reason) |
| 2: GREEN Dispatcher + StubDispatcher | `go test -count=1 ./platform/experience/...` | 0 | PASS |

Dispatcher tests (all PASS): WellFormedReadTool_ValidatedNoSideEffect, WriteTool_GatedDistinctFromRead, OffAllowlistAdapter_Denied, InputViolatesSchema_Rejected, ExternalSideEffect_DeferredNotExecuted, ToolNotBoundByNode_Denied, WrongTenant_SameDenialAsUnknown (byte-identical non-leak proof), DispatcherPort_SatisfiedBySecondImpl (compile-time port-swap proof). Every path asserts `recordingExternalClient.Calls == 0` (no-LLM/no-execution proof).

## Validation Gate Results

| Gate | Command | Exit Code | Status |
|---|---|---|---|
| lint | `go vet ./platform/experience/...` | 0 | PASS |
| lint (CI scope) | `go vet ./...` | 0 | PASS |
| test | `go test -count=1 ./platform/experience/...` | 0 | PASS |

## Post-TRD Verification

- Auto-fix cycles used: 1 (in-test fixture bug, Rule 1).
- Must-haves verified: 3/3 (stub validates envelope without LLM/adapter exec; swap is envelope-preserving via the Dispatcher port; tools bind only the curated allowlist, arbitrary adapter rejected, args format-validated).
- Proto: FROZEN, untouched (`git diff e9044b4 HEAD --stat -- gen/ proto/` empty).
- Gate failures: None.

## Self-Check: PASSED

- FOUND: platform/experience/dispatcher.go
- FOUND: platform/experience/dispatcher_test.go
- FOUND: platform/experience/fixtures/tool_factory.go (extended)
- FOUND commit: 0ae6a2f (test: RED)
- FOUND commit: 5429c28 (feat: GREEN)
- Branch: feat/140-10-stub-dispatcher (off feat/experience-v1-contracts tip e9044b4) — FF-mergeable into feat/experience-v1-contracts.
