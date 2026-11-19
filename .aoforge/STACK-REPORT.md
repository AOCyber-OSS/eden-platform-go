---
generated: "2026-09-29"
profile: "go"
profile_source: file
components: []
counts: { gap: 4, weak: 1, info: 8 }
---

# Stack Report: eden-platform-go

Proposals only — nothing here has been applied. Review, then change CI/runners yourself.

## Gaps

| ID | Component | Finding | Evidence | Proposal |
|---|---|---|---|---|
| GO-FMT | (root) | CI has no Go format check | go.mod | Fail CI on unformatted files; a bare `gofmt -l` lists them and exits 0. `test -z "$(gofmt -l .)"` |
| GO-GEN-DRIFT | (root) | generator config present, but CI never regenerates and runs `git diff --exit-code` | buf.gen.yaml; buf.yaml; sqlc.yaml | Regenerate in CI and fail on drift. `sqlc generate && git diff --exit-code` |
| GO-VULN | (root) | CI has no govulncheck | go.mod | Scan dependencies for known vulnerabilities in CI, on a schedule as well as on push. `govulncheck ./...` |
| LOCAL-MIRROR | (root) | gates run only in CI, with no local runner target: lint (go vet ./...), test (go test ./... -v -race), lint (uses:bufbuild/buf-setup-action) | .github/workflows/ci.yml:lint-and-test: go vet ./...; .github/workflows/ci.yml:lint-and-test: go test ./... -v -race; .github/workflows/ci.yml:lint-and-test: uses:bufbuild/buf-setup-action | Add a task/make/just target per STACK.md key so each CI gate also runs locally. Keys: lint, test. |

## Weak

| ID | Component | Finding | Evidence | Proposal |
|---|---|---|---|---|
| GO-TIDY | (root) | CI has no go.mod tidy check | go.mod | Fail CI when go.mod/go.sum are not tidy (Go >= 1.23). `go mod tidy -diff` |

## Info

| ID | Component | Finding | Evidence | Proposal |
|---|---|---|---|---|
| CI-HYGIENE | (root) | workflow hygiene: ci.yml (no permissions:, 3 actions not pinned to a commit SHA, no timeout-minutes, no concurrency); experience-proto-breaking.yml (no permissions:, 2 actions not pinned to a commit SHA, no timeout-minutes, no concurrency) | .github/workflows/ci.yml; .github/workflows/experience-proto-breaking.yml | Set a least-privilege `permissions:` block, pin actions by SHA, and add `timeout-minutes` and a `concurrency` group. |
| DOCKER-LINT | (root) | CI has no Dockerfile linter (hadolint) | cmd/aoid/Dockerfile | Lint Dockerfiles (hadolint must be installed; it is not assumed). `hadolint cmd/aoid/Dockerfile` |
| DOCKER-PIN | (root) | base images pinned by tag, not digest: golang:1.26-bookworm, gcr.io/distroless/static-debian12:nonroot | cmd/aoid/Dockerfile | Pin each FROM to an @sha256 digest (keep the tag in a comment for readability). |
| DOCKER-SCAN | (root) | CI has no image scan (trivy / grype) | cmd/aoid/Dockerfile | Scan built images for known vulnerabilities. `trivy image <image>` |
| GO-COVER | (root) | CI runs Go tests without coverage | go.mod | Record coverage (no threshold is implied). `go test -coverprofile=coverage.out ./...` |
| GO-FIX | (root) | CI has no `go fix -diff` | go.mod | Report pending modernizer fixes; `go fix -diff` exits non-zero on a diff. `go fix -diff ./...` |
| GO-LINT | (root) | CI has no Go linter (golangci-lint / staticcheck) | go.mod | Add a linter beyond vet; staticcheck needs no config. `staticcheck ./...` |
| GO-SAST | (root) | CI has no SAST pass (gosec / CodeQL) | go.mod | Optional: add a SAST pass. `gosec ./...` |

## Draft notes

| Key | Candidate | Status | Source |
|---|---|---|---|
