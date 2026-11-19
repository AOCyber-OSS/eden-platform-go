---
schema: 1
id: "eden-platform-go"
extends: "go"
commands:
  build: { run: "go build ./cmd/aoid" }
  test: { run: "go test ./... -v -race", scoped: "go test -race {packages}" }
provenance:
  reviewed: "2026-09-29"
  sources: [".github/workflows/ci.yml"]
---

# Stack Profile: eden-platform-go

<!-- Drafted by `df-tools stack init`. Add no `## ` heading below unless this project genuinely diverges from `go`: an empty section would replace the parent's. Recognized sections: Principles, Idioms, Avoid, Layout & architecture, Testing, Dependencies, Generated code, Security, UI. -->
