# syntax=docker/dockerfile:1.7

# Multi-stage build for the aoid binary. Run from the eden-platform-go
# repo root:
#
#   docker build -f cmd/aoid/Dockerfile -t aoid:dev .
#
# The runtime image is distroless/static-debian12 — no shell, no apt, no
# tar — and runs as the non-root nonroot user (uid 65532).

############################
# Stage 1: build
############################
FROM golang:1.27.3-bookworm AS build

WORKDIR /src

# Cache go modules separately from sources so dep changes invalidate the
# layer first.
COPY go.mod go.sum ./
RUN --mount=type=cache,target=/root/.cache/go-build \
    --mount=type=cache,target=/go/pkg/mod \
    go mod download

COPY . .

# CGO_ENABLED=0 + static is required for the distroless target.
RUN --mount=type=cache,target=/root/.cache/go-build \
    --mount=type=cache,target=/go/pkg/mod \
    CGO_ENABLED=0 GOOS=linux GOARCH=amd64 \
    go build -trimpath -ldflags="-s -w" -o /out/aoid ./cmd/aoid

############################
# Stage 2: runtime
############################
FROM gcr.io/distroless/static-debian12:nonroot

WORKDIR /app

COPY --from=build /out/aoid /app/aoid

# Migrations are embedded into the binary via go:embed in
# eden-platform-go/migrations_embed.go, so the runtime image carries no
# migrations directory; pgstore.NewBackend uses the embedded FS directly.

USER nonroot:nonroot
EXPOSE 8090

ENV AOID_LISTEN_ADDR=":8090"

ENTRYPOINT ["/app/aoid"]
