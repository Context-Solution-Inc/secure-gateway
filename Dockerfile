# syntax=docker/dockerfile:1

# --- Build stage ---
FROM golang:1.26 AS build

WORKDIR /src

# Cache module downloads.
COPY go.mod go.sum ./
RUN go mod download

COPY . .

ARG VERSION=dev
ARG COMMIT=unknown
ARG BUILD_DATE=unknown

# Static, stripped binary. CGO disabled so it runs on distroless/static.
RUN CGO_ENABLED=0 GOOS=linux go build \
    -trimpath \
    -ldflags="-s -w \
      -X github.com/lley154/secure-gateway/internal/version.Version=${VERSION} \
      -X github.com/lley154/secure-gateway/internal/version.Commit=${COMMIT} \
      -X github.com/lley154/secure-gateway/internal/version.BuildDate=${BUILD_DATE}" \
    -o /out/relay ./cmd/relay

# --- Runtime stage ---
# distroless/static:nonroot — no shell, no package manager, non-root user.
# Pin by digest in production: gcr.io/distroless/static:nonroot@sha256:<digest>
FROM gcr.io/distroless/static:nonroot

COPY --from=build /out/relay /relay

# wss endpoint; map as needed. Runs as the distroless 'nonroot' user (uid 65532).
EXPOSE 8443
USER nonroot:nonroot

ENTRYPOINT ["/relay"]
