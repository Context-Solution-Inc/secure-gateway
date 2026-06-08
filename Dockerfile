# syntax=docker/dockerfile:1

# --- Build stage ---
# Pinned by digest for reproducible builds (golang:1.26).
FROM golang:1.26@sha256:68cb6d68bed024785b69195b89af7ac7a444f27791435f98647edff595aa0479 AS build

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
# Pinned by digest (tag: nonroot). Re-resolve with:
#   docker pull gcr.io/distroless/static:nonroot   # then copy the printed digest
FROM gcr.io/distroless/static:nonroot@sha256:963fa6c544fe5ce420f1f54fb88b6fb01479f054c8056d0f74cc2c6000df5240

COPY --from=build /out/relay /relay

# wss endpoint; map as needed. Runs as the distroless 'nonroot' user (uid 65532).
EXPOSE 8443
USER nonroot:nonroot

ENTRYPOINT ["/relay"]
