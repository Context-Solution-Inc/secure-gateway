# Secure Device Relay — M1 (relay) + M2 (auth & license) build tooling.

BINARY      := relay
PKG         := github.com/context-solutions-inc/secure-gateway
VERSION     ?= dev
COMMIT      ?= $(shell git rev-parse --short HEAD 2>/dev/null || echo unknown)
BUILD_DATE  ?= $(shell date -u +%Y-%m-%dT%H:%M:%SZ)
LDFLAGS     := -s -w \
  -X $(PKG)/internal/version.Version=$(VERSION) \
  -X $(PKG)/internal/version.Commit=$(COMMIT) \
  -X $(PKG)/internal/version.BuildDate=$(BUILD_DATE)

# Registry for `make push` (image-based prod deploy). Override per release, e.g.:
#   make push IMAGE_REGISTRY=ghcr.io/context-solutions-inc/secure-gateway VERSION=1.0.0
# VERSION is the image tag; it maps to IMAGE_TAG in deploy/compose/.env.
IMAGE_REGISTRY ?= ghcr.io/context-solutions-inc/secure-gateway

# Full soak overrides, e.g.: make soak SOAK_CONNS=10000 SOAK_DURATION=24h
SOAK_CONNS    ?= 1000
SOAK_DURATION ?= 5s

# Full-scale capacity overrides, e.g.: make bench LAT_FRAMES=20000 STORM_CONNS=20000
LAT_FRAMES  ?=
STORM_CONNS ?=

.PHONY: all build relay auth devtoken test race vet fmt lint soak bench docker docker-auth push keys clean

all: vet test build

build: relay auth devtoken

relay:
	CGO_ENABLED=0 go build -trimpath -ldflags="$(LDFLAGS)" -o bin/$(BINARY) ./cmd/relay

auth:
	CGO_ENABLED=0 go build -trimpath -ldflags="$(LDFLAGS)" -o bin/auth ./cmd/auth

devtoken:
	CGO_ENABLED=0 go build -trimpath -o bin/devtoken ./cmd/devtoken

test:
	go test ./...

race:
	go test -race ./...

vet:
	go vet ./...

fmt:
	gofmt -s -w $(shell git ls-files '*.go')

# Build-tagged soak test. Defaults are CI-sized; override SOAK_CONNS/SOAK_DURATION.
soak:
	SOAK_CONNS=$(SOAK_CONNS) SOAK_DURATION=$(SOAK_DURATION) \
	  go test -tags soak -run TestSoak -timeout 25h -v ./test/soak/

# Build-tagged capacity checks (§10.1): forward latency, token-verify, revocation
# propagation, reconnect storm. CI-sized by default; override LAT_FRAMES/STORM_CONNS.
bench:
	LAT_FRAMES=$(LAT_FRAMES) STORM_CONNS=$(STORM_CONNS) \
	  go test -tags bench -run . -bench BenchmarkTokenVerify -benchmem -timeout 10m -v ./test/bench/

docker:
	docker build \
	  --build-arg VERSION=$(VERSION) \
	  --build-arg COMMIT=$(COMMIT) \
	  --build-arg BUILD_DATE=$(BUILD_DATE) \
	  -t secure-gateway/relay:$(VERSION) .

docker-auth:
	docker build -f Dockerfile.auth \
	  --build-arg VERSION=$(VERSION) \
	  --build-arg COMMIT=$(COMMIT) \
	  --build-arg BUILD_DATE=$(BUILD_DATE) \
	  -t secure-gateway/auth:$(VERSION) .

# Build registry-tagged relay+auth images and push them for the image-based prod
# deploy (deploy/compose/docker-compose.prod-image.yml). Requires `docker login`
# to IMAGE_REGISTRY with push access first. Refuses the default placeholder
# registry so a real one is always supplied. VERSION is the image tag — pin a
# real release (not dev/latest), e.g.: make push VERSION=1.0.0 IMAGE_REGISTRY=...
push:
	@case "$(IMAGE_REGISTRY)" in registry.example.com/*) \
	  echo "error: set IMAGE_REGISTRY to a real registry (got placeholder $(IMAGE_REGISTRY))"; exit 1;; esac
	@case "$(VERSION)" in dev|latest) \
	  echo "error: set VERSION to a real release tag, not '$(VERSION)'"; exit 1;; esac
	docker build \
	  --build-arg VERSION=$(VERSION) \
	  --build-arg COMMIT=$(COMMIT) \
	  --build-arg BUILD_DATE=$(BUILD_DATE) \
	  -t $(IMAGE_REGISTRY)/relay:$(VERSION) .
	docker build -f Dockerfile.auth \
	  --build-arg VERSION=$(VERSION) \
	  --build-arg COMMIT=$(COMMIT) \
	  --build-arg BUILD_DATE=$(BUILD_DATE) \
	  -t $(IMAGE_REGISTRY)/auth:$(VERSION) .
	docker push $(IMAGE_REGISTRY)/relay:$(VERSION)
	docker push $(IMAGE_REGISTRY)/auth:$(VERSION)

# Generate a dev signing keypair for local runs (relay verifies with the .pub).
keys:
	go run ./cmd/devtoken -gen-keys -out-dir ./keys -alg ES256

clean:
	rm -rf bin/
