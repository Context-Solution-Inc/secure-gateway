# Secure Device Relay — M1 build tooling.

BINARY      := relay
PKG         := github.com/lley154/secure-gateway
VERSION     ?= dev
COMMIT      ?= $(shell git rev-parse --short HEAD 2>/dev/null || echo unknown)
BUILD_DATE  ?= $(shell date -u +%Y-%m-%dT%H:%M:%SZ)
LDFLAGS     := -s -w \
  -X $(PKG)/internal/version.Version=$(VERSION) \
  -X $(PKG)/internal/version.Commit=$(COMMIT) \
  -X $(PKG)/internal/version.BuildDate=$(BUILD_DATE)

# Full soak overrides, e.g.: make soak SOAK_CONNS=10000 SOAK_DURATION=24h
SOAK_CONNS    ?= 1000
SOAK_DURATION ?= 5s

.PHONY: all build relay devtoken test race vet fmt lint soak docker keys clean

all: vet test build

build: relay devtoken

relay:
	CGO_ENABLED=0 go build -trimpath -ldflags="$(LDFLAGS)" -o bin/$(BINARY) ./cmd/relay

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

docker:
	docker build \
	  --build-arg VERSION=$(VERSION) \
	  --build-arg COMMIT=$(COMMIT) \
	  --build-arg BUILD_DATE=$(BUILD_DATE) \
	  -t secure-gateway/relay:$(VERSION) .

# Generate a dev signing keypair for local runs (relay verifies with the .pub).
keys:
	go run ./cmd/devtoken -gen-keys -out-dir ./keys -alg ES256

clean:
	rm -rf bin/
