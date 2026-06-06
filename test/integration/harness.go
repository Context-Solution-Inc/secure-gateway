// Package integration spins up a full relay (verifier + hub + memory backplane
// + HTTP server) in-process and exercises it with real WebSocket clients.
package integration

import (
	"context"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/lley154/secure-gateway/internal/backplane"
	"github.com/lley154/secure-gateway/internal/backplane/memory"
	"github.com/lley154/secure-gateway/internal/config"
	"github.com/lley154/secure-gateway/internal/devtoken"
	"github.com/lley154/secure-gateway/internal/logging"
	"github.com/lley154/secure-gateway/internal/metrics"
	"github.com/lley154/secure-gateway/internal/relay/hub"
	"github.com/lley154/secure-gateway/internal/relay/server"
	"github.com/lley154/secure-gateway/internal/relay/session"
	"github.com/lley154/secure-gateway/internal/token"
	"github.com/lley154/secure-gateway/test/testclient"
)

const (
	testIssuer = "https://auth.test"
	testAud    = "relay"
)

// harness holds a running in-process relay for tests.
type harness struct {
	signer  *devtoken.Signer
	httpSrv *httptest.Server
	srv     *server.Server
	hub     *hub.Hub
	metrics *metrics.Set
	bp      backplane.Backplane
	wsURL   string
}

// defaultSessionOptions are used unless a test overrides them.
func defaultSessionOptions() session.Options {
	return session.Options{
		OutQueueSize:    64,
		MaxMessageBytes: 256 * 1024,
		PingInterval:    25 * time.Second,
		PongTimeout:     25 * time.Second,
	}
}

// newHarness builds a relay backed by the given backplane (memory by default)
// with default session options. logOut, if non-nil, captures structured logs.
func newHarness(t *testing.T, bp backplane.Backplane, logOut io.Writer) *harness {
	return newHarnessOpts(t, bp, logOut, defaultSessionOptions())
}

// newHarnessOpts is newHarness with explicit session options (e.g. fast
// heartbeats for liveness tests).
func newHarnessOpts(t *testing.T, bp backplane.Backplane, logOut io.Writer, sessOpts session.Options) *harness {
	t.Helper()

	signer, err := devtoken.NewSigner("ES256", "test-kid")
	if err != nil {
		t.Fatal(err)
	}
	pubPEM, err := signer.PublicKeyPEM()
	if err != nil {
		t.Fatal(err)
	}
	ks, err := token.NewStaticSource(pubPEM)
	if err != nil {
		t.Fatal(err)
	}
	verifier, err := token.NewVerifier(token.Config{
		Issuer: testIssuer, Audience: testAud, AllowedAlgs: []string{"ES256"},
		Leeway: 30 * time.Second, KeySource: ks,
	})
	if err != nil {
		t.Fatal(err)
	}

	if bp == nil {
		bp = memory.New(60*time.Second, 64)
	}
	m := metrics.New()

	var out io.Writer = logOut
	level := "error"
	if logOut != nil {
		// A test capturing logs wants everything (e.g. the no-payload audit).
		level = "debug"
	} else {
		out = io.Discard
	}
	if os.Getenv("RELAY_TEST_LOG") != "" {
		out = os.Stderr
		level = os.Getenv("RELAY_TEST_LOG")
	}
	log := logging.New(out, level, "json")

	h := hub.New("test-instance", bp, m, log)
	ctx, cancel := context.WithCancel(context.Background())
	go func() { _ = h.Run(ctx) }()
	t.Cleanup(cancel)

	cfg := &config.Config{
		ListenAddr: "127.0.0.1:0", TLSMinVersion: "1.2", Backplane: config.BackplaneMemory,
		ShutdownDrain: 5 * time.Second,
	}
	srv, err := server.New(cfg, log, m, server.Deps{
		Verifier:       verifier,
		Hub:            h,
		SessionOptions: sessOpts,
	})
	if err != nil {
		t.Fatal(err)
	}

	httpSrv := httptest.NewServer(srv.Handler())
	t.Cleanup(httpSrv.Close)

	return &harness{
		signer:  signer,
		httpSrv: httpSrv,
		srv:     srv,
		hub:     h,
		metrics: m,
		bp:      bp,
		wsURL:   "ws" + strings.TrimPrefix(httpSrv.URL, "http") + "/v1/connect",
	}
}

func (h *harness) mint(t *testing.T, pair, device string, role token.Role) string {
	t.Helper()
	return h.mintTTL(t, pair, device, role, 10*time.Minute)
}

func (h *harness) mintTTL(t *testing.T, pair, device string, role token.Role, ttl time.Duration) string {
	t.Helper()
	tok, err := h.signer.Mint(devtoken.TokenParams{
		Issuer: testIssuer, Audience: testAud, AccountID: "acct_1",
		PairID: pair, DeviceID: device, Role: role, LicenseID: "lic_1", TTL: ttl,
	})
	if err != nil {
		t.Fatal(err)
	}
	return tok
}

func (h *harness) dial(t *testing.T, ctx context.Context, bearer string) (*testclient.Client, error) {
	t.Helper()
	return testclient.Dial(ctx, h.wsURL, bearer, http.DefaultClient)
}
