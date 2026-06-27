//go:build bench

// Package bench holds M5 capacity/performance checks for the §10.1 targets.
//
// These assert at a small, CI-friendly scale and are the local proxy for the
// full-scale load test (which a 2-vCPU box cannot host — see docs/capacity.md).
// Run them with the bench build tag:
//
//	go test -tags bench -run . -v ./test/bench/
//	make bench
//
// Override scale via env (e.g. a beefier host):
//
//	LAT_FRAMES=20000 STORM_CONNS=20000 go test -tags bench -run . ./test/bench/
package bench

import (
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"sort"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/coder/websocket"

	"github.com/context-solutions-inc/secure-gateway/internal/backplane"
	"github.com/context-solutions-inc/secure-gateway/internal/backplane/memory"
	"github.com/context-solutions-inc/secure-gateway/internal/config"
	"github.com/context-solutions-inc/secure-gateway/internal/devtoken"
	"github.com/context-solutions-inc/secure-gateway/internal/logging"
	"github.com/context-solutions-inc/secure-gateway/internal/metrics"
	"github.com/context-solutions-inc/secure-gateway/internal/relay/hub"
	"github.com/context-solutions-inc/secure-gateway/internal/relay/server"
	"github.com/context-solutions-inc/secure-gateway/internal/relay/session"
	"github.com/context-solutions-inc/secure-gateway/internal/token"
	"github.com/context-solutions-inc/secure-gateway/test/testclient"
)

const (
	testIssuer = "https://auth.test"
	testAud    = "relay"
)

// rig is an in-process relay with a signer for minting tokens.
type rig struct {
	signer *devtoken.Signer
	wsURL  string
	bp     backplane.Backplane
}

func newRig(t testing.TB) *rig {
	t.Helper()
	signer, err := devtoken.NewSigner("ES256", "k")
	if err != nil {
		t.Fatal(err)
	}
	pub, _ := signer.PublicKeyPEM()
	ks, _ := token.NewStaticSource(pub)
	verifier, err := token.NewVerifier(token.Config{
		Issuer: testIssuer, Audience: testAud, AllowedAlgs: []string{"ES256"},
		Leeway: 30 * time.Second, KeySource: ks,
	})
	if err != nil {
		t.Fatal(err)
	}
	m := metrics.New()
	log := logging.New(os.Stderr, "error", "json")
	bp := memory.New(60*time.Second, 64)
	h := hub.New("bench", bp, m, log)
	hctx, hcancel := context.WithCancel(context.Background())
	t.Cleanup(hcancel)
	go func() { _ = h.Run(hctx) }()

	cfg := &config.Config{ListenAddr: "127.0.0.1:0", TLSMinVersion: "1.2", ShutdownDrain: time.Second}
	srv, err := server.New(cfg, log, m, server.Deps{
		Verifier: verifier, Hub: h,
		SessionOptions: session.Options{
			OutQueueSize: 64, MaxMessageBytes: 256 * 1024,
			PingInterval: 25 * time.Second, PongTimeout: 25 * time.Second,
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	httpSrv := httptest.NewServer(srv.Handler())
	t.Cleanup(httpSrv.Close)
	return &rig{
		signer: signer,
		wsURL:  "ws" + strings.TrimPrefix(httpSrv.URL, "http") + "/v1/connect",
		bp:     bp,
	}
}

func (r *rig) mint(t testing.TB, pair, dev string, role token.Role) string {
	t.Helper()
	tok, err := r.signer.Mint(devtoken.TokenParams{
		Issuer: testIssuer, Audience: testAud, AccountID: "acct", PairID: pair,
		DeviceID: dev, Role: role, LicenseID: "lic", TTL: time.Hour,
	})
	if err != nil {
		t.Fatal(err)
	}
	return tok
}

func envInt(key string, def int) int {
	if v := os.Getenv(key); v != "" {
		if n, err := strconv.Atoi(v); err == nil {
			return n
		}
	}
	return def
}

func percentile(sorted []time.Duration, p float64) time.Duration {
	if len(sorted) == 0 {
		return 0
	}
	idx := int(p / 100 * float64(len(sorted)-1))
	return sorted[idx]
}

// TestForwardLatencyP99 measures mobile->relay->desktop one-way latency and
// asserts the added relay latency stays well under the §10.1 p99 ≤ 50ms target.
// On a localhost relay this is dominated by loopback + scheduling, so the
// assertion carries generous headroom; it is a regression guard, not a SLA.
func TestForwardLatencyP99(t *testing.T) {
	r := newRig(t)
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()

	pair := "lat"
	mob, err := testclient.Dial(ctx, r.wsURL, r.mint(t, pair, "m", token.RoleMobile), http.DefaultClient)
	if err != nil {
		t.Fatal(err)
	}
	defer mob.Close()
	desk, err := testclient.Dial(ctx, r.wsURL, r.mint(t, pair, "d", token.RoleDesktop), http.DefaultClient)
	if err != nil {
		t.Fatal(err)
	}
	defer desk.Close()
	// Let presence settle so the slot pair is bridged before timing.
	time.Sleep(100 * time.Millisecond)

	frames := envInt("LAT_FRAMES", 2000)
	payload := make([]byte, 256) // representative small control payload
	lats := make([]time.Duration, 0, frames)
	for i := 0; i < frames; i++ {
		start := time.Now()
		if err := mob.SendMsg(ctx, "id-"+strconv.Itoa(i), payload); err != nil {
			t.Fatalf("send %d: %v", i, err)
		}
		if _, err := desk.RecvType(ctx, protocolMsg); err != nil {
			t.Fatalf("recv %d: %v", i, err)
		}
		lats = append(lats, time.Since(start))
	}
	sort.Slice(lats, func(i, j int) bool { return lats[i] < lats[j] })
	p50, p95, p99 := percentile(lats, 50), percentile(lats, 95), percentile(lats, 99)
	t.Logf("forward latency over %d frames: p50=%s p95=%s p99=%s max=%s", frames, p50, p95, p99, lats[len(lats)-1])

	const budget = 50 * time.Millisecond // PRD §10.1 intra-region p99 target
	if p99 > budget {
		t.Errorf("p99 forward latency %s exceeds %s target", p99, budget)
	}
}

const protocolMsg = "msg"

// TestRevocationPropagation asserts a published revocation closes matching
// sessions within the §10.1 ≤ 2s window (FR-3.6).
func TestRevocationPropagation(t *testing.T) {
	r := newRig(t)
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	pair := "rev"
	mob, err := testclient.Dial(ctx, r.wsURL, r.mint(t, pair, "m", token.RoleMobile), http.DefaultClient)
	if err != nil {
		t.Fatal(err)
	}
	defer mob.Close()
	desk, err := testclient.Dial(ctx, r.wsURL, r.mint(t, pair, "d", token.RoleDesktop), http.DefaultClient)
	if err != nil {
		t.Fatal(err)
	}
	defer desk.Close()
	time.Sleep(100 * time.Millisecond)

	closed := make(chan websocket.StatusCode, 1)
	go func() {
		code, _ := mob.WaitClose(ctx)
		closed <- code
	}()

	start := time.Now()
	if err := r.bp.PublishRevocation(ctx, backplane.RevocationEvent{PairID: pair}); err != nil {
		t.Fatal(err)
	}
	select {
	case code := <-closed:
		elapsed := time.Since(start)
		t.Logf("revocation propagated in %s (close code %d)", elapsed, code)
		if elapsed > 2*time.Second {
			t.Errorf("revocation propagation %s exceeds 2s target", elapsed)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("session not closed within 5s of revocation")
	}
}

// TestReconnectStorm opens a cohort of pairs, drops them all at once, and
// asserts the cohort fully re-establishes within the §10.1 storm budget. Scaled
// for CI; the full-instance storm is documented in docs/capacity.md.
func TestReconnectStorm(t *testing.T) {
	r := newRig(t)
	pairs := envInt("STORM_CONNS", 2000) / 2
	if pairs < 1 {
		pairs = 1
	}
	ctx, cancel := context.WithTimeout(context.Background(), 120*time.Second)
	defer cancel()

	dialPair := func(i int) (*testclient.Client, *testclient.Client, error) {
		p := fmt.Sprintf("storm_%d", i)
		mob, err := testclient.Dial(ctx, r.wsURL, r.mint(t, p, "m", token.RoleMobile), http.DefaultClient)
		if err != nil {
			return nil, nil, err
		}
		desk, err := testclient.Dial(ctx, r.wsURL, r.mint(t, p, "d", token.RoleDesktop), http.DefaultClient)
		if err != nil {
			mob.Close()
			return nil, nil, err
		}
		return mob, desk, nil
	}

	// Initial cohort.
	clients := make([]*testclient.Client, 0, pairs*2)
	for i := 0; i < pairs; i++ {
		mob, desk, err := dialPair(i)
		if err != nil {
			t.Fatalf("initial dial %d: %v", i, err)
		}
		clients = append(clients, mob, desk)
	}
	// Drop everyone at once (the "storm" trigger).
	for _, c := range clients {
		c.Close()
	}

	// Re-establish the whole cohort, dialing concurrently with a bounded pool.
	start := time.Now()
	var wg sync.WaitGroup
	sem := make(chan struct{}, 256)
	errCh := make(chan error, pairs)
	reconnected := make([]*testclient.Client, 0, pairs*2)
	var mu sync.Mutex
	for i := 0; i < pairs; i++ {
		wg.Add(1)
		sem <- struct{}{}
		go func(i int) {
			defer wg.Done()
			defer func() { <-sem }()
			mob, desk, err := dialPair(i)
			if err != nil {
				errCh <- err
				return
			}
			mu.Lock()
			reconnected = append(reconnected, mob, desk)
			mu.Unlock()
		}(i)
	}
	wg.Wait()
	elapsed := time.Since(start)
	close(errCh)
	for err := range errCh {
		t.Fatalf("reconnect failed: %v", err)
	}
	for _, c := range reconnected {
		defer c.Close()
	}

	t.Logf("reconnect storm: %d pairs (%d conns) re-established in %s", pairs, pairs*2, elapsed)
	const budget = 60 * time.Second // PRD §10.1 full-instance reconnect target
	if elapsed > budget {
		t.Errorf("reconnect storm %s exceeds %s budget", elapsed, budget)
	}
}

// BenchmarkTokenVerify measures local ES256 verification cost; the companion
// TestTokenVerifyP99 asserts the §10.1 ≤ 1ms p99 target.
func BenchmarkTokenVerify(b *testing.B) {
	v, tok := verifyFixture(b)
	ctx := context.Background()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		if _, err := v.Verify(ctx, tok); err != nil {
			b.Fatalf("verify: %v", err)
		}
	}
}

// TestTokenVerifyP99 asserts token validation overhead is ≤ 1ms p99 (§10.1).
func TestTokenVerifyP99(t *testing.T) {
	v, tok := verifyFixture(t)
	ctx := context.Background()
	const n = 5000
	lats := make([]time.Duration, 0, n)
	for i := 0; i < n; i++ {
		start := time.Now()
		if _, err := v.Verify(ctx, tok); err != nil {
			t.Fatalf("verify: %v", err)
		}
		lats = append(lats, time.Since(start))
	}
	sort.Slice(lats, func(i, j int) bool { return lats[i] < lats[j] })
	p99 := percentile(lats, 99)
	t.Logf("token verify over %d: p50=%s p99=%s max=%s", n, percentile(lats, 50), p99, lats[len(lats)-1])
	if p99 > time.Millisecond {
		t.Errorf("token verify p99 %s exceeds 1ms target", p99)
	}
}

func verifyFixture(t testing.TB) (token.Verifier, string) {
	t.Helper()
	signer, err := devtoken.NewSigner("ES256", "k")
	if err != nil {
		t.Fatal(err)
	}
	pub, _ := signer.PublicKeyPEM()
	ks, _ := token.NewStaticSource(pub)
	v, err := token.NewVerifier(token.Config{
		Issuer: testIssuer, Audience: testAud, AllowedAlgs: []string{"ES256"},
		Leeway: 30 * time.Second, KeySource: ks,
	})
	if err != nil {
		t.Fatal(err)
	}
	tok, err := signer.Mint(devtoken.TokenParams{
		Issuer: testIssuer, Audience: testAud, AccountID: "acct", PairID: "p",
		DeviceID: "d", Role: token.RoleMobile, LicenseID: "lic", TTL: time.Hour,
	})
	if err != nil {
		t.Fatal(err)
	}
	return v, tok
}
