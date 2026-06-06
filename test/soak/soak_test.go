//go:build soak

// Package soak holds the M1 soak test: many idle connections held open while
// goroutine, heap, and file-descriptor counts are sampled to prove there are no
// leaks (PRD M1 exit criterion: 10k idle conns, 24h, zero leaks).
//
// Defaults are modest so it runs in CI; override via env for the full soak:
//
//	SOAK_CONNS=10000 SOAK_DURATION=24h go test -tags soak -run TestSoak -timeout 25h ./test/soak/
package soak

import (
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"runtime"
	"strconv"
	"strings"
	"syscall"
	"testing"
	"time"

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

func envInt(key string, def int) int {
	if v := os.Getenv(key); v != "" {
		if n, err := strconv.Atoi(v); err == nil {
			return n
		}
	}
	return def
}

func envDur(key string, def time.Duration) time.Duration {
	if v := os.Getenv(key); v != "" {
		if d, err := time.ParseDuration(v); err == nil {
			return d
		}
	}
	return def
}

func TestSoak(t *testing.T) {
	pairs := envInt("SOAK_CONNS", 1000) / 2 // each pair is 2 connections
	if pairs < 1 {
		pairs = 1
	}
	duration := envDur("SOAK_DURATION", 5*time.Second)
	raiseFDLimit(t, uint64(pairs*2+1024))

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
	log := logging.New(os.Stderr, "warn", "json")
	h := hub.New("soak", memory.New(60*time.Second, 64), m, log)
	hctx, hcancel := context.WithCancel(context.Background())
	defer hcancel()
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
	defer httpSrv.Close()
	wsURL := "ws" + strings.TrimPrefix(httpSrv.URL, "http") + "/v1/connect"

	mint := func(pair, dev string, role token.Role) string {
		tok, _ := signer.Mint(devtoken.TokenParams{
			Issuer: testIssuer, Audience: testAud, AccountID: "acct", PairID: pair,
			DeviceID: dev, Role: role, LicenseID: "lic", TTL: 24 * time.Hour,
		})
		return tok
	}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	t.Logf("opening %d connections (%d pairs)...", pairs*2, pairs)
	var clients []*testclient.Client
	for i := 0; i < pairs; i++ {
		pair := fmt.Sprintf("pair_%d", i)
		mob, err := testclient.Dial(ctx, wsURL, mint(pair, "m", token.RoleMobile), http.DefaultClient)
		if err != nil {
			t.Fatalf("dial mobile %d: %v", i, err)
		}
		desk, err := testclient.Dial(ctx, wsURL, mint(pair, "d", token.RoleDesktop), http.DefaultClient)
		if err != nil {
			t.Fatalf("dial desktop %d: %v", i, err)
		}
		clients = append(clients, mob, desk)
		// Each client drains frames (and thus auto-pongs) until ctx is canceled.
		for _, c := range []*testclient.Client{mob, desk} {
			go drain(ctx, c)
		}
		if i%200 == 0 {
			time.Sleep(10 * time.Millisecond) // stagger to avoid a synthetic storm
		}
	}
	defer func() {
		for _, c := range clients {
			c.Close()
		}
	}()

	// Warm up, then sample a baseline.
	time.Sleep(2 * time.Second)
	runtime.GC()
	base := sample()
	t.Logf("baseline after connect: %s", base)

	// Hold the connections idle for the soak duration, sampling periodically.
	deadline := time.Now().Add(duration)
	for time.Now().Before(deadline) {
		time.Sleep(min(duration/5+time.Millisecond, 30*time.Second))
		t.Logf("sample: %s", sample())
	}

	runtime.GC()
	final := sample()
	t.Logf("final: %s", final)

	// Assert no unbounded growth after the warm-up baseline (allow generous
	// slack for GC timing and runtime jitter).
	if final.goroutines > base.goroutines+pairs/4+200 {
		t.Errorf("goroutine growth: baseline %d -> final %d", base.goroutines, final.goroutines)
	}
	if base.heapMB > 0 && final.heapMB > base.heapMB*2+32 {
		t.Errorf("heap growth: baseline %dMB -> final %dMB", base.heapMB, final.heapMB)
	}
	if final.fds > 0 && base.fds > 0 && final.fds > base.fds+pairs/4+200 {
		t.Errorf("fd growth: baseline %d -> final %d", base.fds, final.fds)
	}
}

func drain(ctx context.Context, c *testclient.Client) {
	for {
		if _, err := c.Recv(ctx); err != nil {
			return
		}
	}
}

type stats struct {
	goroutines int
	heapMB     uint64
	fds        int
}

func (s stats) String() string {
	return fmt.Sprintf("goroutines=%d heap=%dMB fds=%d", s.goroutines, s.heapMB, s.fds)
}

func sample() stats {
	var ms runtime.MemStats
	runtime.ReadMemStats(&ms)
	return stats{
		goroutines: runtime.NumGoroutine(),
		heapMB:     ms.HeapAlloc / (1024 * 1024),
		fds:        countFDs(),
	}
}

func countFDs() int {
	entries, err := os.ReadDir("/proc/self/fd")
	if err != nil {
		return 0 // not Linux / unavailable
	}
	return len(entries)
}

func raiseFDLimit(t *testing.T, want uint64) {
	var lim syscall.Rlimit
	if err := syscall.Getrlimit(syscall.RLIMIT_NOFILE, &lim); err != nil {
		return
	}
	if lim.Cur >= want {
		return
	}
	target := want
	if target > lim.Max {
		target = lim.Max
	}
	lim.Cur = target
	if err := syscall.Setrlimit(syscall.RLIMIT_NOFILE, &lim); err != nil {
		t.Logf("could not raise nofile limit to %d (cur=%d max=%d): %v", want, lim.Cur, lim.Max, err)
	}
}
