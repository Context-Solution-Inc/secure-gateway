package integration

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/alicebob/miniredis/v2"
	goredis "github.com/redis/go-redis/v9"

	"github.com/lley154/secure-gateway/internal/backplane"
	redisbp "github.com/lley154/secure-gateway/internal/backplane/redis"
	"github.com/lley154/secure-gateway/internal/config"
	"github.com/lley154/secure-gateway/internal/devtoken"
	"github.com/lley154/secure-gateway/internal/logging"
	"github.com/lley154/secure-gateway/internal/metrics"
	"github.com/lley154/secure-gateway/internal/relay/hub"
	"github.com/lley154/secure-gateway/internal/relay/protocol"
	"github.com/lley154/secure-gateway/internal/relay/server"
	"github.com/lley154/secure-gateway/internal/token"
	"github.com/lley154/secure-gateway/test/testclient"
)

// instance is one relay stack sharing a backplane with its peers.
type instance struct {
	wsURL string
}

func buildInstance(t *testing.T, instanceID string, bp backplane.Backplane, verifier token.Verifier) *instance {
	t.Helper()
	m := metrics.New()
	log := logging.New(discardWriter{}, "error", "json")

	h := hub.New(instanceID, bp, m, log)
	ctx, cancel := context.WithCancel(context.Background())
	go func() { _ = h.Run(ctx) }()
	t.Cleanup(cancel)

	cfg := &config.Config{ListenAddr: "127.0.0.1:0", TLSMinVersion: "1.2", ShutdownDrain: time.Second}
	srv, err := server.New(cfg, log, m, server.Deps{
		Verifier: verifier, Hub: h, SessionOptions: defaultSessionOptions(),
	})
	if err != nil {
		t.Fatal(err)
	}
	httpSrv := httptest.NewServer(srv.Handler())
	t.Cleanup(httpSrv.Close)
	return &instance{wsURL: "ws" + strings.TrimPrefix(httpSrv.URL, "http") + "/v1/connect"}
}

type discardWriter struct{}

func (discardWriter) Write(p []byte) (int, error) { return len(p), nil }

// TestCrossInstanceForwarding proves a mobile on instance 1 reaches a desktop on
// instance 2 via the Redis routing fabric (PRD §5.2, step 9 exit criterion).
func TestCrossInstanceForwarding(t *testing.T) {
	mr, err := miniredis.Run()
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(mr.Close)

	newBP := func() backplane.Backplane {
		rdb := goredis.NewClient(&goredis.Options{Addr: mr.Addr()})
		t.Cleanup(func() { _ = rdb.Close() })
		return redisbp.NewWithClient(rdb, 60*time.Second)
	}

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
	mint := func(pair, dev string, role token.Role) string {
		tok, err := signer.Mint(devtoken.TokenParams{
			Issuer: testIssuer, Audience: testAud, AccountID: "acct_1",
			PairID: pair, DeviceID: dev, Role: role, LicenseID: "lic_1", TTL: 10 * time.Minute,
		})
		if err != nil {
			t.Fatal(err)
		}
		return tok
	}

	inst1 := buildInstance(t, "inst-1", newBP(), verifier)
	inst2 := buildInstance(t, "inst-2", newBP(), verifier)

	ctx, cancel := context.WithTimeout(context.Background(), 6*time.Second)
	defer cancel()

	mobile, err := testclient.Dial(ctx, inst1.wsURL, mint("pair_XI", "dev_m", token.RoleMobile), http.DefaultClient)
	if err != nil {
		t.Fatalf("mobile dial inst-1: %v", err)
	}
	defer mobile.Close()
	desktop, err := testclient.Dial(ctx, inst2.wsURL, mint("pair_XI", "dev_d", token.RoleDesktop), http.DefaultClient)
	if err != nil {
		t.Fatalf("desktop dial inst-2: %v", err)
	}
	defer desktop.Close()

	// Give the desktop's slot claim time to land in Redis before routing.
	time.Sleep(150 * time.Millisecond)

	payload := []byte("cross-instance-ciphertext")
	if err := mobile.SendMsg(ctx, "xi-1", payload); err != nil {
		t.Fatal(err)
	}
	got, err := desktop.RecvType(ctx, protocol.TypeMsg)
	if err != nil {
		t.Fatalf("desktop did not receive cross-instance frame: %v", err)
	}
	if got.ID != "xi-1" {
		t.Errorf("id = %q, want xi-1", got.ID)
	}
	pl, err := testclient.DecodePayload(got)
	if err != nil {
		t.Fatal(err)
	}
	if string(pl) != string(payload) {
		t.Errorf("payload = %q, want %q", pl, payload)
	}
}
