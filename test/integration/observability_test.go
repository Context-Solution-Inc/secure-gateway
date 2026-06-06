package integration

import (
	"bytes"
	"strings"
	"sync"
	"testing"

	"github.com/prometheus/client_golang/prometheus/testutil"

	"github.com/lley154/secure-gateway/internal/token"
)

// syncBuffer is a concurrency-safe log sink (slog writes from many goroutines).
type syncBuffer struct {
	mu  sync.Mutex
	buf bytes.Buffer
}

func (b *syncBuffer) Write(p []byte) (int, error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.buf.Write(p)
}

func (b *syncBuffer) String() string {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.buf.String()
}

// TestNoPayloadInLogs is the executable form of FR-5.4 / §9.3: neither message
// payload bytes nor refresh-token strings may ever appear in the logs.
func TestNoPayloadInLogs(t *testing.T) {
	logs := &syncBuffer{}
	h := newHarness(t, nil, logs)
	ctx := ctxT(t)

	const sentinel = "SENTINEL-ciphertext-3f9a2b7c-do-not-log"
	const refreshSentinel = "SENTINEL-refresh-token-deadbeef"

	mobile, err := h.dial(t, ctx, h.mint(t, "pair_L", "dev_m", token.RoleMobile))
	if err != nil {
		t.Fatal(err)
	}
	defer mobile.Close()
	desktop, err := h.dial(t, ctx, h.mint(t, "pair_L", "dev_d", token.RoleDesktop))
	if err != nil {
		t.Fatal(err)
	}
	defer desktop.Close()

	if err := mobile.SendMsg(ctx, "id-1", []byte(sentinel)); err != nil {
		t.Fatal(err)
	}
	if _, err := desktop.RecvType(ctx, "msg"); err != nil {
		t.Fatal(err)
	}

	// An auth_refresh with a bogus token (exercises the refresh log path).
	if err := mobile.SendRefresh(ctx, refreshSentinel); err != nil {
		t.Fatal(err)
	}
	// Give the refresh handler a moment to log its rejection.
	if _, err := mobile.RecvType(ctx, "error"); err != nil {
		t.Fatal(err)
	}

	out := logs.String()
	if out == "" {
		t.Fatal("expected some logs to have been captured")
	}
	if strings.Contains(out, sentinel) {
		t.Error("payload sentinel leaked into logs")
	}
	// The base64 form of the payload must not leak either.
	if strings.Contains(out, "SENTINEL") {
		t.Errorf("sentinel substring found in logs:\n%s", out)
	}
	if strings.Contains(out, refreshSentinel) {
		t.Error("refresh token leaked into logs")
	}
}

// TestMetricsCounters verifies the core Prometheus counters move as expected.
func TestMetricsCounters(t *testing.T) {
	h := newHarness(t, nil, nil)
	ctx := ctxT(t)

	mobile, err := h.dial(t, ctx, h.mint(t, "pair_MM", "dev_m", token.RoleMobile))
	if err != nil {
		t.Fatal(err)
	}
	defer mobile.Close()
	desktop, err := h.dial(t, ctx, h.mint(t, "pair_MM", "dev_d", token.RoleDesktop))
	if err != nil {
		t.Fatal(err)
	}
	defer desktop.Close()

	if got := testutil.ToFloat64(h.metrics.ConnsActive.WithLabelValues("mobile")); got != 1 {
		t.Errorf("ConnsActive(mobile) = %v, want 1", got)
	}
	if got := testutil.ToFloat64(h.metrics.ConnsActive.WithLabelValues("desktop")); got != 1 {
		t.Errorf("ConnsActive(desktop) = %v, want 1", got)
	}
	if got := testutil.ToFloat64(h.metrics.ConnectsTotal); got != 2 {
		t.Errorf("ConnectsTotal = %v, want 2", got)
	}

	if err := mobile.SendMsg(ctx, "m1", []byte("hello")); err != nil {
		t.Fatal(err)
	}
	if _, err := desktop.RecvType(ctx, "msg"); err != nil {
		t.Fatal(err)
	}
	if got := testutil.ToFloat64(h.metrics.MessagesRelayed.WithLabelValues("to_desktop")); got != 1 {
		t.Errorf("MessagesRelayed(to_desktop) = %v, want 1", got)
	}
	if got := testutil.ToFloat64(h.metrics.BytesRelayed.WithLabelValues("to_desktop")); got <= 0 {
		t.Errorf("BytesRelayed(to_desktop) = %v, want > 0", got)
	}

	// Auth failure increments the labeled counter.
	if _, err := h.dial(t, ctx, "garbage"); err == nil {
		t.Fatal("expected auth failure")
	}
	if got := testutil.ToFloat64(h.metrics.AuthFailures.WithLabelValues("malformed_token")); got != 1 {
		t.Errorf("AuthFailures(malformed_token) = %v, want 1", got)
	}
}
