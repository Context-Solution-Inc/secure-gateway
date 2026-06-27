package integration

import (
	"context"
	"testing"
	"time"

	"github.com/coder/websocket"
	"github.com/prometheus/client_golang/prometheus/testutil"

	"github.com/context-solutions-inc/secure-gateway/internal/relay/session"
	"github.com/context-solutions-inc/secure-gateway/internal/token"
)

// TestTokenExpiryCloses verifies a session whose token expires without refresh
// is closed with 4003 (FR-3.5, Appendix B).
func TestTokenExpiryCloses(t *testing.T) {
	h := newHarness(t, nil, nil)
	ctx, cancel := context.WithTimeout(context.Background(), 6*time.Second)
	defer cancel()

	// Short-lived token: valid at connect, expires ~2s later.
	c, err := h.dial(t, ctx, h.mintTTL(t, "pair_T", "dev_m", token.RoleMobile, 2*time.Second))
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()

	code, _ := c.WaitClose(ctx)
	if code != 4003 {
		t.Fatalf("close code = %d, want 4003 token_expired", code)
	}
}

// TestRefreshExtendsSession verifies an auth_refresh before expiry keeps the
// session alive past the original token's expiry.
func TestRefreshExtendsSession(t *testing.T) {
	h := newHarness(t, nil, nil)
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	c, err := h.dial(t, ctx, h.mintTTL(t, "pair_R", "dev_m", token.RoleMobile, 2*time.Second))
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()

	// Refresh well before the 2s expiry with a long-lived token.
	time.Sleep(500 * time.Millisecond)
	fresh := h.mintTTL(t, "pair_R", "dev_m", token.RoleMobile, 10*time.Minute)
	if err := c.SendRefresh(ctx, fresh); err != nil {
		t.Fatal(err)
	}

	// Past the original expiry, the socket must still be open: a Recv with a
	// deadline beyond the original expiry should time out (no close frame),
	// not return a close.
	rctx, rcancel := context.WithTimeout(ctx, 3*time.Second)
	defer rcancel()
	_, err = c.Recv(rctx)
	if err == nil {
		t.Fatal("unexpected message")
	}
	if code := websocket.CloseStatus(err); code != -1 {
		t.Fatalf("session closed with %d after refresh; expected to stay open", code)
	}
	if rctx.Err() == nil {
		t.Fatalf("expected deadline timeout (alive), got %v", err)
	}
}

// TestRefreshIdentityMismatchCloses verifies a refresh token bound to a
// different pair/role is rejected with a protocol close.
func TestRefreshIdentityMismatchCloses(t *testing.T) {
	h := newHarness(t, nil, nil)
	ctx, cancel := context.WithTimeout(context.Background(), 6*time.Second)
	defer cancel()

	c, err := h.dial(t, ctx, h.mint(t, "pair_M", "dev_m", token.RoleMobile))
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()

	// Refresh with a token for a different pair.
	bad := h.mint(t, "pair_OTHER", "dev_m", token.RoleMobile)
	if err := c.SendRefresh(ctx, bad); err != nil {
		t.Fatal(err)
	}
	code, _ := c.WaitClose(ctx)
	if code != 4005 {
		t.Fatalf("close code = %d, want 4005 protocol", code)
	}
}

// TestHeartbeatClosesUnresponsive verifies a client that stops responding to
// pings is closed and deregistered (FR-1.4). The client holds the socket open
// but never reads, so coder/websocket never auto-replies to pings.
func TestHeartbeatClosesUnresponsive(t *testing.T) {
	opts := session.Options{
		OutQueueSize:    64,
		MaxMessageBytes: 256 * 1024,
		PingInterval:    150 * time.Millisecond,
		PongTimeout:     150 * time.Millisecond,
	}
	h := newHarnessOpts(t, nil, nil, opts)
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	c, err := h.dial(t, ctx, h.mint(t, "pair_H", "dev_m", token.RoleMobile))
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	// Intentionally do NOT read from c, so no pong is ever sent.

	deadline := time.Now().Add(4 * time.Second)
	for time.Now().Before(deadline) {
		if testutil.ToFloat64(h.metrics.ConnsActive.WithLabelValues("mobile")) == 0 {
			return // session was closed and deregistered
		}
		time.Sleep(50 * time.Millisecond)
	}
	t.Fatal("unresponsive session was not closed by heartbeat within 4s")
}

// TestHeartbeatKeepsResponsiveAlive is the positive control: a client that
// reads (and thus auto-pongs) stays connected across many ping intervals.
func TestHeartbeatKeepsResponsiveAlive(t *testing.T) {
	opts := session.Options{
		OutQueueSize:    64,
		MaxMessageBytes: 256 * 1024,
		PingInterval:    100 * time.Millisecond,
		PongTimeout:     100 * time.Millisecond,
	}
	h := newHarnessOpts(t, nil, nil, opts)
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	c, err := h.dial(t, ctx, h.mint(t, "pair_K", "dev_m", token.RoleMobile))
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()

	// Drain frames (auto-ponging) for ~1s, then confirm still connected.
	rctx, rcancel := context.WithTimeout(ctx, 1*time.Second)
	defer rcancel()
	_, _ = c.Recv(rctx) // will time out with no app frames; pongs handled internally

	if got := testutil.ToFloat64(h.metrics.ConnsActive.WithLabelValues("mobile")); got != 1 {
		t.Fatalf("responsive session dropped: ConnsActive(mobile) = %v, want 1", got)
	}
}
