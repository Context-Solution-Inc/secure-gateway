package integration

import (
	"context"
	"testing"
	"time"

	"github.com/coder/websocket"

	"github.com/context-solutions-inc/secure-gateway/internal/relay/protocol"
	"github.com/context-solutions-inc/secure-gateway/internal/token"
)

// TestGracefulDrain verifies that on drain a live session receives a
// sys{shutdown} warning and is then closed going-away (1001), and that new
// connections are refused during draining (PRD §9.2, Appendix B).
func TestGracefulDrain(t *testing.T) {
	h := newHarness(t, nil, nil)
	ctx := ctxT(t)

	c, err := h.dial(t, ctx, h.mint(t, "pair_D", "dev_m", token.RoleMobile))
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()

	// Drain in the background so we can observe the warning then the close.
	go h.srv.Drain()

	// Expect a sys{shutdown} warning before the close.
	sys, err := c.RecvType(ctx, protocol.TypeSys)
	if err != nil {
		t.Fatalf("expected sys{shutdown}, got %v", err)
	}
	var body protocol.System
	if err := jsonUnmarshal(sys.Payload, &body); err != nil {
		t.Fatal(err)
	}
	if body.Kind != protocol.SysShutdown {
		t.Errorf("sys kind = %q, want shutdown", body.Kind)
	}

	// Then the connection closes going-away (1001).
	code, _ := c.WaitClose(ctx)
	if code != websocket.StatusGoingAway {
		t.Errorf("close code = %d, want 1001 going-away", code)
	}

	// New connections are refused while draining.
	dctx, dcancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer dcancel()
	if _, err := h.dial(t, dctx, h.mint(t, "pair_D2", "dev_m", token.RoleMobile)); err == nil {
		t.Error("expected new connection to be refused during drain")
	}
}
