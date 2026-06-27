package session

import (
	"context"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/coder/websocket"

	"github.com/context-solutions-inc/secure-gateway/internal/backplane"
	"github.com/context-solutions-inc/secure-gateway/internal/logging"
	"github.com/context-solutions-inc/secure-gateway/internal/relay/protocol"
	"github.com/context-solutions-inc/secure-gateway/internal/token"
)

func testClaims() *token.Claims {
	return &token.Claims{
		AccountID: "acct_1", PairID: "pair_1", DeviceID: "dev_1", Role: token.RoleMobile,
	}
}

// newServerSession spins up a one-shot WebSocket server, dials it, and returns
// the server-side Session under test plus a cleanup. renew()/CloseWith touch a
// real *websocket.Conn, so a live connection is required.
func newServerSession(t *testing.T) *Session {
	t.Helper()
	sessCh := make(chan *Session, 1)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		conn, err := websocket.Accept(w, r, &websocket.AcceptOptions{CompressionMode: websocket.CompressionDisabled})
		if err != nil {
			t.Errorf("accept: %v", err)
			return
		}
		sessCh <- New(conn, testClaims(), "conn_1", Options{}, logging.New(io.Discard, "error", "json"))
		// Keep the handler alive until the test completes.
		<-r.Context().Done()
	}))
	t.Cleanup(srv.Close)

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	t.Cleanup(cancel)
	wsURL := "ws" + srv.URL[len("http"):]
	client, _, err := websocket.Dial(ctx, wsURL, nil)
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	t.Cleanup(func() { _ = client.CloseNow() })

	select {
	case s := <-sessCh:
		return s
	case <-time.After(5 * time.Second):
		t.Fatal("server session not created")
		return nil
	}
}

// TestRenewSelfClosesOnSlotLoss is the SG-05 regression: a confirmed loss of
// slot ownership during heartbeat renewal must self-close the session with
// CloseSuperseded rather than relying on the best-effort eviction channel.
func TestRenewSelfClosesOnSlotLoss(t *testing.T) {
	s := newServerSession(t)
	s.SetSlotRenewer(func(context.Context) error { return backplane.ErrNotSlotOwner })

	s.renew()

	if got := s.CloseCode(); got != protocol.CloseSuperseded {
		t.Fatalf("CloseCode after slot loss = %d, want %d (CloseSuperseded)", got, protocol.CloseSuperseded)
	}
	select {
	case <-s.Context().Done():
	default:
		t.Fatal("session context not canceled after slot loss")
	}
}

// TestRenewIgnoresTransientError verifies a transient transport error (anything
// other than ErrNotSlotOwner) does NOT close the session: the slot TTL outlives
// a single missed renewal, so the next heartbeat retries.
func TestRenewIgnoresTransientError(t *testing.T) {
	s := newServerSession(t)
	s.SetSlotRenewer(func(context.Context) error { return errors.New("redis timeout") })

	s.renew()

	if got := s.CloseCode(); got == protocol.CloseSuperseded {
		t.Fatal("transient renewal error must not supersede the session")
	}
	select {
	case <-s.Context().Done():
		t.Fatal("session context canceled on a transient renewal error")
	default:
	}
}

// TestRenewNoRenewerIsNoop guards the nil-renewer fast path.
func TestRenewNoRenewerIsNoop(t *testing.T) {
	s := newServerSession(t)
	s.renew() // renewSlot is nil; must not panic or close.
	select {
	case <-s.Context().Done():
		t.Fatal("session closed with no renewer installed")
	default:
	}
}
