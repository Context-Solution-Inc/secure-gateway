// Package session owns a single client connection: its read/write pumps,
// heartbeat, token-refresh handling, and close lifecycle (PRD FR-1, FR-3, FR-4).
//
// Concurrency model: exactly two goroutines per connection. The write pump is
// the SOLE writer to the socket (coder/websocket forbids concurrent writers);
// all outbound frames pass through the buffered out channel. The read pump is
// the sole reader. Either pump exiting cancels the session context, which stops
// the other and triggers a single close.
package session

import (
	"context"
	"log/slog"
	"sync"
	"sync/atomic"
	"time"

	"github.com/coder/websocket"

	"github.com/lley154/secure-gateway/internal/logging"
	"github.com/lley154/secure-gateway/internal/relay/protocol"
	"github.com/lley154/secure-gateway/internal/token"
)

// Options configures a Session's transport behavior.
type Options struct {
	OutQueueSize    int
	MaxMessageBytes int64
	PingInterval    time.Duration
	PongTimeout     time.Duration
}

// Delegate receives application frames and control messages from a session's
// read pump. The hub implements it. Methods must not block on the socket.
type Delegate interface {
	// OnFrame handles a decoded inbound frame (msg/ack/auth_refresh). raw is the
	// original bytes for zero-copy forwarding of opaque payloads.
	OnFrame(ctx context.Context, s *Session, env *protocol.Envelope, raw []byte)
}

// Session represents one authenticated WebSocket connection.
type Session struct {
	ID     string
	Claims *token.Claims

	conn *websocket.Conn
	opts Options
	log  *slog.Logger

	out chan []byte

	ctx    context.Context
	cancel context.CancelFunc

	// readCtx governs the read pump's socket lifetime. Canceling it forces the
	// underlying socket closed (coder/websocket closes the conn when a Read
	// context is canceled). It is canceled AFTER the close frame is delivered,
	// separately from ctx, so a relay-initiated close still delivers its code.
	readCtx    context.Context
	readCancel context.CancelFunc

	closeOnce   sync.Once
	closeCode   websocket.StatusCode
	closeReason string

	// expiry is the unix-seconds expiry of the current token; updated on
	// refresh (FR-3.5). Read by the expiry watcher (step 5).
	expiry atomic.Int64

	// lastActivity tracks the last successful pong/read for heartbeat (step 5).
	lastActivity atomic.Int64

	// renewSlot extends the backplane slot TTL on heartbeat; installed by the
	// hub at registration.
	renewSlot func(context.Context) error

	// refreshed is signaled when the token expiry is extended, so the monitor
	// resets its expiry timer.
	refreshed chan struct{}

	// onProtocolViolation, when set, is invoked once per inbound frame that fails
	// to decode or exceeds the size cap (the 4005 path), so the server can record
	// an abuse strike against the client (PRD §10.2). It must not block.
	onProtocolViolation func()
}

// New builds a session around an accepted WebSocket connection.
func New(conn *websocket.Conn, claims *token.Claims, connID string, opts Options, parent *slog.Logger) *Session {
	if opts.OutQueueSize <= 0 {
		opts.OutQueueSize = 64
	}
	ctx, cancel := context.WithCancel(context.Background())
	readCtx, readCancel := context.WithCancel(context.Background())
	s := &Session{
		ID:         connID,
		Claims:     claims,
		conn:       conn,
		opts:       opts,
		out:        make(chan []byte, opts.OutQueueSize),
		ctx:        ctx,
		cancel:     cancel,
		readCtx:    readCtx,
		readCancel: readCancel,
		closeCode:  websocket.StatusNormalClosure,
		refreshed:  make(chan struct{}, 1),
	}
	s.log = parent.With(
		logging.FieldConnID, connID,
		logging.FieldAccountID, claims.AccountID,
		logging.FieldPairID, claims.PairID,
		logging.FieldDeviceID, claims.DeviceID,
		logging.FieldRole, string(claims.Role),
		logging.FieldJTI, claims.ID,
	)
	if claims.ExpiresAt != nil {
		s.expiry.Store(claims.ExpiresAt.Unix())
	}
	return s
}

// Context returns the session context, canceled when the session closes.
func (s *Session) Context() context.Context { return s.ctx }

// Log returns the session's bound structured logger.
func (s *Session) Log() *slog.Logger { return s.log }

// CloseCode returns the recorded close code (valid after close is initiated).
func (s *Session) CloseCode() websocket.StatusCode { return s.closeCode }

// SetSlotRenewer installs the backplane slot-renewal closure (called by hub).
func (s *Session) SetSlotRenewer(fn func(context.Context) error) { s.renewSlot = fn }

// SetProtocolViolationHook installs a callback invoked when an inbound frame is
// rejected as a protocol error / oversize (close 4005). Used for abuse striking.
func (s *Session) SetProtocolViolationHook(fn func()) { s.onProtocolViolation = fn }

// SetExpiry updates the token expiry (unix seconds) after a successful refresh
// and signals the monitor to reset its expiry timer.
func (s *Session) SetExpiry(unix int64) {
	s.expiry.Store(unix)
	select {
	case s.refreshed <- struct{}{}:
	default:
	}
}

// Expiry returns the current token expiry (unix seconds).
func (s *Session) Expiry() int64 { return s.expiry.Load() }

// SlotRole returns this session's role.
func (s *Session) SlotRole() token.Role { return s.Claims.Role }

// Enqueue queues a pre-serialized frame for the write pump. It never blocks: a
// full queue (slow consumer) returns false and the caller should close the
// session rather than wedge a routing goroutine.
func (s *Session) Enqueue(frame []byte) bool {
	select {
	case s.out <- frame:
		return true
	case <-s.ctx.Done():
		return false
	default:
		return false
	}
}

// CloseWith records the close code/reason (first call wins), sends the
// WebSocket close frame so the peer observes the code (Appendix B), then cancels
// the context so all pumps unwind. The close frame is sent BEFORE cancellation
// because canceling the read context would otherwise tear the socket down
// abruptly (1006) without delivering the code.
func (s *Session) CloseWith(code websocket.StatusCode, reason string) {
	s.closeOnce.Do(func() {
		s.closeCode = code
		s.closeReason = reason
		// Stop the write pump and monitor immediately (they select on ctx).
		s.cancel()
		// Deliver the close frame (with its code) in the background. conn.Close
		// writes the frame, then blocks waiting for the peer's close echo on the
		// read mutex held by the read pump. A responsive peer echoes and the
		// read pump tears down quickly; an unresponsive peer would stall, so we
		// force the socket closed after a short grace — long enough for the
		// frame to flush, short enough to free the slot promptly.
		time.AfterFunc(closeGrace, s.readCancel)
		go func() {
			_ = s.conn.Close(code, truncateReason(reason))
			s.readCancel()
		}()
	})
}

// closeGrace bounds how long the close frame has to flush before the socket is
// force-closed when the peer does not complete the close handshake.
const closeGrace = 300 * time.Millisecond

// nowMillis is the envelope timestamp source.
func nowMillis() int64 { return time.Now().UnixMilli() }

// Serve runs both pumps and blocks until the connection closes. parentCtx
// cancellation (server shutdown) also tears the session down.
func (s *Session) Serve(d Delegate) {
	s.lastActivity.Store(time.Now().Unix())

	var wg sync.WaitGroup
	wg.Add(2)
	go func() {
		defer wg.Done()
		s.writePump()
	}()
	go func() {
		defer wg.Done()
		s.monitor()
	}()

	s.readPump(d) // blocks until read error, peer close, or forced close
	s.cancel()    // ensure the write pump and monitor unwind
	s.readCancel()
	wg.Wait()

	// Guarantee the underlying socket/FD is released even when the peer closed
	// on us (no CloseWith path) — CloseNow is idempotent.
	_ = s.conn.CloseNow()
}

// maxTimerDelay stands in for "never" when a token carries no expiry.
const maxTimerDelay = 100 * 365 * 24 * time.Hour

// monitor runs the heartbeat (ping/pong) and the token-expiry timer. It is the
// third per-connection goroutine; the read and write pumps are the other two.
func (s *Session) monitor() {
	ping := time.NewTicker(s.heartbeatInterval())
	defer ping.Stop()
	expiry := time.NewTimer(s.untilExpiry())
	defer expiry.Stop()

	missed := 0
	for {
		select {
		case <-s.ctx.Done():
			return

		case <-ping.C:
			if s.doPing() {
				missed = 0
				s.renew()
			} else {
				missed++
				if missed >= 2 {
					// Peer is unresponsive (FR-1.4). Close going-away so the
					// client reconnects with backoff.
					s.CloseWith(websocket.StatusGoingAway, "heartbeat timeout")
					return
				}
			}

		case <-s.refreshed:
			resetTimer(expiry, s.untilExpiry())

		case <-expiry.C:
			if time.Now().Unix() >= s.expiry.Load() && s.expiry.Load() > 0 {
				s.CloseWith(protocol.CloseTokenExpired, "token expired")
				return
			}
			resetTimer(expiry, s.untilExpiry())
		}
	}
}

func (s *Session) heartbeatInterval() time.Duration {
	if s.opts.PingInterval > 0 {
		return s.opts.PingInterval
	}
	return 25 * time.Second
}

func (s *Session) untilExpiry() time.Duration {
	exp := s.expiry.Load()
	if exp <= 0 {
		return maxTimerDelay
	}
	d := time.Until(time.Unix(exp, 0))
	if d < 0 {
		d = time.Millisecond
	}
	return d
}

// doPing sends a ping and waits for the pong within PongTimeout. coder/websocket
// processes the pong via the concurrent read pump.
func (s *Session) doPing() bool {
	timeout := s.opts.PongTimeout
	if timeout <= 0 {
		timeout = 25 * time.Second
	}
	ctx, cancel := context.WithTimeout(s.ctx, timeout)
	defer cancel()
	return s.conn.Ping(ctx) == nil
}

// renew extends the backplane slot TTL; failure means we were superseded.
func (s *Session) renew() {
	if s.renewSlot == nil {
		return
	}
	ctx, cancel := context.WithTimeout(s.ctx, 5*time.Second)
	defer cancel()
	_ = s.renewSlot(ctx)
}

// resetTimer safely resets t to fire after d.
func resetTimer(t *time.Timer, d time.Duration) {
	if !t.Stop() {
		select {
		case <-t.C:
		default:
		}
	}
	t.Reset(d)
}

// readPump is the sole reader. It decodes frames and dispatches to the delegate.
func (s *Session) readPump(d Delegate) {
	// Transport read limit bounds memory; we enforce the logical per-frame cap
	// in protocol.Decode so oversize yields close 4005 (Appendix B) rather than
	// the library's default 1009. Headroom lets a "just oversize" frame be read
	// and rejected by us; pathological frames hit this backstop.
	if s.opts.MaxMessageBytes > 0 {
		s.conn.SetReadLimit(s.opts.MaxMessageBytes + 16*1024)
	}
	// Read on readCtx (not s.ctx). A relay-initiated close cancels s.ctx first
	// (to stop the write pump/monitor) and delivers the close frame, then
	// cancels readCtx to force the socket down — so the code is delivered before
	// the abrupt teardown that read-context cancellation triggers.
	for {
		_, data, err := s.conn.Read(s.readCtx)
		if err != nil {
			// Peer close or forced local close; the close code is already set
			// (or normal). Just unwind.
			return
		}
		s.lastActivity.Store(time.Now().Unix())

		env, derr := protocol.Decode(data, s.opts.MaxMessageBytes)
		if derr != nil {
			s.log.Warn("protocol error", logging.FieldReason, derr.Error())
			if s.onProtocolViolation != nil {
				s.onProtocolViolation()
			}
			s.CloseWith(protocol.CloseProtocol, "protocol error")
			return
		}
		d.OnFrame(s.ctx, s, env, data)
	}
}

// writePump is the sole writer. It drains out until the session closes. The
// close frame is sent by CloseWith; here we only stop writing.
func (s *Session) writePump() {
	for {
		select {
		case <-s.ctx.Done():
			return
		case frame := <-s.out:
			if err := s.writeFrame(frame); err != nil {
				s.CloseWith(protocol.CloseProtocol, "write error")
				return
			}
		}
	}
}

func (s *Session) writeFrame(frame []byte) error {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	return s.conn.Write(ctx, websocket.MessageText, frame)
}

// truncateReason bounds the close reason to the WebSocket control-frame limit
// (123 bytes for the reason field).
func truncateReason(r string) string {
	const max = 123
	if len(r) > max {
		return r[:max]
	}
	return r
}

// SendSys enqueues a relay-originated sys message.
func (s *Session) SendSys(kind, detail string) bool {
	id, _ := newID()
	env, err := protocol.NewSys(id, nowMillis(), kind, detail)
	if err != nil {
		return false
	}
	b, err := env.Encode()
	if err != nil {
		return false
	}
	return s.Enqueue(b)
}

// SendError enqueues a relay-originated error message.
func (s *Session) SendError(code, detail string) bool {
	id, _ := newID()
	env, err := protocol.NewError(id, nowMillis(), code, detail)
	if err != nil {
		return false
	}
	b, err := env.Encode()
	if err != nil {
		return false
	}
	return s.Enqueue(b)
}
