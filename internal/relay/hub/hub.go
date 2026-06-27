// Package hub is the per-instance connection registry. It claims slots on the
// backplane, indexes local sessions for fast same-instance routing, forwards
// frames to the paired peer (local or cross-instance), and reacts to backplane
// revocation and eviction events (PRD §5.2, FR-3, FR-4).
package hub

import (
	"context"
	"encoding/json"
	"log/slog"
	"sync"
	"time"

	"github.com/coder/websocket"

	"github.com/context-solutions-inc/secure-gateway/internal/backplane"
	"github.com/context-solutions-inc/secure-gateway/internal/logging"
	"github.com/context-solutions-inc/secure-gateway/internal/metrics"
	"github.com/context-solutions-inc/secure-gateway/internal/relay/protocol"
	"github.com/context-solutions-inc/secure-gateway/internal/relay/session"
)

// Refresher re-validates an auth_refresh token over the live socket (FR-3.5).
// Installed by the server; nil disables in-socket refresh.
type Refresher interface {
	Refresh(ctx context.Context, s *session.Session, rawToken string)
}

// Hub coordinates sessions on one relay instance.
type Hub struct {
	instanceID string
	bp         backplane.Backplane
	metrics    *metrics.Set
	log        *slog.Logger
	refresher  Refresher

	local sync.Map // map[backplane.SlotKey]*session.Session
}

// New creates a Hub.
func New(instanceID string, bp backplane.Backplane, m *metrics.Set, log *slog.Logger) *Hub {
	return &Hub{instanceID: instanceID, bp: bp, metrics: m, log: log}
}

// SetRefresher installs the auth_refresh handler.
func (h *Hub) SetRefresher(r Refresher) { h.refresher = r }

func slotKey(s *session.Session) backplane.SlotKey {
	return backplane.SlotKey{PairID: s.Claims.PairID, Role: s.Claims.Role}
}

func peerKey(s *session.Session) backplane.SlotKey {
	return backplane.SlotKey{PairID: s.Claims.PairID, Role: s.Claims.Role.Opposite()}
}

// Register claims the session's slot, evicts any prior holder, indexes the
// session locally, and announces peer presence. It returns an error only if the
// slot could not be claimed (backplane unavailable => fail closed, PRD §10.3).
func (h *Hub) Register(ctx context.Context, s *session.Session) error {
	key := slotKey(s)
	res, err := h.bp.ClaimSlot(ctx, key, s.ID, h.instanceID)
	if err != nil {
		return err
	}
	if !res.Won {
		// No current policy returns this, but honor the contract.
		s.CloseWith(protocol.CloseSuperseded, "slot in use")
		return nil
	}

	// Supersede a displaced local holder (FR-3.4 default: newest wins).
	if res.EvictedConnID != "" && res.EvictedOnThisInstance {
		if v, ok := h.local.Load(key); ok {
			if old := v.(*session.Session); old.ID == res.EvictedConnID {
				old.CloseWith(protocol.CloseSuperseded, "connected elsewhere")
				h.metrics.SlotEvictions.Inc()
			}
		}
	}

	h.local.Store(key, s)
	h.metrics.ConnsActive.WithLabelValues(string(s.Claims.Role)).Inc()
	h.metrics.ConnectsTotal.Inc()
	s.SetSlotRenewer(h.renewer(key, s.ID))

	h.announcePresence(ctx, s)
	s.Log().Info("session registered")
	return nil
}

// Deregister removes the session from the local index iff it still owns the
// slot, releases the backplane slot, and notifies the peer of going offline.
func (h *Hub) Deregister(ctx context.Context, s *session.Session) {
	key := slotKey(s)
	// Only delete if this exact session is the current holder; a superseded
	// session must not remove the winner's entry.
	wasHolder := h.local.CompareAndDelete(key, s)
	_ = h.bp.ReleaseSlot(ctx, key, s.ID)
	h.metrics.ConnsActive.WithLabelValues(string(s.Claims.Role)).Dec()

	// Tell a locally-connected peer we went offline — but ONLY if we were still
	// the live holder. When the phone reconnects on a new network its new session
	// registers (announcing peer_online) and supersedes this one; this superseded
	// session's deferred deregister must not then clobber the peer back to
	// PEER_OFFLINE while the winner is alive and routing (status stuck DOWN bug).
	if wasHolder {
		if v, ok := h.local.Load(peerKey(s)); ok {
			v.(*session.Session).SendSys(protocol.SysPeerOffline, "")
		}
	}
	s.Log().Info("session deregistered", logging.FieldCloseCode, int(s.CloseCode()))
}

// announcePresence informs both ends when a pair becomes mutually online.
func (h *Hub) announcePresence(ctx context.Context, s *session.Session) {
	pk := peerKey(s)
	if v, ok := h.local.Load(pk); ok {
		peer := v.(*session.Session)
		s.SendSys(protocol.SysPeerOnline, "")
		peer.SendSys(protocol.SysPeerOnline, "")
		return
	}
	// Cross-instance presence is delivered via the routing fabric in multi-
	// instance mode (step 9); single-instance soak/echo uses the local path.
	if inst, _ := h.bp.LookupInstance(ctx, pk); inst != "" && inst != h.instanceID {
		s.SendSys(protocol.SysPeerOnline, "")
	}
}

// OnFrame implements session.Delegate.
func (h *Hub) OnFrame(ctx context.Context, s *session.Session, env *protocol.Envelope, raw []byte) {
	switch env.Type {
	case protocol.TypeMsg, protocol.TypeAck:
		h.Route(ctx, s, raw)
	case protocol.TypeAuthRefresh:
		if h.refresher != nil {
			h.refresher.Refresh(ctx, s, refreshToken(env))
		}
	default:
		// sys/error are relay-originated; ignore if a client sends them.
	}
}

// Route forwards a frame to the paired peer.
func (h *Hub) Route(ctx context.Context, from *session.Session, raw []byte) {
	start := time.Now()
	pk := peerKey(from)
	direction := "to_" + string(pk.Role)

	if v, ok := h.local.Load(pk); ok {
		peer := v.(*session.Session)
		if peer.Enqueue(raw) {
			h.recordRelay(direction, len(raw), start)
			return
		}
		// Slow/dead consumer: drop the peer rather than wedge this goroutine.
		peer.CloseWith(protocol.CloseProtocol, "write queue overflow")
		from.SendError(protocol.ErrPeerOffline, "")
		h.metrics.PeerOffline.Inc()
		return
	}

	inst, err := h.bp.LookupInstance(ctx, pk)
	if err == nil && inst != "" && inst != h.instanceID {
		f := backplane.RoutedFrame{PairID: pk.PairID, ToRole: pk.Role, FromConn: from.ID, Data: raw}
		if perr := h.bp.Publish(ctx, inst, f); perr == nil {
			h.recordRelay(direction, len(raw), start)
			return
		}
	}

	from.SendError(protocol.ErrPeerOffline, "")
	h.metrics.PeerOffline.Inc()
}

func (h *Hub) recordRelay(direction string, n int, start time.Time) {
	h.metrics.MessagesRelayed.WithLabelValues(direction).Inc()
	h.metrics.BytesRelayed.WithLabelValues(direction).Add(float64(n))
	h.metrics.ForwardLatency.Observe(time.Since(start).Seconds())
}

// renewer returns a closure the session calls on heartbeat to extend its slot.
func (h *Hub) renewer(key backplane.SlotKey, connID string) func(context.Context) error {
	return func(ctx context.Context) error {
		return h.bp.RenewSlot(ctx, key, connID)
	}
}

// Run consumes backplane frame, revocation, and eviction streams until ctx is
// canceled. It runs for the lifetime of the relay instance.
func (h *Hub) Run(ctx context.Context) error {
	frames, err := h.bp.SubscribeFrames(ctx, h.instanceID)
	if err != nil {
		return err
	}
	revs, err := h.bp.SubscribeRevocations(ctx)
	if err != nil {
		return err
	}
	evicts, err := h.bp.SubscribeEvictions(ctx, h.instanceID)
	if err != nil {
		return err
	}
	for {
		select {
		case <-ctx.Done():
			return nil
		case f := <-frames:
			h.deliverLocal(f)
		case ev := <-revs:
			h.revoke(ev)
		case k := <-evicts:
			h.evictLocal(k)
		}
	}
}

func (h *Hub) deliverLocal(f backplane.RoutedFrame) {
	key := backplane.SlotKey{PairID: f.PairID, Role: f.ToRole}
	if v, ok := h.local.Load(key); ok {
		v.(*session.Session).Enqueue(f.Data)
	}
}

// revoke closes local sessions matching the revocation scope within ≤2s
// (FR-3.6).
func (h *Hub) revoke(ev backplane.RevocationEvent) {
	h.local.Range(func(_, v any) bool {
		s := v.(*session.Session)
		if (ev.PairID != "" && s.Claims.PairID == ev.PairID) ||
			(ev.AccountID != "" && s.Claims.AccountID == ev.AccountID) {
			s.CloseWith(protocol.CloseRevoked, "revoked")
			h.metrics.Revocations.Inc()
		}
		return true
	})
}

// DrainNotify enqueues a sys{shutdown} warning to every local session. The
// write pumps remain running, so a brief grace after this call lets the warning
// flush before the sessions are closed (PRD §9.2).
func (h *Hub) DrainNotify(detail string) int {
	n := 0
	h.local.Range(func(_, v any) bool {
		v.(*session.Session).SendSys(protocol.SysShutdown, detail)
		n++
		return true
	})
	return n
}

// CloseAll closes every local session with the given code/reason.
func (h *Hub) CloseAll(code websocket.StatusCode, reason string) {
	h.local.Range(func(_, v any) bool {
		v.(*session.Session).CloseWith(code, reason)
		return true
	})
}

func (h *Hub) evictLocal(key backplane.SlotKey) {
	if v, ok := h.local.Load(key); ok {
		s := v.(*session.Session)
		s.CloseWith(protocol.CloseSuperseded, "connected elsewhere")
		h.metrics.SlotEvictions.Inc()
	}
}

// refreshToken extracts the bearer token from an auth_refresh envelope payload
// (JSON {"token":"..."}). The token is control data, never logged.
func refreshToken(env *protocol.Envelope) string {
	if len(env.Payload) == 0 {
		return ""
	}
	var body struct {
		Token string `json:"token"`
	}
	if err := json.Unmarshal(env.Payload, &body); err != nil {
		return ""
	}
	return body.Token
}

var _ session.Delegate = (*Hub)(nil)
