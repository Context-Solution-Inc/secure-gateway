package server

import (
	"encoding/json"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/coder/websocket"

	"github.com/context-solutions-inc/secure-gateway/internal/httpsec"
	"github.com/context-solutions-inc/secure-gateway/internal/logging"
	"github.com/context-solutions-inc/secure-gateway/internal/relay/session"
	"github.com/context-solutions-inc/secure-gateway/internal/token"
)

// handleConnect authenticates and upgrades a client connection (FR-1, FR-3).
// The token is verified BEFORE the WebSocket upgrade; failures return a
// machine-readable reason as JSON with the appropriate 401/403 status.
func (s *Server) handleConnect(w http.ResponseWriter, r *http.Request) {
	if s.draining.Load() {
		http.Error(w, "server draining", http.StatusServiceUnavailable)
		return
	}

	// Abuse controls run before any token work and before the upgrade (FR-1.3,
	// PRD §10.2). A banned or rate-limited IP gets HTTP 429 + Retry-After.
	var ip string
	if s.bans != nil || s.ipLimiter != nil {
		ip = httpsec.ClientIP(r, s.cfg.TrustProxy)
	}
	if s.bans != nil {
		if banned, retry := s.bans.Banned(ip); banned {
			s.metrics.RateLimited.WithLabelValues("ban").Inc()
			s.reject429(w, retry)
			return
		}
	}
	if s.ipLimiter != nil && !s.ipLimiter.Allow(ip) {
		s.metrics.RateLimited.WithLabelValues("ip").Inc()
		s.reject429(w, time.Second)
		return
	}

	raw, reason := bearerToken(r)
	if reason != "" {
		s.rejectConnect(w, &token.AuthError{Reason: reason, HTTPStatus: http.StatusUnauthorized})
		return
	}

	claims, authErr := s.deps.Verifier.Verify(r.Context(), raw)
	if authErr != nil {
		s.rejectConnect(w, authErr)
		return
	}

	conn, err := websocket.Accept(w, r, &websocket.AcceptOptions{
		CompressionMode: websocket.CompressionDisabled,
	})
	if err != nil {
		// Accept already wrote a response on failure.
		s.log.Warn("websocket upgrade failed", logging.FieldReason, err.Error())
		return
	}

	connID := session.NewConnID()
	sess := session.New(conn, claims, connID, s.deps.SessionOptions, s.log)

	// Repeated protocol-error/oversize frames (close 4005) accrue strikes against
	// the source IP; enough strikes earn a temporary ban (PRD §10.2).
	if s.bans != nil {
		sess.SetProtocolViolationHook(func() {
			if s.bans.Strike(ip) {
				s.metrics.BansActive.Set(float64(s.bans.ActiveBans()))
				s.log.Warn("ip temporarily banned for protocol abuse", "ip", ip)
			}
		})
	}

	ctx := s.sessionCtx()
	if err := s.deps.Hub.Register(ctx, sess); err != nil {
		// Backplane unavailable => fail closed (PRD §10.3).
		s.log.Error("slot claim failed; rejecting connection", logging.FieldReason, err.Error())
		_ = conn.Close(websocket.StatusTryAgainLater, "registry unavailable")
		return
	}
	defer s.deps.Hub.Deregister(ctx, sess)

	sess.Serve(s.deps.Hub)
}

// rejectConnect writes a pre-upgrade auth rejection with a machine reason code.
func (s *Server) rejectConnect(w http.ResponseWriter, ae *token.AuthError) {
	s.metrics.AuthFailures.WithLabelValues(string(ae.Reason)).Inc()
	status := ae.HTTPStatus
	if status == 0 {
		status = http.StatusUnauthorized
	}
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(map[string]string{"reason": string(ae.Reason)})
}

// reject429 writes a pre-upgrade Too Many Requests response with a Retry-After
// header (seconds, rounded up to at least 1).
func (s *Server) reject429(w http.ResponseWriter, retry time.Duration) {
	secs := int(retry / time.Second)
	if retry%time.Second != 0 || secs < 1 {
		secs++
	}
	w.Header().Set("Retry-After", strconv.Itoa(secs))
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusTooManyRequests)
	_ = json.NewEncoder(w).Encode(map[string]string{"reason": "rate_limited"})
}

// bearerToken extracts the token from the Authorization header. Tokens in the
// URL/query string are rejected outright (FR-1.2).
func bearerToken(r *http.Request) (string, token.Reason) {
	if r.URL.Query().Has("token") || r.URL.Query().Has("access_token") {
		return "", token.ReasonMalformed
	}
	h := r.Header.Get("Authorization")
	if h == "" {
		return "", token.ReasonMissingToken
	}
	const prefix = "Bearer "
	if !strings.HasPrefix(h, prefix) {
		return "", token.ReasonMalformed
	}
	tok := strings.TrimSpace(h[len(prefix):])
	if tok == "" {
		return "", token.ReasonMissingToken
	}
	return tok, ""
}
