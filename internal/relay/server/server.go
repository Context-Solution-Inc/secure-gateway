// Package server wires the relay's HTTP surface: the /v1/connect WebSocket
// upgrade endpoint, /healthz, and /metrics, plus TLS configuration and
// signal-driven graceful shutdown.
package server

import (
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"sync/atomic"
	"time"

	"github.com/coder/websocket"
	"github.com/prometheus/client_golang/prometheus/promhttp"

	"github.com/lley154/secure-gateway/internal/config"
	"github.com/lley154/secure-gateway/internal/httpsec"
	"github.com/lley154/secure-gateway/internal/metrics"
	"github.com/lley154/secure-gateway/internal/ratelimit"
	"github.com/lley154/secure-gateway/internal/relay/hub"
	"github.com/lley154/secure-gateway/internal/relay/session"
	"github.com/lley154/secure-gateway/internal/token"
)

// Deps are the relay dependencies the server needs to serve connections.
type Deps struct {
	Verifier       token.Verifier
	Hub            *hub.Hub
	SessionOptions session.Options
}

// Server owns the HTTP listener and connection lifecycle.
type Server struct {
	cfg     *config.Config
	log     *slog.Logger
	metrics *metrics.Set
	deps    Deps
	http    *http.Server

	// ipLimiter throttles per-IP connection attempts; bans tracks 4005 abuse
	// offenders. Both are nil when rate limiting is disabled.
	ipLimiter *ratelimit.KeyedLimiter
	bans      *ratelimit.BanTracker

	// baseCtx is the session lifetime context, set when Run starts.
	baseCtx atomic.Pointer[context.Context]

	// draining is set during graceful shutdown so new upgrades are refused.
	draining atomic.Bool
}

// New builds the Server and its mux.
func New(cfg *config.Config, log *slog.Logger, m *metrics.Set, deps Deps) (*Server, error) {
	if deps.Verifier == nil || deps.Hub == nil {
		return nil, errors.New("server requires a verifier and hub")
	}
	s := &Server{cfg: cfg, log: log, metrics: m, deps: deps}

	if cfg.RateLimitEnabled {
		s.ipLimiter = ratelimit.NewKeyedLimiter(float64(cfg.RateLimitIPPerMin), cfg.RateLimitIPBurst)
		s.bans = ratelimit.NewBanTracker(cfg.AbuseStrikeThreshold, cfg.AbuseStrikeWindow, cfg.AbuseBanWindow)
	}

	// Install the live-socket token-refresh handler (FR-3.5).
	deps.Hub.SetRefresher(&refresher{verifier: deps.Verifier, log: log})

	mux := http.NewServeMux()
	mux.HandleFunc("/healthz", s.handleHealthz)
	mux.Handle("/metrics", promhttp.HandlerFor(m.Registry, promhttp.HandlerOpts{}))
	mux.HandleFunc("/v1/connect", s.handleConnect)

	tlsCfg, err := s.tlsConfig()
	if err != nil {
		return nil, err
	}

	s.http = &http.Server{
		Addr:              cfg.ListenAddr,
		Handler:           httpsec.HSTS(mux), // HSTS on the HTTP surface (PRD §10.2)
		TLSConfig:         tlsCfg,
		ReadHeaderTimeout: 10 * time.Second,
	}
	return s, nil
}

// Handler returns the server's HTTP handler, for use with httptest in tests.
func (s *Server) Handler() http.Handler { return s.http.Handler }

func (s *Server) tlsConfig() (*tls.Config, error) {
	// nil when no cert is set (TLS terminated by a fronting proxy).
	return httpsec.ServerTLSConfig(s.cfg.TLSCertFile, s.cfg.TLSMinVersion), nil
}

// sweepLimiters periodically reclaims idle rate-limiter entries and refreshes
// the active-bans gauge until the server context is canceled.
func (s *Server) sweepLimiters(ctx context.Context) {
	t := time.NewTicker(time.Minute)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
			if s.ipLimiter != nil {
				s.ipLimiter.Sweep(10 * time.Minute)
			}
			if s.bans != nil {
				s.bans.Sweep()
				s.metrics.BansActive.Set(float64(s.bans.ActiveBans()))
			}
		}
	}
}

func (s *Server) handleHealthz(w http.ResponseWriter, _ *http.Request) {
	w.Header().Set("Content-Type", "text/plain; charset=utf-8")
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write([]byte("ok\n"))
}

// sessionCtx returns the base session context (server lifetime).
func (s *Server) sessionCtx() context.Context {
	if p := s.baseCtx.Load(); p != nil {
		return *p
	}
	return context.Background()
}

// Run starts serving and blocks until ctx is canceled, then drains.
func (s *Server) Run(ctx context.Context) error {
	s.baseCtx.Store(&ctx)

	if s.ipLimiter != nil || s.bans != nil {
		go s.sweepLimiters(ctx)
	}

	errCh := make(chan error, 1)
	go func() {
		var err error
		if s.http.TLSConfig != nil {
			err = s.http.ListenAndServeTLS(s.cfg.TLSCertFile, s.cfg.TLSKeyFile)
		} else {
			err = s.http.ListenAndServe()
		}
		errCh <- err
	}()

	s.log.Info("relay listening",
		"addr", s.cfg.ListenAddr,
		"tls", s.http.TLSConfig != nil,
		"backplane", string(s.cfg.Backplane),
		"instance_id", s.cfg.InstanceID,
	)

	select {
	case err := <-errCh:
		if errors.Is(err, http.ErrServerClosed) {
			return nil
		}
		return fmt.Errorf("listen: %w", err)
	case <-ctx.Done():
		return s.shutdown()
	}
}

func (s *Server) shutdown() error {
	s.log.Info("draining connections", "timeout", s.cfg.ShutdownDrain)
	// 1. Notify clients and close sessions with going-away so they reconnect
	//    elsewhere with jitter (Appendix B 1001).
	s.Drain()
	// 2. Stop the listener and wait for in-flight handlers to return (they
	//    return as their sessions close), bounded by the drain budget.
	sctx, cancel := context.WithTimeout(context.Background(), s.cfg.ShutdownDrain)
	defer cancel()
	if err := s.http.Shutdown(sctx); err != nil {
		return fmt.Errorf("graceful shutdown: %w", err)
	}
	return nil
}

// notifyGrace is how long sys{shutdown} warnings get to flush before sessions
// are closed.
const notifyGrace = 200 * time.Millisecond

// Drain refuses new connections, sends sys{shutdown} to every live session,
// waits briefly for the warning to flush, then closes all sessions going-away.
// It is invoked by shutdown and exported for tests.
func (s *Server) Drain() {
	s.draining.Store(true)
	n := s.deps.Hub.DrainNotify("server draining")
	if n > 0 {
		grace := notifyGrace
		if s.cfg.ShutdownDrain > 0 && grace > s.cfg.ShutdownDrain/2 {
			grace = s.cfg.ShutdownDrain / 2
		}
		time.Sleep(grace)
	}
	s.deps.Hub.CloseAll(websocket.StatusGoingAway, "server draining")
}
