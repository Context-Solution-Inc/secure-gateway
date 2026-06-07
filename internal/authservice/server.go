package authservice

import (
	"context"
	"crypto/tls"
	"fmt"
	"net/http"
	"time"

	"github.com/prometheus/client_golang/prometheus/promhttp"

	"github.com/lley154/secure-gateway/internal/httpsec"
)

// ServerConfig is the HTTP/TLS lifecycle configuration for the auth server.
type ServerConfig struct {
	ListenAddr    string
	TLSCertFile   string
	TLSKeyFile    string
	TLSMinVersion string // "1.2" | "1.3"
	ShutdownDrain time.Duration

	// Rate limiting (PRD §10.2).
	TrustProxy             bool
	RateLimitEnabled       bool
	RateLimitIPPerMin      int
	RateLimitIPBurst       int
	RateLimitAccountPerMin int
	RateLimitAccountBurst  int
}

// Server owns the HTTP listener for the auth service.
type Server struct {
	svc  *Service
	cfg  ServerConfig
	rl   *rateLimiters
	http *http.Server
}

// NewServer builds the routed HTTP server for svc.
func NewServer(svc *Service, cfg ServerConfig) (*Server, error) {
	s := &Server{svc: svc, cfg: cfg, rl: newRateLimiters(cfg)}

	mux := http.NewServeMux()
	mux.HandleFunc("GET /healthz", svc.handleHealth)
	mux.Handle("GET /metrics", promhttp.HandlerFor(svc.metrics.Registry, promhttp.HandlerOpts{}))
	mux.HandleFunc("GET /.well-known/jwks.json", svc.handleJWKS)
	mux.HandleFunc("POST /v1/webhooks/stripe", svc.handleWebhook)
	mux.HandleFunc("POST /v1/accounts", svc.handleCreateAccount)
	mux.HandleFunc("POST /v1/devices", svc.handleRegisterDevice)
	// Sensitive endpoints (pairing + token issuance/refresh) are rate limited.
	mux.HandleFunc("POST /v1/pairing-tokens", s.limit(svc.handleCreatePairingToken))
	mux.HandleFunc("POST /v1/pairing-tokens/poll", svc.handlePollPairingToken)
	mux.HandleFunc("POST /v1/pairings", s.limit(svc.handleCompletePairing))
	mux.HandleFunc("POST /v1/pairings/unpair", svc.handleUnpair)
	mux.HandleFunc("POST /v1/token", s.limit(svc.handleIssueToken))
	mux.HandleFunc("POST /v1/token/refresh", s.limit(svc.handleRefreshToken))

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

// Handler exposes the mux for httptest in integration tests.
func (s *Server) Handler() http.Handler { return s.http.Handler }

func (s *Server) tlsConfig() (*tls.Config, error) {
	if s.cfg.TLSCertFile == "" {
		return nil, nil // TLS terminated by a fronting proxy.
	}
	min := uint16(tls.VersionTLS12)
	if s.cfg.TLSMinVersion == "1.3" {
		min = tls.VersionTLS13
	}
	return &tls.Config{
		MinVersion:   min,
		CipherSuites: httpsec.ModernCipherSuites(), // explicit modern allow-list (TLS 1.2 leg)
	}, nil
}

// Run serves until ctx is canceled, then shuts down gracefully.
func (s *Server) Run(ctx context.Context) error {
	if s.rl.ip != nil {
		go s.rl.sweep(ctx)
	}

	errCh := make(chan error, 1)
	go func() {
		if s.http.TLSConfig != nil {
			errCh <- s.http.ListenAndServeTLS(s.cfg.TLSCertFile, s.cfg.TLSKeyFile)
		} else {
			errCh <- s.http.ListenAndServe()
		}
	}()
	s.svc.log.Info("auth service listening", "addr", s.cfg.ListenAddr, "tls", s.http.TLSConfig != nil)

	select {
	case err := <-errCh:
		if err == http.ErrServerClosed {
			return nil
		}
		return fmt.Errorf("listen: %w", err)
	case <-ctx.Done():
		sctx, cancel := context.WithTimeout(context.Background(), s.cfg.ShutdownDrain)
		defer cancel()
		if err := s.http.Shutdown(sctx); err != nil {
			return fmt.Errorf("graceful shutdown: %w", err)
		}
		return nil
	}
}
