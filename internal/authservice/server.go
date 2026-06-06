package authservice

import (
	"context"
	"crypto/tls"
	"fmt"
	"net/http"
	"time"

	"github.com/prometheus/client_golang/prometheus/promhttp"
)

// ServerConfig is the HTTP/TLS lifecycle configuration for the auth server.
type ServerConfig struct {
	ListenAddr    string
	TLSCertFile   string
	TLSKeyFile    string
	TLSMinVersion string // "1.2" | "1.3"
	ShutdownDrain time.Duration
}

// Server owns the HTTP listener for the auth service.
type Server struct {
	svc  *Service
	cfg  ServerConfig
	http *http.Server
}

// NewServer builds the routed HTTP server for svc.
func NewServer(svc *Service, cfg ServerConfig) (*Server, error) {
	s := &Server{svc: svc, cfg: cfg}

	mux := http.NewServeMux()
	mux.HandleFunc("GET /healthz", svc.handleHealth)
	mux.Handle("GET /metrics", promhttp.HandlerFor(svc.metrics.Registry, promhttp.HandlerOpts{}))
	mux.HandleFunc("GET /.well-known/jwks.json", svc.handleJWKS)
	mux.HandleFunc("POST /v1/webhooks/stripe", svc.handleWebhook)
	mux.HandleFunc("POST /v1/accounts", svc.handleCreateAccount)
	mux.HandleFunc("POST /v1/devices", svc.handleRegisterDevice)
	mux.HandleFunc("POST /v1/pairing-tokens", svc.handleCreatePairingToken)
	mux.HandleFunc("POST /v1/pairing-tokens/poll", svc.handlePollPairingToken)
	mux.HandleFunc("POST /v1/pairings", svc.handleCompletePairing)
	mux.HandleFunc("POST /v1/pairings/unpair", svc.handleUnpair)
	mux.HandleFunc("POST /v1/token", svc.handleIssueToken)
	mux.HandleFunc("POST /v1/token/refresh", svc.handleRefreshToken)

	tlsCfg, err := s.tlsConfig()
	if err != nil {
		return nil, err
	}
	s.http = &http.Server{
		Addr:              cfg.ListenAddr,
		Handler:           mux,
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
	return &tls.Config{MinVersion: min}, nil
}

// Run serves until ctx is canceled, then shuts down gracefully.
func (s *Server) Run(ctx context.Context) error {
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
