// Command relay is the public-facing secure device relay (PRD §9).
//
// It validates connection tokens, pairs the two ends of a licensed device pair,
// and forwards opaque end-to-end-encrypted frames between them. It mints no
// credentials and decrypts no payloads.
package main

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"os"
	"os/signal"
	"syscall"

	"github.com/lley154/secure-gateway/internal/backplane"
	"github.com/lley154/secure-gateway/internal/backplane/memory"
	redisbp "github.com/lley154/secure-gateway/internal/backplane/redis"
	"github.com/lley154/secure-gateway/internal/config"
	"github.com/lley154/secure-gateway/internal/logging"
	"github.com/lley154/secure-gateway/internal/metrics"
	"github.com/lley154/secure-gateway/internal/relay/hub"
	"github.com/lley154/secure-gateway/internal/relay/server"
	"github.com/lley154/secure-gateway/internal/relay/session"
	"github.com/lley154/secure-gateway/internal/token"
	"github.com/lley154/secure-gateway/internal/version"
)

func main() {
	if err := run(); err != nil {
		fmt.Fprintln(os.Stderr, "relay:", err)
		os.Exit(1)
	}
}

func run() error {
	cfg, err := config.Load()
	if err != nil {
		return err
	}
	if cfg.InstanceID == "" {
		cfg.InstanceID = generateInstanceID()
	}

	log := logging.New(os.Stdout, cfg.LogLevel, cfg.LogFormat)
	log.Info("starting relay", "version", version.String(), "instance_id", cfg.InstanceID)

	m := metrics.New()

	verifier, err := buildVerifier(cfg)
	if err != nil {
		return err
	}

	bp, err := buildBackplane(cfg)
	if err != nil {
		return err
	}
	defer bp.Close()

	h := hub.New(cfg.InstanceID, bp, m, log)

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	// The hub's backplane consumer runs for the instance lifetime.
	hubDone := make(chan struct{})
	go func() {
		defer close(hubDone)
		if err := h.Run(ctx); err != nil {
			log.Error("hub run exited", "error", err)
		}
	}()

	srv, err := server.New(cfg, log, m, server.Deps{
		Verifier: verifier,
		Hub:      h,
		SessionOptions: session.Options{
			OutQueueSize:    cfg.OutQueueSize,
			MaxMessageBytes: cfg.MaxMessageBytes,
			PingInterval:    cfg.PingInterval,
			PongTimeout:     cfg.PongTimeout,
		},
	})
	if err != nil {
		return err
	}

	if err := srv.Run(ctx); err != nil {
		return err
	}
	<-hubDone
	log.Info("relay stopped cleanly")
	return nil
}

func buildVerifier(cfg *config.Config) (token.Verifier, error) {
	var ks token.KeySource
	var err error
	if cfg.JWKSURL != "" {
		ks = token.NewJWKSSource(cfg.JWKSURL)
	} else {
		ks, err = token.NewStaticSourceFromFile(cfg.JWTPublicKeyFile)
		if err != nil {
			return nil, err
		}
	}
	return token.NewVerifier(token.Config{
		Issuer:      cfg.JWTIssuer,
		Audience:    cfg.JWTAudience,
		AllowedAlgs: cfg.JWTAlgs,
		Leeway:      cfg.JWTLeeway,
		KeySource:   ks,
	})
}

func buildBackplane(cfg *config.Config) (backplane.Backplane, error) {
	switch cfg.Backplane {
	case config.BackplaneMemory:
		return memory.New(cfg.SlotTTL, cfg.OutQueueSize), nil
	case config.BackplaneRedis:
		return redisbp.New(cfg.RedisAddr, cfg.RedisPassword, cfg.RedisDB, cfg.SlotTTL)
	default:
		return nil, fmt.Errorf("unknown backplane %q", cfg.Backplane)
	}
}

func generateInstanceID() string {
	host, _ := os.Hostname()
	var buf [4]byte
	_, _ = rand.Read(buf[:])
	if host == "" {
		host = "relay"
	}
	return host + "-" + hex.EncodeToString(buf[:])
}
