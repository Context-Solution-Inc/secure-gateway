// Command auth is the Auth & License Service (PRD §5.1, §6): it owns accounts,
// devices, pairings, and licenses; mirrors Stripe subscription state via signed
// webhooks; issues and refreshes short-lived connection JWTs only for valid
// licenses; serves the JWKS the relay verifies against; and publishes
// revocations to the shared backplane for immediate cutoff. It holds the JWT
// signing key; the relay never links token-minting code.
package main

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"

	"github.com/lley154/secure-gateway/internal/authconfig"
	"github.com/lley154/secure-gateway/internal/authmetrics"
	"github.com/lley154/secure-gateway/internal/authservice"
	"github.com/lley154/secure-gateway/internal/authstore"
	memstore "github.com/lley154/secure-gateway/internal/authstore/memory"
	pgstore "github.com/lley154/secure-gateway/internal/authstore/postgres"
	"github.com/lley154/secure-gateway/internal/backplane"
	bpmem "github.com/lley154/secure-gateway/internal/backplane/memory"
	redisbp "github.com/lley154/secure-gateway/internal/backplane/redis"
	"github.com/lley154/secure-gateway/internal/billing"
	"github.com/lley154/secure-gateway/internal/logging"
	"github.com/lley154/secure-gateway/internal/obs"
	"github.com/lley154/secure-gateway/internal/signer"
	"github.com/lley154/secure-gateway/internal/version"
)

func main() {
	if err := run(); err != nil {
		fmt.Fprintln(os.Stderr, "auth:", err)
		os.Exit(1)
	}
}

func run() error {
	cfg, err := authconfig.Load()
	if err != nil {
		return err
	}
	if cfg.InstanceID == "" {
		cfg.InstanceID = generateInstanceID()
	}

	log := logging.New(os.Stdout, cfg.LogLevel, cfg.LogFormat)
	log.Info("starting auth service", "version", version.String(), "instance_id", cfg.InstanceID)
	if !cfg.StripeEnabled {
		log.Warn("BILLING DISABLED — Stripe is not configured; secure links are NOT gated on a subscription and open licenses are auto-provisioned (AUTH_BILLING_DISABLED=true)")
	}

	m := authmetrics.New()

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	store, err := buildStore(ctx, cfg)
	if err != nil {
		return err
	}
	defer store.Close()

	if err := seedDevData(ctx, store, cfg, log); err != nil {
		return err
	}

	bp, err := buildBackplane(cfg)
	if err != nil {
		return err
	}
	defer bp.Close()

	sgn, err := loadSigner(cfg)
	if err != nil {
		return err
	}

	var api billing.StripeAPI
	if cfg.StripeSecretKey != "" {
		api = billing.NewRealAPI(cfg.StripeSecretKey)
	}

	proc := billing.NewProcessor(billing.Config{
		Store: store, Backplane: bp, API: api, Logger: log,
		Grace: cfg.GracePeriod, WebhookSecret: cfg.StripeWebhookSecret,
		OnLicenseProvisioned:  m.LicensesProvisioned.Inc,
		OnRevocationPublished: m.RevocationsPublished.Inc,
	})

	svc := authservice.NewService(authservice.Deps{
		Store: store, Signer: sgn, Processor: proc, Backplane: bp, Metrics: m, Logger: log,
		Issuer: cfg.JWTIssuer, Audience: cfg.JWTAudience,
		TokenTTL: cfg.TokenTTL, RefreshTTL: cfg.RefreshTTL, PairingTokenTTL: cfg.PairingTokenTTL,
		Grace: cfg.GracePeriod, AdminKey: cfg.AdminKey,
		RelayURL: cfg.RelayURL, AuthURL: cfg.PublicURL,
		CheckoutPriceID: cfg.StripePriceID, ClaimTTL: cfg.ClaimTTL,
		BillingEnabled: cfg.StripeEnabled,
	})

	srv, err := authservice.NewServer(svc, authservice.ServerConfig{
		ListenAddr: cfg.ListenAddr, MetricsAddr: cfg.MetricsAddr,
		TLSCertFile: cfg.TLSCertFile, TLSKeyFile: cfg.TLSKeyFile,
		TLSMinVersion: cfg.TLSMinVersion, ShutdownDrain: cfg.ShutdownDrain,
		TrustProxy:             cfg.TrustProxy,
		RateLimitEnabled:       cfg.RateLimitEnabled,
		RateLimitIPPerMin:      cfg.RateLimitIPPerMin,
		RateLimitIPBurst:       cfg.RateLimitIPBurst,
		RateLimitAccountPerMin: cfg.RateLimitAccountPerMin,
		RateLimitAccountBurst:  cfg.RateLimitAccountBurst,
	})
	if err != nil {
		return err
	}

	// Background workers: webhook retry queue, and (if Stripe is configured)
	// nightly reconciliation to heal the mirror against missed webhooks.
	workersDone := make(chan struct{})
	go func() {
		defer close(workersDone)
		runWorkers(ctx, proc, api, cfg, m, log)
	}()

	// Background telemetry: backplane health, webhook queue depth/lag, TLS cert
	// expiry (PRD §9.3).
	go runAuthCollectors(ctx, m, store, bp, cfg.TLSCertFile)

	if err := srv.Run(ctx); err != nil {
		return err
	}
	<-workersDone
	log.Info("auth service stopped cleanly")
	return nil
}

// runAuthCollectors samples backplane health, webhook queue depth/lag, and TLS
// cert expiry into Prometheus gauges on a ticker until ctx is canceled.
func runAuthCollectors(ctx context.Context, m *authmetrics.Set, store authstore.Store, bp backplane.Backplane, tlsCertFile string) {
	const (
		interval = 15 * time.Second
		queueCap = 5000 // cap the listing; the gauge saturates beyond this
	)
	t := time.NewTicker(interval)
	defer t.Stop()
	sample := func() {
		hctx, cancel := context.WithTimeout(ctx, 3*time.Second)
		defer cancel()

		up := 0.0
		if bp.HealthCheck(hctx) == nil {
			up = 1
		}
		m.BackplaneUp.Set(up)

		// Pending + failed events are "in flight"; track depth and the oldest age.
		pending := 0
		var oldest time.Time
		for _, st := range []authstore.WebhookStatus{authstore.WebhookPending, authstore.WebhookFailed} {
			evs, err := store.ListWebhookEventsByStatus(hctx, st, queueCap)
			if err != nil {
				return // store unavailable; leave gauges at their last value
			}
			pending += len(evs)
			for _, e := range evs {
				if oldest.IsZero() || e.ReceivedAt.Before(oldest) {
					oldest = e.ReceivedAt
				}
			}
		}
		m.WebhooksPending.Set(float64(pending))
		lag := 0.0
		if !oldest.IsZero() {
			lag = time.Since(oldest).Seconds()
		}
		m.WebhookOldestPendingSeconds.Set(lag)

		if dead, err := store.ListWebhookEventsByStatus(hctx, authstore.WebhookDead, queueCap); err == nil {
			m.WebhooksDead.Set(float64(len(dead)))
		}

		if secs, ok := obs.CertExpirySeconds(tlsCertFile, time.Now()); ok {
			m.TLSCertExpiry.Set(secs)
		}

		// GC expired desktop checkout claims (cheap indexed delete).
		_, _ = store.DeleteExpiredCheckoutClaims(hctx, time.Now())
	}
	sample()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
			sample()
		}
	}
}

func runWorkers(ctx context.Context, proc *billing.Processor, api billing.StripeAPI, cfg *authconfig.Config, m *authmetrics.Set, log *slog.Logger) {
	retry := time.NewTicker(time.Minute)
	defer retry.Stop()

	reconcile := time.NewTicker(cfg.ReconcileInterval)
	defer reconcile.Stop()

	for {
		select {
		case <-ctx.Done():
			return
		case <-retry.C:
			if _, dead, err := proc.RetryFailed(ctx, 100); err != nil {
				log.Error("webhook retry worker", "error", err)
			} else if dead > 0 {
				log.Warn("webhook events dead-lettered", "count", dead)
			}
		case <-reconcile.C:
			if api == nil {
				continue // reconciliation needs the Stripe API
			}
			if err := proc.Reconcile(ctx); err != nil {
				m.ReconcileRuns.WithLabelValues("error").Inc()
				log.Error("reconciliation", "error", err)
			} else {
				m.ReconcileRuns.WithLabelValues("ok").Inc()
			}
		}
	}
}

// seedDevData provisions a deterministic account license for local/dev and the M4 SDK
// cross-platform E2E. There is no admin HTTP path to mint a license (licenses come only
// from signed Stripe webhooks), and no endpoint to read a license_id back, so the SDK E2E
// needs known credentials. AUTH_DEV_SEED="<account_id>,<license_id>,<subscription_id>"
// seeds an active subscription (max_pairs=1) and license directly into the store. The
// account itself is created at test time via the admin POST /v1/accounts (which sets the
// secret). This is dev-only and refuses to run against a non-memory store.
func seedDevData(ctx context.Context, store authstore.Store, cfg *authconfig.Config, log *slog.Logger) error {
	spec := os.Getenv("AUTH_DEV_SEED")
	if spec == "" {
		return nil
	}
	if cfg.Store != authconfig.StoreMemory {
		return errors.New("AUTH_DEV_SEED is only allowed with AUTH_STORE=memory")
	}
	parts := strings.Split(spec, ",")
	if len(parts) != 3 {
		return errors.New("AUTH_DEV_SEED must be account_id,license_id,subscription_id")
	}
	acct, lic, sub := parts[0], parts[1], parts[2]
	now := time.Now()
	if err := store.UpsertSubscription(ctx, authstore.Subscription{
		ID: sub, AccountID: acct, Status: authstore.SubActive, MaxPairs: 1,
		CurrentPeriodEnd: now.Add(365 * 24 * time.Hour), UpdatedAt: now,
	}); err != nil {
		return fmt.Errorf("seed subscription: %w", err)
	}
	if err := store.CreateLicense(ctx, authstore.License{
		ID: lic, AccountID: acct, SubscriptionID: sub, Status: authstore.LicenseActive, CreatedAt: now,
	}); err != nil && !errors.Is(err, authstore.ErrConflict) {
		return fmt.Errorf("seed license: %w", err)
	}
	log.Warn("DEV SEED active — provisioned test license (memory store only)",
		"account", acct, "license", lic, "subscription", sub)
	return nil
}

func buildStore(ctx context.Context, cfg *authconfig.Config) (authstore.Store, error) {
	switch cfg.Store {
	case authconfig.StoreMemory:
		return memstore.New(), nil
	case authconfig.StorePostgres:
		return pgstore.Open(ctx, cfg.DBDSN)
	default:
		return nil, fmt.Errorf("unknown store %q", cfg.Store)
	}
}

func buildBackplane(cfg *authconfig.Config) (backplane.Backplane, error) {
	const slotTTL = time.Minute // unused by auth (it only publishes revocations)
	switch cfg.Backplane {
	case authconfig.BackplaneMemory:
		return bpmem.New(slotTTL, 64), nil
	case authconfig.BackplaneRedis:
		return redisbp.New(cfg.RedisAddr, cfg.RedisPassword, cfg.RedisDB, slotTTL)
	default:
		return nil, fmt.Errorf("unknown backplane %q", cfg.Backplane)
	}
}

// keyFile is the devtoken-produced signer material (JSON). The auth service
// reuses it so `make keys` output works directly; a raw PEM private key file is
// also accepted.
type keyFile struct {
	Alg     string `json:"alg"`
	Kid     string `json:"kid"`
	PrivPEM string `json:"priv_pem"`
}

func loadSigner(cfg *authconfig.Config) (*signer.Signer, error) {
	data, err := os.ReadFile(cfg.SigningKeyFile)
	if err != nil {
		return nil, fmt.Errorf("read signing key: %w", err)
	}
	var kf keyFile
	if json.Unmarshal(data, &kf) == nil && kf.PrivPEM != "" {
		return signer.SignerFromPEM(kf.Alg, kf.Kid, []byte(kf.PrivPEM))
	}
	// Fall back to a raw PEM private key file, using the configured alg/kid.
	return signer.SignerFromPEM(cfg.JWTAlg, cfg.JWTKID, data)
}

func generateInstanceID() string {
	host, _ := os.Hostname()
	var buf [4]byte
	_, _ = rand.Read(buf[:])
	if host == "" {
		host = "auth"
	}
	return host + "-" + hex.EncodeToString(buf[:])
}
