// Package authconfig loads and validates the Auth & License Service
// configuration from environment variables (all prefixed AUTH_). It produces a
// typed Config; cmd/auth wires concrete dependencies (store, backplane, signer,
// Stripe) from it. Mirrors internal/config's helper/validation style.
package authconfig

import (
	"errors"
	"fmt"
	"os"
	"strconv"
	"strings"
	"time"
)

// StoreKind selects the authstore backend.
type StoreKind string

const (
	StoreMemory   StoreKind = "memory"
	StorePostgres StoreKind = "postgres"
)

// BackplaneKind selects the revocation-publish backend.
type BackplaneKind string

const (
	BackplaneMemory BackplaneKind = "memory"
	BackplaneRedis  BackplaneKind = "redis"
)

// Config is the fully-resolved auth-service configuration.
type Config struct {
	// Server
	ListenAddr  string // AUTH_LISTEN_ADDR
	MetricsAddr string // AUTH_METRICS_ADDR; empty => /metrics on the main listener, else a private listener (SG-06/SG-11)
	InstanceID  string // AUTH_INSTANCE_ID; auto-generated when empty

	// TLS
	TLSCertFile   string // AUTH_TLS_CERT_FILE; empty => plain HTTP (behind a TLS-terminating proxy)
	TLSKeyFile    string // AUTH_TLS_KEY_FILE
	TLSMinVersion string // AUTH_TLS_MIN_VERSION ("1.2" | "1.3")

	// Datastore
	Store StoreKind // AUTH_STORE (memory|postgres)
	DBDSN string    // AUTH_DB_DSN (required for postgres)

	// Backplane (for publishing revocations)
	Backplane     BackplaneKind // AUTH_BACKPLANE (memory|redis)
	RedisAddr     string        // AUTH_REDIS_ADDR
	RedisPassword string        // AUTH_REDIS_PASSWORD
	RedisDB       int           // AUTH_REDIS_DB

	// JWT signing (the relay verifies with the public half via JWKS)
	JWTIssuer      string        // AUTH_JWT_ISSUER (required)
	JWTAudience    string        // AUTH_JWT_AUDIENCE
	JWTAlg         string        // AUTH_JWT_ALG (ES256|EdDSA)
	JWTKID         string        // AUTH_JWT_KID
	SigningKeyFile string        // AUTH_JWT_SIGNING_KEY_FILE (PKCS#8 PEM private key)
	TokenTTL       time.Duration // AUTH_TOKEN_TTL (connection JWT lifetime)
	RefreshTTL     time.Duration // AUTH_REFRESH_TTL (refresh token lifetime)

	// Pairing (QR flow, FR-2.1)
	PairingTokenTTL time.Duration // AUTH_PAIRING_TOKEN_TTL (one-time QR token lifetime; ≤ 5m)
	RelayURL        string        // AUTH_RELAY_URL (advertised in the QR endpoints)
	PublicURL       string        // AUTH_PUBLIC_URL (this service's URL, advertised in the QR endpoints)

	// Licensing
	GracePeriod time.Duration // AUTH_GRACE_PERIOD (past_due grace; PRD default 7d)

	// AdminKey gates account-secret provisioning (POST /v1/accounts). This is the
	// M2 seam for the (undecided, OQ5) account backend to mint an auth-service
	// credential for an account; when empty the endpoint is disabled.
	AdminKey string // AUTH_ADMIN_KEY

	// Stripe. The three credential vars below are an all-or-none unit: set all
	// three to enable billing, or none (with BillingDisabled=true) to run the
	// gateway with secure links ungated. Any partial combination is rejected at
	// load so an accidental omission can never silently disable gating.
	StripeSecretKey     string        // AUTH_STRIPE_SECRET_KEY (reconciliation + checkout API)
	StripeWebhookSecret string        // AUTH_STRIPE_WEBHOOK_SECRET (subscription webhooks)
	StripePriceID       string        // AUTH_STRIPE_PRICE_ID (desktop subscription plan; enables /checkout/start)
	ReconcileInterval   time.Duration // AUTH_RECONCILE_INTERVAL (nightly heal)

	// BillingDisabled (AUTH_BILLING_DISABLED) is the explicit acknowledgement
	// required to boot with no Stripe configuration. StripeEnabled is the
	// resolved verdict: true iff all three Stripe credentials are present.
	BillingDisabled bool
	StripeEnabled   bool

	// Desktop subscription onboarding (claim-token flow).
	ClaimTTL time.Duration // AUTH_CLAIM_TTL (one-time checkout-claim lifetime; default 30m)

	// Rate limiting (PRD §10.2). In-process, per-instance.
	TrustProxy             bool // AUTH_TRUST_PROXY: honor X-Forwarded-For for client IP
	RateLimitEnabled       bool // AUTH_RATELIMIT_ENABLED (default true)
	RateLimitIPPerMin      int  // AUTH_RATELIMIT_IP_PER_MIN: per-IP requests/min on sensitive endpoints
	RateLimitIPBurst       int  // AUTH_RATELIMIT_IP_BURST
	RateLimitAccountPerMin int  // AUTH_RATELIMIT_ACCOUNT_PER_MIN: per-account auth attempts/min
	RateLimitAccountBurst  int  // AUTH_RATELIMIT_ACCOUNT_BURST

	// Lifecycle
	ShutdownDrain time.Duration // AUTH_SHUTDOWN_DRAIN

	// Logging
	LogLevel  string // AUTH_LOG_LEVEL (debug|info|warn|error)
	LogFormat string // AUTH_LOG_FORMAT (json|text)
}

type getenvFn func(string) string

// Load reads configuration from the process environment.
func Load() (*Config, error) { return loadFrom(os.Getenv) }

func loadFrom(getenv getenvFn) (*Config, error) {
	c := &Config{
		ListenAddr:          str(getenv, "AUTH_LISTEN_ADDR", ":8080"),
		MetricsAddr:         str(getenv, "AUTH_METRICS_ADDR", ""),
		InstanceID:          str(getenv, "AUTH_INSTANCE_ID", ""),
		TLSCertFile:         str(getenv, "AUTH_TLS_CERT_FILE", ""),
		TLSKeyFile:          str(getenv, "AUTH_TLS_KEY_FILE", ""),
		TLSMinVersion:       str(getenv, "AUTH_TLS_MIN_VERSION", "1.2"),
		Store:               StoreKind(str(getenv, "AUTH_STORE", string(StoreMemory))),
		DBDSN:               str(getenv, "AUTH_DB_DSN", ""),
		Backplane:           BackplaneKind(str(getenv, "AUTH_BACKPLANE", string(BackplaneMemory))),
		RedisAddr:           str(getenv, "AUTH_REDIS_ADDR", ""),
		RedisPassword:       str(getenv, "AUTH_REDIS_PASSWORD", ""),
		JWTIssuer:           str(getenv, "AUTH_JWT_ISSUER", ""),
		JWTAudience:         str(getenv, "AUTH_JWT_AUDIENCE", "relay"),
		JWTAlg:              str(getenv, "AUTH_JWT_ALG", "ES256"),
		JWTKID:              str(getenv, "AUTH_JWT_KID", "auth-1"),
		SigningKeyFile:      str(getenv, "AUTH_JWT_SIGNING_KEY_FILE", ""),
		StripeSecretKey:     str(getenv, "AUTH_STRIPE_SECRET_KEY", ""),
		StripeWebhookSecret: str(getenv, "AUTH_STRIPE_WEBHOOK_SECRET", ""),
		StripePriceID:       str(getenv, "AUTH_STRIPE_PRICE_ID", ""),
		AdminKey:            str(getenv, "AUTH_ADMIN_KEY", ""),
		RelayURL:            str(getenv, "AUTH_RELAY_URL", ""),
		PublicURL:           str(getenv, "AUTH_PUBLIC_URL", ""),
		LogLevel:            str(getenv, "AUTH_LOG_LEVEL", "info"),
		LogFormat:           str(getenv, "AUTH_LOG_FORMAT", "json"),
	}

	var errs []error
	collect := func(err error) {
		if err != nil {
			errs = append(errs, err)
		}
	}

	c.TrustProxy = boolean(getenv, "AUTH_TRUST_PROXY", false, &errs)
	c.RateLimitEnabled = boolean(getenv, "AUTH_RATELIMIT_ENABLED", true, &errs)
	c.BillingDisabled = boolean(getenv, "AUTH_BILLING_DISABLED", false, &errs)

	var err error
	if c.RedisDB, err = integer(getenv, "AUTH_REDIS_DB", 0); err != nil {
		collect(err)
	}
	if c.RateLimitIPPerMin, err = integer(getenv, "AUTH_RATELIMIT_IP_PER_MIN", 60); err != nil {
		collect(err)
	}
	if c.RateLimitIPBurst, err = integer(getenv, "AUTH_RATELIMIT_IP_BURST", 20); err != nil {
		collect(err)
	}
	if c.RateLimitAccountPerMin, err = integer(getenv, "AUTH_RATELIMIT_ACCOUNT_PER_MIN", 30); err != nil {
		collect(err)
	}
	if c.RateLimitAccountBurst, err = integer(getenv, "AUTH_RATELIMIT_ACCOUNT_BURST", 10); err != nil {
		collect(err)
	}
	if c.TokenTTL, err = duration(getenv, "AUTH_TOKEN_TTL", 10*time.Minute); err != nil {
		collect(err)
	}
	if c.RefreshTTL, err = duration(getenv, "AUTH_REFRESH_TTL", 720*time.Hour); err != nil {
		collect(err)
	}
	if c.PairingTokenTTL, err = duration(getenv, "AUTH_PAIRING_TOKEN_TTL", 5*time.Minute); err != nil {
		collect(err)
	}
	if c.GracePeriod, err = duration(getenv, "AUTH_GRACE_PERIOD", 168*time.Hour); err != nil {
		collect(err)
	}
	if c.ReconcileInterval, err = duration(getenv, "AUTH_RECONCILE_INTERVAL", 24*time.Hour); err != nil {
		collect(err)
	}
	if c.ClaimTTL, err = duration(getenv, "AUTH_CLAIM_TTL", 30*time.Minute); err != nil {
		collect(err)
	}
	if c.ShutdownDrain, err = duration(getenv, "AUTH_SHUTDOWN_DRAIN", 30*time.Second); err != nil {
		collect(err)
	}

	collect(c.validate())

	if len(errs) > 0 {
		return nil, fmt.Errorf("invalid configuration: %w", errors.Join(errs...))
	}
	return c, nil
}

func (c *Config) validate() error {
	var errs []error

	if c.JWTIssuer == "" {
		errs = append(errs, errors.New("AUTH_JWT_ISSUER is required"))
	}
	if c.SigningKeyFile == "" {
		errs = append(errs, errors.New("AUTH_JWT_SIGNING_KEY_FILE is required"))
	}
	switch c.JWTAlg {
	case "ES256", "EdDSA":
	default:
		errs = append(errs, fmt.Errorf("AUTH_JWT_ALG must be ES256 or EdDSA, got %q", c.JWTAlg))
	}
	// Stripe is all-or-none. The three credentials enable billing together; with
	// none set the gateway may run ungated only when the operator explicitly
	// acknowledges it via AUTH_BILLING_DISABLED=true. Any partial combination is
	// a configuration error so dropping a single var (e.g. AUTH_STRIPE_PRICE_ID)
	// fails loudly instead of silently disabling subscription gating.
	switch n := stripeVarsSet(c); n {
	case 3:
		c.StripeEnabled = true
		// The desktop checkout flow needs a public URL (the Stripe success_url
		// base, /v1/checkout/return).
		if c.PublicURL == "" {
			errs = append(errs, errors.New("AUTH_PUBLIC_URL is required when Stripe is enabled"))
		}
	case 0:
		c.StripeEnabled = false
		if !c.BillingDisabled {
			errs = append(errs, errors.New("Stripe is not configured: set AUTH_STRIPE_WEBHOOK_SECRET, AUTH_STRIPE_SECRET_KEY and AUTH_STRIPE_PRICE_ID, or set AUTH_BILLING_DISABLED=true to run the gateway without billing (secure links ungated)"))
		}
	default:
		c.StripeEnabled = false
		errs = append(errs, fmt.Errorf("incomplete Stripe configuration: set all three of AUTH_STRIPE_WEBHOOK_SECRET, AUTH_STRIPE_SECRET_KEY, AUTH_STRIPE_PRICE_ID (or none with AUTH_BILLING_DISABLED=true); missing: %s", strings.Join(missingStripeVars(c), ", ")))
	}

	if (c.TLSCertFile == "") != (c.TLSKeyFile == "") {
		errs = append(errs, errors.New("AUTH_TLS_CERT_FILE and AUTH_TLS_KEY_FILE must be set together"))
	}
	switch c.TLSMinVersion {
	case "1.2", "1.3":
	default:
		errs = append(errs, fmt.Errorf("AUTH_TLS_MIN_VERSION must be 1.2 or 1.3, got %q", c.TLSMinVersion))
	}

	switch c.Store {
	case StoreMemory:
	case StorePostgres:
		if c.DBDSN == "" {
			errs = append(errs, errors.New("AUTH_DB_DSN is required when AUTH_STORE=postgres"))
		}
	default:
		errs = append(errs, fmt.Errorf("AUTH_STORE must be memory or postgres, got %q", c.Store))
	}

	switch c.Backplane {
	case BackplaneMemory:
	case BackplaneRedis:
		if c.RedisAddr == "" {
			errs = append(errs, errors.New("AUTH_REDIS_ADDR is required when AUTH_BACKPLANE=redis"))
		}
	default:
		errs = append(errs, fmt.Errorf("AUTH_BACKPLANE must be memory or redis, got %q", c.Backplane))
	}

	if c.TokenTTL <= 0 {
		errs = append(errs, errors.New("AUTH_TOKEN_TTL must be positive"))
	}
	if c.RefreshTTL <= 0 {
		errs = append(errs, errors.New("AUTH_REFRESH_TTL must be positive"))
	}
	if c.PairingTokenTTL <= 0 || c.PairingTokenTTL > 5*time.Minute {
		errs = append(errs, errors.New("AUTH_PAIRING_TOKEN_TTL must be positive and ≤ 5m (FR-2.1)"))
	}

	if c.RateLimitEnabled {
		if c.RateLimitIPPerMin <= 0 || c.RateLimitIPBurst <= 0 {
			errs = append(errs, errors.New("AUTH_RATELIMIT_IP_PER_MIN and AUTH_RATELIMIT_IP_BURST must be positive when AUTH_RATELIMIT_ENABLED=true"))
		}
		if c.RateLimitAccountPerMin <= 0 || c.RateLimitAccountBurst <= 0 {
			errs = append(errs, errors.New("AUTH_RATELIMIT_ACCOUNT_PER_MIN and AUTH_RATELIMIT_ACCOUNT_BURST must be positive when AUTH_RATELIMIT_ENABLED=true"))
		}
	}

	switch c.LogLevel {
	case "debug", "info", "warn", "error":
	default:
		errs = append(errs, fmt.Errorf("AUTH_LOG_LEVEL must be debug|info|warn|error, got %q", c.LogLevel))
	}
	switch c.LogFormat {
	case "json", "text":
	default:
		errs = append(errs, fmt.Errorf("AUTH_LOG_FORMAT must be json|text, got %q", c.LogFormat))
	}

	return errors.Join(errs...)
}

// stripeVarsSet counts how many of the three all-or-none Stripe credentials are
// present (webhook secret, secret key, price id).
func stripeVarsSet(c *Config) int {
	n := 0
	for _, v := range []string{c.StripeWebhookSecret, c.StripeSecretKey, c.StripePriceID} {
		if v != "" {
			n++
		}
	}
	return n
}

// missingStripeVars names the Stripe credentials that are absent, for a precise
// error on a partial configuration.
func missingStripeVars(c *Config) []string {
	var missing []string
	if c.StripeWebhookSecret == "" {
		missing = append(missing, "AUTH_STRIPE_WEBHOOK_SECRET")
	}
	if c.StripeSecretKey == "" {
		missing = append(missing, "AUTH_STRIPE_SECRET_KEY")
	}
	if c.StripePriceID == "" {
		missing = append(missing, "AUTH_STRIPE_PRICE_ID")
	}
	return missing
}

// --- small env helpers (mirrors internal/config) ---

func str(getenv getenvFn, key, def string) string {
	if v := getenv(key); v != "" {
		return v
	}
	return def
}

func boolean(getenv getenvFn, key string, def bool, errs *[]error) bool {
	v := getenv(key)
	if v == "" {
		return def
	}
	b, err := strconv.ParseBool(strings.TrimSpace(v))
	if err != nil {
		*errs = append(*errs, fmt.Errorf("%s: %w", key, err))
		return def
	}
	return b
}

func integer(getenv getenvFn, key string, def int) (int, error) {
	v := getenv(key)
	if v == "" {
		return def, nil
	}
	n, err := strconv.Atoi(strings.TrimSpace(v))
	if err != nil {
		return def, fmt.Errorf("%s: %w", key, err)
	}
	return n, nil
}

func duration(getenv getenvFn, key string, def time.Duration) (time.Duration, error) {
	v := getenv(key)
	if v == "" {
		return def, nil
	}
	d, err := time.ParseDuration(v)
	if err != nil {
		return def, fmt.Errorf("%s: %w", key, err)
	}
	return d, nil
}
