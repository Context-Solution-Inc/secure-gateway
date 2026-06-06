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
	ListenAddr string // AUTH_LISTEN_ADDR
	InstanceID string // AUTH_INSTANCE_ID; auto-generated when empty

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

	// Stripe
	StripeSecretKey     string        // AUTH_STRIPE_SECRET_KEY (for reconciliation API)
	StripeWebhookSecret string        // AUTH_STRIPE_WEBHOOK_SECRET (required)
	ReconcileInterval   time.Duration // AUTH_RECONCILE_INTERVAL (nightly heal)

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

	var err error
	if c.RedisDB, err = integer(getenv, "AUTH_REDIS_DB", 0); err != nil {
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
	if c.StripeWebhookSecret == "" {
		errs = append(errs, errors.New("AUTH_STRIPE_WEBHOOK_SECRET is required"))
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

// --- small env helpers (mirrors internal/config) ---

func str(getenv getenvFn, key, def string) string {
	if v := getenv(key); v != "" {
		return v
	}
	return def
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
