// Package config loads and validates the relay configuration from environment
// variables (all prefixed RELAY_). It produces a typed Config; callers wire
// concrete dependencies (backplane, verifier) from it.
//
// The auth & license service (M2) will add a sibling sub-struct here without
// disturbing relay config.
package config

import (
	"errors"
	"fmt"
	"os"
	"strconv"
	"strings"
	"time"
)

// BackplaneKind selects the slot/routing/revocation backend.
type BackplaneKind string

const (
	BackplaneMemory BackplaneKind = "memory"
	BackplaneRedis  BackplaneKind = "redis"
)

// Config is the fully-resolved relay configuration.
type Config struct {
	// Server
	ListenAddr  string // RELAY_LISTEN_ADDR
	MetricsAddr string // RELAY_METRICS_ADDR; empty => served on the main listener at /metrics
	InstanceID  string // RELAY_INSTANCE_ID; auto-generated when empty

	// TLS
	TLSCertFile   string // RELAY_TLS_CERT_FILE; empty => plain HTTP (behind a TLS-terminating proxy)
	TLSKeyFile    string // RELAY_TLS_KEY_FILE
	TLSMinVersion string // RELAY_TLS_MIN_VERSION ("1.2" | "1.3")
	TrustProxy    bool   // RELAY_TRUST_PROXY: honor X-Forwarded-For for client IP

	// JWT verification
	JWTIssuer        string        // RELAY_JWT_ISSUER (required)
	JWTAudience      string        // RELAY_JWT_AUDIENCE
	JWTAlgs          []string      // RELAY_JWT_ALGS (allow-list)
	JWKSURL          string        // RELAY_JWKS_URL (prod); mutually exclusive with JWTPublicKeyFile
	JWTPublicKeyFile string        // RELAY_JWT_PUBLIC_KEY_FILE (dev/test, PEM)
	JWTLeeway        time.Duration // RELAY_JWT_LEEWAY

	// Protocol / session
	MaxMessageBytes int64         // RELAY_MAX_MESSAGE_BYTES
	PingInterval    time.Duration // RELAY_PING_INTERVAL
	PongTimeout     time.Duration // RELAY_PONG_TIMEOUT
	OutQueueSize    int           // RELAY_OUT_QUEUE_SIZE
	SlotTTL         time.Duration // RELAY_SLOT_TTL (must exceed 2x PingInterval)

	// Backplane
	Backplane     BackplaneKind // RELAY_BACKPLANE
	RedisAddr     string        // RELAY_REDIS_ADDR
	RedisPassword string        // RELAY_REDIS_PASSWORD
	RedisDB       int           // RELAY_REDIS_DB

	// Lifecycle
	ShutdownDrain time.Duration // RELAY_SHUTDOWN_DRAIN

	// Logging
	LogLevel  string // RELAY_LOG_LEVEL (debug|info|warn|error)
	LogFormat string // RELAY_LOG_FORMAT (json|text)
}

// getenv is overridable in tests.
type getenvFn func(string) string

// Load reads configuration from the process environment.
func Load() (*Config, error) {
	return loadFrom(os.Getenv)
}

func loadFrom(getenv getenvFn) (*Config, error) {
	c := &Config{
		ListenAddr:       str(getenv, "RELAY_LISTEN_ADDR", ":8443"),
		MetricsAddr:      str(getenv, "RELAY_METRICS_ADDR", ""),
		InstanceID:       str(getenv, "RELAY_INSTANCE_ID", ""),
		TLSCertFile:      str(getenv, "RELAY_TLS_CERT_FILE", ""),
		TLSKeyFile:       str(getenv, "RELAY_TLS_KEY_FILE", ""),
		TLSMinVersion:    str(getenv, "RELAY_TLS_MIN_VERSION", "1.2"),
		JWTIssuer:        str(getenv, "RELAY_JWT_ISSUER", ""),
		JWTAudience:      str(getenv, "RELAY_JWT_AUDIENCE", "relay"),
		JWKSURL:          str(getenv, "RELAY_JWKS_URL", ""),
		JWTPublicKeyFile: str(getenv, "RELAY_JWT_PUBLIC_KEY_FILE", ""),
		Backplane:        BackplaneKind(str(getenv, "RELAY_BACKPLANE", string(BackplaneMemory))),
		RedisAddr:        str(getenv, "RELAY_REDIS_ADDR", ""),
		RedisPassword:    str(getenv, "RELAY_REDIS_PASSWORD", ""),
		LogLevel:         str(getenv, "RELAY_LOG_LEVEL", "info"),
		LogFormat:        str(getenv, "RELAY_LOG_FORMAT", "json"),
	}

	var errs []error
	collect := func(err error) {
		if err != nil {
			errs = append(errs, err)
		}
	}

	c.JWTAlgs = strList(getenv, "RELAY_JWT_ALGS", []string{"ES256", "EdDSA"})
	c.TrustProxy = boolean(getenv, "RELAY_TRUST_PROXY", false, &errs)

	var err error
	if c.JWTLeeway, err = duration(getenv, "RELAY_JWT_LEEWAY", 30*time.Second); err != nil {
		collect(err)
	}
	if c.MaxMessageBytes, err = bytesize(getenv, "RELAY_MAX_MESSAGE_BYTES", 256*1024); err != nil {
		collect(err)
	}
	if c.PingInterval, err = duration(getenv, "RELAY_PING_INTERVAL", 25*time.Second); err != nil {
		collect(err)
	}
	if c.PongTimeout, err = duration(getenv, "RELAY_PONG_TIMEOUT", 25*time.Second); err != nil {
		collect(err)
	}
	if c.OutQueueSize, err = integer(getenv, "RELAY_OUT_QUEUE_SIZE", 64); err != nil {
		collect(err)
	}
	if c.SlotTTL, err = duration(getenv, "RELAY_SLOT_TTL", 60*time.Second); err != nil {
		collect(err)
	}
	if c.RedisDB, err = integer(getenv, "RELAY_REDIS_DB", 0); err != nil {
		collect(err)
	}
	if c.ShutdownDrain, err = duration(getenv, "RELAY_SHUTDOWN_DRAIN", 30*time.Second); err != nil {
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
		errs = append(errs, errors.New("RELAY_JWT_ISSUER is required"))
	}
	if c.JWKSURL == "" && c.JWTPublicKeyFile == "" {
		errs = append(errs, errors.New("one of RELAY_JWKS_URL or RELAY_JWT_PUBLIC_KEY_FILE is required"))
	}
	if c.JWKSURL != "" && c.JWTPublicKeyFile != "" {
		errs = append(errs, errors.New("RELAY_JWKS_URL and RELAY_JWT_PUBLIC_KEY_FILE are mutually exclusive"))
	}
	if len(c.JWTAlgs) == 0 {
		errs = append(errs, errors.New("RELAY_JWT_ALGS must list at least one algorithm"))
	}
	for _, a := range c.JWTAlgs {
		switch a {
		case "ES256", "ES384", "ES512", "EdDSA":
		default:
			errs = append(errs, fmt.Errorf("RELAY_JWT_ALGS: unsupported or insecure algorithm %q (asymmetric only)", a))
		}
	}

	if (c.TLSCertFile == "") != (c.TLSKeyFile == "") {
		errs = append(errs, errors.New("RELAY_TLS_CERT_FILE and RELAY_TLS_KEY_FILE must be set together"))
	}
	switch c.TLSMinVersion {
	case "1.2", "1.3":
	default:
		errs = append(errs, fmt.Errorf("RELAY_TLS_MIN_VERSION must be 1.2 or 1.3, got %q", c.TLSMinVersion))
	}

	switch c.Backplane {
	case BackplaneMemory:
	case BackplaneRedis:
		if c.RedisAddr == "" {
			errs = append(errs, errors.New("RELAY_REDIS_ADDR is required when RELAY_BACKPLANE=redis"))
		}
	default:
		errs = append(errs, fmt.Errorf("RELAY_BACKPLANE must be memory or redis, got %q", c.Backplane))
	}

	if c.MaxMessageBytes <= 0 {
		errs = append(errs, errors.New("RELAY_MAX_MESSAGE_BYTES must be positive"))
	}
	if c.OutQueueSize <= 0 {
		errs = append(errs, errors.New("RELAY_OUT_QUEUE_SIZE must be positive"))
	}
	if c.PingInterval <= 0 {
		errs = append(errs, errors.New("RELAY_PING_INTERVAL must be positive"))
	}
	// Slot TTL must outlive a missed-heartbeat window so a live connection never
	// loses its slot to TTL expiry between renewals.
	if c.SlotTTL <= 2*c.PingInterval {
		errs = append(errs, fmt.Errorf("RELAY_SLOT_TTL (%s) must exceed 2x RELAY_PING_INTERVAL (%s)", c.SlotTTL, c.PingInterval))
	}

	switch c.LogLevel {
	case "debug", "info", "warn", "error":
	default:
		errs = append(errs, fmt.Errorf("RELAY_LOG_LEVEL must be debug|info|warn|error, got %q", c.LogLevel))
	}
	switch c.LogFormat {
	case "json", "text":
	default:
		errs = append(errs, fmt.Errorf("RELAY_LOG_FORMAT must be json|text, got %q", c.LogFormat))
	}

	return errors.Join(errs...)
}

// --- small env helpers ---

func str(getenv getenvFn, key, def string) string {
	if v := getenv(key); v != "" {
		return v
	}
	return def
}

func strList(getenv getenvFn, key string, def []string) []string {
	v := getenv(key)
	if v == "" {
		return def
	}
	parts := strings.Split(v, ",")
	out := make([]string, 0, len(parts))
	for _, p := range parts {
		if p = strings.TrimSpace(p); p != "" {
			out = append(out, p)
		}
	}
	return out
}

func boolean(getenv getenvFn, key string, def bool, errs *[]error) bool {
	v := getenv(key)
	if v == "" {
		return def
	}
	b, err := strconv.ParseBool(v)
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
	n, err := strconv.Atoi(v)
	if err != nil {
		return def, fmt.Errorf("%s: %w", key, err)
	}
	return n, nil
}

func bytesize(getenv getenvFn, key string, def int64) (int64, error) {
	v := getenv(key)
	if v == "" {
		return def, nil
	}
	n, err := strconv.ParseInt(v, 10, 64)
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
