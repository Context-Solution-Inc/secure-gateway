package config

import (
	"strings"
	"testing"
	"time"
)

// env builds a getenv func from a map for hermetic tests.
func env(m map[string]string) getenvFn {
	return func(k string) string { return m[k] }
}

// valid is the minimum environment that loads successfully (dev/static-key mode).
func valid() map[string]string {
	return map[string]string{
		"RELAY_JWT_ISSUER":          "https://auth.example.com",
		"RELAY_JWT_PUBLIC_KEY_FILE": "/keys/relay.pem",
	}
}

func TestLoadDefaults(t *testing.T) {
	c, err := loadFrom(env(valid()))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if c.ListenAddr != ":8443" {
		t.Errorf("ListenAddr = %q, want :8443", c.ListenAddr)
	}
	if c.JWTAudience != "relay" {
		t.Errorf("JWTAudience = %q, want relay", c.JWTAudience)
	}
	if c.MaxMessageBytes != 256*1024 {
		t.Errorf("MaxMessageBytes = %d, want %d", c.MaxMessageBytes, 256*1024)
	}
	if c.PingInterval != 25*time.Second {
		t.Errorf("PingInterval = %s, want 25s", c.PingInterval)
	}
	if c.SlotTTL != 60*time.Second {
		t.Errorf("SlotTTL = %s, want 60s", c.SlotTTL)
	}
	if c.Backplane != BackplaneMemory {
		t.Errorf("Backplane = %q, want memory", c.Backplane)
	}
	want := []string{"ES256", "EdDSA"}
	if strings.Join(c.JWTAlgs, ",") != strings.Join(want, ",") {
		t.Errorf("JWTAlgs = %v, want %v", c.JWTAlgs, want)
	}
}

func TestLoadOverrides(t *testing.T) {
	m := valid()
	m["RELAY_LISTEN_ADDR"] = ":9000"
	m["RELAY_MAX_MESSAGE_BYTES"] = "1048576"
	m["RELAY_PING_INTERVAL"] = "10s"
	m["RELAY_SLOT_TTL"] = "45s"
	m["RELAY_JWT_ALGS"] = "EdDSA, ES384"
	m["RELAY_TRUST_PROXY"] = "true"
	c, err := loadFrom(env(m))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if c.ListenAddr != ":9000" {
		t.Errorf("ListenAddr = %q", c.ListenAddr)
	}
	if c.MaxMessageBytes != 1048576 {
		t.Errorf("MaxMessageBytes = %d", c.MaxMessageBytes)
	}
	if !c.TrustProxy {
		t.Errorf("TrustProxy = false, want true")
	}
	if strings.Join(c.JWTAlgs, ",") != "EdDSA,ES384" {
		t.Errorf("JWTAlgs = %v", c.JWTAlgs)
	}
}

func TestValidationErrors(t *testing.T) {
	tests := []struct {
		name   string
		mutate func(map[string]string)
		substr string
	}{
		{"missing issuer", func(m map[string]string) { delete(m, "RELAY_JWT_ISSUER") }, "RELAY_JWT_ISSUER is required"},
		{"no key source", func(m map[string]string) { delete(m, "RELAY_JWT_PUBLIC_KEY_FILE") }, "RELAY_JWKS_URL or RELAY_JWT_PUBLIC_KEY_FILE"},
		{"both key sources", func(m map[string]string) { m["RELAY_JWKS_URL"] = "https://auth/jwks" }, "mutually exclusive"},
		{"insecure alg", func(m map[string]string) { m["RELAY_JWT_ALGS"] = "HS256" }, "asymmetric only"},
		{"half tls", func(m map[string]string) { m["RELAY_TLS_CERT_FILE"] = "/c.pem" }, "must be set together"},
		{"bad tls version", func(m map[string]string) { m["RELAY_TLS_MIN_VERSION"] = "1.1" }, "RELAY_TLS_MIN_VERSION"},
		{"redis without addr", func(m map[string]string) { m["RELAY_BACKPLANE"] = "redis" }, "RELAY_REDIS_ADDR is required"},
		{"bad backplane", func(m map[string]string) { m["RELAY_BACKPLANE"] = "kafka" }, "RELAY_BACKPLANE must be"},
		{"slot ttl too small", func(m map[string]string) { m["RELAY_SLOT_TTL"] = "30s" }, "must exceed 2x"},
		{"bad duration", func(m map[string]string) { m["RELAY_PING_INTERVAL"] = "soon" }, "RELAY_PING_INTERVAL"},
		{"bad log level", func(m map[string]string) { m["RELAY_LOG_LEVEL"] = "loud" }, "RELAY_LOG_LEVEL"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			m := valid()
			tt.mutate(m)
			_, err := loadFrom(env(m))
			if err == nil {
				t.Fatalf("expected error containing %q, got nil", tt.substr)
			}
			if !strings.Contains(err.Error(), tt.substr) {
				t.Errorf("error %q does not contain %q", err.Error(), tt.substr)
			}
		})
	}
}

func TestRedisConfigValid(t *testing.T) {
	m := valid()
	m["RELAY_BACKPLANE"] = "redis"
	m["RELAY_REDIS_ADDR"] = "localhost:6379"
	m["RELAY_REDIS_DB"] = "2"
	c, err := loadFrom(env(m))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if c.RedisDB != 2 {
		t.Errorf("RedisDB = %d, want 2", c.RedisDB)
	}
}
