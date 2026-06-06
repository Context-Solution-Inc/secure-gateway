package authconfig

import (
	"strings"
	"testing"
	"time"
)

func env(m map[string]string) getenvFn {
	return func(k string) string { return m[k] }
}

func base() map[string]string {
	return map[string]string{
		"AUTH_JWT_ISSUER":            "https://auth.example.com",
		"AUTH_JWT_SIGNING_KEY_FILE":  "/keys/auth.key.pem",
		"AUTH_STRIPE_WEBHOOK_SECRET": "whsec_x",
	}
}

func TestLoadDefaults(t *testing.T) {
	c, err := loadFrom(env(base()))
	if err != nil {
		t.Fatalf("load: %v", err)
	}
	if c.ListenAddr != ":8080" || c.JWTAudience != "relay" || c.JWTAlg != "ES256" {
		t.Fatalf("unexpected defaults: %+v", c)
	}
	if c.TokenTTL != 10*time.Minute || c.GracePeriod != 168*time.Hour {
		t.Fatalf("unexpected ttl/grace: token=%s grace=%s", c.TokenTTL, c.GracePeriod)
	}
	if c.Store != StoreMemory || c.Backplane != BackplaneMemory {
		t.Fatalf("unexpected backends: %+v", c)
	}
}

func TestLoadRequiredFields(t *testing.T) {
	for _, key := range []string{"AUTH_JWT_ISSUER", "AUTH_JWT_SIGNING_KEY_FILE", "AUTH_STRIPE_WEBHOOK_SECRET"} {
		m := base()
		delete(m, key)
		if _, err := loadFrom(env(m)); err == nil {
			t.Fatalf("expected error when %s missing", key)
		}
	}
}

func TestLoadPostgresRequiresDSN(t *testing.T) {
	m := base()
	m["AUTH_STORE"] = "postgres"
	if _, err := loadFrom(env(m)); err == nil || !strings.Contains(err.Error(), "AUTH_DB_DSN") {
		t.Fatalf("expected AUTH_DB_DSN error, got %v", err)
	}
	m["AUTH_DB_DSN"] = "postgres://localhost/db"
	if _, err := loadFrom(env(m)); err != nil {
		t.Fatalf("postgres with DSN should load: %v", err)
	}
}

func TestLoadRedisRequiresAddr(t *testing.T) {
	m := base()
	m["AUTH_BACKPLANE"] = "redis"
	if _, err := loadFrom(env(m)); err == nil || !strings.Contains(err.Error(), "AUTH_REDIS_ADDR") {
		t.Fatalf("expected AUTH_REDIS_ADDR error, got %v", err)
	}
}

func TestLoadRejectsBadAlg(t *testing.T) {
	m := base()
	m["AUTH_JWT_ALG"] = "HS256"
	if _, err := loadFrom(env(m)); err == nil {
		t.Fatal("expected rejection of symmetric alg")
	}
}
