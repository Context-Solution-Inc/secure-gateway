package authconfig

import (
	"strings"
	"testing"
	"time"
)

func env(m map[string]string) getenvFn {
	return func(k string) string { return m[k] }
}

// base is a valid Stripe-enabled configuration: the three Stripe credentials are
// an all-or-none unit, so a usable baseline supplies all three plus the public
// URL the checkout return needs.
func base() map[string]string {
	return map[string]string{
		"AUTH_JWT_ISSUER":            "https://auth.example.com",
		"AUTH_JWT_SIGNING_KEY_FILE":  "/keys/auth.key.pem",
		"AUTH_STRIPE_WEBHOOK_SECRET": "whsec_x",
		"AUTH_STRIPE_SECRET_KEY":     "sk_test_x",
		"AUTH_STRIPE_PRICE_ID":       "price_x",
		"AUTH_PUBLIC_URL":            "https://auth.example.com",
	}
}

// noStripe is a valid billing-disabled configuration: no Stripe credentials and
// the explicit opt-out acknowledgement.
func noStripe() map[string]string {
	return map[string]string{
		"AUTH_JWT_ISSUER":           "https://auth.example.com",
		"AUTH_JWT_SIGNING_KEY_FILE": "/keys/auth.key.pem",
		"AUTH_BILLING_DISABLED":     "true",
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

func TestStripeEnabledWithFullConfig(t *testing.T) {
	c, err := loadFrom(env(base()))
	if err != nil {
		t.Fatalf("load: %v", err)
	}
	if !c.StripeEnabled {
		t.Fatal("expected StripeEnabled with all three credentials set")
	}
}

func TestStripeEnabledRequiresPublicURL(t *testing.T) {
	m := base()
	delete(m, "AUTH_PUBLIC_URL")
	if _, err := loadFrom(env(m)); err == nil || !strings.Contains(err.Error(), "AUTH_PUBLIC_URL") {
		t.Fatalf("expected AUTH_PUBLIC_URL error when Stripe enabled, got %v", err)
	}
}

func TestBillingDisabledWithFlag(t *testing.T) {
	c, err := loadFrom(env(noStripe()))
	if err != nil {
		t.Fatalf("billing-disabled config should load: %v", err)
	}
	if c.StripeEnabled {
		t.Fatal("expected StripeEnabled=false with no Stripe credentials")
	}
}

func TestNoStripeWithoutFlagRefusesToBoot(t *testing.T) {
	m := noStripe()
	delete(m, "AUTH_BILLING_DISABLED")
	_, err := loadFrom(env(m))
	if err == nil || !strings.Contains(err.Error(), "AUTH_BILLING_DISABLED") {
		t.Fatalf("expected refuse-to-boot error pointing at AUTH_BILLING_DISABLED, got %v", err)
	}
}

func TestPartialStripeConfigErrorsAndNamesMissing(t *testing.T) {
	all := []string{"AUTH_STRIPE_WEBHOOK_SECRET", "AUTH_STRIPE_SECRET_KEY", "AUTH_STRIPE_PRICE_ID"}
	// Drop each var individually from a full config: any partial combination must
	// error and name exactly the missing var(s), even with the opt-out flag set.
	for _, missing := range all {
		m := base()
		delete(m, missing)
		m["AUTH_BILLING_DISABLED"] = "true" // must not rescue a partial config
		_, err := loadFrom(env(m))
		if err == nil {
			t.Fatalf("expected error for partial Stripe config missing %s", missing)
		}
		if !strings.Contains(err.Error(), missing) {
			t.Fatalf("error should name missing var %s, got %v", missing, err)
		}
		for _, present := range all {
			if present != missing && strings.Contains(err.Error(), "missing: ") &&
				strings.Contains(strings.SplitN(err.Error(), "missing: ", 2)[1], present) {
				t.Fatalf("error should not list present var %s as missing: %v", present, err)
			}
		}
	}
}
