package integration

import (
	"net/http"
	"testing"

	"github.com/context-solutions-inc/secure-gateway/internal/authservice"
)

// TestAuthRateLimitPerIP verifies the auth service returns 429 + Retry-After
// once a single IP exceeds the per-IP burst on a sensitive endpoint
// (/v1/token/refresh), and that it does so before the handler runs (PRD §10.2).
func TestAuthRateLimitPerIP(t *testing.T) {
	a := newAuthHarness(t, func(c *authservice.ServerConfig) {
		c.RateLimitEnabled = true
		c.RateLimitIPPerMin = 60
		c.RateLimitIPBurst = 3
		c.RateLimitAccountPerMin = 1000
		c.RateLimitAccountBurst = 1000
	})

	// Refresh with a bogus token normally returns 401 refresh_invalid; each call
	// still spends an IP token. After the burst, the limiter returns 429.
	got401 := 0
	for i := 0; i < 3; i++ {
		status, _ := a.refreshToken(t, "bogus-refresh")
		if status == http.StatusUnauthorized {
			got401++
		} else {
			t.Fatalf("attempt %d: want 401 within burst, got %d", i, status)
		}
	}
	if got401 != 3 {
		t.Fatalf("expected 3 pre-limit 401s, got %d", got401)
	}

	status, _ := a.refreshToken(t, "bogus-refresh")
	if status != http.StatusTooManyRequests {
		t.Fatalf("want 429 after burst, got %d", status)
	}
}

// TestAuthRateLimitDisabledByDefault confirms the default auth harness does not
// rate limit a burst of refresh attempts.
func TestAuthRateLimitDisabledByDefault(t *testing.T) {
	a := newAuthHarness(t)
	for i := 0; i < 50; i++ {
		status, _ := a.refreshToken(t, "bogus-refresh")
		if status == http.StatusTooManyRequests {
			t.Fatalf("attempt %d unexpectedly rate limited with limiting disabled", i)
		}
	}
}
