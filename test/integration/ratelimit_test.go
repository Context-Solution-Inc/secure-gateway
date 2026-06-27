package integration

import (
	"context"
	"net/http"
	"strconv"
	"testing"
	"time"

	"github.com/prometheus/client_golang/prometheus/testutil"

	"github.com/context-solutions-inc/secure-gateway/internal/config"
	"github.com/context-solutions-inc/secure-gateway/internal/token"
)

// TestRateLimitPerIPRejectsBeforeUpgrade verifies the relay returns HTTP 429 +
// Retry-After once a single IP exceeds the connection-attempt burst, and that
// the rejection happens before the WebSocket upgrade (PRD §10.2, FR-1.3).
func TestRateLimitPerIPRejectsBeforeUpgrade(t *testing.T) {
	h := newHarnessFull(t, nil, nil, defaultSessionOptions(), func(c *config.Config) {
		c.RateLimitEnabled = true
		c.RateLimitIPPerMin = 60 // 1/s sustained
		c.RateLimitIPBurst = 2
		c.AbuseStrikeThreshold = 0 // bans disabled for this test
	})

	url := h.httpSrv.URL + "/v1/connect"
	// The burst (2) is consumed by unauthenticated attempts (each returns 401
	// missing_token but still spends a token); the next attempt trips the limiter.
	for i := 0; i < 2; i++ {
		resp, err := http.Get(url)
		if err != nil {
			t.Fatal(err)
		}
		resp.Body.Close()
		if resp.StatusCode != http.StatusUnauthorized {
			t.Fatalf("attempt %d: want 401 (missing token), got %d", i, resp.StatusCode)
		}
	}

	resp, err := http.Get(url)
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusTooManyRequests {
		t.Fatalf("want 429 after burst, got %d", resp.StatusCode)
	}
	if ra := resp.Header.Get("Retry-After"); ra == "" {
		t.Fatal("429 response missing Retry-After header")
	}
	if got := testutil.ToFloat64(h.metrics.RateLimited.WithLabelValues("ip")); got < 1 {
		t.Errorf("relay_rate_limited_total{kind=ip} = %v, want >= 1", got)
	}
}

// TestAbuseBanAfterProtocolStrikes verifies that repeated protocol-error frames
// (close 4005) from one IP earn a temporary ban that rejects later connection
// attempts with 429 (PRD §10.2).
func TestAbuseBanAfterProtocolStrikes(t *testing.T) {
	const threshold = 3
	h := newHarnessFull(t, nil, nil, defaultSessionOptions(), func(c *config.Config) {
		c.RateLimitEnabled = true
		c.RateLimitIPPerMin = 100000 // effectively unlimited for this test
		c.RateLimitIPBurst = 100000
		c.AbuseStrikeThreshold = threshold
		c.AbuseStrikeWindow = time.Minute
		c.AbuseBanWindow = time.Minute
	})

	for i := 0; i < threshold; i++ {
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		// Distinct pair per iteration so slot eviction never races with the
		// reconnect; strikes still accrue on the (shared) source IP.
		pair := "pair_ban_" + strconv.Itoa(i)
		cl, err := h.dial(t, ctx, h.mint(t, pair, "dev_m", token.RoleMobile))
		if err != nil {
			cancel()
			t.Fatalf("strike %d: dial failed: %v", i, err)
		}
		// An undecodable frame is a protocol error: the relay records a strike
		// (synchronously, in its read loop) and closes the session. We only wait
		// for the close here — the exact 4005 code is covered by the protocol-error
		// tests and its delivery is timing-sensitive under -race; the ban outcome
		// asserted below is the behavior under test.
		if err := cl.SendRaw(ctx, []byte("not-json")); err != nil {
			cancel()
			t.Fatalf("strike %d: send failed: %v", i, err)
		}
		cl.WaitClose(ctx)
		cl.Close()
		cancel()
	}

	// The IP is now banned; a fresh connection attempt is refused pre-upgrade.
	resp, err := http.Get(h.httpSrv.URL + "/v1/connect")
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusTooManyRequests {
		t.Fatalf("want 429 (banned), got %d", resp.StatusCode)
	}
	if resp.Header.Get("Retry-After") == "" {
		t.Fatal("ban 429 missing Retry-After header")
	}
	if got := testutil.ToFloat64(h.metrics.RateLimited.WithLabelValues("ban")); got < 1 {
		t.Errorf("relay_rate_limited_total{kind=ban} = %v, want >= 1", got)
	}
	if got := testutil.ToFloat64(h.metrics.BansActive); got < 1 {
		t.Errorf("relay_bans_active = %v, want >= 1", got)
	}
}

// TestRateLimitDisabledByDefault confirms the default harness (rate limiting
// off) does not 429 a burst of unauthenticated attempts.
func TestRateLimitDisabledByDefault(t *testing.T) {
	h := newHarness(t, nil, nil)
	for i := 0; i < 50; i++ {
		resp, err := http.Get(h.httpSrv.URL + "/v1/connect")
		if err != nil {
			t.Fatal(err)
		}
		resp.Body.Close()
		if resp.StatusCode == http.StatusTooManyRequests {
			t.Fatalf("attempt %d unexpectedly rate limited with limiting disabled", i)
		}
	}
}
