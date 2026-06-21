package integration

import (
	"io"
	"net/http"
	"testing"

	"github.com/lley154/secure-gateway/internal/authservice"
)

// TestMetricsOffMainMuxWhenPrivateAddrSet is the SG-06/SG-11 regression: when a
// private metrics address is configured, /metrics must NOT be served on the main
// (edge-proxied) listener, so it cannot be scraped from the public internet.
func TestMetricsOffMainMuxWhenPrivateAddrSet(t *testing.T) {
	// Default (no metrics addr): /metrics is on the main mux for dev convenience.
	def := newAuthHarness(t)
	if code := getStatus(t, def.authSrv.URL+"/metrics"); code != http.StatusOK {
		t.Fatalf("default: want /metrics 200 on main mux, got %d", code)
	}

	// With AUTH_METRICS_ADDR set, /metrics is removed from the main mux (404). The
	// real metrics are served on the separate private listener started by Run.
	priv := newAuthHarness(t, func(c *authservice.ServerConfig) { c.MetricsAddr = "127.0.0.1:0" })
	if code := getStatus(t, priv.authSrv.URL+"/metrics"); code != http.StatusNotFound {
		t.Fatalf("private addr set: want /metrics 404 on main mux, got %d", code)
	}
	// Health stays on the main mux either way.
	if code := getStatus(t, priv.authSrv.URL+"/healthz"); code != http.StatusOK {
		t.Fatalf("healthz on main mux: want 200, got %d", code)
	}
}

func getStatus(t *testing.T, url string) int {
	t.Helper()
	resp, err := http.Get(url)
	if err != nil {
		t.Fatalf("GET %s: %v", url, err)
	}
	defer resp.Body.Close()
	_, _ = io.Copy(io.Discard, resp.Body)
	return resp.StatusCode
}
