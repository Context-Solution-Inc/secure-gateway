package httpsec

import (
	"crypto/tls"
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestHSTSHeaderSet(t *testing.T) {
	h := HSTS(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/anything", nil))

	got := rec.Header().Get("Strict-Transport-Security")
	if got == "" {
		t.Fatal("HSTS header not set")
	}
	if got != "max-age=63072000; includeSubDomains" {
		t.Fatalf("unexpected HSTS value: %q", got)
	}
}

func TestServerTLSConfig(t *testing.T) {
	if cfg := ServerTLSConfig("", "1.2"); cfg != nil {
		t.Fatal("empty cert file should yield nil (proxy-terminated)")
	}
	cfg := ServerTLSConfig("/some/cert.pem", "1.2")
	if cfg == nil {
		t.Fatal("expected a config when cert file set")
	}
	if cfg.MinVersion != tls.VersionTLS12 {
		t.Fatalf("MinVersion = %d, want TLS 1.2", cfg.MinVersion)
	}
	if len(cfg.CipherSuites) == 0 {
		t.Fatal("expected the modern cipher allow-list")
	}
	if got := ServerTLSConfig("/some/cert.pem", "1.3"); got.MinVersion != tls.VersionTLS13 {
		t.Fatalf("MinVersion = %d, want TLS 1.3", got.MinVersion)
	}
}

func TestClientIP(t *testing.T) {
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	req.RemoteAddr = "203.0.113.7:54321"
	req.Header.Set("X-Forwarded-For", "198.51.100.9, 10.0.0.1")

	// trustProxy=false: use the socket peer (port stripped), ignore XFF.
	if got := ClientIP(req, false); got != "203.0.113.7" {
		t.Fatalf("untrusted: got %q, want 203.0.113.7", got)
	}
	// trustProxy=true: first hop of XFF.
	if got := ClientIP(req, true); got != "198.51.100.9" {
		t.Fatalf("trusted: got %q, want 198.51.100.9", got)
	}
	// trustProxy=true with no XFF falls back to the socket peer.
	req.Header.Del("X-Forwarded-For")
	if got := ClientIP(req, true); got != "203.0.113.7" {
		t.Fatalf("trusted no-xff: got %q, want 203.0.113.7", got)
	}
}

func TestModernCipherSuitesAreAEADForwardSecret(t *testing.T) {
	suites := ModernCipherSuites()
	if len(suites) == 0 {
		t.Fatal("expected a non-empty cipher allow-list")
	}
	// Every listed suite must be one Go classifies as secure (not in the
	// InsecureCipherSuites set) and must be an ECDHE (forward-secret) AEAD.
	insecure := map[uint16]bool{}
	for _, cs := range tls.InsecureCipherSuites() {
		insecure[cs.ID] = true
	}
	known := map[uint16]string{}
	for _, cs := range tls.CipherSuites() {
		known[cs.ID] = cs.Name
	}
	for _, id := range suites {
		if insecure[id] {
			t.Errorf("cipher %#x is in Go's insecure set", id)
		}
		if _, ok := known[id]; !ok {
			t.Errorf("cipher %#x is not a known secure suite", id)
		}
	}
}
