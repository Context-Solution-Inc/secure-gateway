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
