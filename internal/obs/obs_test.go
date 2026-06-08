package obs

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"math/big"
	"os"
	"path/filepath"
	"testing"
	"time"
)

func writeTestCert(t *testing.T, notAfter time.Time) string {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: "relay.test"},
		NotBefore:    notAfter.Add(-24 * time.Hour),
		NotAfter:     notAfter,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(t.TempDir(), "cert.pem")
	f, err := os.Create(path)
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	if err := pem.Encode(f, &pem.Block{Type: "CERTIFICATE", Bytes: der}); err != nil {
		t.Fatal(err)
	}
	return path
}

func TestCertNotAfter(t *testing.T) {
	want := time.Now().Add(30 * 24 * time.Hour).Truncate(time.Second)
	path := writeTestCert(t, want)
	got, err := CertNotAfter(path)
	if err != nil {
		t.Fatal(err)
	}
	if !got.Equal(want) {
		t.Fatalf("NotAfter = %s, want %s", got, want)
	}
}

func TestCertExpirySeconds(t *testing.T) {
	now := time.Now()
	path := writeTestCert(t, now.Add(time.Hour))
	secs, ok := CertExpirySeconds(path, now)
	if !ok {
		t.Fatal("expected ok for valid cert")
	}
	if secs < 3500 || secs > 3700 {
		t.Fatalf("expiry seconds = %v, want ~3600", secs)
	}

	// Missing / empty path => not ok, gauge stays at 0.
	if _, ok := CertExpirySeconds("", now); ok {
		t.Fatal("empty cert path should not be ok")
	}
	if _, ok := CertExpirySeconds(filepath.Join(t.TempDir(), "nope.pem"), now); ok {
		t.Fatal("missing cert file should not be ok")
	}
}

func TestFDUsage(t *testing.T) {
	used, limit := FDUsage()
	// On Linux (/proc available) both should be positive; tolerate non-Linux
	// where used may be 0.
	if limit <= 0 {
		t.Skip("rlimit unavailable on this platform")
	}
	if used < 0 {
		t.Fatalf("used = %v, want >= 0", used)
	}
	if used > limit {
		t.Fatalf("used %v exceeds limit %v", used, limit)
	}
}
