// Package obs provides small host/process telemetry helpers used to populate the
// PRD §9.3 saturation and certificate-expiry metrics (fd usage, TLS cert
// expiry). It is deliberately dependency-free so both the relay and auth
// services can sample on a background ticker.
package obs

import (
	"crypto/x509"
	"encoding/pem"
	"errors"
	"os"
	"syscall"
	"time"
)

// FDUsage reports the number of open file descriptors and the process's nofile
// soft limit. used is 0 when /proc is unavailable (non-Linux); limit is 0 when
// the rlimit cannot be read.
func FDUsage() (used float64, limit float64) {
	if entries, err := os.ReadDir("/proc/self/fd"); err == nil {
		// Subtract 1 for the fd opened by ReadDir itself.
		n := len(entries) - 1
		if n < 0 {
			n = 0
		}
		used = float64(n)
	}
	var rl syscall.Rlimit
	if err := syscall.Getrlimit(syscall.RLIMIT_NOFILE, &rl); err == nil {
		limit = float64(rl.Cur)
	}
	return used, limit
}

// CertNotAfter parses the leaf certificate in a PEM file and returns its
// NotAfter. The file is re-read on each call so certificate rotation is picked
// up. Returns an error if certFile is empty or contains no certificate.
func CertNotAfter(certFile string) (time.Time, error) {
	if certFile == "" {
		return time.Time{}, errors.New("no certificate file configured")
	}
	raw, err := os.ReadFile(certFile)
	if err != nil {
		return time.Time{}, err
	}
	for len(raw) > 0 {
		var block *pem.Block
		block, raw = pem.Decode(raw)
		if block == nil {
			break
		}
		if block.Type != "CERTIFICATE" {
			continue
		}
		cert, err := x509.ParseCertificate(block.Bytes)
		if err != nil {
			return time.Time{}, err
		}
		return cert.NotAfter, nil // first cert is the leaf
	}
	return time.Time{}, errors.New("no certificate found in file")
}

// CertExpirySeconds returns seconds until the leaf cert expires (may be
// negative if already expired). The second return is false when no cert is
// configured/parseable, so callers can leave the gauge at 0.
func CertExpirySeconds(certFile string, now time.Time) (float64, bool) {
	notAfter, err := CertNotAfter(certFile)
	if err != nil {
		return 0, false
	}
	return notAfter.Sub(now).Seconds(), true
}
