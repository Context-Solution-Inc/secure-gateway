// Package httpsec holds the deliberate HTTP/TLS hardening shared by the relay
// and auth HTTP surfaces (PRD §10.2): a modern, forward-secret cipher allow-list
// for the TLS 1.2 leg and an HSTS response header.
package httpsec

import (
	"crypto/tls"
	"net"
	"net/http"
	"strings"
)

// ModernCipherSuites is the explicit TLS 1.2 cipher allow-list: ECDHE key
// exchange (forward secrecy) with AEAD ciphers only. TLS 1.3 cipher selection is
// not configurable in Go (the runtime picks safe suites), so this applies to the
// 1.2 leg; it mirrors Go's secure defaults but makes the choice deliberate and
// pins it against future default changes.
func ModernCipherSuites() []uint16 {
	return []uint16{
		tls.TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256,
		tls.TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,
		tls.TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384,
		tls.TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384,
		tls.TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305,
		tls.TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305,
	}
}

// hstsValue is a 2-year max-age with subdomains (PRD §10.2 "HSTS on any HTTP
// surface"). Preload is intentionally omitted; opt in per deployment.
const hstsValue = "max-age=63072000; includeSubDomains"

// HSTS wraps next, adding a Strict-Transport-Security header to every response.
// Clients honor it only over HTTPS, so it is safe whether TLS terminates here or
// at a fronting proxy.
func HSTS(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Strict-Transport-Security", hstsValue)
		next.ServeHTTP(w, r)
	})
}

// ServerTLSConfig builds the deliberate server TLS config: the modern cipher
// allow-list (TLS 1.2 leg) and the configured minimum version. It returns nil
// when certFile is empty (TLS terminated by a fronting proxy). minVersion is
// "1.2" (default) or "1.3".
func ServerTLSConfig(certFile, minVersion string) *tls.Config {
	if certFile == "" {
		return nil
	}
	min := uint16(tls.VersionTLS12)
	if minVersion == "1.3" {
		min = tls.VersionTLS13
	}
	return &tls.Config{
		MinVersion:   min,
		CipherSuites: ModernCipherSuites(),
	}
}

// ClientIP resolves the client's IP for keying (e.g. rate limiting). When
// trustProxy is set it uses the first hop of X-Forwarded-For — set trustProxy
// ONLY behind a proxy that REPLACES X-Forwarded-For with the immediate client IP
// (or strips inbound copies); otherwise a client can spoof the header. When
// trustProxy is false it uses the socket peer address. The port is stripped.
func ClientIP(r *http.Request, trustProxy bool) string {
	if trustProxy {
		if xff := r.Header.Get("X-Forwarded-For"); xff != "" {
			if first := strings.TrimSpace(strings.Split(xff, ",")[0]); first != "" {
				return first
			}
		}
	}
	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		return r.RemoteAddr
	}
	return host
}
