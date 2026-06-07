// Package httpsec holds the deliberate HTTP/TLS hardening shared by the relay
// and auth HTTP surfaces (PRD §10.2): a modern, forward-secret cipher allow-list
// for the TLS 1.2 leg and an HSTS response header.
package httpsec

import (
	"crypto/tls"
	"net/http"
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
