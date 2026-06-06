// Package authmetrics declares the Auth & License Service's Prometheus
// collectors (all prefixed auth_), mirroring internal/metrics' Set pattern: a
// fresh registry owned by the Set so tests get isolated metrics.
package authmetrics

import "github.com/prometheus/client_golang/prometheus"

// Set bundles the auth-service collectors and their registry.
type Set struct {
	Registry *prometheus.Registry

	// TokensIssued: connection tokens minted, labeled by role.
	TokensIssued *prometheus.CounterVec
	// TokenRequestsRejected: token issue/refresh denied, by reason code.
	TokenRequestsRejected *prometheus.CounterVec
	// WebhooksReceived: Stripe webhooks accepted (valid signature), by event type.
	WebhooksReceived *prometheus.CounterVec
	// WebhooksRejected: webhook requests refused, by reason (bad_signature|replay|error).
	WebhooksRejected *prometheus.CounterVec
	// WebhookProcessingFailures: handler failures (drives the failed/dead queue).
	WebhookProcessingFailures prometheus.Counter
	// RevocationsPublished: revocation events emitted to the backplane.
	RevocationsPublished prometheus.Counter
	// LicensesProvisioned: license keys minted.
	LicensesProvisioned prometheus.Counter
	// ReconcileRuns: nightly reconciliation runs, by outcome (ok|error).
	ReconcileRuns *prometheus.CounterVec
}

// New constructs and registers all auth metrics on a fresh registry.
func New() *Set {
	reg := prometheus.NewRegistry()
	s := &Set{
		Registry: reg,
		TokensIssued: prometheus.NewCounterVec(prometheus.CounterOpts{
			Name: "auth_tokens_issued_total",
			Help: "Connection tokens issued, by role.",
		}, []string{"role"}),
		TokenRequestsRejected: prometheus.NewCounterVec(prometheus.CounterOpts{
			Name: "auth_token_requests_rejected_total",
			Help: "Token issue/refresh requests rejected, by reason code.",
		}, []string{"reason"}),
		WebhooksReceived: prometheus.NewCounterVec(prometheus.CounterOpts{
			Name: "auth_webhooks_received_total",
			Help: "Signature-verified Stripe webhooks received, by event type.",
		}, []string{"type"}),
		WebhooksRejected: prometheus.NewCounterVec(prometheus.CounterOpts{
			Name: "auth_webhooks_rejected_total",
			Help: "Webhook requests rejected, by reason.",
		}, []string{"reason"}),
		WebhookProcessingFailures: prometheus.NewCounter(prometheus.CounterOpts{
			Name: "auth_webhook_processing_failures_total",
			Help: "Webhook handler failures (events enter the failed/dead queue).",
		}),
		RevocationsPublished: prometheus.NewCounter(prometheus.CounterOpts{
			Name: "auth_revocations_published_total",
			Help: "Revocation events published to the backplane.",
		}),
		LicensesProvisioned: prometheus.NewCounter(prometheus.CounterOpts{
			Name: "auth_licenses_provisioned_total",
			Help: "License keys provisioned.",
		}),
		ReconcileRuns: prometheus.NewCounterVec(prometheus.CounterOpts{
			Name: "auth_reconcile_runs_total",
			Help: "Reconciliation runs, by outcome.",
		}, []string{"outcome"}),
	}
	reg.MustRegister(
		s.TokensIssued, s.TokenRequestsRejected, s.WebhooksReceived, s.WebhooksRejected,
		s.WebhookProcessingFailures, s.RevocationsPublished, s.LicensesProvisioned, s.ReconcileRuns,
	)
	return s
}
