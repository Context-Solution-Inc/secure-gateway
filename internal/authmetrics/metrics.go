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
	// RateLimited: requests rejected by the rate limiter, by kind (ip|account).
	RateLimited *prometheus.CounterVec
	// BackplaneUp: 1 when the revocation backplane is reachable, else 0.
	BackplaneUp prometheus.Gauge
	// WebhooksPending/WebhooksDead: durable webhook queue depth by terminal state.
	WebhooksPending prometheus.Gauge
	WebhooksDead    prometheus.Gauge
	// WebhookOldestPendingSeconds: age of the oldest unprocessed webhook (lag).
	WebhookOldestPendingSeconds prometheus.Gauge
	// TLSCertExpiry: seconds until the serving cert expires (0 if proxy-terminated).
	TLSCertExpiry prometheus.Gauge
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
		RateLimited: prometheus.NewCounterVec(prometheus.CounterOpts{
			Name: "auth_rate_limited_total",
			Help: "Requests rejected by the rate limiter, by kind (ip|account).",
		}, []string{"kind"}),
		BackplaneUp: prometheus.NewGauge(prometheus.GaugeOpts{
			Name: "auth_backplane_up",
			Help: "1 when the revocation backplane is reachable, else 0.",
		}),
		WebhooksPending: prometheus.NewGauge(prometheus.GaugeOpts{
			Name: "auth_webhooks_pending",
			Help: "Durable webhook events awaiting (re)processing.",
		}),
		WebhooksDead: prometheus.NewGauge(prometheus.GaugeOpts{
			Name: "auth_webhooks_dead",
			Help: "Webhook events dead-lettered after exhausting retries.",
		}),
		WebhookOldestPendingSeconds: prometheus.NewGauge(prometheus.GaugeOpts{
			Name: "auth_webhook_oldest_pending_seconds",
			Help: "Age of the oldest unprocessed webhook event (processing lag).",
		}),
		TLSCertExpiry: prometheus.NewGauge(prometheus.GaugeOpts{
			Name: "auth_tls_cert_expiry_seconds",
			Help: "Seconds until the serving TLS certificate expires (0 if proxy-terminated).",
		}),
	}
	reg.MustRegister(
		s.TokensIssued, s.TokenRequestsRejected, s.WebhooksReceived, s.WebhooksRejected,
		s.WebhookProcessingFailures, s.RevocationsPublished, s.LicensesProvisioned, s.ReconcileRuns,
		s.RateLimited, s.BackplaneUp, s.WebhooksPending, s.WebhooksDead,
		s.WebhookOldestPendingSeconds, s.TLSCertExpiry,
	)
	return s
}
