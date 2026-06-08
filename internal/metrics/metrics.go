// Package metrics defines the relay's Prometheus collectors (PRD §9.3).
//
// A Set bundles every collector against a dedicated registry so tests can
// assert values in isolation via prometheus/testutil.
package metrics

import (
	"github.com/prometheus/client_golang/prometheus"
)

// Set holds all relay metrics and the registry they are registered on.
type Set struct {
	Registry *prometheus.Registry

	// ConnsActive: current connections, labeled by role (mobile|desktop).
	ConnsActive *prometheus.GaugeVec
	// AuthFailures: pre-upgrade auth rejections, labeled by machine reason code.
	AuthFailures *prometheus.CounterVec
	// MessagesRelayed: frames forwarded, labeled by direction (to_mobile|to_desktop).
	MessagesRelayed *prometheus.CounterVec
	// BytesRelayed: payload+envelope bytes forwarded, labeled by direction.
	BytesRelayed *prometheus.CounterVec
	// ForwardLatency: relay forwarding latency (frame in -> enqueued out) seconds.
	ForwardLatency prometheus.Histogram
	// SlotEvictions: connections superseded by a newer claim.
	SlotEvictions prometheus.Counter
	// Revocations: sessions closed due to a revocation event.
	Revocations prometheus.Counter
	// ConnectsTotal: accepted upgrades (reconnect-storm gauge is derived via rate()).
	ConnectsTotal prometheus.Counter
	// PeerOffline: msg sends that found no peer slot.
	PeerOffline prometheus.Counter
	// RateLimited: pre-upgrade rejections by kind (ip|ban) (PRD §10.2).
	RateLimited *prometheus.CounterVec
	// BansActive: IPs currently in a temporary ban (4005 abuse).
	BansActive prometheus.Gauge
	// FDUsed/FDLimit: open file descriptors vs the process nofile limit (PRD §9.3).
	FDUsed  prometheus.Gauge
	FDLimit prometheus.Gauge
	// BackplaneUp: 1 when the backplane (Redis/memory) is reachable, else 0.
	BackplaneUp prometheus.Gauge
	// TLSCertExpiry: seconds until the serving cert's NotAfter (0 when proxy-terminated).
	TLSCertExpiry prometheus.Gauge
}

// New constructs and registers the full metric set on a fresh registry.
func New() *Set {
	reg := prometheus.NewRegistry()
	s := &Set{
		Registry: reg,
		ConnsActive: prometheus.NewGaugeVec(prometheus.GaugeOpts{
			Name: "relay_connections_active",
			Help: "Current active WebSocket connections by role.",
		}, []string{"role"}),
		AuthFailures: prometheus.NewCounterVec(prometheus.CounterOpts{
			Name: "relay_auth_failures_total",
			Help: "Connection auth failures by machine-readable reason code.",
		}, []string{"reason"}),
		MessagesRelayed: prometheus.NewCounterVec(prometheus.CounterOpts{
			Name: "relay_messages_relayed_total",
			Help: "Frames forwarded between paired endpoints by direction.",
		}, []string{"direction"}),
		BytesRelayed: prometheus.NewCounterVec(prometheus.CounterOpts{
			Name: "relay_bytes_relayed_total",
			Help: "Bytes forwarded between paired endpoints by direction.",
		}, []string{"direction"}),
		ForwardLatency: prometheus.NewHistogram(prometheus.HistogramOpts{
			Name:    "relay_forward_latency_seconds",
			Help:    "Relay forwarding latency from frame receipt to peer enqueue.",
			Buckets: prometheus.ExponentialBuckets(0.0001, 2, 14), // 100us .. ~800ms
		}),
		SlotEvictions: prometheus.NewCounter(prometheus.CounterOpts{
			Name: "relay_slot_evictions_total",
			Help: "Connections evicted (superseded) by a newer slot claim.",
		}),
		Revocations: prometheus.NewCounter(prometheus.CounterOpts{
			Name: "relay_revocations_executed_total",
			Help: "Sessions closed due to revocation events.",
		}),
		ConnectsTotal: prometheus.NewCounter(prometheus.CounterOpts{
			Name: "relay_connects_total",
			Help: "Accepted WebSocket upgrades (use rate() for reconnect-storm gauge).",
		}),
		PeerOffline: prometheus.NewCounter(prometheus.CounterOpts{
			Name: "relay_peer_offline_total",
			Help: "Message sends that found no online peer.",
		}),
		RateLimited: prometheus.NewCounterVec(prometheus.CounterOpts{
			Name: "relay_rate_limited_total",
			Help: "Pre-upgrade connection rejections by kind (ip|ban).",
		}, []string{"kind"}),
		BansActive: prometheus.NewGauge(prometheus.GaugeOpts{
			Name: "relay_bans_active",
			Help: "Client IPs currently in a temporary abuse ban.",
		}),
		FDUsed: prometheus.NewGauge(prometheus.GaugeOpts{
			Name: "relay_fd_used",
			Help: "Open file descriptors held by the process.",
		}),
		FDLimit: prometheus.NewGauge(prometheus.GaugeOpts{
			Name: "relay_fd_limit",
			Help: "Process open-file (nofile) soft limit.",
		}),
		BackplaneUp: prometheus.NewGauge(prometheus.GaugeOpts{
			Name: "relay_backplane_up",
			Help: "1 when the slot/routing backplane is reachable, else 0.",
		}),
		TLSCertExpiry: prometheus.NewGauge(prometheus.GaugeOpts{
			Name: "relay_tls_cert_expiry_seconds",
			Help: "Seconds until the serving TLS certificate expires (0 if proxy-terminated).",
		}),
	}
	reg.MustRegister(
		s.ConnsActive, s.AuthFailures, s.MessagesRelayed, s.BytesRelayed,
		s.ForwardLatency, s.SlotEvictions, s.Revocations, s.ConnectsTotal, s.PeerOffline,
		s.RateLimited, s.BansActive, s.FDUsed, s.FDLimit, s.BackplaneUp, s.TLSCertExpiry,
	)
	return s
}
