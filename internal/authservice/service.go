// Package authservice is the HTTP surface of the Auth & License Service: Stripe
// webhooks, device registration, minimal pairing, connection-token issue/refresh
// (PRD §6.5 #1 enforcement), and the JWKS the relay verifies against. It depends
// on authstore.Store, a signer, and a billing.Processor; cmd/auth wires concrete
// implementations.
package authservice

import (
	"log/slog"
	"time"

	"github.com/lley154/secure-gateway/internal/authmetrics"
	"github.com/lley154/secure-gateway/internal/authstore"
	"github.com/lley154/secure-gateway/internal/billing"
	"github.com/lley154/secure-gateway/internal/signer"
)

// Service holds the dependencies shared by all handlers.
type Service struct {
	store   authstore.Store
	signer  *signer.Signer
	proc    *billing.Processor
	metrics *authmetrics.Set
	log     *slog.Logger

	issuer     string
	audience   string
	tokenTTL   time.Duration
	refreshTTL time.Duration
	grace      time.Duration
	adminKey   string
	now        func() time.Time
}

// Deps are the constructor dependencies for a Service.
type Deps struct {
	Store      authstore.Store
	Signer     *signer.Signer
	Processor  *billing.Processor
	Metrics    *authmetrics.Set
	Logger     *slog.Logger
	Issuer     string
	Audience   string
	TokenTTL   time.Duration
	RefreshTTL time.Duration
	Grace      time.Duration
	AdminKey   string
	Now        func() time.Time // optional; defaults to time.Now
}

// NewService builds a Service from its dependencies.
func NewService(d Deps) *Service {
	now := d.Now
	if now == nil {
		now = time.Now
	}
	log := d.Logger
	if log == nil {
		log = slog.Default()
	}
	return &Service{
		store: d.Store, signer: d.Signer, proc: d.Processor, metrics: d.Metrics, log: log,
		issuer: d.Issuer, audience: d.Audience, tokenTTL: d.TokenTTL, refreshTTL: d.RefreshTTL,
		grace: d.Grace, adminKey: d.AdminKey, now: now,
	}
}
