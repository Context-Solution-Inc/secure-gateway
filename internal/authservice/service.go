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
	"github.com/lley154/secure-gateway/internal/backplane"
	"github.com/lley154/secure-gateway/internal/billing"
	"github.com/lley154/secure-gateway/internal/signer"
)

// Service holds the dependencies shared by all handlers.
type Service struct {
	store   authstore.Store
	signer  *signer.Signer
	proc    *billing.Processor
	bp      backplane.Backplane
	metrics *authmetrics.Set
	log     *slog.Logger

	issuer          string
	audience        string
	tokenTTL        time.Duration
	refreshTTL      time.Duration
	pairingTokenTTL time.Duration
	grace           time.Duration
	adminKey        string
	relayURL        string // advertised in the QR payload endpoints
	authURL         string // advertised in the QR payload endpoints; also the checkout return base
	checkoutPriceID string // Stripe price id for the desktop subscription plan
	claimTTL        time.Duration
	billingEnabled  bool // when false, secure links are ungated and an open license is auto-provisioned
	now             func() time.Time
}

// Deps are the constructor dependencies for a Service.
type Deps struct {
	Store           authstore.Store
	Signer          *signer.Signer
	Processor       *billing.Processor
	Backplane       backplane.Backplane // publishes revocations for re-pair/unpair (FR-2.4/2.5)
	Metrics         *authmetrics.Set
	Logger          *slog.Logger
	Issuer          string
	Audience        string
	TokenTTL        time.Duration
	RefreshTTL      time.Duration
	PairingTokenTTL time.Duration
	Grace           time.Duration
	AdminKey        string
	RelayURL        string
	AuthURL         string
	CheckoutPriceID string
	ClaimTTL        time.Duration
	BillingEnabled  bool             // when false, gating is bypassed and an open license is auto-provisioned
	Now             func() time.Time // optional; defaults to time.Now
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
	pairingTTL := d.PairingTokenTTL
	if pairingTTL <= 0 {
		pairingTTL = 5 * time.Minute // FR-2.1 cap
	}
	claimTTL := d.ClaimTTL
	if claimTTL <= 0 {
		claimTTL = 30 * time.Minute // must outlive a payment + browser return
	}
	return &Service{
		store: d.Store, signer: d.Signer, proc: d.Processor, bp: d.Backplane, metrics: d.Metrics, log: log,
		issuer: d.Issuer, audience: d.Audience, tokenTTL: d.TokenTTL, refreshTTL: d.RefreshTTL,
		pairingTokenTTL: pairingTTL, grace: d.Grace, adminKey: d.AdminKey,
		relayURL: d.RelayURL, authURL: d.AuthURL,
		checkoutPriceID: d.CheckoutPriceID, claimTTL: claimTTL, billingEnabled: d.BillingEnabled, now: now,
	}
}
