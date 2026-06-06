package billing

import (
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"time"

	stripe "github.com/stripe/stripe-go/v82"
	"github.com/stripe/stripe-go/v82/webhook"

	"github.com/lley154/secure-gateway/internal/authstore"
	"github.com/lley154/secure-gateway/internal/backplane"
	"github.com/lley154/secure-gateway/internal/license"
	"github.com/lley154/secure-gateway/internal/logging"
)

// maxAttempts caps webhook retry attempts before an event is dead-lettered.
const maxAttempts = 5

// Clock returns the current time; injectable so tests are deterministic.
type Clock func() time.Time

// Processor verifies and applies Stripe webhook events and reconciles the local
// mirror. It owns no HTTP surface; the auth service wires it to a handler.
type Processor struct {
	store         authstore.Store
	bp            backplane.Backplane
	api           StripeAPI
	log           *slog.Logger
	grace         time.Duration
	webhookSecret string
	now           Clock

	onProvision  func()
	onRevocation func()
}

// Config configures a Processor.
type Config struct {
	Store         authstore.Store
	Backplane     backplane.Backplane
	API           StripeAPI
	Logger        *slog.Logger
	Grace         time.Duration
	WebhookSecret string
	Now           Clock // optional; defaults to time.Now

	// OnLicenseProvisioned and OnRevocationPublished are optional observers
	// (e.g. metric counters) invoked once per provisioned license / published
	// revocation. They keep the processor decoupled from Prometheus.
	OnLicenseProvisioned  func()
	OnRevocationPublished func()
}

// NewProcessor builds a Processor.
func NewProcessor(c Config) *Processor {
	now := c.Now
	if now == nil {
		now = time.Now
	}
	log := c.Logger
	if log == nil {
		log = slog.Default()
	}
	return &Processor{
		store: c.Store, bp: c.Backplane, api: c.API, log: log,
		grace: c.Grace, webhookSecret: c.WebhookSecret, now: now,
		onProvision: c.OnLicenseProvisioned, onRevocation: c.OnRevocationPublished,
	}
}

// Verify checks the Stripe signature on a raw webhook request body and returns
// the parsed event (PRD §10.2: signature verification is mandatory).
func (p *Processor) Verify(payload []byte, sigHeader string) (stripe.Event, error) {
	return webhook.ConstructEvent(payload, sigHeader, p.webhookSecret)
}

// Record stores the event for idempotent, durable processing and reports
// whether it is new. A return of inserted=false means this event id was already
// received and must not be processed again (Stripe retries; PRD §6.4).
func (p *Processor) Record(ctx context.Context, ev stripe.Event, payload []byte) (bool, error) {
	return p.store.InsertWebhookEventIfAbsent(ctx, authstore.WebhookEvent{
		ID:         ev.ID,
		Type:       string(ev.Type),
		Status:     authstore.WebhookPending,
		Payload:    payload,
		ReceivedAt: p.now(),
	})
}

// Process applies a recorded event and updates its durable status. On handler
// error the event is left "failed" with an incremented attempt count for the
// retry worker; success marks it "processed".
func (p *Processor) Process(ctx context.Context, ev stripe.Event) error {
	err := p.dispatch(ctx, ev)
	if err != nil {
		// Best-effort status bump; the recorded event already exists.
		_ = p.store.SetWebhookStatus(ctx, ev.ID, authstore.WebhookFailed, 1, time.Time{})
		return err
	}
	return p.store.SetWebhookStatus(ctx, ev.ID, authstore.WebhookProcessed, 0, p.now())
}

// RetryFailed re-processes failed events, dead-lettering those past maxAttempts.
// Intended to run on a ticker (and is called directly by tests).
func (p *Processor) RetryFailed(ctx context.Context, limit int) (processed, dead int, err error) {
	events, err := p.store.ListWebhookEventsByStatus(ctx, authstore.WebhookFailed, limit)
	if err != nil {
		return 0, 0, err
	}
	for _, e := range events {
		var ev stripe.Event
		if uerr := json.Unmarshal(e.Payload, &ev); uerr != nil {
			// Unparseable payloads can never succeed; dead-letter immediately.
			_ = p.store.SetWebhookStatus(ctx, e.ID, authstore.WebhookDead, e.Attempts, p.now())
			dead++
			continue
		}
		if derr := p.dispatch(ctx, ev); derr != nil {
			attempts := e.Attempts + 1
			status := authstore.WebhookFailed
			if attempts >= maxAttempts {
				status = authstore.WebhookDead
				dead++
				p.log.Error("webhook dead-lettered", "event_id", e.ID, "type", e.Type, "attempts", attempts, logging.FieldReason, derr.Error())
			}
			_ = p.store.SetWebhookStatus(ctx, e.ID, status, attempts, time.Time{})
			continue
		}
		_ = p.store.SetWebhookStatus(ctx, e.ID, authstore.WebhookProcessed, 0, p.now())
		processed++
	}
	return processed, dead, nil
}

// dispatch routes a verified event to its handler (PRD §6.4 table). Unhandled
// event types succeed as no-ops so they are not retried forever.
func (p *Processor) dispatch(ctx context.Context, ev stripe.Event) error {
	switch ev.Type {
	case stripe.EventTypeCheckoutSessionCompleted:
		return p.handleCheckoutCompleted(ctx, ev)
	case stripe.EventTypeCustomerSubscriptionCreated, stripe.EventTypeCustomerSubscriptionUpdated:
		return p.handleSubscriptionUpsert(ctx, ev)
	case stripe.EventTypeCustomerSubscriptionDeleted:
		return p.handleSubscriptionDeleted(ctx, ev)
	case stripe.EventTypeInvoicePaymentFailed:
		return p.handleInvoicePaymentFailed(ctx, ev)
	case stripe.EventTypeInvoicePaid:
		return p.handleInvoicePaid(ctx, ev)
	default:
		p.log.Debug("ignoring unhandled webhook event", "type", string(ev.Type))
		return nil
	}
}

// --- Handlers ---

func (p *Processor) handleCheckoutCompleted(ctx context.Context, ev stripe.Event) error {
	var cs stripe.CheckoutSession
	if err := json.Unmarshal(ev.Data.Raw, &cs); err != nil {
		return fmt.Errorf("parse checkout session: %w", err)
	}
	customerID := customerIDOf(cs.Customer)
	if customerID == "" {
		return fmt.Errorf("checkout session %s has no customer", cs.ID)
	}
	// The app passes its account id as client_reference_id at Checkout creation;
	// this is where customer↔account is linked (PRD §6.4).
	accountID := cs.ClientReferenceID
	if accountID == "" {
		accountID = authstore.NewID("acct")
	}
	if err := p.store.UpsertAccount(ctx, authstore.Account{ID: accountID, StripeCustomerID: customerID, CreatedAt: p.now()}); err != nil {
		return fmt.Errorf("link account: %w", err)
	}
	// Provision licenses from the subscription. The checkout event carries the
	// subscription id; fetch the full object for status/items/metadata.
	subID := subscriptionIDOf(cs.Subscription)
	if subID == "" {
		return fmt.Errorf("checkout session %s has no subscription", cs.ID)
	}
	sub, err := p.api.GetSubscription(ctx, subID)
	if err != nil {
		return fmt.Errorf("fetch subscription %s: %w", subID, err)
	}
	return p.syncSubscription(ctx, sub, accountID)
}

func (p *Processor) handleSubscriptionUpsert(ctx context.Context, ev stripe.Event) error {
	var sub stripe.Subscription
	if err := json.Unmarshal(ev.Data.Raw, &sub); err != nil {
		return fmt.Errorf("parse subscription: %w", err)
	}
	accountID, err := p.resolveAccount(ctx, customerIDOf(sub.Customer))
	if err != nil {
		return err
	}
	return p.syncSubscription(ctx, &sub, accountID)
}

func (p *Processor) handleSubscriptionDeleted(ctx context.Context, ev stripe.Event) error {
	var sub stripe.Subscription
	if err := json.Unmarshal(ev.Data.Raw, &sub); err != nil {
		return fmt.Errorf("parse subscription: %w", err)
	}
	// Mirror the terminal status, then revoke every license on the subscription
	// and cut its live sessions (PRD §6.4).
	accountID, err := p.resolveAccount(ctx, customerIDOf(sub.Customer))
	if err != nil {
		return err
	}
	mirror := authstore.Subscription{
		ID: sub.ID, AccountID: accountID, Status: authstore.SubCanceled,
		MaxPairs: maxPairsFor(&sub), UpdatedAt: p.now(),
	}
	if err := p.store.UpsertSubscription(ctx, mirror); err != nil {
		return err
	}
	return p.enforce(ctx, sub.ID, license.Revoked)
}

func (p *Processor) handleInvoicePaymentFailed(ctx context.Context, ev stripe.Event) error {
	subID, err := invoiceSubscriptionID(ev)
	if err != nil {
		return err
	}
	mirror, err := p.store.GetSubscription(ctx, subID)
	if err != nil {
		return fmt.Errorf("invoice.payment_failed for unknown subscription %s: %w", subID, err)
	}
	// Enter grace (PRD §6.3/§6.4): keep the license valid, set the deadline, mark
	// past_due so Evaluate yields Grace. The user is notified in-app (out of scope).
	mirror.Status = authstore.SubPastDue
	if mirror.GraceUntil.IsZero() {
		mirror.GraceUntil = p.now().Add(p.grace)
	}
	mirror.UpdatedAt = p.now()
	return p.store.UpsertSubscription(ctx, mirror)
}

func (p *Processor) handleInvoicePaid(ctx context.Context, ev stripe.Event) error {
	subID, err := invoiceSubscriptionID(ev)
	if err != nil {
		return err
	}
	mirror, err := p.store.GetSubscription(ctx, subID)
	if err != nil {
		// A paid invoice for a not-yet-mirrored subscription is benign; the
		// subscription.created/updated event will establish the mirror.
		return nil
	}
	// Clear grace state (PRD §6.4). A past_due that has now paid returns to active.
	mirror.GraceUntil = time.Time{}
	if mirror.Status == authstore.SubPastDue {
		mirror.Status = authstore.SubActive
	}
	mirror.UpdatedAt = p.now()
	if err := p.store.UpsertSubscription(ctx, mirror); err != nil {
		return err
	}
	// Reactivate licenses that grace/suspension may have revoked.
	return p.reactivate(ctx, subID)
}

// --- Shared subscription sync ---

// syncSubscription upserts the mirror for sub, provisions licenses up to
// max_pairs, and applies enforcement or reactivation per the derived behavior.
// Shared by webhook handlers and reconciliation.
func (p *Processor) syncSubscription(ctx context.Context, sub *stripe.Subscription, accountID string) error {
	now := p.now()
	status := authstore.SubStatus(string(sub.Status))
	mirror := authstore.Subscription{
		ID:               sub.ID,
		AccountID:        accountID,
		Status:           status,
		MaxPairs:         maxPairsFor(sub),
		CurrentPeriodEnd: currentPeriodEnd(sub),
		UpdatedAt:        now,
	}
	// Preserve/compute the grace deadline for past_due.
	if existing, err := p.store.GetSubscription(ctx, sub.ID); err == nil {
		mirror.GraceUntil = existing.GraceUntil
	}
	if status == authstore.SubPastDue && mirror.GraceUntil.IsZero() {
		mirror.GraceUntil = now.Add(p.grace)
	}
	if status != authstore.SubPastDue {
		mirror.GraceUntil = time.Time{}
	}
	if err := p.store.UpsertSubscription(ctx, mirror); err != nil {
		return err
	}
	if err := p.ensureLicenses(ctx, mirror, sub); err != nil {
		return err
	}

	behavior := license.Evaluate(mirror, now)
	switch {
	case license.Enforced(behavior):
		return p.enforce(ctx, sub.ID, behavior)
	default:
		return p.reactivate(ctx, sub.ID)
	}
}

// ensureLicenses provisions licenses for the subscription up to max_pairs,
// idempotently (existing licenses are counted, never duplicated).
func (p *Processor) ensureLicenses(ctx context.Context, mirror authstore.Subscription, sub *stripe.Subscription) error {
	existing, err := p.store.ListLicensesBySubscription(ctx, mirror.ID)
	if err != nil {
		return err
	}
	itemID := firstItemID(sub)
	for i := len(existing); i < mirror.MaxPairs; i++ {
		l := authstore.License{
			ID:                 license.NewKey(),
			AccountID:          mirror.AccountID,
			SubscriptionID:     mirror.ID,
			SubscriptionItemID: itemID,
			Status:             authstore.LicenseActive,
			CreatedAt:          p.now(),
		}
		if err := p.store.CreateLicense(ctx, l); err != nil {
			return fmt.Errorf("provision license: %w", err)
		}
		if p.onProvision != nil {
			p.onProvision()
		}
		p.log.Info("license provisioned", logging.FieldAccountID, mirror.AccountID, "license_id", l.ID, "subscription_id", mirror.ID)
	}
	// max_pairs downgrade: excess licenses are retained and flagged for the user
	// to choose which pair(s) to deactivate (PRD §6.4); not auto-deleted in M2.
	if len(existing) > mirror.MaxPairs {
		p.log.Warn("subscription downgraded below active license count; excess licenses retained for user action",
			"subscription_id", mirror.ID, "licenses", len(existing), "max_pairs", mirror.MaxPairs)
	}
	return nil
}

// enforce revokes (for Revoked) and cuts live sessions for every active pairing
// on the subscription's licenses (PRD §6.5 #2). For Suspended, pairing records
// are retained for easy resume but sessions are still cut.
func (p *Processor) enforce(ctx context.Context, subID string, behavior license.Behavior) error {
	licenses, err := p.store.ListLicensesBySubscription(ctx, subID)
	if err != nil {
		return err
	}
	for _, l := range licenses {
		if behavior == license.Revoked {
			if err := p.store.SetLicenseStatus(ctx, l.ID, authstore.LicenseRevoked); err != nil {
				return err
			}
		}
		pairs, err := p.store.ListActivePairingsByLicense(ctx, l.ID)
		if err != nil {
			return err
		}
		for _, pr := range pairs {
			if behavior == license.Revoked {
				if err := p.store.SetPairingStatus(ctx, pr.PairID, authstore.PairingRevoked); err != nil {
					return err
				}
			}
			if err := p.bp.PublishRevocation(ctx, backplane.RevocationEvent{PairID: pr.PairID}); err != nil {
				return fmt.Errorf("publish revocation for %s: %w", pr.PairID, err)
			}
			if p.onRevocation != nil {
				p.onRevocation()
			}
			p.log.Info("revocation published", "pair_id", pr.PairID, "license_id", l.ID, logging.FieldReason, behavior.String())
		}
	}
	return nil
}

// reactivate restores active status to licenses on a now-valid subscription
// (e.g. a paused subscription resumed). Pairings retained during suspension stay
// usable; cancellation is terminal and never reaches here.
func (p *Processor) reactivate(ctx context.Context, subID string) error {
	licenses, err := p.store.ListLicensesBySubscription(ctx, subID)
	if err != nil {
		return err
	}
	for _, l := range licenses {
		if l.Status != authstore.LicenseActive {
			if err := p.store.SetLicenseStatus(ctx, l.ID, authstore.LicenseActive); err != nil {
				return err
			}
		}
	}
	return nil
}

// resolveAccount returns the account id linked to a Stripe customer, creating a
// placeholder account if events arrive before checkout linkage.
func (p *Processor) resolveAccount(ctx context.Context, customerID string) (string, error) {
	if customerID == "" {
		return "", fmt.Errorf("event has no customer")
	}
	acct, err := p.store.GetAccountByCustomer(ctx, customerID)
	if err == nil {
		return acct.ID, nil
	}
	id := authstore.NewID("acct")
	if uerr := p.store.UpsertAccount(ctx, authstore.Account{ID: id, StripeCustomerID: customerID, CreatedAt: p.now()}); uerr != nil {
		return "", uerr
	}
	return id, nil
}
