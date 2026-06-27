package billing_test

import (
	"context"
	"io"
	"log/slog"
	"testing"
	"time"

	stripe "github.com/stripe/stripe-go/v82"
	"github.com/stripe/stripe-go/v82/webhook"

	"github.com/context-solutions-inc/secure-gateway/internal/authstore"
	"github.com/context-solutions-inc/secure-gateway/internal/authstore/memory"
	"github.com/context-solutions-inc/secure-gateway/internal/backplane"
	bpmem "github.com/context-solutions-inc/secure-gateway/internal/backplane/memory"
	"github.com/context-solutions-inc/secure-gateway/internal/billing"
	"github.com/context-solutions-inc/secure-gateway/internal/billing/fake"
	"github.com/context-solutions-inc/secure-gateway/internal/license"
)

const secret = "whsec_test_secret"

type fixture struct {
	store *memory.Store
	bp    *bpmem.Backplane
	api   *fake.API
	wh    *fake.Webhook
	proc  *billing.Processor
	revs  <-chan backplane.RevocationEvent
}

func newFixture(t *testing.T) *fixture {
	t.Helper()
	store := memory.New()
	bp := bpmem.New(time.Minute, 64)
	api := fake.NewAPI()
	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)
	revs, err := bp.SubscribeRevocations(ctx)
	if err != nil {
		t.Fatal(err)
	}
	proc := billing.NewProcessor(billing.Config{
		Store: store, Backplane: bp, API: api,
		Logger:        slog.New(slog.NewTextHandler(io.Discard, nil)),
		Grace:         168 * time.Hour,
		WebhookSecret: secret,
	})
	return &fixture{store: store, bp: bp, api: api, wh: fake.NewWebhook(secret), proc: proc, revs: revs}
}

// deliver verifies, records, and processes an event the way the HTTP handler
// would, asserting it was treated as new.
func (f *fixture) deliver(t *testing.T, body []byte, sig string) {
	t.Helper()
	ctx := context.Background()
	ev, err := f.proc.Verify(body, sig)
	if err != nil {
		t.Fatalf("verify: %v", err)
	}
	inserted, err := f.proc.Record(ctx, ev, body)
	if err != nil || !inserted {
		t.Fatalf("record: inserted=%v err=%v", inserted, err)
	}
	if err := f.proc.Process(ctx, ev); err != nil {
		t.Fatalf("process %s: %v", ev.Type, err)
	}
}

func TestVerifyRejectsBadSignature(t *testing.T) {
	f := newFixture(t)
	body, _ := f.wh.Event(stripe.EventTypeInvoicePaid, fake.InvoiceObject("in_1", "sub_1"))
	if _, err := f.proc.Verify(body, "t=1,v1=deadbeef"); err == nil {
		t.Fatal("expected signature verification to fail")
	}
}

func TestIdempotentRecord(t *testing.T) {
	f := newFixture(t)
	ctx := context.Background()
	body, sig := f.wh.Event(stripe.EventTypeInvoicePaid, fake.InvoiceObject("in_1", "sub_x"))
	ev, err := f.proc.Verify(body, sig)
	if err != nil {
		t.Fatal(err)
	}
	first, err := f.proc.Record(ctx, ev, body)
	if err != nil || !first {
		t.Fatalf("first record: %v %v", first, err)
	}
	second, err := f.proc.Record(ctx, ev, body)
	if err != nil || second {
		t.Fatalf("second record should be idempotent: inserted=%v err=%v", second, err)
	}
}

func TestCheckoutProvisionsLicense(t *testing.T) {
	f := newFixture(t)
	ctx := context.Background()
	// The checkout fetch reads the subscription from the API.
	f.api.Set(fake.Subscription("sub_1", "cus_1", stripe.SubscriptionStatusActive, 1))
	body, sig := f.wh.Event(stripe.EventTypeCheckoutSessionCompleted,
		fake.CheckoutCompletedObject("cs_1", "cus_1", "acct_1", "sub_1"))
	f.deliver(t, body, sig)

	acct, err := f.store.GetAccountByCustomer(ctx, "cus_1")
	if err != nil || acct.ID != "acct_1" {
		t.Fatalf("account link: %+v err=%v", acct, err)
	}
	lics, _ := f.store.ListLicensesBySubscription(ctx, "sub_1")
	if len(lics) != 1 || lics[0].Status != authstore.LicenseActive {
		t.Fatalf("license provisioning: %+v", lics)
	}
	sub, _ := f.store.GetSubscription(ctx, "sub_1")
	if license.Evaluate(sub, time.Now()) != license.Valid {
		t.Fatalf("active sub should be Valid: %+v", sub)
	}
	// Re-delivering an equivalent created event must not double-provision.
	body2, sig2 := f.wh.Event(stripe.EventTypeCustomerSubscriptionCreated,
		fake.MarshalSubscription(fake.Subscription("sub_1", "cus_1", stripe.SubscriptionStatusActive, 1)))
	f.deliver(t, body2, sig2)
	lics, _ = f.store.ListLicensesBySubscription(ctx, "sub_1")
	if len(lics) != 1 {
		t.Fatalf("idempotent provisioning expected 1 license, got %d", len(lics))
	}
}

func TestGracePreservesIssuance(t *testing.T) {
	f := newFixture(t)
	ctx := context.Background()
	f.api.Set(fake.Subscription("sub_1", "cus_1", stripe.SubscriptionStatusActive, 1))
	body, sig := f.wh.Event(stripe.EventTypeCheckoutSessionCompleted,
		fake.CheckoutCompletedObject("cs_1", "cus_1", "acct_1", "sub_1"))
	f.deliver(t, body, sig)

	// Payment failed → grace.
	body, sig = f.wh.Event(stripe.EventTypeInvoicePaymentFailed, fake.InvoiceObject("in_1", "sub_1"))
	f.deliver(t, body, sig)
	sub, _ := f.store.GetSubscription(ctx, "sub_1")
	if got := license.Evaluate(sub, time.Now()); got != license.Grace {
		t.Fatalf("after payment_failed want Grace, got %v (%+v)", got, sub)
	}
	if !license.Issuable(license.Evaluate(sub, time.Now())) {
		t.Fatal("grace must remain issuable")
	}
	// Invoice paid → grace cleared, back to valid.
	body, sig = f.wh.Event(stripe.EventTypeInvoicePaid, fake.InvoiceObject("in_2", "sub_1"))
	f.deliver(t, body, sig)
	sub, _ = f.store.GetSubscription(ctx, "sub_1")
	if license.Evaluate(sub, time.Now()) != license.Valid {
		t.Fatalf("after invoice.paid want Valid, got %+v", sub)
	}
}

func TestCancelRevokesAndPublishes(t *testing.T) {
	f := newFixture(t)
	ctx := context.Background()
	f.api.Set(fake.Subscription("sub_1", "cus_1", stripe.SubscriptionStatusActive, 1))
	body, sig := f.wh.Event(stripe.EventTypeCheckoutSessionCompleted,
		fake.CheckoutCompletedObject("cs_1", "cus_1", "acct_1", "sub_1"))
	f.deliver(t, body, sig)
	lics, _ := f.store.ListLicensesBySubscription(ctx, "sub_1")
	licID := lics[0].ID
	// An active pairing exists on the license.
	if err := f.store.CreatePairing(ctx, authstore.Pairing{
		PairID: "pair_1", LicenseID: licID, AccountID: "acct_1",
		MobileDeviceID: "dev_m", DesktopDeviceID: "dev_d", Status: authstore.PairingActive,
	}); err != nil {
		t.Fatal(err)
	}

	body, sig = f.wh.Event(stripe.EventTypeCustomerSubscriptionDeleted,
		fake.MarshalSubscription(fake.Subscription("sub_1", "cus_1", stripe.SubscriptionStatusCanceled, 1)))
	f.deliver(t, body, sig)

	// License revoked, pairing revoked, and a revocation published for the pair.
	got, _ := f.store.GetLicense(ctx, licID)
	if got.Status != authstore.LicenseRevoked {
		t.Fatalf("license not revoked: %+v", got)
	}
	pr, _ := f.store.GetPairing(ctx, "pair_1")
	if pr.Status != authstore.PairingRevoked {
		t.Fatalf("pairing not revoked: %+v", pr)
	}
	select {
	case ev := <-f.revs:
		if ev.PairID != "pair_1" {
			t.Fatalf("revocation for wrong pair: %+v", ev)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("no revocation published within 2s")
	}
}

func TestDeadLetterAfterMaxAttempts(t *testing.T) {
	f := newFixture(t)
	ctx := context.Background()
	// invoice.payment_failed for a subscription that was never mirrored always
	// fails (unknown subscription), so it should dead-letter after retries.
	body, sig := f.wh.Event(stripe.EventTypeInvoicePaymentFailed, fake.InvoiceObject("in_1", "sub_missing"))
	ev, err := f.proc.Verify(body, sig)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := f.proc.Record(ctx, ev, body); err != nil {
		t.Fatal(err)
	}
	if err := f.proc.Process(ctx, ev); err == nil {
		t.Fatal("expected processing to fail for unknown subscription")
	}
	// Retry until dead-lettered.
	for i := 0; i < 10; i++ {
		_, dead, err := f.proc.RetryFailed(ctx, 100)
		if err != nil {
			t.Fatal(err)
		}
		if dead == 1 {
			break
		}
	}
	deadEvents, _ := f.store.ListWebhookEventsByStatus(ctx, authstore.WebhookDead, 0)
	if len(deadEvents) != 1 {
		t.Fatalf("expected 1 dead-lettered event, got %d", len(deadEvents))
	}
}

func TestReconcileHealsMirror(t *testing.T) {
	f := newFixture(t)
	ctx := context.Background()
	// Seed an account link and a stale active mirror, then have Stripe report
	// the subscription canceled. Reconciliation must heal the mirror + revoke.
	f.store.UpsertAccount(ctx, authstore.Account{ID: "acct_1", StripeCustomerID: "cus_1"})
	f.store.UpsertSubscription(ctx, authstore.Subscription{ID: "sub_1", AccountID: "acct_1", Status: authstore.SubActive, MaxPairs: 1})
	f.store.CreateLicense(ctx, authstore.License{ID: "lic_1", AccountID: "acct_1", SubscriptionID: "sub_1", Status: authstore.LicenseActive})

	f.api.Set(fake.Subscription("sub_1", "cus_1", stripe.SubscriptionStatusCanceled, 1))
	if err := f.proc.Reconcile(ctx); err != nil {
		t.Fatal(err)
	}
	sub, _ := f.store.GetSubscription(ctx, "sub_1")
	if sub.Status != authstore.SubCanceled {
		t.Fatalf("mirror not healed: %+v", sub)
	}
	got, _ := f.store.GetLicense(ctx, "lic_1")
	if got.Status != authstore.LicenseRevoked {
		t.Fatalf("license not revoked by reconcile: %+v", got)
	}
}

// TestVerifyAcceptsMismatchedAPIVersion is the regression guard for the live-
// webhook 400s: a real Stripe account signs events with its own api_version,
// which differs from stripe-go's pinned stripe.APIVersion. The default
// webhook.ConstructEvent rejects those, so every live event 400'd and the
// desktop checkout claim never went ready. Verify must accept them (it reads
// only version-stable fields). The hermetic fake stamps the SDK version, so
// this test forces a deliberately different one.
func TestVerifyAcceptsMismatchedAPIVersion(t *testing.T) {
	f := newFixture(t)
	const otherVersion = "2099-12-31" // certainly != stripe.APIVersion
	body, sig := f.wh.EventWithAPIVersion(
		stripe.EventTypeCheckoutSessionCompleted,
		fake.CheckoutCompletedWithNonce("cs_v", "cus_v", "sub_v", "nonce_versioncheck"),
		otherVersion,
	)

	// Sanity: the default constructor (pre-fix behavior) DOES reject this, so the
	// scenario genuinely exercises the version-mismatch path.
	if _, err := webhook.ConstructEvent(body, sig, secret); err == nil {
		t.Fatal("precondition: default ConstructEvent should reject a mismatched api_version")
	}

	// The fix: Verify accepts it.
	ev, err := f.proc.Verify(body, sig)
	if err != nil {
		t.Fatalf("Verify rejected a live-API-version event (regression): %v", err)
	}
	if ev.Type != stripe.EventTypeCheckoutSessionCompleted {
		t.Fatalf("unexpected event type: %s", ev.Type)
	}

	// A genuinely bad signature must still fail (the fix only relaxes the version
	// check, not signature verification).
	if _, err := f.proc.Verify(body, "t=1,v1=deadbeef"); err == nil {
		t.Fatal("Verify accepted a bad signature")
	}
}

// Regression: when customer.subscription.created is processed BEFORE
// checkout.session.completed (Stripe can deliver them in that order), the
// subscription event creates+provisions an account via resolveAccount. The
// checkout event — which carries no client_reference_id in the desktop claim-token
// flow — must REUSE that account, not mint a fresh one, or the claim binds the
// desktop to an account whose license belongs to a different one (→ 404
// license_not_found at pairing).
func TestCheckoutReusesAccountFromEarlierSubscriptionEvent(t *testing.T) {
	f := newFixture(t)
	ctx := context.Background()
	const nonce = "nonce-abcdef-0123456789"

	// Desktop started checkout: a pending claim keyed by the nonce, no account yet.
	if err := f.store.CreateCheckoutClaim(ctx, authstore.CheckoutClaim{
		Nonce: nonce, StripeSessionID: "cs_1", Status: authstore.ClaimPending,
		CreatedAt: time.Now(), ExpiresAt: time.Now().Add(time.Hour),
	}); err != nil {
		t.Fatalf("create claim: %v", err)
	}
	f.api.Set(fake.Subscription("sub_1", "cus_1", stripe.SubscriptionStatusActive, 1))

	// Subscription event first: creates an account + provisions the license.
	body, sig := f.wh.Event(stripe.EventTypeCustomerSubscriptionCreated,
		fake.MarshalSubscription(fake.Subscription("sub_1", "cus_1", stripe.SubscriptionStatusActive, 1)))
	f.deliver(t, body, sig)

	// Checkout completes with NO client_reference_id (claim-token flow).
	body, sig = f.wh.Event(stripe.EventTypeCheckoutSessionCompleted,
		fake.CheckoutCompletedWithNonce("cs_1", "cus_1", "sub_1", nonce))
	f.deliver(t, body, sig)

	lics, _ := f.store.ListLicensesBySubscription(ctx, "sub_1")
	if len(lics) != 1 {
		t.Fatalf("want exactly 1 license, got %d", len(lics))
	}
	claim, err := f.store.GetCheckoutClaim(ctx, nonce)
	if err != nil {
		t.Fatalf("get claim: %v", err)
	}
	if claim.Status != authstore.ClaimReady {
		t.Fatalf("claim status = %v, want ready", claim.Status)
	}
	// The crux: the account the claim hands the desktop MUST own the license.
	if claim.AccountID != lics[0].AccountID {
		t.Fatalf("account mismatch: claim=%s license=%s", claim.AccountID, lics[0].AccountID)
	}
	if claim.LicenseID != lics[0].ID {
		t.Fatalf("license mismatch: claim=%s license=%s", claim.LicenseID, lics[0].ID)
	}
}
