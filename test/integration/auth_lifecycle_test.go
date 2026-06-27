package integration

import (
	"context"
	"net/http"
	"testing"
	"time"

	"github.com/coder/websocket"
	stripe "github.com/stripe/stripe-go/v82"

	"github.com/context-solutions-inc/secure-gateway/internal/authstore"
	"github.com/context-solutions-inc/secure-gateway/internal/billing/fake"
	"github.com/context-solutions-inc/secure-gateway/internal/relay/protocol"
	"github.com/context-solutions-inc/secure-gateway/test/testclient"
)

// TestSubscriptionLifecycleE2E is the M2 exit criterion: purchase → use → fail
// payment → grace → cancel → cutoff, driven end-to-end through the auth service
// (signed webhooks, token issuance) and the relay (connect, forward, revoke),
// fully hermetic (memory store, fake Stripe, shared memory backplane).
func TestSubscriptionLifecycleE2E(t *testing.T) {
	a := newAuthHarness(t)
	ctx := context.Background()

	// 1. PURCHASE: checkout.session.completed provisions a license (max_pairs=1).
	a.api.Set(fake.Subscription("sub_e2e", "cus_e2e", stripe.SubscriptionStatusActive, 1))
	if code := a.sendWebhook(t, stripe.EventTypeCheckoutSessionCompleted,
		fake.CheckoutCompletedObject("cs_e2e", "cus_e2e", "acct_e2e", "sub_e2e")); code != http.StatusOK {
		t.Fatalf("checkout webhook status %d", code)
	}
	lics, _ := a.store.ListLicensesBySubscription(ctx, "sub_e2e")
	if len(lics) != 1 {
		t.Fatalf("want 1 provisioned license, got %d", len(lics))
	}
	licenseID := lics[0].ID

	// Register devices and pair them via the M3 QR pairing-token flow.
	secret := a.createAccount(t, "acct_e2e")
	mobileID := a.registerDevice(t, secret, "mobile")
	desktopID := a.registerDevice(t, secret, "desktop")
	pairID, _, _ := a.qrPair(t, secret, licenseID, mobileID, desktopID)

	// 2. USE: issue tokens, connect both ends to the relay, forward a frame.
	_, mobileTok := a.issueToken(t, secret, mobileID, pairID)
	_, desktopTok := a.issueToken(t, secret, desktopID, pairID)
	if mobileTok.Token == "" || desktopTok.Token == "" {
		t.Fatal("expected tokens to be issued for an active subscription")
	}

	dctx, dcancel := context.WithTimeout(ctx, 5*time.Second)
	defer dcancel()
	desktop, err := a.dialRelay(t, dctx, desktopTok.Token)
	if err != nil {
		t.Fatalf("desktop dial: %v", err)
	}
	defer desktop.Close()
	mobile, err := a.dialRelay(t, dctx, mobileTok.Token)
	if err != nil {
		t.Fatalf("mobile dial: %v", err)
	}
	defer mobile.Close()

	// Mobile sends an (opaque) frame; desktop receives it.
	payload := []byte("ciphertext-from-mobile")
	if err := mobile.SendMsg(dctx, "msg-1", payload); err != nil {
		t.Fatalf("send: %v", err)
	}
	env, err := desktop.RecvType(dctx, protocol.TypeMsg)
	if err != nil {
		t.Fatalf("recv: %v", err)
	}
	got, err := testclient.DecodePayload(env)
	if err != nil || string(got) != string(payload) {
		t.Fatalf("payload mismatch: got %q err=%v", got, err)
	}

	// Refresh works while valid, and the relay accepts the refreshed token.
	rstatus, refreshed := a.refreshToken(t, mobileTok.RefreshToken)
	if rstatus != http.StatusOK || refreshed.Token == "" {
		t.Fatalf("refresh while valid: status %d", rstatus)
	}
	if err := mobile.SendRefresh(dctx, refreshed.Token); err != nil {
		t.Fatalf("send refresh over socket: %v", err)
	}

	// 3. FAIL PAYMENT → GRACE: tokens still issue.
	if code := a.sendWebhook(t, stripe.EventTypeInvoicePaymentFailed, fake.InvoiceObject("in_e2e_1", "sub_e2e")); code != http.StatusOK {
		t.Fatalf("payment_failed webhook status %d", code)
	}
	if status, tok := a.issueToken(t, secret, mobileID, pairID); status != http.StatusOK || tok.Token == "" {
		t.Fatalf("grace must still issue tokens, got status %d", status)
	}

	// 4. CANCEL → CUTOFF: subscription.deleted revokes and closes live sessions.
	if code := a.sendWebhook(t, stripe.EventTypeCustomerSubscriptionDeleted,
		fake.MarshalSubscription(fake.Subscription("sub_e2e", "cus_e2e", stripe.SubscriptionStatusCanceled, 1))); code != http.StatusOK {
		t.Fatalf("cancel webhook status %d", code)
	}

	// Both live relay sessions close with 4004 revoked within the 2s budget.
	assertClosed4004(t, mobile)
	assertClosed4004(t, desktop)

	// And token issuance is now refused (cutoff).
	if status, _ := a.issueToken(t, secret, mobileID, pairID); status == http.StatusOK {
		t.Fatalf("token issuance must be refused after cancel, got %d", status)
	}
	// Refresh is refused too.
	if status, _ := a.refreshToken(t, refreshed.RefreshToken); status == http.StatusOK {
		t.Fatal("refresh must be refused after cancel")
	}

	// License and pairing are marked revoked in the mirror.
	gotLic, _ := a.store.GetLicense(ctx, licenseID)
	if gotLic.Status != authstore.LicenseRevoked {
		t.Fatalf("license should be revoked, got %s", gotLic.Status)
	}
}

func assertClosed4004(t *testing.T, c *testclient.Client) {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	code, _ := c.WaitClose(ctx)
	if code != websocket.StatusCode(4004) {
		t.Fatalf("expected close 4004 revoked, got %d", code)
	}
}
