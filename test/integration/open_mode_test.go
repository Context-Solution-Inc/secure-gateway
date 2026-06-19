package integration

import (
	"encoding/base64"
	"encoding/json"
	"net/http"
	"testing"

	stripe "github.com/stripe/stripe-go/v82"
)

// TestOpenModePairingFlow covers the AUTH_BILLING_DISABLED open mode: account
// creation auto-provisions an open license, and the full secure-link flow
// (pairing token → completion → connection token) succeeds with no Stripe
// subscription webhook. Stripe-only endpoints are disabled.
func TestOpenModePairingFlow(t *testing.T) {
	a := newAuthHarnessNoBilling(t)

	// Account creation hands back an open license id (no checkout needed).
	secret, licenseID := a.createAccountOpen(t, "acct_open")
	if licenseID == "" {
		t.Fatal("expected an auto-provisioned license_id in open mode")
	}

	desktopID := a.registerDevice(t, secret, "desktop")
	mobileID := a.registerDevice(t, secret, "mobile")

	desktopPub := base64.StdEncoding.EncodeToString([]byte("desktop-x25519-public-key-32by!!"))
	mobilePub := base64.StdEncoding.EncodeToString([]byte("mobile-x25519-public-key-32byte!"))

	// Secure link is created without any subscription gating.
	status, issued := a.issuePairingToken(t, secret, licenseID, desktopID, desktopPub)
	if status != http.StatusOK {
		t.Fatalf("issue pairing token: status %d", status)
	}

	cstatus, pairID, _ := a.completePairing(t, issued.PairingToken, mobileID, mobilePub)
	if cstatus != http.StatusOK || pairID == "" {
		t.Fatalf("complete pairing: status %d pair %q", cstatus, pairID)
	}

	// Connection token issuance is also ungated.
	if st, _ := a.issueToken(t, secret, mobileID, pairID); st != http.StatusOK {
		t.Fatalf("issue token: status %d", st)
	}
}

// TestOpenModeProvisioningIsIdempotent verifies that re-creating an account
// (e.g. admin secret rotation) reuses the existing open license rather than
// minting a new one.
func TestOpenModeProvisioningIsIdempotent(t *testing.T) {
	a := newAuthHarnessNoBilling(t)
	_, first := a.createAccountOpen(t, "acct_idem")
	_, second := a.createAccountOpen(t, "acct_idem")
	if first == "" || first != second {
		t.Fatalf("expected stable license id across calls: first=%q second=%q", first, second)
	}
}

// TestOpenModeStripeEndpointsDisabled confirms the Stripe-only surfaces refuse
// service when billing is disabled.
func TestOpenModeStripeEndpointsDisabled(t *testing.T) {
	a := newAuthHarnessNoBilling(t)

	// Webhook is rejected outright (there is no secret to verify against).
	if code := a.sendWebhook(t, stripe.EventTypeCheckoutSessionCompleted, json.RawMessage(`{}`)); code != http.StatusServiceUnavailable {
		t.Fatalf("webhook in open mode: want 503, got %d", code)
	}

	// Checkout start is unavailable (no price configured).
	if status, _ := a.do(t, http.MethodPost, "/v1/checkout/start", "", map[string]string{}); status != http.StatusServiceUnavailable {
		t.Fatalf("checkout start in open mode: want 503, got %d", status)
	}
}
