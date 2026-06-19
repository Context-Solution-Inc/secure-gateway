package integration

import (
	"encoding/base64"
	"encoding/json"
	"net/http"
	"net/url"
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

// TestOpenModeWebhookDisabled confirms the Stripe webhook surface refuses service
// when billing is disabled.
func TestOpenModeWebhookDisabled(t *testing.T) {
	a := newAuthHarnessNoBilling(t)
	if code := a.sendWebhook(t, stripe.EventTypeCheckoutSessionCompleted, json.RawMessage(`{}`)); code != http.StatusServiceUnavailable {
		t.Fatalf("webhook in open mode: want 503, got %d", code)
	}
}

// TestOpenModeCheckoutAutoCreatesAccount covers the desktop "upgrade" flow with
// billing disabled: POST /v1/checkout/start auto-provisions an account + open
// license and returns a claim_code, which the desktop redeems (by nonce, as its
// fallback poll does) for a working credential — with no client changes.
func TestOpenModeCheckoutAutoCreatesAccount(t *testing.T) {
	a := newAuthHarnessNoBilling(t)

	nonce := "opencheckoutnonce0000000000"
	redirect := "http://127.0.0.1:53127/subscribe/callback"

	// 1. Start checkout: 200 with a checkout_url carrying a claim_code (rather
	//    than a Stripe URL).
	status, body := a.do(t, http.MethodPost, "/v1/checkout/start", "", map[string]string{
		"nonce": nonce, "redirect_uri": redirect,
	})
	if status != http.StatusOK {
		t.Fatalf("checkout start: status %d body %s", status, body)
	}
	var start struct {
		CheckoutURL string `json:"checkout_url"`
		ExpiresIn   int    `json:"expires_in"`
	}
	mustUnmarshal(t, body, &start)
	u, err := url.Parse(start.CheckoutURL)
	if err != nil {
		t.Fatalf("parse checkout_url %q: %v", start.CheckoutURL, err)
	}
	if u.Query().Get("claim_code") == "" {
		t.Fatalf("expected claim_code in checkout_url, got %q", start.CheckoutURL)
	}

	// 2. Claim by nonce (the desktop's fallback poll path) → ready credential.
	cstatus, cbody := a.do(t, http.MethodPost, "/v1/accounts/claim", "", map[string]string{"nonce": nonce})
	if cstatus != http.StatusOK {
		t.Fatalf("claim: status %d body %s", cstatus, cbody)
	}
	var claim struct {
		AccountID     string `json:"account_id"`
		AccountSecret string `json:"account_secret"`
		LicenseID     string `json:"license_id"`
	}
	mustUnmarshal(t, cbody, &claim)
	if claim.AccountSecret == "" || claim.LicenseID == "" {
		t.Fatalf("claim missing credential fields: %+v", claim)
	}

	// 3. The claimed credential drives the full secure-link flow.
	secret := claim.AccountSecret
	desktopID := a.registerDevice(t, secret, "desktop")
	mobileID := a.registerDevice(t, secret, "mobile")
	desktopPub := base64.StdEncoding.EncodeToString([]byte("desktop-x25519-public-key-32by!!"))
	mobilePub := base64.StdEncoding.EncodeToString([]byte("mobile-x25519-public-key-32byte!"))

	pstatus, issued := a.issuePairingToken(t, secret, claim.LicenseID, desktopID, desktopPub)
	if pstatus != http.StatusOK {
		t.Fatalf("issue pairing token: status %d", pstatus)
	}
	if cs, pairID, _ := a.completePairing(t, issued.PairingToken, mobileID, mobilePub); cs != http.StatusOK || pairID == "" {
		t.Fatalf("complete pairing: status %d pair %q", cs, pairID)
	}

	// 4. Re-claiming the consumed nonce is rejected (single-use).
	if again, _ := a.do(t, http.MethodPost, "/v1/accounts/claim", "", map[string]string{"nonce": nonce}); again != http.StatusConflict {
		t.Fatalf("claim replay: want 409, got %d", again)
	}
}
