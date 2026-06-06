package integration

import (
	"context"
	"encoding/base64"
	"net/http"
	"testing"
	"time"

	stripe "github.com/stripe/stripe-go/v82"

	"github.com/lley154/secure-gateway/internal/authstore"
	"github.com/lley154/secure-gateway/internal/backplane"
	"github.com/lley154/secure-gateway/internal/billing/fake"
)

// provisionLicense drives a checkout webhook to provision a license with the
// given pair capacity, then mints the account bearer secret for it.
func (a *authHarness) provisionLicense(t *testing.T, ctx context.Context, account, sub, cus string, maxPairs int) (licenseID, secret string) {
	t.Helper()
	a.api.Set(fake.Subscription(sub, cus, stripe.SubscriptionStatusActive, maxPairs))
	if code := a.sendWebhook(t, stripe.EventTypeCheckoutSessionCompleted,
		fake.CheckoutCompletedObject("cs_"+sub, cus, account, sub)); code != http.StatusOK {
		t.Fatalf("checkout webhook status %d", code)
	}
	lics, _ := a.store.ListLicensesBySubscription(ctx, sub)
	if len(lics) != 1 {
		t.Fatalf("want 1 license, got %d", len(lics))
	}
	return lics[0].ID, a.createAccount(t, account)
}

// issuePairingToken performs the desktop's POST /v1/pairing-tokens and returns
// the raw response fields.
func (a *authHarness) issuePairingToken(t *testing.T, secret, licenseID, desktopID, desktopPubB64 string) (int, struct {
	PairingToken string `json:"pairing_token"`
	ExpiresIn    int    `json:"expires_in"`
	QR           struct {
		V               int               `json:"v"`
		PairingToken    string            `json:"pairing_token"`
		DesktopPubKey   string            `json:"desktop_pubkey"`
		DesktopDeviceID string            `json:"desktop_device_id"`
		Endpoints       map[string]string `json:"endpoints"`
	} `json:"qr"`
}) {
	t.Helper()
	status, body := a.do(t, http.MethodPost, "/v1/pairing-tokens", secret, map[string]string{
		"license_id": licenseID, "desktop_device_id": desktopID, "desktop_public_key": desktopPubB64,
	})
	var r struct {
		PairingToken string `json:"pairing_token"`
		ExpiresIn    int    `json:"expires_in"`
		QR           struct {
			V               int               `json:"v"`
			PairingToken    string            `json:"pairing_token"`
			DesktopPubKey   string            `json:"desktop_pubkey"`
			DesktopDeviceID string            `json:"desktop_device_id"`
			Endpoints       map[string]string `json:"endpoints"`
		} `json:"qr"`
	}
	if status == http.StatusOK {
		mustUnmarshal(t, body, &r)
	}
	return status, r
}

func (a *authHarness) completePairing(t *testing.T, pairingToken, mobileID, mobilePubB64 string) (int, string, string) {
	t.Helper()
	status, body := a.do(t, http.MethodPost, "/v1/pairings", "", map[string]string{
		"pairing_token": pairingToken, "mobile_device_id": mobileID, "mobile_public_key": mobilePubB64,
	})
	var r struct {
		PairID           string `json:"pair_id"`
		DesktopPublicKey string `json:"desktop_public_key"`
	}
	if status == http.StatusOK {
		mustUnmarshal(t, body, &r)
	}
	return status, r.PairID, r.DesktopPublicKey
}

func (a *authHarness) pollPairing(t *testing.T, secret, pairingToken string) (status string, pairID, mobilePub string) {
	t.Helper()
	code, body := a.do(t, http.MethodPost, "/v1/pairing-tokens/poll", secret, map[string]string{"pairing_token": pairingToken})
	if code != http.StatusOK {
		t.Fatalf("poll: status %d body %s", code, body)
	}
	var r struct {
		Status          string `json:"status"`
		PairID          string `json:"pair_id"`
		MobilePublicKey string `json:"mobile_public_key"`
	}
	mustUnmarshal(t, body, &r)
	return r.Status, r.PairID, r.MobilePublicKey
}

// TestQRPairingFlow covers the M3 QR pairing flow end to end: token issuance with
// a versioned QR payload, desktop polling, mobile completion, one-time-use
// enforcement, re-pairing (FR-2.4), and unpairing (FR-2.5) — including the
// revocations published on the backplane.
func TestQRPairingFlow(t *testing.T) {
	a := newAuthHarness(t)
	ctx := context.Background()

	revs := a.subscribeRevocations(t, ctx)

	licenseID, secret := a.provisionLicense(t, ctx, "acct_qr", "sub_qr", "cus_qr", 1)
	mobileID := a.registerDevice(t, secret, "mobile")
	desktopID := a.registerDevice(t, secret, "desktop")

	desktopPub := base64.StdEncoding.EncodeToString([]byte("desktop-x25519-public-key-32by!!"))
	mobilePub := base64.StdEncoding.EncodeToString([]byte("mobile-x25519-public-key-32byte!"))

	// Desktop issues a pairing token; the QR payload is versioned and complete.
	status, issued := a.issuePairingToken(t, secret, licenseID, desktopID, desktopPub)
	if status != http.StatusOK {
		t.Fatalf("issue token: status %d", status)
	}
	if issued.QR.V != 1 || issued.QR.DesktopPubKey != desktopPub || issued.QR.DesktopDeviceID != desktopID {
		t.Fatalf("unexpected QR payload: %+v", issued.QR)
	}
	if issued.QR.Endpoints["relay"] == "" || issued.QR.Endpoints["auth"] == "" {
		t.Fatalf("QR endpoints missing: %+v", issued.QR.Endpoints)
	}

	// Before completion the desktop poll reports pending.
	if st, _, _ := a.pollPairing(t, secret, issued.PairingToken); st != "pending" {
		t.Fatalf("poll before completion: got %q", st)
	}

	// Mobile completes pairing and receives the desktop's public key.
	cstatus, pairID, gotDesktopPub := a.completePairing(t, issued.PairingToken, mobileID, mobilePub)
	if cstatus != http.StatusOK || pairID == "" {
		t.Fatalf("complete: status %d pair %q", cstatus, pairID)
	}
	if gotDesktopPub != desktopPub {
		t.Fatalf("complete returned wrong desktop pubkey: %q", gotDesktopPub)
	}

	// After completion the desktop poll reports completed + the mobile key.
	st, polledPair, polledMobilePub := a.pollPairing(t, secret, issued.PairingToken)
	if st != "completed" || polledPair != pairID || polledMobilePub != mobilePub {
		t.Fatalf("poll after completion: status=%q pair=%q mobilePub=%q", st, polledPair, polledMobilePub)
	}

	// The token is single-use: a replay of the now-consumed token is rejected
	// (the validity check treats a consumed token as invalid).
	if again, _, _ := a.completePairing(t, issued.PairingToken, mobileID, mobilePub); again != http.StatusUnauthorized {
		t.Fatalf("token replay: want 401, got %d", again)
	}

	// Re-pairing (new phone): a fresh token + new mobile device replaces the
	// device entry in place, keeping pair_id and publishing a revocation (FR-2.4).
	newMobileID := a.registerDevice(t, secret, "mobile")
	_, issued2 := a.issuePairingToken(t, secret, licenseID, desktopID, desktopPub)
	rstatus, rePairID, _ := a.completePairing(t, issued2.PairingToken, newMobileID, mobilePub)
	if rstatus != http.StatusOK {
		t.Fatalf("re-pair: status %d", rstatus)
	}
	if rePairID != pairID {
		t.Fatalf("re-pair should keep pair_id: got %q want %q", rePairID, pairID)
	}
	got, _ := a.store.GetPairing(ctx, pairID)
	if got.MobileDeviceID != newMobileID {
		t.Fatalf("re-pair did not replace mobile device: %+v", got)
	}
	if n, _ := a.store.ActivePairCount(ctx, licenseID); n != 1 {
		t.Fatalf("re-pair must not consume an extra slot: count=%d", n)
	}
	assertRevocation(t, revs, pairID)

	// Unpairing revokes the pairing, frees the slot, and publishes a revocation.
	ustatus, _ := a.do(t, http.MethodPost, "/v1/pairings/unpair", secret, map[string]string{"pair_id": pairID})
	if ustatus != http.StatusOK {
		t.Fatalf("unpair: status %d", ustatus)
	}
	gotPairing, _ := a.store.GetPairing(ctx, pairID)
	if gotPairing.Status != authstore.PairingRevoked {
		t.Fatalf("unpair did not revoke: %s", gotPairing.Status)
	}
	if n, _ := a.store.ActivePairCount(ctx, licenseID); n != 0 {
		t.Fatalf("unpair must free the slot: count=%d", n)
	}
	assertRevocation(t, revs, pairID)
}

// TestQRPairingCapacityExceeded verifies the capacity gate (FR-2.2): a second,
// distinct desktop cannot pair on a single-pair license.
func TestQRPairingCapacityExceeded(t *testing.T) {
	a := newAuthHarness(t)
	ctx := context.Background()

	licenseID, secret := a.provisionLicense(t, ctx, "acct_cap", "sub_cap", "cus_cap", 1)
	desktopID := a.registerDevice(t, secret, "desktop")
	mobileID := a.registerDevice(t, secret, "mobile")
	pub := base64.StdEncoding.EncodeToString([]byte("a-32-byte-x25519-public-key-here"))

	// First pair succeeds.
	_, issued := a.issuePairingToken(t, secret, licenseID, desktopID, pub)
	if st, _, _ := a.completePairing(t, issued.PairingToken, mobileID, pub); st != http.StatusOK {
		t.Fatalf("first pair: status %d", st)
	}

	// A second, different desktop cannot get a token (capacity full).
	desktop2 := a.registerDevice(t, secret, "desktop")
	if st, _ := a.issuePairingToken(t, secret, licenseID, desktop2, pub); st != http.StatusConflict {
		t.Fatalf("capacity gate: want 409, got %d", st)
	}
}

// --- revocation helpers ---

func (a *authHarness) subscribeRevocations(t *testing.T, ctx context.Context) <-chan backplane.RevocationEvent {
	t.Helper()
	sctx, cancel := context.WithCancel(ctx)
	t.Cleanup(cancel) // stop the subscription goroutine when the test ends
	ch, err := a.bp.SubscribeRevocations(sctx)
	if err != nil {
		t.Fatal(err)
	}
	return ch
}

func assertRevocation(t *testing.T, ch <-chan backplane.RevocationEvent, wantPair string) {
	t.Helper()
	select {
	case ev := <-ch:
		if ev.PairID != wantPair {
			t.Fatalf("revocation for wrong pair: got %q want %q", ev.PairID, wantPair)
		}
	case <-time.After(2 * time.Second):
		t.Fatalf("no revocation published for %s within 2s", wantPair)
	}
}
