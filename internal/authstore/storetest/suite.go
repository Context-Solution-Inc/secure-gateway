// Package storetest provides a shared conformance suite so the in-memory and
// Postgres authstore.Store implementations stay behaviorally identical. Each
// implementation's test package calls Run with a constructor.
package storetest

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/lley154/secure-gateway/internal/authstore"
	"github.com/lley154/secure-gateway/internal/token"
)

// Run exercises the full Store contract against the store returned by newStore.
// newStore must return a fresh, empty store on each call.
func Run(t *testing.T, newStore func(t *testing.T) authstore.Store) {
	t.Helper()
	t.Run("Accounts", func(t *testing.T) { testAccounts(t, newStore(t)) })
	t.Run("Subscriptions", func(t *testing.T) { testSubscriptions(t, newStore(t)) })
	t.Run("Licenses", func(t *testing.T) { testLicenses(t, newStore(t)) })
	t.Run("Devices", func(t *testing.T) { testDevices(t, newStore(t)) })
	t.Run("Pairings", func(t *testing.T) { testPairings(t, newStore(t)) })
	t.Run("RefreshTokens", func(t *testing.T) { testRefreshTokens(t, newStore(t)) })
	t.Run("PairingTokens", func(t *testing.T) { testPairingTokens(t, newStore(t)) })
	t.Run("CheckoutClaims", func(t *testing.T) { testCheckoutClaims(t, newStore(t)) })
	t.Run("WebhookEvents", func(t *testing.T) { testWebhookEvents(t, newStore(t)) })
}

func testAccounts(t *testing.T, s authstore.Store) {
	ctx := context.Background()
	if _, err := s.GetAccount(ctx, "missing"); !errors.Is(err, authstore.ErrNotFound) {
		t.Fatalf("GetAccount missing: want ErrNotFound, got %v", err)
	}
	a := authstore.Account{ID: "acct_1", StripeCustomerID: "cus_1", SecretHash: "h1"}
	if err := s.UpsertAccount(ctx, a); err != nil {
		t.Fatal(err)
	}
	got, err := s.GetAccount(ctx, "acct_1")
	if err != nil || got.StripeCustomerID != "cus_1" || got.SecretHash != "h1" {
		t.Fatalf("GetAccount: %+v err=%v", got, err)
	}
	byCust, err := s.GetAccountByCustomer(ctx, "cus_1")
	if err != nil || byCust.ID != "acct_1" {
		t.Fatalf("GetAccountByCustomer: %+v err=%v", byCust, err)
	}
	// Upsert must not wipe customer link or secret when those fields are empty.
	if err := s.UpsertAccount(ctx, authstore.Account{ID: "acct_1"}); err != nil {
		t.Fatal(err)
	}
	got, _ = s.GetAccount(ctx, "acct_1")
	if got.StripeCustomerID != "cus_1" || got.SecretHash != "h1" {
		t.Fatalf("upsert clobbered fields: %+v", got)
	}
}

func testSubscriptions(t *testing.T, s authstore.Store) {
	ctx := context.Background()
	now := time.Now().Truncate(time.Millisecond)
	sub := authstore.Subscription{
		ID: "sub_1", AccountID: "acct_1", Status: authstore.SubActive,
		MaxPairs: 2, CurrentPeriodEnd: now.Add(720 * time.Hour), UpdatedAt: now,
	}
	if err := s.UpsertSubscription(ctx, sub); err != nil {
		t.Fatal(err)
	}
	got, err := s.GetSubscription(ctx, "sub_1")
	if err != nil || got.Status != authstore.SubActive || got.MaxPairs != 2 {
		t.Fatalf("GetSubscription: %+v err=%v", got, err)
	}
	// Update status + grace.
	sub.Status = authstore.SubPastDue
	sub.GraceUntil = now.Add(168 * time.Hour)
	if err := s.UpsertSubscription(ctx, sub); err != nil {
		t.Fatal(err)
	}
	got, _ = s.GetSubscription(ctx, "sub_1")
	if got.Status != authstore.SubPastDue || got.GraceUntil.IsZero() {
		t.Fatalf("update: %+v", got)
	}
	list, err := s.ListSubscriptions(ctx)
	if err != nil || len(list) != 1 {
		t.Fatalf("ListSubscriptions: %d err=%v", len(list), err)
	}
}

func testLicenses(t *testing.T, s authstore.Store) {
	ctx := context.Background()
	l := authstore.License{ID: "lic_1", AccountID: "acct_1", SubscriptionID: "sub_1", SubscriptionItemID: "si_1", Status: authstore.LicenseActive}
	if err := s.CreateLicense(ctx, l); err != nil {
		t.Fatal(err)
	}
	if err := s.CreateLicense(ctx, l); !errors.Is(err, authstore.ErrConflict) {
		t.Fatalf("duplicate CreateLicense: want ErrConflict, got %v", err)
	}
	if err := s.CreateLicense(ctx, authstore.License{ID: "lic_2", AccountID: "acct_1", SubscriptionID: "sub_2", Status: authstore.LicenseActive}); err != nil {
		t.Fatal(err)
	}
	byAcct, err := s.ListLicensesByAccount(ctx, "acct_1")
	if err != nil || len(byAcct) != 2 {
		t.Fatalf("ListLicensesByAccount: %d err=%v", len(byAcct), err)
	}
	bySub, err := s.ListLicensesBySubscription(ctx, "sub_1")
	if err != nil || len(bySub) != 1 || bySub[0].ID != "lic_1" {
		t.Fatalf("ListLicensesBySubscription: %+v err=%v", bySub, err)
	}
	if err := s.SetLicenseStatus(ctx, "lic_1", authstore.LicenseRevoked); err != nil {
		t.Fatal(err)
	}
	got, _ := s.GetLicense(ctx, "lic_1")
	if got.Status != authstore.LicenseRevoked {
		t.Fatalf("SetLicenseStatus: %+v", got)
	}
	if err := s.SetLicenseStatus(ctx, "missing", authstore.LicenseRevoked); !errors.Is(err, authstore.ErrNotFound) {
		t.Fatalf("SetLicenseStatus missing: want ErrNotFound, got %v", err)
	}
}

func testDevices(t *testing.T, s authstore.Store) {
	ctx := context.Background()
	d := authstore.Device{ID: "dev_1", AccountID: "acct_1", Role: token.RoleMobile, PublicKey: []byte{1, 2, 3}}
	if err := s.UpsertDevice(ctx, d); err != nil {
		t.Fatal(err)
	}
	got, err := s.GetDevice(ctx, "dev_1")
	if err != nil || got.Role != token.RoleMobile || len(got.PublicKey) != 3 {
		t.Fatalf("GetDevice: %+v err=%v", got, err)
	}
	// Mutating the returned slice must not affect stored state.
	got.PublicKey[0] = 9
	again, _ := s.GetDevice(ctx, "dev_1")
	if again.PublicKey[0] != 1 {
		t.Fatalf("returned slice aliases stored state: %v", again.PublicKey)
	}
	if _, err := s.GetDevice(ctx, "missing"); !errors.Is(err, authstore.ErrNotFound) {
		t.Fatalf("GetDevice missing: want ErrNotFound, got %v", err)
	}
}

func testPairings(t *testing.T, s authstore.Store) {
	ctx := context.Background()
	p := authstore.Pairing{PairID: "pair_1", LicenseID: "lic_1", AccountID: "acct_1", MobileDeviceID: "dev_m", DesktopDeviceID: "dev_d", Status: authstore.PairingActive}
	if err := s.CreatePairing(ctx, p); err != nil {
		t.Fatal(err)
	}
	if err := s.CreatePairing(ctx, p); !errors.Is(err, authstore.ErrConflict) {
		t.Fatalf("duplicate CreatePairing: want ErrConflict, got %v", err)
	}
	n, err := s.ActivePairCount(ctx, "lic_1")
	if err != nil || n != 1 {
		t.Fatalf("ActivePairCount: %d err=%v", n, err)
	}
	byLic, _ := s.ListActivePairingsByLicense(ctx, "lic_1")
	byAcct, _ := s.ListActivePairingsByAccount(ctx, "acct_1")
	if len(byLic) != 1 || len(byAcct) != 1 {
		t.Fatalf("list active: lic=%d acct=%d", len(byLic), len(byAcct))
	}
	// Re-pairing replaces the device entry in place, keeping pair_id (FR-2.4).
	if err := s.UpdatePairingDevices(ctx, "pair_1", "dev_m2", "dev_d2"); err != nil {
		t.Fatal(err)
	}
	got, _ := s.GetPairing(ctx, "pair_1")
	if got.MobileDeviceID != "dev_m2" || got.DesktopDeviceID != "dev_d2" {
		t.Fatalf("UpdatePairingDevices: %+v", got)
	}
	if err := s.UpdatePairingDevices(ctx, "missing", "a", "b"); !errors.Is(err, authstore.ErrNotFound) {
		t.Fatalf("UpdatePairingDevices missing: want ErrNotFound, got %v", err)
	}
	if err := s.SetPairingStatus(ctx, "pair_1", authstore.PairingRevoked); err != nil {
		t.Fatal(err)
	}
	n, _ = s.ActivePairCount(ctx, "lic_1")
	if n != 0 {
		t.Fatalf("ActivePairCount after revoke: %d", n)
	}
	byLic, _ = s.ListActivePairingsByLicense(ctx, "lic_1")
	if len(byLic) != 0 {
		t.Fatalf("revoked pairing still listed active: %d", len(byLic))
	}
}

func testRefreshTokens(t *testing.T, s authstore.Store) {
	ctx := context.Background()
	now := time.Now()
	r := authstore.RefreshToken{ID: "rt_hash_1", DeviceID: "dev_1", AccountID: "acct_1", PairID: "pair_1", ExpiresAt: now.Add(time.Hour)}
	if err := s.PutRefreshToken(ctx, r); err != nil {
		t.Fatal(err)
	}
	got, err := s.GetRefreshToken(ctx, "rt_hash_1")
	if err != nil || !got.Active(now) {
		t.Fatalf("GetRefreshToken: %+v err=%v active=%v", got, err, got.Active(now))
	}
	if err := s.RevokeRefreshToken(ctx, "rt_hash_1"); err != nil {
		t.Fatal(err)
	}
	got, _ = s.GetRefreshToken(ctx, "rt_hash_1")
	if got.Active(now) {
		t.Fatalf("token still active after revoke: %+v", got)
	}
	if _, err := s.GetRefreshToken(ctx, "missing"); !errors.Is(err, authstore.ErrNotFound) {
		t.Fatalf("GetRefreshToken missing: want ErrNotFound, got %v", err)
	}
}

func testPairingTokens(t *testing.T, s authstore.Store) {
	ctx := context.Background()
	now := time.Now()
	tok := authstore.PairingToken{
		ID: "pt_hash_1", AccountID: "acct_1", LicenseID: "lic_1", DesktopDeviceID: "dev_d",
		ExpiresAt: now.Add(5 * time.Minute),
	}
	if err := s.CreatePairingToken(ctx, tok); err != nil {
		t.Fatal(err)
	}
	if err := s.CreatePairingToken(ctx, tok); !errors.Is(err, authstore.ErrConflict) {
		t.Fatalf("duplicate CreatePairingToken: want ErrConflict, got %v", err)
	}
	got, err := s.GetPairingToken(ctx, "pt_hash_1")
	if err != nil || !got.Active(now) || got.LicenseID != "lic_1" || got.DesktopDeviceID != "dev_d" {
		t.Fatalf("GetPairingToken: %+v err=%v active=%v", got, err, got.Active(now))
	}
	// Consume sets the result pair id and flips Active to false.
	if err := s.ConsumePairingToken(ctx, "pt_hash_1", "pair_99", now); err != nil {
		t.Fatal(err)
	}
	got, _ = s.GetPairingToken(ctx, "pt_hash_1")
	if got.Active(now) || got.ResultPairID != "pair_99" {
		t.Fatalf("after consume: %+v active=%v", got, got.Active(now))
	}
	// Second consume must fail (single-use).
	if err := s.ConsumePairingToken(ctx, "pt_hash_1", "pair_other", now); !errors.Is(err, authstore.ErrConflict) {
		t.Fatalf("double consume: want ErrConflict, got %v", err)
	}
	if err := s.ConsumePairingToken(ctx, "missing", "p", now); !errors.Is(err, authstore.ErrNotFound) {
		t.Fatalf("consume missing: want ErrNotFound, got %v", err)
	}
	if _, err := s.GetPairingToken(ctx, "missing"); !errors.Is(err, authstore.ErrNotFound) {
		t.Fatalf("GetPairingToken missing: want ErrNotFound, got %v", err)
	}
	// An expired token reports inactive.
	exp := authstore.PairingToken{ID: "pt_hash_2", AccountID: "acct_1", LicenseID: "lic_1", DesktopDeviceID: "dev_d", ExpiresAt: now.Add(-time.Minute)}
	if err := s.CreatePairingToken(ctx, exp); err != nil {
		t.Fatal(err)
	}
	got, _ = s.GetPairingToken(ctx, "pt_hash_2")
	if got.Active(now) {
		t.Fatalf("expired token reports active: %+v", got)
	}
}

func testCheckoutClaims(t *testing.T, s authstore.Store) {
	ctx := context.Background()
	now := time.Now()
	if _, err := s.GetCheckoutClaim(ctx, "missing"); !errors.Is(err, authstore.ErrNotFound) {
		t.Fatalf("GetCheckoutClaim missing: want ErrNotFound, got %v", err)
	}
	c := authstore.CheckoutClaim{
		Nonce: "nonce_1", StripeSessionID: "cs_1", RedirectURI: "http://127.0.0.1:8080/subscribe/callback",
		Status: authstore.ClaimPending, CreatedAt: now, ExpiresAt: now.Add(30 * time.Minute),
	}
	if err := s.CreateCheckoutClaim(ctx, c); err != nil {
		t.Fatal(err)
	}
	if err := s.CreateCheckoutClaim(ctx, c); !errors.Is(err, authstore.ErrConflict) {
		t.Fatalf("duplicate CreateCheckoutClaim: want ErrConflict, got %v", err)
	}
	// Cannot consume or set code while still pending.
	if _, err := s.ConsumeCheckoutClaim(ctx, "nonce_1", now); !errors.Is(err, authstore.ErrNotFound) {
		t.Fatalf("consume pending: want ErrNotFound, got %v", err)
	}
	if err := s.SetCheckoutClaimCode(ctx, "nonce_1", "codehash"); !errors.Is(err, authstore.ErrNotFound) {
		t.Fatalf("set code while pending: want ErrNotFound, got %v", err)
	}
	// Mark ready binds the provisioned ids.
	if err := s.MarkCheckoutClaimReady(ctx, "nonce_1", "acct_1", "lic_1", "sub_1", "cs_1"); err != nil {
		t.Fatal(err)
	}
	// Second mark-ready is an idempotent no-op (Stripe retry).
	if err := s.MarkCheckoutClaimReady(ctx, "nonce_1", "acct_X", "lic_X", "sub_X", "cs_X"); err != nil {
		t.Fatalf("idempotent mark-ready: %v", err)
	}
	got, err := s.GetCheckoutClaim(ctx, "nonce_1")
	if err != nil || got.Status != authstore.ClaimReady || got.AccountID != "acct_1" || got.SubscriptionID != "sub_1" {
		t.Fatalf("after mark-ready: %+v err=%v", got, err)
	}
	// Set + look up by code.
	if err := s.SetCheckoutClaimCode(ctx, "nonce_1", "codehash"); err != nil {
		t.Fatal(err)
	}
	byCode, err := s.GetCheckoutClaimByCode(ctx, "codehash")
	if err != nil || byCode.Nonce != "nonce_1" {
		t.Fatalf("GetCheckoutClaimByCode: %+v err=%v", byCode, err)
	}
	if _, err := s.GetCheckoutClaimByCode(ctx, ""); !errors.Is(err, authstore.ErrNotFound) {
		t.Fatalf("GetCheckoutClaimByCode empty: want ErrNotFound, got %v", err)
	}
	// Consume succeeds once and returns the bound row.
	consumed, err := s.ConsumeCheckoutClaim(ctx, "nonce_1", now)
	if err != nil || consumed.AccountID != "acct_1" || consumed.Status != authstore.ClaimConsumed {
		t.Fatalf("consume: %+v err=%v", consumed, err)
	}
	// Second consume must fail (single-use).
	if _, err := s.ConsumeCheckoutClaim(ctx, "nonce_1", now); !errors.Is(err, authstore.ErrConflict) {
		t.Fatalf("double consume: want ErrConflict, got %v", err)
	}
	// Expired-claim GC.
	exp := authstore.CheckoutClaim{Nonce: "nonce_2", RedirectURI: "http://127.0.0.1:9/cb", Status: authstore.ClaimPending, CreatedAt: now.Add(-time.Hour), ExpiresAt: now.Add(-time.Minute)}
	if err := s.CreateCheckoutClaim(ctx, exp); err != nil {
		t.Fatal(err)
	}
	n, err := s.DeleteExpiredCheckoutClaims(ctx, now)
	if err != nil || n != 1 {
		t.Fatalf("DeleteExpiredCheckoutClaims: n=%d err=%v", n, err)
	}
	if _, err := s.GetCheckoutClaim(ctx, "nonce_2"); !errors.Is(err, authstore.ErrNotFound) {
		t.Fatalf("expired claim not deleted: %v", err)
	}
}

func testWebhookEvents(t *testing.T, s authstore.Store) {
	ctx := context.Background()
	e := authstore.WebhookEvent{ID: "evt_1", Type: "invoice.paid", Status: authstore.WebhookProcessed, Payload: []byte(`{"a":1}`), ReceivedAt: time.Now()}
	inserted, err := s.InsertWebhookEventIfAbsent(ctx, e)
	if err != nil || !inserted {
		t.Fatalf("first insert: inserted=%v err=%v", inserted, err)
	}
	inserted, err = s.InsertWebhookEventIfAbsent(ctx, e)
	if err != nil || inserted {
		t.Fatalf("idempotent insert: inserted=%v err=%v (want false)", inserted, err)
	}
	// Move it to failed and back via the status setter.
	if err := s.SetWebhookStatus(ctx, "evt_1", authstore.WebhookFailed, 2, time.Time{}); err != nil {
		t.Fatal(err)
	}
	failed, err := s.ListWebhookEventsByStatus(ctx, authstore.WebhookFailed, 10)
	if err != nil || len(failed) != 1 || failed[0].Attempts != 2 {
		t.Fatalf("ListWebhookEventsByStatus failed: %+v err=%v", failed, err)
	}
	if err := s.SetWebhookStatus(ctx, "evt_1", authstore.WebhookDead, 5, time.Now()); err != nil {
		t.Fatal(err)
	}
	dead, _ := s.ListWebhookEventsByStatus(ctx, authstore.WebhookDead, 0)
	if len(dead) != 1 {
		t.Fatalf("dead list: %d", len(dead))
	}
}
