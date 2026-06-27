// Package storetest provides a shared conformance suite so the in-memory and
// Postgres authstore.Store implementations stay behaviorally identical. Each
// implementation's test package calls Run with a constructor.
package storetest

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/context-solutions-inc/secure-gateway/internal/authstore"
	"github.com/context-solutions-inc/secure-gateway/internal/token"
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
	t.Run("PairingCapacity", func(t *testing.T) { testPairingCapacity(t, newStore(t)) })
	t.Run("RefreshTokens", func(t *testing.T) { testRefreshTokens(t, newStore(t)) })
	t.Run("PairingTokens", func(t *testing.T) { testPairingTokens(t, newStore(t)) })
	t.Run("PairCredentials", func(t *testing.T) { testPairCredentials(t, newStore(t)) })
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

	// Per-account device cap support (SG-10): count is account-scoped.
	if err := s.UpsertDevice(ctx, authstore.Device{ID: "dev_2", AccountID: "acct_1", Role: token.RoleDesktop, PublicKey: []byte{4, 5}}); err != nil {
		t.Fatal(err)
	}
	if err := s.UpsertDevice(ctx, authstore.Device{ID: "dev_3", AccountID: "acct_other", Role: token.RoleMobile, PublicKey: []byte{6}}); err != nil {
		t.Fatal(err)
	}
	if n, err := s.CountDevicesByAccount(ctx, "acct_1"); err != nil || n != 2 {
		t.Fatalf("CountDevicesByAccount(acct_1): got %d err=%v, want 2", n, err)
	}
	if n, err := s.CountDevicesByAccount(ctx, "acct_none"); err != nil || n != 0 {
		t.Fatalf("CountDevicesByAccount(acct_none): got %d err=%v, want 0", n, err)
	}

	// Idempotent re-registration lookup (SG-10): match on account+role+public_key.
	found, err := s.FindDeviceByAccountRoleKey(ctx, "acct_1", token.RoleMobile, []byte{1, 2, 3})
	if err != nil || found.ID != "dev_1" {
		t.Fatalf("FindDeviceByAccountRoleKey: got %+v err=%v, want dev_1", found, err)
	}
	// Mutating the returned slice must not affect stored state.
	found.PublicKey[0] = 9
	if again, _ := s.FindDeviceByAccountRoleKey(ctx, "acct_1", token.RoleMobile, []byte{1, 2, 3}); again.PublicKey[0] != 1 {
		t.Fatalf("FindDeviceByAccountRoleKey returned slice aliases stored state: %v", again.PublicKey)
	}
	// Wrong role, wrong key, and empty key never match.
	if _, err := s.FindDeviceByAccountRoleKey(ctx, "acct_1", token.RoleDesktop, []byte{1, 2, 3}); !errors.Is(err, authstore.ErrNotFound) {
		t.Fatalf("FindDeviceByAccountRoleKey wrong role: want ErrNotFound, got %v", err)
	}
	if _, err := s.FindDeviceByAccountRoleKey(ctx, "acct_1", token.RoleMobile, []byte{9, 9}); !errors.Is(err, authstore.ErrNotFound) {
		t.Fatalf("FindDeviceByAccountRoleKey wrong key: want ErrNotFound, got %v", err)
	}
	if _, err := s.FindDeviceByAccountRoleKey(ctx, "acct_1", token.RoleMobile, nil); !errors.Is(err, authstore.ErrNotFound) {
		t.Fatalf("FindDeviceByAccountRoleKey empty key: want ErrNotFound, got %v", err)
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

// testPairingCapacity covers the atomic capacity gate (SG-16): the count and the
// insert happen in one transaction, so a license can never exceed max_pairs.
func testPairingCapacity(t *testing.T, s authstore.Store) {
	ctx := context.Background()
	// The Postgres gate locks the license row (FOR UPDATE), so it must exist.
	if err := s.CreateLicense(ctx, authstore.License{ID: "lic_cap", AccountID: "acct_cap", SubscriptionID: "sub_cap", Status: authstore.LicenseActive}); err != nil {
		t.Fatal(err)
	}
	mk := func(id string) authstore.Pairing {
		return authstore.Pairing{PairID: id, LicenseID: "lic_cap", AccountID: "acct_cap", MobileDeviceID: "m_" + id, DesktopDeviceID: "d_" + id, Status: authstore.PairingActive}
	}
	const maxPairs = 2
	if err := s.CreatePairingWithinCapacity(ctx, mk("cap_a"), maxPairs); err != nil {
		t.Fatalf("first within-capacity insert: %v", err)
	}
	if err := s.CreatePairingWithinCapacity(ctx, mk("cap_b"), maxPairs); err != nil {
		t.Fatalf("second within-capacity insert: %v", err)
	}
	// Third exceeds max_pairs=2 and must be refused.
	if err := s.CreatePairingWithinCapacity(ctx, mk("cap_c"), maxPairs); !errors.Is(err, authstore.ErrCapacityExceeded) {
		t.Fatalf("over-capacity insert: want ErrCapacityExceeded, got %v", err)
	}
	if n, _ := s.ActivePairCount(ctx, "lic_cap"); n != 2 {
		t.Fatalf("ActivePairCount after over-capacity reject: got %d, want 2", n)
	}
	// A duplicate pair_id is a conflict, distinct from capacity.
	if err := s.CreatePairingWithinCapacity(ctx, mk("cap_a"), maxPairs); !errors.Is(err, authstore.ErrConflict) {
		t.Fatalf("duplicate within-capacity insert: want ErrConflict, got %v", err)
	}
	// Freeing a slot lets a new pairing in again.
	if err := s.SetPairingStatus(ctx, "cap_a", authstore.PairingRevoked); err != nil {
		t.Fatal(err)
	}
	if err := s.CreatePairingWithinCapacity(ctx, mk("cap_c"), maxPairs); err != nil {
		t.Fatalf("insert after freeing a slot: %v", err)
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

	// ConsumeRefreshToken is the atomic single-use rotation gate (SG-03): the
	// first consume succeeds and revokes; a second consume must return ErrConflict
	// so a replayed token cannot yield a second token pair.
	c := authstore.RefreshToken{ID: "rt_hash_2", DeviceID: "dev_2", AccountID: "acct_1", PairID: "pair_1", ExpiresAt: now.Add(time.Hour)}
	if err := s.PutRefreshToken(ctx, c); err != nil {
		t.Fatal(err)
	}
	if err := s.ConsumeRefreshToken(ctx, "rt_hash_2", now); err != nil {
		t.Fatalf("first consume: %v", err)
	}
	if got, _ := s.GetRefreshToken(ctx, "rt_hash_2"); got.Active(now) {
		t.Fatalf("token still active after consume: %+v", got)
	}
	if err := s.ConsumeRefreshToken(ctx, "rt_hash_2", now); !errors.Is(err, authstore.ErrConflict) {
		t.Fatalf("double consume: want ErrConflict, got %v", err)
	}
	if err := s.ConsumeRefreshToken(ctx, "missing", now); !errors.Is(err, authstore.ErrNotFound) {
		t.Fatalf("consume missing: want ErrNotFound, got %v", err)
	}

	// RevokeRefreshTokensByDevice revokes every still-active token for a device
	// (SG-04) and is idempotent across devices with no active tokens.
	for _, id := range []string{"rt_dev3_a", "rt_dev3_b"} {
		if err := s.PutRefreshToken(ctx, authstore.RefreshToken{ID: id, DeviceID: "dev_3", AccountID: "acct_1", PairID: "pair_1", ExpiresAt: now.Add(time.Hour)}); err != nil {
			t.Fatal(err)
		}
	}
	keep := authstore.RefreshToken{ID: "rt_dev4", DeviceID: "dev_4", AccountID: "acct_1", PairID: "pair_1", ExpiresAt: now.Add(time.Hour)}
	if err := s.PutRefreshToken(ctx, keep); err != nil {
		t.Fatal(err)
	}
	if err := s.RevokeRefreshTokensByDevice(ctx, "dev_3", now); err != nil {
		t.Fatal(err)
	}
	for _, id := range []string{"rt_dev3_a", "rt_dev3_b"} {
		if got, _ := s.GetRefreshToken(ctx, id); got.Active(now) {
			t.Fatalf("device token still active after bulk revoke: %s", id)
		}
	}
	if got, _ := s.GetRefreshToken(ctx, "rt_dev4"); !got.Active(now) {
		t.Fatalf("other device's token wrongly revoked: %+v", got)
	}
	// Idempotent: revoking a device with no active tokens is not an error.
	if err := s.RevokeRefreshTokensByDevice(ctx, "dev_3", now); err != nil {
		t.Fatalf("idempotent revoke: %v", err)
	}
	if err := s.RevokeRefreshTokensByDevice(ctx, "no_such_device", now); err != nil {
		t.Fatalf("revoke unknown device: %v", err)
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

func testPairCredentials(t *testing.T, s authstore.Store) {
	ctx := context.Background()
	now := time.Now().Truncate(time.Millisecond)
	if _, err := s.GetPairCredential(ctx, "missing"); !errors.Is(err, authstore.ErrNotFound) {
		t.Fatalf("GetPairCredential missing: want ErrNotFound, got %v", err)
	}
	c := authstore.PairCredential{
		PairID: "pair_1", AccountID: "acct_1", LicenseID: "lic_1",
		MobileDeviceID: "dev_m1", SecretHash: "h1", CreatedAt: now,
	}
	if err := s.PutPairCredential(ctx, c); err != nil {
		t.Fatal(err)
	}
	got, err := s.GetPairCredential(ctx, "pair_1")
	if err != nil || got.SecretHash != "h1" || got.MobileDeviceID != "dev_m1" || !got.Active(now) {
		t.Fatalf("GetPairCredential: %+v err=%v active=%v", got, err, got.Active(now))
	}
	// Re-pairing rotates in place: same pair_id, new device + secret, still active.
	rot := c
	rot.MobileDeviceID = "dev_m2"
	rot.SecretHash = "h2"
	if err := s.PutPairCredential(ctx, rot); err != nil {
		t.Fatal(err)
	}
	got, _ = s.GetPairCredential(ctx, "pair_1")
	if got.SecretHash != "h2" || got.MobileDeviceID != "dev_m2" || !got.Active(now) {
		t.Fatalf("after rotate: %+v active=%v", got, got.Active(now))
	}
	// Revoke flips Active to false; revoking again / a missing pair is idempotent.
	if err := s.RevokePairCredential(ctx, "pair_1", now); err != nil {
		t.Fatal(err)
	}
	got, _ = s.GetPairCredential(ctx, "pair_1")
	if got.Active(now) {
		t.Fatalf("revoked credential reports active: %+v", got)
	}
	if err := s.RevokePairCredential(ctx, "pair_1", now); err != nil {
		t.Fatalf("re-revoke should be idempotent, got %v", err)
	}
	if err := s.RevokePairCredential(ctx, "missing", now); err != nil {
		t.Fatalf("revoke missing should be idempotent, got %v", err)
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
