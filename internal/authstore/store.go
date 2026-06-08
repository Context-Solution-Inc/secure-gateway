// Package authstore is the persistence seam for the Auth & License Service: the
// authoritative-local mirror of accounts, Stripe subscriptions, licenses,
// devices, pairings, refresh tokens, and processed webhook events (PRD §6.1).
//
// Stripe remains the source of truth for subscription state; this store is a
// synchronized mirror, never an independent authority. Two implementations
// satisfy Store: an in-memory one (subpackage memory, used for tests and the
// hermetic E2E) and a Postgres one (subpackage postgres). Only cmd/auth selects
// a concrete implementation; the service depends on this interface alone, the
// same way the relay's hub depends on backplane.Backplane.
package authstore

import (
	"context"
	"crypto/rand"
	"encoding/base32"
	"errors"
	"time"

	"github.com/lley154/secure-gateway/internal/token"
)

// Errors returned by Store implementations.
var (
	// ErrNotFound is returned when a requested record does not exist.
	ErrNotFound = errors.New("authstore: not found")
	// ErrConflict is returned when a uniqueness constraint is violated (e.g. a
	// pairing already exists for the device pair).
	ErrConflict = errors.New("authstore: conflict")
)

// SubStatus is the raw Stripe subscription status, mirrored verbatim so license
// behavior (PRD §6.3) is always derived from Stripe's own vocabulary.
type SubStatus string

const (
	SubTrialing          SubStatus = "trialing"
	SubActive            SubStatus = "active"
	SubPastDue           SubStatus = "past_due"
	SubCanceled          SubStatus = "canceled"
	SubUnpaid            SubStatus = "unpaid"
	SubIncompleteExpired SubStatus = "incomplete_expired"
	SubPaused            SubStatus = "paused"
)

// LicenseStatus is the local license lifecycle state. Validity for token
// issuance is derived jointly from this and the underlying subscription.
type LicenseStatus string

const (
	LicenseActive  LicenseStatus = "active"
	LicenseRevoked LicenseStatus = "revoked"
)

// PairingStatus is the pairing lifecycle state (FR-2.5).
type PairingStatus string

const (
	PairingActive  PairingStatus = "active"
	PairingRevoked PairingStatus = "revoked"
)

// WebhookStatus tracks durable webhook processing for idempotency and
// dead-lettering (PRD §6.4).
type WebhookStatus string

const (
	WebhookPending   WebhookStatus = "pending"
	WebhookProcessed WebhookStatus = "processed"
	WebhookFailed    WebhookStatus = "failed"
	WebhookDead      WebhookStatus = "dead"
)

// Account maps 1:1 to a Stripe Customer (PRD §6.1). Secret is the bcrypt-style
// hash of the account bearer secret used by the M2-minimal auth check; it is
// never returned to clients and never logged.
type Account struct {
	ID               string
	StripeCustomerID string
	SecretHash       string
	CreatedAt        time.Time
}

// Subscription mirrors a Stripe Subscription. MaxPairs is resolved from the
// price/product metadata (PRD §6.1). GraceUntil, when non-zero, is the instant a
// past_due subscription stops being honored (PRD §6.3).
type Subscription struct {
	ID               string
	AccountID        string
	Status           SubStatus
	MaxPairs         int
	CurrentPeriodEnd time.Time
	GraceUntil       time.Time
	UpdatedAt        time.Time
}

// License is a durable, account-scoped entitlement slot bound to a subscription
// item (PRD §6.1). The displayed key is the ID ("lic_…").
type License struct {
	ID                 string
	AccountID          string
	SubscriptionID     string
	SubscriptionItemID string
	Status             LicenseStatus
	CreatedAt          time.Time
}

// Device is a registered mobile or desktop installation. PublicKey is the
// device's X25519 public key; it is optional in M2 and populated by the M3 QR
// pairing flow.
type Device struct {
	ID        string
	AccountID string
	Role      token.Role
	PublicKey []byte
	CreatedAt time.Time
}

// Pairing binds a license to a mobile+desktop device pair and yields the
// pair_id carried in connection tokens (PRD §6.1, Appendix A).
type Pairing struct {
	PairID          string
	LicenseID       string
	AccountID       string
	MobileDeviceID  string
	DesktopDeviceID string
	Status          PairingStatus
	CreatedAt       time.Time
}

// RefreshToken is an opaque, rotating credential exchanged for connection JWTs.
// ID is a hash of the secret presented by the client; the secret itself is
// never stored (FR-3.1).
type RefreshToken struct {
	ID        string
	DeviceID  string
	AccountID string
	PairID    string
	ExpiresAt time.Time
	RevokedAt time.Time
}

// Active reports whether the refresh token is currently usable at now.
func (r RefreshToken) Active(now time.Time) bool {
	return r.RevokedAt.IsZero() && now.Before(r.ExpiresAt)
}

// PairingToken is the one-time, short-lived credential the desktop embeds in the
// QR code (FR-2.1). The mobile presents it to complete pairing. Like
// RefreshToken, ID is a hash of the secret; the secret itself is never stored.
// The token is bound at issue time to the desktop's account/license/device so
// the mobile cannot forge that binding. ResultPairID is filled on completion so
// the desktop's poll learns the new pair_id.
type PairingToken struct {
	ID              string // hash of the secret presented by clients
	AccountID       string
	LicenseID       string
	DesktopDeviceID string
	ExpiresAt       time.Time
	ConsumedAt      time.Time // zero => pending
	ResultPairID    string
}

// Active reports whether the pairing token is currently usable at now (not yet
// consumed and not expired).
func (t PairingToken) Active(now time.Time) bool {
	return t.ConsumedAt.IsZero() && now.Before(t.ExpiresAt)
}

// ClaimStatus tracks the lifecycle of a desktop checkout-claim (one-time
// onboarding so a freshly-paid desktop can learn its account credential).
type ClaimStatus string

const (
	// ClaimPending: checkout started, webhook not yet processed.
	ClaimPending ClaimStatus = "pending"
	// ClaimReady: webhook bound account/license/subscription; claimable.
	ClaimReady ClaimStatus = "ready"
	// ClaimConsumed: credential handed out exactly once; terminal.
	ClaimConsumed ClaimStatus = "consumed"
)

// CheckoutClaim binds a desktop-generated nonce to the account/license/
// subscription provisioned by a Stripe Checkout, so the desktop can claim its
// credentials exactly once after payment. No secret is ever stored here: the
// account secret is minted at claim time and only its hash is written to the
// account; ClaimCodeHash is the hash of the one-time code delivered over the
// loopback redirect. RedirectURI is the desktop's validated loopback callback.
type CheckoutClaim struct {
	Nonce           string // desktop-generated, primary key
	StripeSessionID string
	RedirectURI     string
	ClaimCodeHash   string // hash of the one-time code; empty until /return mints it
	AccountID       string
	LicenseID       string
	SubscriptionID  string
	Status          ClaimStatus
	CreatedAt       time.Time
	ExpiresAt       time.Time
	ConsumedAt      time.Time // zero => not consumed
}

// Active reports whether the claim is usable at now (not consumed, not expired).
func (c CheckoutClaim) Active(now time.Time) bool {
	return c.Status != ClaimConsumed && now.Before(c.ExpiresAt)
}

// WebhookEvent records a received Stripe event for idempotent, durable
// processing with dead-lettering (PRD §6.4).
type WebhookEvent struct {
	ID          string // Stripe event id (evt_…), primary key
	Type        string
	Status      WebhookStatus
	Attempts    int
	Payload     []byte
	ReceivedAt  time.Time
	ProcessedAt time.Time
}

// Store is the persistence contract. All methods take a context and return
// ErrNotFound for missing single-record lookups.
type Store interface {
	// Accounts.
	UpsertAccount(ctx context.Context, a Account) error
	GetAccount(ctx context.Context, id string) (Account, error)
	GetAccountByCustomer(ctx context.Context, stripeCustomerID string) (Account, error)

	// Subscriptions (the Stripe mirror).
	UpsertSubscription(ctx context.Context, s Subscription) error
	GetSubscription(ctx context.Context, id string) (Subscription, error)
	ListSubscriptions(ctx context.Context) ([]Subscription, error)

	// Licenses.
	CreateLicense(ctx context.Context, l License) error
	GetLicense(ctx context.Context, id string) (License, error)
	ListLicensesByAccount(ctx context.Context, accountID string) ([]License, error)
	ListLicensesBySubscription(ctx context.Context, subscriptionID string) ([]License, error)
	SetLicenseStatus(ctx context.Context, id string, status LicenseStatus) error

	// Devices.
	UpsertDevice(ctx context.Context, d Device) error
	GetDevice(ctx context.Context, id string) (Device, error)

	// Pairings.
	CreatePairing(ctx context.Context, p Pairing) error
	GetPairing(ctx context.Context, pairID string) (Pairing, error)
	ListActivePairingsByLicense(ctx context.Context, licenseID string) ([]Pairing, error)
	ListActivePairingsByAccount(ctx context.Context, accountID string) ([]Pairing, error)
	SetPairingStatus(ctx context.Context, pairID string, status PairingStatus) error
	// UpdatePairingDevices replaces the device entries on an existing pairing,
	// keeping its pair_id, for re-pairing (FR-2.4).
	UpdatePairingDevices(ctx context.Context, pairID, mobileDeviceID, desktopDeviceID string) error
	// ActivePairCount counts active pairings against a license, for the
	// capacity check (pairs in use < max_pairs, FR-2.2).
	ActivePairCount(ctx context.Context, licenseID string) (int, error)

	// Refresh tokens.
	PutRefreshToken(ctx context.Context, r RefreshToken) error
	GetRefreshToken(ctx context.Context, id string) (RefreshToken, error)
	RevokeRefreshToken(ctx context.Context, id string) error

	// Pairing tokens (one-time QR credential, FR-2.1).
	CreatePairingToken(ctx context.Context, t PairingToken) error
	GetPairingToken(ctx context.Context, id string) (PairingToken, error)
	// ConsumePairingToken marks a token consumed and records the resulting
	// pair_id. It returns ErrConflict if the token was already consumed, so
	// completion is atomic and single-use under concurrent requests.
	ConsumePairingToken(ctx context.Context, id, resultPairID string, consumedAt time.Time) error

	// Checkout claims (one-time desktop subscription onboarding).
	CreateCheckoutClaim(ctx context.Context, c CheckoutClaim) error
	GetCheckoutClaim(ctx context.Context, nonce string) (CheckoutClaim, error)
	GetCheckoutClaimByCode(ctx context.Context, claimCodeHash string) (CheckoutClaim, error)
	// MarkCheckoutClaimReady binds the provisioned ids and flips pending->ready.
	// It is a no-op (no error) when the claim is not pending, so Stripe webhook
	// retries are idempotent.
	MarkCheckoutClaimReady(ctx context.Context, nonce, accountID, licenseID, subscriptionID, sessionID string) error
	// SetCheckoutClaimCode (re)sets the one-time code hash while ready, so a
	// browser refresh of the success page rotates the code and stays valid.
	SetCheckoutClaimCode(ctx context.Context, nonce, claimCodeHash string) error
	// ConsumeCheckoutClaim atomically flips ready->consumed and returns the row.
	// It returns ErrConflict if already consumed and ErrNotFound if missing or
	// still pending, so the credential is handed out at most once.
	ConsumeCheckoutClaim(ctx context.Context, nonce string, consumedAt time.Time) (CheckoutClaim, error)
	// DeleteExpiredCheckoutClaims is GC for the periodic sweeper.
	DeleteExpiredCheckoutClaims(ctx context.Context, before time.Time) (int, error)

	// Webhook events (idempotency + dead-letter).
	// InsertWebhookEventIfAbsent returns inserted=false if the event id was
	// already recorded, giving callers exactly-once handling under Stripe retries.
	InsertWebhookEventIfAbsent(ctx context.Context, e WebhookEvent) (inserted bool, err error)
	SetWebhookStatus(ctx context.Context, id string, status WebhookStatus, attempts int, processedAt time.Time) error
	ListWebhookEventsByStatus(ctx context.Context, status WebhookStatus, limit int) ([]WebhookEvent, error)

	// Operational.
	HealthCheck(ctx context.Context) error
	Close() error
}

// NewID returns a random, URL-safe identifier with the given prefix (e.g.
// "acct", "dev", "pair"), matching the opaque-id convention used across the PRD.
func NewID(prefix string) string {
	return prefix + "_" + randToken(16)
}

// randToken returns n bytes of crypto-random data as lowercase base32 without
// padding (no ambiguous +/ characters; safe in URLs, headers, and SQL).
func randToken(n int) string {
	b := make([]byte, n)
	if _, err := rand.Read(b); err != nil {
		// crypto/rand failure is fatal for a security service; surface loudly
		// rather than minting a predictable id.
		panic("authstore: crypto/rand failed: " + err.Error())
	}
	enc := base32.StdEncoding.WithPadding(base32.NoPadding)
	out := enc.EncodeToString(b)
	// lowercase for nicer display; base32 std alphabet is A-Z2-7.
	return toLower(out)
}

func toLower(s string) string {
	b := []byte(s)
	for i, c := range b {
		if c >= 'A' && c <= 'Z' {
			b[i] = c + ('a' - 'A')
		}
	}
	return string(b)
}
