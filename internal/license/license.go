// Package license holds the entitlement rules that turn mirrored Stripe
// subscription state into a license behavior, plus license-key generation.
// These rules are the first enforcement point of PRD §6.5: the Auth service
// refuses to issue or refresh a connection token for an invalid license.
package license

import (
	"crypto/rand"
	"encoding/base32"
	"strconv"
	"strings"
	"time"

	"github.com/lley154/secure-gateway/internal/authstore"
)

// Behavior is the license posture derived from a subscription (PRD §6.3).
type Behavior int

const (
	// Valid: trialing/active. Tokens issued normally.
	Valid Behavior = iota
	// Grace: past_due within the grace window. Tokens still issued; user notified.
	Grace
	// Revoked: canceled/unpaid/incomplete_expired (or past_due past grace).
	Revoked
	// Suspended: paused. Enforced like revoked, but pairing records are retained.
	Suspended
)

func (b Behavior) String() string {
	switch b {
	case Valid:
		return "valid"
	case Grace:
		return "grace"
	case Revoked:
		return "revoked"
	case Suspended:
		return "suspended"
	default:
		return "unknown"
	}
}

// Evaluate maps a subscription to its license behavior at the instant now,
// implementing the PRD §6.3 table. Unknown statuses fail closed (Revoked).
func Evaluate(sub authstore.Subscription, now time.Time) Behavior {
	switch sub.Status {
	case authstore.SubTrialing, authstore.SubActive:
		return Valid
	case authstore.SubPastDue:
		// Within the recorded grace deadline → Grace; past it → Revoked. A
		// not-yet-computed deadline (zero) is treated as in-grace; the webhook
		// that set past_due sets GraceUntil, and reconciliation recomputes it.
		if sub.GraceUntil.IsZero() || now.Before(sub.GraceUntil) {
			return Grace
		}
		return Revoked
	case authstore.SubPaused:
		return Suspended
	case authstore.SubCanceled, authstore.SubUnpaid, authstore.SubIncompleteExpired:
		return Revoked
	default:
		return Revoked
	}
}

// Issuable reports whether a connection token may be issued for this behavior
// (PRD §6.5 #1): only Valid and Grace are honored.
func Issuable(b Behavior) bool { return b == Valid || b == Grace }

// Enforced reports whether the behavior demands an immediate cutoff of live
// sessions via the revocation channel (Revoked or Suspended).
func Enforced(b Behavior) bool { return b == Revoked || b == Suspended }

// MaxPairs reads the entitlement count from price/product metadata
// (metadata.max_pairs, PRD §6.1), defaulting to 1 and never returning < 1, so
// new plans can be added in Stripe without code changes.
func MaxPairs(metadata map[string]string) int {
	if metadata != nil {
		if v, ok := metadata["max_pairs"]; ok {
			if n, err := strconv.Atoi(strings.TrimSpace(v)); err == nil && n >= 1 {
				return n
			}
		}
	}
	return 1
}

// NewKey returns a fresh, opaque license key ("lic_…"), the durable identifier a
// desktop installation activates with (PRD §6.1). 20 random bytes → 32 base32
// chars of entropy.
func NewKey() string {
	b := make([]byte, 20)
	if _, err := rand.Read(b); err != nil {
		panic("license: crypto/rand failed: " + err.Error())
	}
	enc := base32.StdEncoding.WithPadding(base32.NoPadding)
	return "lic_" + strings.ToLower(enc.EncodeToString(b))
}
