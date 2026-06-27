// Package backplane is the seam between the relay's per-instance hub and the
// shared state needed to run many relay instances: connection slots (atomic
// claim/evict), cross-instance message routing, and the revocation channel
// (PRD §5.1, §9.1).
//
// Two implementations satisfy Backplane: an in-memory single-instance one
// (subpackage memory, used for the M1 soak) and a Redis one (subpackage redis).
// Only cmd/relay selects a concrete implementation; the hub depends on this
// interface alone.
package backplane

import (
	"context"
	"errors"

	"github.com/context-solutions-inc/secure-gateway/internal/token"
)

// SlotKey identifies the single live connection slot for a (pair, role). Per
// pair there is exactly one mobile slot and one desktop slot (FR-3.4).
type SlotKey struct {
	PairID string
	Role   token.Role
}

func (k SlotKey) String() string {
	return "pair:" + k.PairID + ":" + string(k.Role)
}

// ClaimResult reports the outcome of a slot claim.
type ClaimResult struct {
	// Won is true if the caller now owns the slot. With the default
	// evict-older policy the newcomer always wins, so Won is true on success.
	Won bool
	// EvictedConnID is the previous holder displaced by this claim, or "" if
	// the slot was free. The displaced connection must be closed 4001.
	EvictedConnID string
	// EvictedOnThisInstance is true when the displaced connection is owned by
	// the claiming instance (close it locally); false means another instance
	// owns it and will be notified via the eviction channel.
	EvictedOnThisInstance bool
}

// RoutedFrame is a pre-serialized envelope plus the routing metadata needed to
// deliver it to the peer's instance.
type RoutedFrame struct {
	PairID   string
	ToRole   token.Role
	FromConn string
	Data     []byte
}

// RevocationEvent instructs all instances to close sessions matching either a
// pair_id or an account_id (FR-3.6, §6.5).
type RevocationEvent struct {
	PairID    string
	AccountID string
}

// Errors returned by Backplane implementations.
var (
	// ErrNotSlotOwner indicates the connection no longer owns the slot
	// (it was superseded). Callers should stop renewing.
	ErrNotSlotOwner = errors.New("connection no longer owns slot")
	// ErrUnavailable indicates the backing store is unreachable; new slot
	// claims must fail closed (PRD §10.3).
	ErrUnavailable = errors.New("backplane unavailable")
)

// Backplane is the shared registry + routing + revocation contract.
type Backplane interface {
	// ClaimSlot atomically claims key for (connID, instanceID), evicting any
	// older holder per the eviction policy and returning it for superseding.
	ClaimSlot(ctx context.Context, key SlotKey, connID, instanceID string) (ClaimResult, error)

	// RenewSlot extends the slot's liveness TTL; returns ErrNotSlotOwner if the
	// caller has been superseded.
	RenewSlot(ctx context.Context, key SlotKey, connID string) error

	// ReleaseSlot frees the slot iff still owned by connID (compare-and-delete),
	// so a superseded connection never deletes the winner's slot.
	ReleaseSlot(ctx context.Context, key SlotKey, connID string) error

	// LookupInstance returns the instance id currently owning key, or "" if the
	// slot is free. Used for cross-instance routing.
	LookupInstance(ctx context.Context, key SlotKey) (string, error)

	// Publish forwards a frame toward the peer's owning instance.
	Publish(ctx context.Context, instanceID string, f RoutedFrame) error

	// SubscribeFrames returns frames destined for sessions on instanceID.
	SubscribeFrames(ctx context.Context, instanceID string) (<-chan RoutedFrame, error)

	// SubscribeRevocations returns revocation events for all instances.
	SubscribeRevocations(ctx context.Context) (<-chan RevocationEvent, error)

	// SubscribeEvictions returns slot keys whose local holder on instanceID was
	// displaced by a claim from another instance.
	SubscribeEvictions(ctx context.Context, instanceID string) (<-chan SlotKey, error)

	// PublishRevocation announces a revocation to all instances. (Used by the
	// Auth service in M2 and by tests now.)
	PublishRevocation(ctx context.Context, ev RevocationEvent) error

	// HealthCheck reports backing-store reachability.
	HealthCheck(ctx context.Context) error

	// Close releases resources.
	Close() error
}
