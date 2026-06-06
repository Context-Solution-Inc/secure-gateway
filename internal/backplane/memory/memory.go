// Package memory is a single-instance, in-process Backplane implementation used
// for the M1 soak test and any deployment that runs exactly one relay instance.
//
// Slot claims are mutex-guarded map operations; routing and revocation are
// in-process channel fan-out. It implements the same contract as the Redis
// backplane so the relay logic is identical regardless of which is wired.
package memory

import (
	"context"
	"sync"
	"time"

	"github.com/lley154/secure-gateway/internal/backplane"
)

type entry struct {
	connID     string
	instanceID string
	expiresAt  time.Time
}

// Backplane is the in-memory implementation.
type Backplane struct {
	ttl   time.Duration
	now   func() time.Time
	qsize int

	mu    sync.Mutex
	slots map[backplane.SlotKey]entry

	subMu     sync.Mutex
	frames    map[string]chan backplane.RoutedFrame
	evictions map[string]chan backplane.SlotKey
	revs      []chan backplane.RevocationEvent
}

// New creates an in-memory backplane. ttl is the slot liveness window;
// qsize bounds each subscriber channel.
func New(ttl time.Duration, qsize int) *Backplane {
	return newWithClock(ttl, qsize, time.Now)
}

func newWithClock(ttl time.Duration, qsize int, now func() time.Time) *Backplane {
	if qsize <= 0 {
		qsize = 256
	}
	return &Backplane{
		ttl:       ttl,
		now:       now,
		qsize:     qsize,
		slots:     map[backplane.SlotKey]entry{},
		frames:    map[string]chan backplane.RoutedFrame{},
		evictions: map[string]chan backplane.SlotKey{},
	}
}

func (b *Backplane) ClaimSlot(_ context.Context, key backplane.SlotKey, connID, instanceID string) (backplane.ClaimResult, error) {
	b.mu.Lock()
	defer b.mu.Unlock()

	now := b.now()
	res := backplane.ClaimResult{Won: true}
	if cur, ok := b.slots[key]; ok && cur.expiresAt.After(now) && cur.connID != connID {
		// Evict-older policy: the newcomer wins; displace the live holder.
		res.EvictedConnID = cur.connID
		res.EvictedOnThisInstance = cur.instanceID == instanceID
		if !res.EvictedOnThisInstance {
			b.notifyEviction(cur.instanceID, key)
		}
	}
	b.slots[key] = entry{connID: connID, instanceID: instanceID, expiresAt: now.Add(b.ttl)}
	return res, nil
}

func (b *Backplane) RenewSlot(_ context.Context, key backplane.SlotKey, connID string) error {
	b.mu.Lock()
	defer b.mu.Unlock()
	cur, ok := b.slots[key]
	if !ok || cur.connID != connID {
		return backplane.ErrNotSlotOwner
	}
	cur.expiresAt = b.now().Add(b.ttl)
	b.slots[key] = cur
	return nil
}

func (b *Backplane) ReleaseSlot(_ context.Context, key backplane.SlotKey, connID string) error {
	b.mu.Lock()
	defer b.mu.Unlock()
	if cur, ok := b.slots[key]; ok && cur.connID == connID {
		delete(b.slots, key)
	}
	return nil
}

func (b *Backplane) LookupInstance(_ context.Context, key backplane.SlotKey) (string, error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	if cur, ok := b.slots[key]; ok && cur.expiresAt.After(b.now()) {
		return cur.instanceID, nil
	}
	return "", nil
}

func (b *Backplane) Publish(_ context.Context, instanceID string, f backplane.RoutedFrame) error {
	b.subMu.Lock()
	ch := b.frames[instanceID]
	b.subMu.Unlock()
	if ch == nil {
		return nil // no subscriber; peer not present on that instance
	}
	select {
	case ch <- f:
	default:
		// Drop on a full subscriber queue rather than block a router goroutine.
		// The hub's local fast path is the normal delivery route; this channel
		// only matters cross-instance (never in single-instance memory mode).
	}
	return nil
}

func (b *Backplane) SubscribeFrames(ctx context.Context, instanceID string) (<-chan backplane.RoutedFrame, error) {
	ch := make(chan backplane.RoutedFrame, b.qsize)
	b.subMu.Lock()
	b.frames[instanceID] = ch
	b.subMu.Unlock()
	go func() {
		<-ctx.Done()
		b.subMu.Lock()
		delete(b.frames, instanceID)
		b.subMu.Unlock()
	}()
	return ch, nil
}

func (b *Backplane) SubscribeEvictions(ctx context.Context, instanceID string) (<-chan backplane.SlotKey, error) {
	ch := make(chan backplane.SlotKey, b.qsize)
	b.subMu.Lock()
	b.evictions[instanceID] = ch
	b.subMu.Unlock()
	go func() {
		<-ctx.Done()
		b.subMu.Lock()
		delete(b.evictions, instanceID)
		b.subMu.Unlock()
	}()
	return ch, nil
}

func (b *Backplane) SubscribeRevocations(ctx context.Context) (<-chan backplane.RevocationEvent, error) {
	ch := make(chan backplane.RevocationEvent, b.qsize)
	b.subMu.Lock()
	b.revs = append(b.revs, ch)
	b.subMu.Unlock()
	go func() {
		<-ctx.Done()
		b.subMu.Lock()
		for i, c := range b.revs {
			if c == ch {
				b.revs = append(b.revs[:i], b.revs[i+1:]...)
				break
			}
		}
		b.subMu.Unlock()
	}()
	return ch, nil
}

func (b *Backplane) PublishRevocation(_ context.Context, ev backplane.RevocationEvent) error {
	b.subMu.Lock()
	subs := make([]chan backplane.RevocationEvent, len(b.revs))
	copy(subs, b.revs)
	b.subMu.Unlock()
	for _, ch := range subs {
		select {
		case ch <- ev:
		default:
		}
	}
	return nil
}

func (b *Backplane) notifyEviction(instanceID string, key backplane.SlotKey) {
	// caller holds b.mu; take subMu to read the subscriber map.
	b.subMu.Lock()
	ch := b.evictions[instanceID]
	b.subMu.Unlock()
	if ch == nil {
		return
	}
	select {
	case ch <- key:
	default:
	}
}

func (b *Backplane) HealthCheck(context.Context) error { return nil }

func (b *Backplane) Close() error { return nil }

// Compile-time assertion that *Backplane satisfies the interface.
var _ backplane.Backplane = (*Backplane)(nil)
