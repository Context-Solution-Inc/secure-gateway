package memory

import (
	"context"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/context-solutions-inc/secure-gateway/internal/backplane"
	"github.com/context-solutions-inc/secure-gateway/internal/token"
)

func key() backplane.SlotKey {
	return backplane.SlotKey{PairID: "pair_1", Role: token.RoleMobile}
}

func TestClaimEvictsOlder(t *testing.T) {
	b := New(time.Minute, 16)
	ctx := context.Background()

	r1, err := b.ClaimSlot(ctx, key(), "conn-A", "inst-1")
	if err != nil {
		t.Fatal(err)
	}
	if !r1.Won || r1.EvictedConnID != "" {
		t.Fatalf("first claim: %+v", r1)
	}

	r2, err := b.ClaimSlot(ctx, key(), "conn-B", "inst-1")
	if err != nil {
		t.Fatal(err)
	}
	if !r2.Won {
		t.Fatalf("second claim did not win: %+v", r2)
	}
	if r2.EvictedConnID != "conn-A" {
		t.Errorf("EvictedConnID = %q, want conn-A", r2.EvictedConnID)
	}
	if !r2.EvictedOnThisInstance {
		t.Errorf("expected eviction on this instance")
	}

	inst, _ := b.LookupInstance(ctx, key())
	if inst != "inst-1" {
		t.Errorf("owner instance = %q", inst)
	}
}

func TestReclaimSameConnNoEvict(t *testing.T) {
	b := New(time.Minute, 16)
	ctx := context.Background()
	_, _ = b.ClaimSlot(ctx, key(), "conn-A", "inst-1")
	r, _ := b.ClaimSlot(ctx, key(), "conn-A", "inst-1")
	if r.EvictedConnID != "" {
		t.Errorf("reclaim by same conn should not evict, got %q", r.EvictedConnID)
	}
}

func TestRenewAndReleaseOwnership(t *testing.T) {
	b := New(time.Minute, 16)
	ctx := context.Background()
	_, _ = b.ClaimSlot(ctx, key(), "conn-A", "inst-1")

	if err := b.RenewSlot(ctx, key(), "conn-A"); err != nil {
		t.Errorf("renew by owner: %v", err)
	}
	if err := b.RenewSlot(ctx, key(), "conn-OTHER"); err != backplane.ErrNotSlotOwner {
		t.Errorf("renew by non-owner: got %v, want ErrNotSlotOwner", err)
	}

	// Compare-and-delete: a superseded conn must not delete the winner's slot.
	_, _ = b.ClaimSlot(ctx, key(), "conn-B", "inst-1") // evicts A
	if err := b.ReleaseSlot(ctx, key(), "conn-A"); err != nil {
		t.Errorf("release by superseded conn: %v", err)
	}
	if inst, _ := b.LookupInstance(ctx, key()); inst != "inst-1" {
		t.Errorf("winner slot was wrongly cleared (owner=%q)", inst)
	}
	// The owner can release.
	if err := b.ReleaseSlot(ctx, key(), "conn-B"); err != nil {
		t.Fatal(err)
	}
	if inst, _ := b.LookupInstance(ctx, key()); inst != "" {
		t.Errorf("slot not freed, owner=%q", inst)
	}
}

func TestTTLExpiry(t *testing.T) {
	now := time.Unix(1_000_000, 0)
	clock := func() time.Time { return now }
	b := newWithClock(time.Minute, 16, clock)
	ctx := context.Background()

	_, _ = b.ClaimSlot(ctx, key(), "conn-A", "inst-1")
	now = now.Add(2 * time.Minute) // A's slot has now expired

	// A fresh claim sees the slot as free (no eviction of an expired holder).
	r, _ := b.ClaimSlot(ctx, key(), "conn-B", "inst-1")
	if r.EvictedConnID != "" {
		t.Errorf("expired holder should not be reported as evicted, got %q", r.EvictedConnID)
	}
}

func TestConcurrentClaimsSingleWinner(t *testing.T) {
	b := New(time.Minute, 16)
	ctx := context.Background()
	const n = 100

	var wins int64
	var lastOwner atomic.Value
	var wg sync.WaitGroup
	start := make(chan struct{})
	for i := 0; i < n; i++ {
		wg.Add(1)
		connID := "conn-" + string(rune('A'+i%26)) + "-" + time.Duration(i).String()
		go func(id string) {
			defer wg.Done()
			<-start
			r, err := b.ClaimSlot(ctx, key(), id, "inst-1")
			if err != nil {
				t.Errorf("claim: %v", err)
				return
			}
			if r.Won {
				atomic.AddInt64(&wins, 1)
			}
			lastOwner.Store(id)
		}(connID)
	}
	close(start)
	wg.Wait()

	// Evict-older policy: every claim "wins" the slot in turn, but exactly one
	// owner remains and the map holds a single entry.
	if wins != n {
		t.Errorf("wins = %d, want %d", wins, n)
	}
	b.mu.Lock()
	if len(b.slots) != 1 {
		t.Errorf("slot map size = %d, want 1", len(b.slots))
	}
	b.mu.Unlock()
}

func TestRevocationBroadcast(t *testing.T) {
	b := New(time.Minute, 16)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	c1, _ := b.SubscribeRevocations(ctx)
	c2, _ := b.SubscribeRevocations(ctx)

	ev := backplane.RevocationEvent{PairID: "pair_1"}
	if err := b.PublishRevocation(ctx, ev); err != nil {
		t.Fatal(err)
	}
	for i, ch := range []<-chan backplane.RevocationEvent{c1, c2} {
		select {
		case got := <-ch:
			if got.PairID != "pair_1" {
				t.Errorf("sub %d: pair = %q", i, got.PairID)
			}
		case <-time.After(time.Second):
			t.Errorf("sub %d: no revocation received", i)
		}
	}
}

func TestPublishRoutesToInstanceSubscriber(t *testing.T) {
	b := New(time.Minute, 16)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	ch, _ := b.SubscribeFrames(ctx, "inst-1")
	f := backplane.RoutedFrame{PairID: "pair_1", ToRole: token.RoleDesktop, FromConn: "c", Data: []byte("hi")}
	if err := b.Publish(ctx, "inst-1", f); err != nil {
		t.Fatal(err)
	}
	select {
	case got := <-ch:
		if string(got.Data) != "hi" {
			t.Errorf("data = %q", got.Data)
		}
	case <-time.After(time.Second):
		t.Fatal("no frame delivered")
	}
}
