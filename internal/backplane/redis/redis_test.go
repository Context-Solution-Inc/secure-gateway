package redis

import (
	"context"
	"testing"
	"time"

	"github.com/alicebob/miniredis/v2"
	goredis "github.com/redis/go-redis/v9"

	"github.com/lley154/secure-gateway/internal/backplane"
	"github.com/lley154/secure-gateway/internal/token"
)

func newTestBackplane(t *testing.T, ttl time.Duration) (*Backplane, *miniredis.Miniredis) {
	t.Helper()
	mr, err := miniredis.Run()
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(mr.Close)
	rdb := goredis.NewClient(&goredis.Options{Addr: mr.Addr()})
	t.Cleanup(func() { _ = rdb.Close() })
	return NewWithClient(rdb, ttl), mr
}

func key() backplane.SlotKey {
	return backplane.SlotKey{PairID: "pair_1", Role: token.RoleMobile}
}

func TestClaimEvictsOlder(t *testing.T) {
	b, _ := newTestBackplane(t, time.Minute)
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
	if r2.EvictedConnID != "conn-A" || !r2.EvictedOnThisInstance {
		t.Fatalf("second claim: %+v", r2)
	}

	inst, _ := b.LookupInstance(ctx, key())
	if inst != "inst-1" {
		t.Errorf("owner = %q, want inst-1", inst)
	}
}

func TestReclaimSameConnNoEvict(t *testing.T) {
	b, _ := newTestBackplane(t, time.Minute)
	ctx := context.Background()
	_, _ = b.ClaimSlot(ctx, key(), "conn-A", "inst-1")
	r, _ := b.ClaimSlot(ctx, key(), "conn-A", "inst-1")
	if r.EvictedConnID != "" {
		t.Errorf("reclaim by same conn evicted %q", r.EvictedConnID)
	}
}

func TestRenewAndRelease(t *testing.T) {
	b, _ := newTestBackplane(t, time.Minute)
	ctx := context.Background()
	_, _ = b.ClaimSlot(ctx, key(), "conn-A", "inst-1")

	if err := b.RenewSlot(ctx, key(), "conn-A"); err != nil {
		t.Errorf("renew owner: %v", err)
	}
	if err := b.RenewSlot(ctx, key(), "conn-X"); err != backplane.ErrNotSlotOwner {
		t.Errorf("renew non-owner: got %v, want ErrNotSlotOwner", err)
	}

	// Superseded conn must not delete the winner's slot.
	_, _ = b.ClaimSlot(ctx, key(), "conn-B", "inst-1")
	if err := b.ReleaseSlot(ctx, key(), "conn-A"); err != nil {
		t.Fatal(err)
	}
	if inst, _ := b.LookupInstance(ctx, key()); inst != "inst-1" {
		t.Errorf("winner slot wrongly cleared, owner=%q", inst)
	}
	if err := b.ReleaseSlot(ctx, key(), "conn-B"); err != nil {
		t.Fatal(err)
	}
	if inst, _ := b.LookupInstance(ctx, key()); inst != "" {
		t.Errorf("slot not freed, owner=%q", inst)
	}
}

func TestTTLExpiry(t *testing.T) {
	b, mr := newTestBackplane(t, time.Minute)
	ctx := context.Background()
	_, _ = b.ClaimSlot(ctx, key(), "conn-A", "inst-1")

	mr.FastForward(2 * time.Minute) // expire the slot

	if inst, _ := b.LookupInstance(ctx, key()); inst != "" {
		t.Errorf("expired slot still owned by %q", inst)
	}
	// A fresh claim sees no live holder to evict.
	r, _ := b.ClaimSlot(ctx, key(), "conn-B", "inst-1")
	if r.EvictedConnID != "" {
		t.Errorf("expired holder reported as evicted: %q", r.EvictedConnID)
	}
}

func TestFrameRouting(t *testing.T) {
	b, _ := newTestBackplane(t, time.Minute)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	ch, err := b.SubscribeFrames(ctx, "inst-1")
	if err != nil {
		t.Fatal(err)
	}
	time.Sleep(100 * time.Millisecond) // let the subscription register

	want := backplane.RoutedFrame{PairID: "pair_1", ToRole: token.RoleDesktop, FromConn: "c", Data: []byte("opaque-bytes")}
	if err := b.Publish(ctx, "inst-1", want); err != nil {
		t.Fatal(err)
	}
	select {
	case got := <-ch:
		if string(got.Data) != "opaque-bytes" || got.ToRole != token.RoleDesktop {
			t.Errorf("frame mismatch: %+v", got)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("no frame delivered")
	}
}

func TestRevocationPubSub(t *testing.T) {
	b, _ := newTestBackplane(t, time.Minute)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	ch, _ := b.SubscribeRevocations(ctx)
	time.Sleep(100 * time.Millisecond)

	if err := b.PublishRevocation(ctx, backplane.RevocationEvent{PairID: "pair_1"}); err != nil {
		t.Fatal(err)
	}
	select {
	case got := <-ch:
		if got.PairID != "pair_1" {
			t.Errorf("pair = %q", got.PairID)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("no revocation delivered")
	}
}

// TestCrossInstanceEviction verifies that when instance 2 claims a slot held by
// instance 1, instance 1 is notified on its eviction channel.
func TestCrossInstanceEviction(t *testing.T) {
	b, _ := newTestBackplane(t, time.Minute)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	evicts, _ := b.SubscribeEvictions(ctx, "inst-1")
	time.Sleep(100 * time.Millisecond)

	// inst-1 holds the slot.
	if _, err := b.ClaimSlot(ctx, key(), "conn-A", "inst-1"); err != nil {
		t.Fatal(err)
	}
	// inst-2 claims the same slot, displacing inst-1's connection.
	r, err := b.ClaimSlot(ctx, key(), "conn-B", "inst-2")
	if err != nil {
		t.Fatal(err)
	}
	if r.EvictedConnID != "conn-A" || r.EvictedOnThisInstance {
		t.Fatalf("claim result: %+v (expected cross-instance eviction)", r)
	}
	select {
	case k := <-evicts:
		if k != key() {
			t.Errorf("eviction key = %v, want %v", k, key())
		}
	case <-time.After(2 * time.Second):
		t.Fatal("inst-1 was not notified of cross-instance eviction")
	}
}
