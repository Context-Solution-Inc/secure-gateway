package ratelimit

import (
	"testing"
	"time"
)

func TestKeyedLimiterBurstThenDeny(t *testing.T) {
	// 60/min == 1/sec sustained, burst 3.
	k := NewKeyedLimiter(60, 3)
	allowed := 0
	for i := 0; i < 5; i++ {
		if k.Allow("1.2.3.4") {
			allowed++
		}
	}
	if allowed != 3 {
		t.Fatalf("expected 3 immediate allows (burst), got %d", allowed)
	}
	// A different key has its own bucket.
	if !k.Allow("5.6.7.8") {
		t.Fatal("independent key should be allowed")
	}
}

func TestKeyedLimiterDisabled(t *testing.T) {
	for _, k := range []*KeyedLimiter{NewKeyedLimiter(0, 10), NewKeyedLimiter(60, 0), (*KeyedLimiter)(nil)} {
		for i := 0; i < 100; i++ {
			if !k.Allow("x") {
				t.Fatal("disabled limiter must always allow")
			}
		}
	}
}

func TestKeyedLimiterSweep(t *testing.T) {
	now := time.Unix(1_000, 0)
	k := NewKeyedLimiter(60, 1)
	k.now = func() time.Time { return now }
	k.Allow("a")
	k.Allow("b")
	if k.Size() != 2 {
		t.Fatalf("expected 2 keys, got %d", k.Size())
	}
	now = now.Add(2 * time.Minute)
	k.Allow("b") // refresh b's seen time
	k.Sweep(time.Minute)
	if k.Size() != 1 {
		t.Fatalf("expected 1 key after sweep, got %d", k.Size())
	}
}

func TestBanTrackerBansAfterThreshold(t *testing.T) {
	now := time.Unix(1_000, 0)
	b := NewBanTracker(3, time.Minute, 15*time.Minute)
	b.now = func() time.Time { return now }

	if banned, _ := b.Banned("ip"); banned {
		t.Fatal("should not be banned initially")
	}
	if b.Strike("ip") || b.Strike("ip") {
		t.Fatal("should not ban before threshold")
	}
	if !b.Strike("ip") {
		t.Fatal("third strike should ban")
	}
	banned, retry := b.Banned("ip")
	if !banned {
		t.Fatal("should be banned after threshold")
	}
	if retry <= 0 || retry > 15*time.Minute {
		t.Fatalf("unexpected retry-after %s", retry)
	}
	if b.ActiveBans() != 1 {
		t.Fatalf("expected 1 active ban, got %d", b.ActiveBans())
	}

	// Ban expires.
	now = now.Add(16 * time.Minute)
	if banned, _ := b.Banned("ip"); banned {
		t.Fatal("ban should have expired")
	}
	if b.ActiveBans() != 0 {
		t.Fatalf("expected 0 active bans, got %d", b.ActiveBans())
	}
}

func TestBanTrackerStrikeWindowResets(t *testing.T) {
	now := time.Unix(1_000, 0)
	b := NewBanTracker(3, time.Minute, 15*time.Minute)
	b.now = func() time.Time { return now }

	b.Strike("ip")
	b.Strike("ip")
	// Past the strike window: count restarts, so two more strikes do not ban.
	now = now.Add(2 * time.Minute)
	if b.Strike("ip") {
		t.Fatal("strike after window reset should not ban (count restarted)")
	}
	if b.Strike("ip") {
		t.Fatal("still below threshold within fresh window")
	}
}

func TestBanTrackerSweep(t *testing.T) {
	now := time.Unix(1_000, 0)
	b := NewBanTracker(3, time.Minute, 15*time.Minute)
	b.now = func() time.Time { return now }
	b.Strike("transient")
	now = now.Add(2 * time.Minute)
	b.Sweep()
	if banned, _ := b.Banned("transient"); banned {
		t.Fatal("transient key should not be banned")
	}
	// After sweep the stale entry is gone (a fresh strike starts a new window).
	if b.Strike("transient") {
		t.Fatal("unexpected ban")
	}
}

func TestBanTrackerDisabled(t *testing.T) {
	for _, b := range []*BanTracker{NewBanTracker(0, time.Minute, time.Minute), (*BanTracker)(nil)} {
		for i := 0; i < 100; i++ {
			if b.Strike("x") {
				t.Fatal("disabled tracker must never ban")
			}
		}
		if banned, _ := b.Banned("x"); banned {
			t.Fatal("disabled tracker must never report banned")
		}
	}
}
