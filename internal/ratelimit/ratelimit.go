// Package ratelimit provides in-process abuse controls shared by the relay and
// auth services (PRD §10.2): a per-key token-bucket limiter and a strike/ban
// tracker for repeat offenders.
//
// Limits are per-process. Behind multiple instances each instance enforces its
// own buckets; this is acceptable for v1 (see docs/threat-model.md). Both types
// are safe for concurrent use and bound memory by sweeping idle keys.
package ratelimit

import (
	"sync"
	"time"

	"golang.org/x/time/rate"
)

// KeyedLimiter holds an independent token bucket per key (e.g. client IP or
// account ID). Idle buckets are reclaimed by Sweep.
type KeyedLimiter struct {
	mu      sync.Mutex
	limit   rate.Limit
	burst   int
	entries map[string]*limiterEntry
	now     func() time.Time
}

type limiterEntry struct {
	lim  *rate.Limiter
	seen time.Time
}

// NewKeyedLimiter builds a limiter allowing perMinute sustained events per key
// with the given burst. A non-positive perMinute or burst yields a limiter that
// always allows (disabled).
func NewKeyedLimiter(perMinute float64, burst int) *KeyedLimiter {
	return &KeyedLimiter{
		limit:   rate.Limit(perMinute / 60.0),
		burst:   burst,
		entries: make(map[string]*limiterEntry),
		now:     time.Now,
	}
}

// disabled reports whether the limiter should allow everything.
func (k *KeyedLimiter) disabled() bool { return k == nil || k.limit <= 0 || k.burst <= 0 }

// Allow reports whether an event for key may proceed now, consuming a token.
func (k *KeyedLimiter) Allow(key string) bool {
	if k.disabled() {
		return true
	}
	k.mu.Lock()
	e := k.entries[key]
	if e == nil {
		e = &limiterEntry{lim: rate.NewLimiter(k.limit, k.burst)}
		k.entries[key] = e
	}
	e.seen = k.now()
	lim := e.lim
	k.mu.Unlock()
	return lim.Allow()
}

// Sweep drops buckets not used within idle, bounding memory under churn (e.g.
// short-lived client IPs). Call periodically from a background ticker.
func (k *KeyedLimiter) Sweep(idle time.Duration) {
	if k == nil {
		return
	}
	cutoff := k.now().Add(-idle)
	k.mu.Lock()
	for key, e := range k.entries {
		if e.seen.Before(cutoff) {
			delete(k.entries, key)
		}
	}
	k.mu.Unlock()
}

// Size returns the number of tracked keys (for tests/metrics).
func (k *KeyedLimiter) Size() int {
	if k == nil {
		return 0
	}
	k.mu.Lock()
	defer k.mu.Unlock()
	return len(k.entries)
}

// BanTracker records strikes per key and bans a key once it accumulates
// threshold strikes within strikeWindow. A banned key stays banned for
// banWindow. Used for protocol-error/oversize (4005) offenders at the relay.
type BanTracker struct {
	mu           sync.Mutex
	threshold    int
	strikeWindow time.Duration
	banWindow    time.Duration
	entries      map[string]*banEntry
	now          func() time.Time
}

type banEntry struct {
	strikes     int
	windowStart time.Time
	bannedUntil time.Time
}

// NewBanTracker builds a tracker. A non-positive threshold disables banning
// (Strike never bans, Banned always reports false).
func NewBanTracker(threshold int, strikeWindow, banWindow time.Duration) *BanTracker {
	return &BanTracker{
		threshold:    threshold,
		strikeWindow: strikeWindow,
		banWindow:    banWindow,
		entries:      make(map[string]*banEntry),
		now:          time.Now,
	}
}

func (b *BanTracker) disabled() bool { return b == nil || b.threshold <= 0 }

// Strike records one offense for key and reports whether key is now banned.
func (b *BanTracker) Strike(key string) bool {
	if b.disabled() {
		return false
	}
	now := b.now()
	b.mu.Lock()
	defer b.mu.Unlock()
	e := b.entries[key]
	if e == nil {
		e = &banEntry{windowStart: now}
		b.entries[key] = e
	}
	if now.After(e.bannedUntil) && now.Sub(e.windowStart) > b.strikeWindow {
		// Stale strike window: restart counting.
		e.strikes = 0
		e.windowStart = now
	}
	e.strikes++
	if e.strikes >= b.threshold {
		e.bannedUntil = now.Add(b.banWindow)
		e.strikes = 0
		e.windowStart = now
		return true
	}
	return false
}

// Banned reports whether key is currently banned and, if so, the remaining ban
// duration (suitable for a Retry-After header).
func (b *BanTracker) Banned(key string) (bool, time.Duration) {
	if b.disabled() {
		return false, 0
	}
	now := b.now()
	b.mu.Lock()
	defer b.mu.Unlock()
	e := b.entries[key]
	if e == nil || !now.Before(e.bannedUntil) {
		return false, 0
	}
	return true, e.bannedUntil.Sub(now)
}

// ActiveBans counts keys currently banned (for the relay_bans_active gauge).
func (b *BanTracker) ActiveBans() int {
	if b.disabled() {
		return 0
	}
	now := b.now()
	b.mu.Lock()
	defer b.mu.Unlock()
	n := 0
	for _, e := range b.entries {
		if now.Before(e.bannedUntil) {
			n++
		}
	}
	return n
}

// Sweep drops entries that are neither banned nor within an active strike
// window, bounding memory.
func (b *BanTracker) Sweep() {
	if b.disabled() {
		return
	}
	now := b.now()
	b.mu.Lock()
	for key, e := range b.entries {
		if now.Before(e.bannedUntil) {
			continue
		}
		if now.Sub(e.windowStart) > b.strikeWindow {
			delete(b.entries, key)
		}
	}
	b.mu.Unlock()
}
