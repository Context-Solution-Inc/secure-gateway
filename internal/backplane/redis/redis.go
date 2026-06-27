// Package redis implements the Backplane over Redis for multi-instance relay
// deployments (PRD §5.1, §9.1). Slot claims are atomic Lua scripts; cross-
// instance routing, revocation, and eviction use pub/sub channels.
//
// It implements the same backplane.Backplane contract as the in-memory
// implementation, so relay logic is identical regardless of which is wired.
package redis

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"time"

	goredis "github.com/redis/go-redis/v9"

	"github.com/context-solutions-inc/secure-gateway/internal/backplane"
	"github.com/context-solutions-inc/secure-gateway/internal/token"
)

// Channel names / key prefixes.
const (
	slotPrefix     = "slot:"  // slot:<SlotKey.String()>
	routePrefix    = "route:" // route:<instanceID>
	evictPrefix    = "evict:" // evict:<instanceID>
	revocationChan = "revocations"
)

// Backplane is the Redis-backed implementation.
type Backplane struct {
	rdb *goredis.Client
	ttl time.Duration
}

// New connects to Redis and returns a Backplane. ttl is the slot liveness
// window.
func New(addr, password string, db int, ttl time.Duration) (*Backplane, error) {
	rdb := goredis.NewClient(&goredis.Options{Addr: addr, Password: password, DB: db})
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	if err := rdb.Ping(ctx).Err(); err != nil {
		return nil, fmt.Errorf("connect redis: %w", err)
	}
	return &Backplane{rdb: rdb, ttl: ttl}, nil
}

// NewWithClient builds a Backplane around an existing client (used in tests).
func NewWithClient(rdb *goredis.Client, ttl time.Duration) *Backplane {
	return &Backplane{rdb: rdb, ttl: ttl}
}

func slotRedisKey(k backplane.SlotKey) string { return slotPrefix + k.String() }

// slotValue encodes (instanceID, connID) as "instance|conn".
func slotValue(instanceID, connID string) string { return instanceID + "|" + connID }

func splitSlotValue(v string) (instanceID, connID string) {
	if i := strings.IndexByte(v, '|'); i >= 0 {
		return v[:i], v[i+1:]
	}
	return "", v
}

// claimScript atomically claims a slot for instance|conn, returning the
// displaced holder as {connID, instanceID} ("" if the slot was free or the same
// connection re-claims).
var claimScript = goredis.NewScript(`
local cur = redis.call('GET', KEYS[1])
local evictedConn = ''
local evictedInst = ''
if cur then
  local sep = string.find(cur, '|', 1, true)
  local curInst = string.sub(cur, 1, sep-1)
  local curConn = string.sub(cur, sep+1)
  if curConn ~= ARGV[3] then
    evictedConn = curConn
    evictedInst = curInst
  end
end
redis.call('SET', KEYS[1], ARGV[1], 'PX', ARGV[2])
return {evictedConn, evictedInst}
`)

var renewScript = goredis.NewScript(`
local cur = redis.call('GET', KEYS[1])
if cur then
  local sep = string.find(cur, '|', 1, true)
  local curConn = string.sub(cur, sep+1)
  if curConn == ARGV[1] then
    redis.call('PEXPIRE', KEYS[1], ARGV[2])
    return 1
  end
end
return 0
`)

var releaseScript = goredis.NewScript(`
local cur = redis.call('GET', KEYS[1])
if cur then
  local sep = string.find(cur, '|', 1, true)
  local curConn = string.sub(cur, sep+1)
  if curConn == ARGV[1] then
    redis.call('DEL', KEYS[1])
  end
end
return 1
`)

func (b *Backplane) ClaimSlot(ctx context.Context, key backplane.SlotKey, connID, instanceID string) (backplane.ClaimResult, error) {
	ttlMs := b.ttl.Milliseconds()
	res, err := claimScript.Run(ctx, b.rdb,
		[]string{slotRedisKey(key)},
		slotValue(instanceID, connID), ttlMs, connID,
	).Result()
	if err != nil {
		// Fail closed: the caller rejects the connection (PRD §10.3).
		return backplane.ClaimResult{}, fmt.Errorf("%w: claim slot: %v", backplane.ErrUnavailable, err)
	}
	vals, ok := res.([]interface{})
	if !ok || len(vals) != 2 {
		return backplane.ClaimResult{}, fmt.Errorf("%w: unexpected claim result", backplane.ErrUnavailable)
	}
	evictedConn, _ := vals[0].(string)
	evictedInst, _ := vals[1].(string)

	out := backplane.ClaimResult{Won: true, EvictedConnID: evictedConn}
	if evictedConn != "" {
		out.EvictedOnThisInstance = evictedInst == instanceID
		if !out.EvictedOnThisInstance {
			// Tell the owning instance to close the displaced connection 4001.
			b.publishJSON(ctx, evictPrefix+evictedInst, key)
		}
	}
	return out, nil
}

func (b *Backplane) RenewSlot(ctx context.Context, key backplane.SlotKey, connID string) error {
	n, err := renewScript.Run(ctx, b.rdb, []string{slotRedisKey(key)}, connID, b.ttl.Milliseconds()).Int()
	if err != nil {
		return fmt.Errorf("renew slot: %w", err)
	}
	if n == 0 {
		return backplane.ErrNotSlotOwner
	}
	return nil
}

func (b *Backplane) ReleaseSlot(ctx context.Context, key backplane.SlotKey, connID string) error {
	return releaseScript.Run(ctx, b.rdb, []string{slotRedisKey(key)}, connID).Err()
}

func (b *Backplane) LookupInstance(ctx context.Context, key backplane.SlotKey) (string, error) {
	v, err := b.rdb.Get(ctx, slotRedisKey(key)).Result()
	if errors.Is(err, goredis.Nil) {
		return "", nil
	}
	if err != nil {
		return "", err
	}
	inst, _ := splitSlotValue(v)
	return inst, nil
}

func (b *Backplane) Publish(ctx context.Context, instanceID string, f backplane.RoutedFrame) error {
	return b.publishJSON(ctx, routePrefix+instanceID, f)
}

func (b *Backplane) PublishRevocation(ctx context.Context, ev backplane.RevocationEvent) error {
	return b.publishJSON(ctx, revocationChan, ev)
}

func (b *Backplane) publishJSON(ctx context.Context, channel string, v any) error {
	data, err := json.Marshal(v)
	if err != nil {
		return err
	}
	return b.rdb.Publish(ctx, channel, data).Err()
}

func (b *Backplane) SubscribeFrames(ctx context.Context, instanceID string) (<-chan backplane.RoutedFrame, error) {
	out := make(chan backplane.RoutedFrame, 256)
	sub := b.rdb.Subscribe(ctx, routePrefix+instanceID)
	go pump(ctx, sub, out, func(data []byte) (backplane.RoutedFrame, bool) {
		var f backplane.RoutedFrame
		if json.Unmarshal(data, &f) != nil {
			return f, false
		}
		return f, true
	})
	return out, nil
}

func (b *Backplane) SubscribeRevocations(ctx context.Context) (<-chan backplane.RevocationEvent, error) {
	out := make(chan backplane.RevocationEvent, 256)
	sub := b.rdb.Subscribe(ctx, revocationChan)
	go pump(ctx, sub, out, func(data []byte) (backplane.RevocationEvent, bool) {
		var ev backplane.RevocationEvent
		if json.Unmarshal(data, &ev) != nil {
			return ev, false
		}
		return ev, true
	})
	return out, nil
}

func (b *Backplane) SubscribeEvictions(ctx context.Context, instanceID string) (<-chan backplane.SlotKey, error) {
	out := make(chan backplane.SlotKey, 256)
	sub := b.rdb.Subscribe(ctx, evictPrefix+instanceID)
	go pump(ctx, sub, out, func(data []byte) (backplane.SlotKey, bool) {
		var k backplane.SlotKey
		if json.Unmarshal(data, &k) != nil {
			return k, false
		}
		// Defend against an empty/garbled role.
		if k.Role != token.RoleMobile && k.Role != token.RoleDesktop {
			return k, false
		}
		return k, true
	})
	return out, nil
}

// pump forwards decoded pub/sub messages to out until ctx is canceled.
func pump[T any](ctx context.Context, sub *goredis.PubSub, out chan<- T, decode func([]byte) (T, bool)) {
	defer sub.Close()
	ch := sub.Channel()
	for {
		select {
		case <-ctx.Done():
			return
		case msg, ok := <-ch:
			if !ok {
				return
			}
			v, valid := decode([]byte(msg.Payload))
			if !valid {
				continue
			}
			select {
			case out <- v:
			case <-ctx.Done():
				return
			default:
				// Drop rather than block the pub/sub reader.
			}
		}
	}
}

func (b *Backplane) HealthCheck(ctx context.Context) error {
	return b.rdb.Ping(ctx).Err()
}

func (b *Backplane) Close() error {
	return b.rdb.Close()
}

var _ backplane.Backplane = (*Backplane)(nil)
