// Package memory is an in-memory authstore.Store for tests and the hermetic
// subscription-lifecycle E2E. It is safe for concurrent use and copies records
// in and out so callers cannot mutate stored state through shared slices.
package memory

import (
	"context"
	"sort"
	"sync"
	"time"

	"github.com/lley154/secure-gateway/internal/authstore"
)

// Store is a concurrency-safe in-memory authstore.Store.
type Store struct {
	mu sync.RWMutex

	accounts        map[string]authstore.Account
	customerToAcct  map[string]string // stripe customer id -> account id
	subscriptions   map[string]authstore.Subscription
	licenses        map[string]authstore.License
	devices         map[string]authstore.Device
	pairings        map[string]authstore.Pairing
	refreshTokens   map[string]authstore.RefreshToken
	webhookEvents   map[string]authstore.WebhookEvent
}

// New returns an empty in-memory store.
func New() *Store {
	return &Store{
		accounts:       map[string]authstore.Account{},
		customerToAcct: map[string]string{},
		subscriptions:  map[string]authstore.Subscription{},
		licenses:       map[string]authstore.License{},
		devices:        map[string]authstore.Device{},
		pairings:       map[string]authstore.Pairing{},
		refreshTokens:  map[string]authstore.RefreshToken{},
		webhookEvents:  map[string]authstore.WebhookEvent{},
	}
}

func cloneBytes(b []byte) []byte {
	if b == nil {
		return nil
	}
	c := make([]byte, len(b))
	copy(c, b)
	return c
}

// --- Accounts ---

func (s *Store) UpsertAccount(_ context.Context, a authstore.Account) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	// Merge on empty so a partial upsert never wipes the customer link or secret
	// (mirrors the Postgres COALESCE upsert).
	if existing, ok := s.accounts[a.ID]; ok {
		if a.StripeCustomerID == "" {
			a.StripeCustomerID = existing.StripeCustomerID
		}
		if a.SecretHash == "" {
			a.SecretHash = existing.SecretHash
		}
		if a.CreatedAt.IsZero() {
			a.CreatedAt = existing.CreatedAt
		}
	}
	s.accounts[a.ID] = a
	if a.StripeCustomerID != "" {
		s.customerToAcct[a.StripeCustomerID] = a.ID
	}
	return nil
}

func (s *Store) GetAccount(_ context.Context, id string) (authstore.Account, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	a, ok := s.accounts[id]
	if !ok {
		return authstore.Account{}, authstore.ErrNotFound
	}
	return a, nil
}

func (s *Store) GetAccountByCustomer(_ context.Context, customerID string) (authstore.Account, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	id, ok := s.customerToAcct[customerID]
	if !ok {
		return authstore.Account{}, authstore.ErrNotFound
	}
	return s.accounts[id], nil
}

// --- Subscriptions ---

func (s *Store) UpsertSubscription(_ context.Context, sub authstore.Subscription) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.subscriptions[sub.ID] = sub
	return nil
}

func (s *Store) GetSubscription(_ context.Context, id string) (authstore.Subscription, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	sub, ok := s.subscriptions[id]
	if !ok {
		return authstore.Subscription{}, authstore.ErrNotFound
	}
	return sub, nil
}

func (s *Store) ListSubscriptions(_ context.Context) ([]authstore.Subscription, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	out := make([]authstore.Subscription, 0, len(s.subscriptions))
	for _, sub := range s.subscriptions {
		out = append(out, sub)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].ID < out[j].ID })
	return out, nil
}

// --- Licenses ---

func (s *Store) CreateLicense(_ context.Context, l authstore.License) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if _, ok := s.licenses[l.ID]; ok {
		return authstore.ErrConflict
	}
	s.licenses[l.ID] = l
	return nil
}

func (s *Store) GetLicense(_ context.Context, id string) (authstore.License, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	l, ok := s.licenses[id]
	if !ok {
		return authstore.License{}, authstore.ErrNotFound
	}
	return l, nil
}

func (s *Store) ListLicensesByAccount(_ context.Context, accountID string) ([]authstore.License, error) {
	return s.listLicenses(func(l authstore.License) bool { return l.AccountID == accountID }), nil
}

func (s *Store) ListLicensesBySubscription(_ context.Context, subID string) ([]authstore.License, error) {
	return s.listLicenses(func(l authstore.License) bool { return l.SubscriptionID == subID }), nil
}

func (s *Store) listLicenses(pred func(authstore.License) bool) []authstore.License {
	s.mu.RLock()
	defer s.mu.RUnlock()
	var out []authstore.License
	for _, l := range s.licenses {
		if pred(l) {
			out = append(out, l)
		}
	}
	sort.Slice(out, func(i, j int) bool { return out[i].ID < out[j].ID })
	return out
}

func (s *Store) SetLicenseStatus(_ context.Context, id string, status authstore.LicenseStatus) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	l, ok := s.licenses[id]
	if !ok {
		return authstore.ErrNotFound
	}
	l.Status = status
	s.licenses[id] = l
	return nil
}

// --- Devices ---

func (s *Store) UpsertDevice(_ context.Context, d authstore.Device) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	// Preserve an existing public key when the upsert omits it (mirrors the
	// Postgres COALESCE upsert; M2 registers devices without keys, M3 fills them).
	if d.PublicKey == nil {
		if existing, ok := s.devices[d.ID]; ok {
			d.PublicKey = existing.PublicKey
		}
	}
	d.PublicKey = cloneBytes(d.PublicKey)
	s.devices[d.ID] = d
	return nil
}

func (s *Store) GetDevice(_ context.Context, id string) (authstore.Device, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	d, ok := s.devices[id]
	if !ok {
		return authstore.Device{}, authstore.ErrNotFound
	}
	d.PublicKey = cloneBytes(d.PublicKey)
	return d, nil
}

// --- Pairings ---

func (s *Store) CreatePairing(_ context.Context, p authstore.Pairing) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if _, ok := s.pairings[p.PairID]; ok {
		return authstore.ErrConflict
	}
	s.pairings[p.PairID] = p
	return nil
}

func (s *Store) GetPairing(_ context.Context, pairID string) (authstore.Pairing, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	p, ok := s.pairings[pairID]
	if !ok {
		return authstore.Pairing{}, authstore.ErrNotFound
	}
	return p, nil
}

func (s *Store) ListActivePairingsByLicense(_ context.Context, licenseID string) ([]authstore.Pairing, error) {
	return s.listPairings(func(p authstore.Pairing) bool {
		return p.LicenseID == licenseID && p.Status == authstore.PairingActive
	}), nil
}

func (s *Store) ListActivePairingsByAccount(_ context.Context, accountID string) ([]authstore.Pairing, error) {
	return s.listPairings(func(p authstore.Pairing) bool {
		return p.AccountID == accountID && p.Status == authstore.PairingActive
	}), nil
}

func (s *Store) listPairings(pred func(authstore.Pairing) bool) []authstore.Pairing {
	s.mu.RLock()
	defer s.mu.RUnlock()
	var out []authstore.Pairing
	for _, p := range s.pairings {
		if pred(p) {
			out = append(out, p)
		}
	}
	sort.Slice(out, func(i, j int) bool { return out[i].PairID < out[j].PairID })
	return out
}

func (s *Store) SetPairingStatus(_ context.Context, pairID string, status authstore.PairingStatus) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	p, ok := s.pairings[pairID]
	if !ok {
		return authstore.ErrNotFound
	}
	p.Status = status
	s.pairings[pairID] = p
	return nil
}

func (s *Store) ActivePairCount(_ context.Context, licenseID string) (int, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	n := 0
	for _, p := range s.pairings {
		if p.LicenseID == licenseID && p.Status == authstore.PairingActive {
			n++
		}
	}
	return n, nil
}

// --- Refresh tokens ---

func (s *Store) PutRefreshToken(_ context.Context, r authstore.RefreshToken) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.refreshTokens[r.ID] = r
	return nil
}

func (s *Store) GetRefreshToken(_ context.Context, id string) (authstore.RefreshToken, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	r, ok := s.refreshTokens[id]
	if !ok {
		return authstore.RefreshToken{}, authstore.ErrNotFound
	}
	return r, nil
}

func (s *Store) RevokeRefreshToken(_ context.Context, id string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	r, ok := s.refreshTokens[id]
	if !ok {
		return authstore.ErrNotFound
	}
	if r.RevokedAt.IsZero() {
		r.RevokedAt = time.Now()
		s.refreshTokens[id] = r
	}
	return nil
}

// --- Webhook events ---

func (s *Store) InsertWebhookEventIfAbsent(_ context.Context, e authstore.WebhookEvent) (bool, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if _, ok := s.webhookEvents[e.ID]; ok {
		return false, nil
	}
	e.Payload = cloneBytes(e.Payload)
	s.webhookEvents[e.ID] = e
	return true, nil
}

func (s *Store) SetWebhookStatus(_ context.Context, id string, status authstore.WebhookStatus, attempts int, processedAt time.Time) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	e, ok := s.webhookEvents[id]
	if !ok {
		return authstore.ErrNotFound
	}
	e.Status = status
	e.Attempts = attempts
	e.ProcessedAt = processedAt
	s.webhookEvents[id] = e
	return nil
}

func (s *Store) ListWebhookEventsByStatus(_ context.Context, status authstore.WebhookStatus, limit int) ([]authstore.WebhookEvent, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	var out []authstore.WebhookEvent
	for _, e := range s.webhookEvents {
		if e.Status == status {
			e.Payload = cloneBytes(e.Payload)
			out = append(out, e)
		}
	}
	sort.Slice(out, func(i, j int) bool { return out[i].ReceivedAt.Before(out[j].ReceivedAt) })
	if limit > 0 && len(out) > limit {
		out = out[:limit]
	}
	return out, nil
}

// --- Operational ---

func (s *Store) HealthCheck(_ context.Context) error { return nil }
func (s *Store) Close() error                         { return nil }
