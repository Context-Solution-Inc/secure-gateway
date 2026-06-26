// Package postgres is the production authstore.Store, backed by Postgres via
// pgx/v5 (pure Go, so CGO_ENABLED=0 is preserved). Schema migrations are
// embedded and applied idempotently on Open.
package postgres

import (
	"context"
	"embed"
	"errors"
	"fmt"
	"sort"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/lley154/secure-gateway/internal/authstore"
	"github.com/lley154/secure-gateway/internal/token"
)

//go:embed migrations/*.sql
var migrationsFS embed.FS

// Store is a Postgres-backed authstore.Store.
type Store struct {
	pool *pgxpool.Pool
}

// Open connects to Postgres using dsn, applies embedded migrations, and returns
// a ready Store.
func Open(ctx context.Context, dsn string) (*Store, error) {
	pool, err := pgxpool.New(ctx, dsn)
	if err != nil {
		return nil, fmt.Errorf("connect postgres: %w", err)
	}
	s := &Store{pool: pool}
	if err := s.migrate(ctx); err != nil {
		pool.Close()
		return nil, err
	}
	return s, nil
}

// NewWithPool wraps an existing pool (used by tests to share a connection).
func NewWithPool(pool *pgxpool.Pool) *Store { return &Store{pool: pool} }

// Migrate applies the embedded migrations; exported so tests can re-run it.
func (s *Store) Migrate(ctx context.Context) error { return s.migrate(ctx) }

func (s *Store) migrate(ctx context.Context) error {
	entries, err := migrationsFS.ReadDir("migrations")
	if err != nil {
		return fmt.Errorf("read migrations: %w", err)
	}
	names := make([]string, 0, len(entries))
	for _, e := range entries {
		if !e.IsDir() {
			names = append(names, e.Name())
		}
	}
	sort.Strings(names) // lexical order == migration order (0001_, 0002_, …)
	for _, name := range names {
		sqlBytes, err := migrationsFS.ReadFile("migrations/" + name)
		if err != nil {
			return fmt.Errorf("read migration %s: %w", name, err)
		}
		if _, err := s.pool.Exec(ctx, string(sqlBytes)); err != nil {
			return fmt.Errorf("apply migration %s: %w", name, err)
		}
	}
	return nil
}

// nilIfZero returns nil for a zero time so it is written as SQL NULL.
func nilIfZero(t time.Time) any {
	if t.IsZero() {
		return nil
	}
	return t
}

// deref returns the zero time when p is nil (NULL column).
func deref(p *time.Time) time.Time {
	if p == nil {
		return time.Time{}
	}
	return *p
}

func mapErr(err error) error {
	if errors.Is(err, pgx.ErrNoRows) {
		return authstore.ErrNotFound
	}
	var pgErr *pgconn.PgError
	if errors.As(err, &pgErr) && pgErr.Code == "23505" { // unique_violation
		return authstore.ErrConflict
	}
	return err
}

// --- Accounts ---

func (s *Store) UpsertAccount(ctx context.Context, a authstore.Account) error {
	const q = `
		INSERT INTO accounts (id, stripe_customer_id, secret_hash, created_at)
		VALUES ($1, NULLIF($2,''), $3, COALESCE($4, now()))
		ON CONFLICT (id) DO UPDATE SET
			stripe_customer_id = COALESCE(NULLIF(EXCLUDED.stripe_customer_id,''), accounts.stripe_customer_id),
			secret_hash        = CASE WHEN EXCLUDED.secret_hash <> '' THEN EXCLUDED.secret_hash ELSE accounts.secret_hash END`
	_, err := s.pool.Exec(ctx, q, a.ID, a.StripeCustomerID, a.SecretHash, nilIfZero(a.CreatedAt))
	return mapErr(err)
}

func (s *Store) GetAccount(ctx context.Context, id string) (authstore.Account, error) {
	const q = `SELECT id, COALESCE(stripe_customer_id,''), secret_hash, created_at FROM accounts WHERE id=$1`
	var a authstore.Account
	err := s.pool.QueryRow(ctx, q, id).Scan(&a.ID, &a.StripeCustomerID, &a.SecretHash, &a.CreatedAt)
	if err != nil {
		return authstore.Account{}, mapErr(err)
	}
	return a, nil
}

func (s *Store) GetAccountByCustomer(ctx context.Context, customerID string) (authstore.Account, error) {
	const q = `SELECT id, COALESCE(stripe_customer_id,''), secret_hash, created_at FROM accounts WHERE stripe_customer_id=$1`
	var a authstore.Account
	err := s.pool.QueryRow(ctx, q, customerID).Scan(&a.ID, &a.StripeCustomerID, &a.SecretHash, &a.CreatedAt)
	if err != nil {
		return authstore.Account{}, mapErr(err)
	}
	return a, nil
}

// --- Subscriptions ---

func (s *Store) UpsertSubscription(ctx context.Context, sub authstore.Subscription) error {
	const q = `
		INSERT INTO subscriptions (id, account_id, status, max_pairs, current_period_end, grace_until, updated_at)
		VALUES ($1,$2,$3,$4,$5,$6, COALESCE($7, now()))
		ON CONFLICT (id) DO UPDATE SET
			account_id=EXCLUDED.account_id, status=EXCLUDED.status, max_pairs=EXCLUDED.max_pairs,
			current_period_end=EXCLUDED.current_period_end, grace_until=EXCLUDED.grace_until,
			updated_at=EXCLUDED.updated_at`
	_, err := s.pool.Exec(ctx, q, sub.ID, sub.AccountID, string(sub.Status), sub.MaxPairs,
		nilIfZero(sub.CurrentPeriodEnd), nilIfZero(sub.GraceUntil), nilIfZero(sub.UpdatedAt))
	return mapErr(err)
}

func scanSubscription(row pgx.Row) (authstore.Subscription, error) {
	var sub authstore.Subscription
	var status string
	var cpe, grace *time.Time
	if err := row.Scan(&sub.ID, &sub.AccountID, &status, &sub.MaxPairs, &cpe, &grace, &sub.UpdatedAt); err != nil {
		return authstore.Subscription{}, mapErr(err)
	}
	sub.Status = authstore.SubStatus(status)
	sub.CurrentPeriodEnd, sub.GraceUntil = deref(cpe), deref(grace)
	return sub, nil
}

const subCols = `id, account_id, status, max_pairs, current_period_end, grace_until, updated_at`

func (s *Store) GetSubscription(ctx context.Context, id string) (authstore.Subscription, error) {
	return scanSubscription(s.pool.QueryRow(ctx, `SELECT `+subCols+` FROM subscriptions WHERE id=$1`, id))
}

func (s *Store) ListSubscriptions(ctx context.Context) ([]authstore.Subscription, error) {
	rows, err := s.pool.Query(ctx, `SELECT `+subCols+` FROM subscriptions ORDER BY id`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []authstore.Subscription
	for rows.Next() {
		sub, err := scanSubscription(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, sub)
	}
	return out, rows.Err()
}

// --- Licenses ---

func (s *Store) CreateLicense(ctx context.Context, l authstore.License) error {
	const q = `INSERT INTO licenses (id, account_id, subscription_id, subscription_item_id, status, created_at)
		VALUES ($1,$2,$3,$4,$5, COALESCE($6, now()))`
	_, err := s.pool.Exec(ctx, q, l.ID, l.AccountID, l.SubscriptionID, l.SubscriptionItemID, string(l.Status), nilIfZero(l.CreatedAt))
	return mapErr(err)
}

const licCols = `id, account_id, subscription_id, subscription_item_id, status, created_at`

func scanLicense(row pgx.Row) (authstore.License, error) {
	var l authstore.License
	var status string
	if err := row.Scan(&l.ID, &l.AccountID, &l.SubscriptionID, &l.SubscriptionItemID, &status, &l.CreatedAt); err != nil {
		return authstore.License{}, mapErr(err)
	}
	l.Status = authstore.LicenseStatus(status)
	return l, nil
}

func (s *Store) GetLicense(ctx context.Context, id string) (authstore.License, error) {
	return scanLicense(s.pool.QueryRow(ctx, `SELECT `+licCols+` FROM licenses WHERE id=$1`, id))
}

func (s *Store) ListLicensesByAccount(ctx context.Context, accountID string) ([]authstore.License, error) {
	return s.queryLicenses(ctx, `SELECT `+licCols+` FROM licenses WHERE account_id=$1 ORDER BY id`, accountID)
}

func (s *Store) ListLicensesBySubscription(ctx context.Context, subID string) ([]authstore.License, error) {
	return s.queryLicenses(ctx, `SELECT `+licCols+` FROM licenses WHERE subscription_id=$1 ORDER BY id`, subID)
}

func (s *Store) queryLicenses(ctx context.Context, q string, args ...any) ([]authstore.License, error) {
	rows, err := s.pool.Query(ctx, q, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []authstore.License
	for rows.Next() {
		l, err := scanLicense(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, l)
	}
	return out, rows.Err()
}

func (s *Store) SetLicenseStatus(ctx context.Context, id string, status authstore.LicenseStatus) error {
	tag, err := s.pool.Exec(ctx, `UPDATE licenses SET status=$2 WHERE id=$1`, id, string(status))
	if err != nil {
		return mapErr(err)
	}
	if tag.RowsAffected() == 0 {
		return authstore.ErrNotFound
	}
	return nil
}

// --- Devices ---

func (s *Store) UpsertDevice(ctx context.Context, d authstore.Device) error {
	const q = `INSERT INTO devices (id, account_id, role, public_key, created_at)
		VALUES ($1,$2,$3,$4, COALESCE($5, now()))
		ON CONFLICT (id) DO UPDATE SET account_id=EXCLUDED.account_id, role=EXCLUDED.role,
			public_key=COALESCE(EXCLUDED.public_key, devices.public_key)`
	_, err := s.pool.Exec(ctx, q, d.ID, d.AccountID, string(d.Role), d.PublicKey, nilIfZero(d.CreatedAt))
	return mapErr(err)
}

func (s *Store) GetDevice(ctx context.Context, id string) (authstore.Device, error) {
	const q = `SELECT id, account_id, role, public_key, created_at FROM devices WHERE id=$1`
	var d authstore.Device
	var role string
	if err := s.pool.QueryRow(ctx, q, id).Scan(&d.ID, &d.AccountID, &role, &d.PublicKey, &d.CreatedAt); err != nil {
		return authstore.Device{}, mapErr(err)
	}
	d.Role = token.Role(role)
	return d, nil
}

func (s *Store) CountDevicesByAccount(ctx context.Context, accountID string) (int, error) {
	var n int
	err := s.pool.QueryRow(ctx, `SELECT count(*) FROM devices WHERE account_id=$1`, accountID).Scan(&n)
	return n, mapErr(err)
}

func (s *Store) FindDeviceByAccountRoleKey(ctx context.Context, accountID string, role token.Role, publicKey []byte) (authstore.Device, error) {
	if len(publicKey) == 0 {
		return authstore.Device{}, authstore.ErrNotFound
	}
	const q = `SELECT id, account_id, role, public_key, created_at FROM devices
		WHERE account_id=$1 AND role=$2 AND public_key=$3 ORDER BY created_at LIMIT 1`
	var d authstore.Device
	var r string
	if err := s.pool.QueryRow(ctx, q, accountID, string(role), publicKey).Scan(&d.ID, &d.AccountID, &r, &d.PublicKey, &d.CreatedAt); err != nil {
		return authstore.Device{}, mapErr(err)
	}
	d.Role = token.Role(r)
	return d, nil
}

// --- Pairings ---

func (s *Store) CreatePairing(ctx context.Context, p authstore.Pairing) error {
	const q = `INSERT INTO pairings (pair_id, license_id, account_id, mobile_device_id, desktop_device_id, status, created_at)
		VALUES ($1,$2,$3,$4,$5,$6, COALESCE($7, now()))`
	_, err := s.pool.Exec(ctx, q, p.PairID, p.LicenseID, p.AccountID, p.MobileDeviceID, p.DesktopDeviceID, string(p.Status), nilIfZero(p.CreatedAt))
	return mapErr(err)
}

func (s *Store) CreatePairingWithinCapacity(ctx context.Context, p authstore.Pairing, maxPairs int) (err error) {
	tx, err := s.pool.Begin(ctx)
	if err != nil {
		return mapErr(err)
	}
	// Roll back unless we explicitly commit; rollback after commit is a no-op.
	defer func() { _ = tx.Rollback(ctx) }()

	// Lock the license row so concurrent completions for the same license
	// serialize here, closing the TOCTOU between the count and the insert (SG-16).
	var licID string
	if err := tx.QueryRow(ctx, `SELECT id FROM licenses WHERE id=$1 FOR UPDATE`, p.LicenseID).Scan(&licID); err != nil {
		return mapErr(err)
	}
	var inUse int
	if err := tx.QueryRow(ctx, `SELECT count(*) FROM pairings WHERE license_id=$1 AND status=$2`,
		p.LicenseID, string(authstore.PairingActive)).Scan(&inUse); err != nil {
		return mapErr(err)
	}
	if inUse >= maxPairs {
		return authstore.ErrCapacityExceeded
	}
	const q = `INSERT INTO pairings (pair_id, license_id, account_id, mobile_device_id, desktop_device_id, status, created_at)
		VALUES ($1,$2,$3,$4,$5,$6, COALESCE($7, now()))`
	if _, err := tx.Exec(ctx, q, p.PairID, p.LicenseID, p.AccountID, p.MobileDeviceID, p.DesktopDeviceID, string(p.Status), nilIfZero(p.CreatedAt)); err != nil {
		return mapErr(err)
	}
	return mapErr(tx.Commit(ctx))
}

const pairCols = `pair_id, license_id, account_id, mobile_device_id, desktop_device_id, status, created_at`

func scanPairing(row pgx.Row) (authstore.Pairing, error) {
	var p authstore.Pairing
	var status string
	if err := row.Scan(&p.PairID, &p.LicenseID, &p.AccountID, &p.MobileDeviceID, &p.DesktopDeviceID, &status, &p.CreatedAt); err != nil {
		return authstore.Pairing{}, mapErr(err)
	}
	p.Status = authstore.PairingStatus(status)
	return p, nil
}

func (s *Store) GetPairing(ctx context.Context, pairID string) (authstore.Pairing, error) {
	return scanPairing(s.pool.QueryRow(ctx, `SELECT `+pairCols+` FROM pairings WHERE pair_id=$1`, pairID))
}

func (s *Store) ListActivePairingsByLicense(ctx context.Context, licenseID string) ([]authstore.Pairing, error) {
	return s.queryPairings(ctx, `SELECT `+pairCols+` FROM pairings WHERE license_id=$1 AND status=$2 ORDER BY pair_id`, licenseID, string(authstore.PairingActive))
}

func (s *Store) ListActivePairingsByAccount(ctx context.Context, accountID string) ([]authstore.Pairing, error) {
	return s.queryPairings(ctx, `SELECT `+pairCols+` FROM pairings WHERE account_id=$1 AND status=$2 ORDER BY pair_id`, accountID, string(authstore.PairingActive))
}

func (s *Store) queryPairings(ctx context.Context, q string, args ...any) ([]authstore.Pairing, error) {
	rows, err := s.pool.Query(ctx, q, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []authstore.Pairing
	for rows.Next() {
		p, err := scanPairing(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, p)
	}
	return out, rows.Err()
}

func (s *Store) SetPairingStatus(ctx context.Context, pairID string, status authstore.PairingStatus) error {
	tag, err := s.pool.Exec(ctx, `UPDATE pairings SET status=$2 WHERE pair_id=$1`, pairID, string(status))
	if err != nil {
		return mapErr(err)
	}
	if tag.RowsAffected() == 0 {
		return authstore.ErrNotFound
	}
	return nil
}

func (s *Store) UpdatePairingDevices(ctx context.Context, pairID, mobileDeviceID, desktopDeviceID string) error {
	tag, err := s.pool.Exec(ctx, `UPDATE pairings SET mobile_device_id=$2, desktop_device_id=$3 WHERE pair_id=$1`,
		pairID, mobileDeviceID, desktopDeviceID)
	if err != nil {
		return mapErr(err)
	}
	if tag.RowsAffected() == 0 {
		return authstore.ErrNotFound
	}
	return nil
}

func (s *Store) ActivePairCount(ctx context.Context, licenseID string) (int, error) {
	var n int
	err := s.pool.QueryRow(ctx, `SELECT count(*) FROM pairings WHERE license_id=$1 AND status=$2`, licenseID, string(authstore.PairingActive)).Scan(&n)
	return n, err
}

// --- Refresh tokens ---

func (s *Store) PutRefreshToken(ctx context.Context, r authstore.RefreshToken) error {
	const q = `INSERT INTO refresh_tokens (id, device_id, account_id, pair_id, expires_at, revoked_at)
		VALUES ($1,$2,$3,$4,$5,$6)
		ON CONFLICT (id) DO UPDATE SET device_id=EXCLUDED.device_id, account_id=EXCLUDED.account_id,
			pair_id=EXCLUDED.pair_id, expires_at=EXCLUDED.expires_at, revoked_at=EXCLUDED.revoked_at`
	_, err := s.pool.Exec(ctx, q, r.ID, r.DeviceID, r.AccountID, r.PairID, r.ExpiresAt, nilIfZero(r.RevokedAt))
	return mapErr(err)
}

func (s *Store) GetRefreshToken(ctx context.Context, id string) (authstore.RefreshToken, error) {
	const q = `SELECT id, device_id, account_id, pair_id, expires_at, revoked_at FROM refresh_tokens WHERE id=$1`
	var r authstore.RefreshToken
	var revoked *time.Time
	if err := s.pool.QueryRow(ctx, q, id).Scan(&r.ID, &r.DeviceID, &r.AccountID, &r.PairID, &r.ExpiresAt, &revoked); err != nil {
		return authstore.RefreshToken{}, mapErr(err)
	}
	r.RevokedAt = deref(revoked)
	return r, nil
}

func (s *Store) RevokeRefreshToken(ctx context.Context, id string) error {
	tag, err := s.pool.Exec(ctx, `UPDATE refresh_tokens SET revoked_at=now() WHERE id=$1 AND revoked_at IS NULL`, id)
	if err != nil {
		return mapErr(err)
	}
	if tag.RowsAffected() == 0 {
		// Either missing or already revoked; distinguish for a clean ErrNotFound.
		var exists bool
		if err := s.pool.QueryRow(ctx, `SELECT true FROM refresh_tokens WHERE id=$1`, id).Scan(&exists); err != nil {
			return mapErr(err)
		}
	}
	return nil
}

func (s *Store) ConsumeRefreshToken(ctx context.Context, id string, consumedAt time.Time) error {
	// Atomic single-use rotation: only the row that is still active is revoked.
	tag, err := s.pool.Exec(ctx,
		`UPDATE refresh_tokens SET revoked_at=$2 WHERE id=$1 AND revoked_at IS NULL`,
		id, consumedAt)
	if err != nil {
		return mapErr(err)
	}
	if tag.RowsAffected() == 0 {
		// Distinguish missing (ErrNotFound) from already-revoked (ErrConflict).
		var exists bool
		if err := s.pool.QueryRow(ctx, `SELECT true FROM refresh_tokens WHERE id=$1`, id).Scan(&exists); err != nil {
			return mapErr(err)
		}
		return authstore.ErrConflict
	}
	return nil
}

func (s *Store) RevokeRefreshTokensByDevice(ctx context.Context, deviceID string, revokedAt time.Time) error {
	// Idempotent bulk revoke: revoking zero still-active tokens is not an error.
	_, err := s.pool.Exec(ctx,
		`UPDATE refresh_tokens SET revoked_at=$2 WHERE device_id=$1 AND revoked_at IS NULL`,
		deviceID, revokedAt)
	return mapErr(err)
}

// --- Pair credentials (security L2) ---

func (s *Store) PutPairCredential(ctx context.Context, c authstore.PairCredential) error {
	// Upsert by pair_id: re-pairing rotates the secret + mobile device in place and
	// clears any prior revocation (a fresh credential is active).
	const q = `INSERT INTO pair_credentials (pair_id, account_id, license_id, mobile_device_id, secret_hash, created_at, revoked_at)
		VALUES ($1,$2,$3,$4,$5,$6,$7)
		ON CONFLICT (pair_id) DO UPDATE SET account_id=EXCLUDED.account_id, license_id=EXCLUDED.license_id,
			mobile_device_id=EXCLUDED.mobile_device_id, secret_hash=EXCLUDED.secret_hash,
			created_at=EXCLUDED.created_at, revoked_at=EXCLUDED.revoked_at`
	_, err := s.pool.Exec(ctx, q, c.PairID, c.AccountID, c.LicenseID, c.MobileDeviceID, c.SecretHash, c.CreatedAt, nilIfZero(c.RevokedAt))
	return mapErr(err)
}

func (s *Store) GetPairCredential(ctx context.Context, pairID string) (authstore.PairCredential, error) {
	const q = `SELECT pair_id, account_id, license_id, mobile_device_id, secret_hash, created_at, revoked_at FROM pair_credentials WHERE pair_id=$1`
	var c authstore.PairCredential
	var revoked *time.Time
	if err := s.pool.QueryRow(ctx, q, pairID).Scan(&c.PairID, &c.AccountID, &c.LicenseID, &c.MobileDeviceID, &c.SecretHash, &c.CreatedAt, &revoked); err != nil {
		return authstore.PairCredential{}, mapErr(err)
	}
	c.RevokedAt = deref(revoked)
	return c, nil
}

func (s *Store) RevokePairCredential(ctx context.Context, pairID string, revokedAt time.Time) error {
	// Idempotent: revoking a missing or already-revoked credential is not an error.
	_, err := s.pool.Exec(ctx,
		`UPDATE pair_credentials SET revoked_at=$2 WHERE pair_id=$1 AND revoked_at IS NULL`,
		pairID, revokedAt)
	return mapErr(err)
}

// --- Pairing tokens ---

func (s *Store) CreatePairingToken(ctx context.Context, t authstore.PairingToken) error {
	const q = `INSERT INTO pairing_tokens (id, account_id, license_id, desktop_device_id, expires_at, consumed_at, result_pair_id)
		VALUES ($1,$2,$3,$4,$5,$6,$7)`
	_, err := s.pool.Exec(ctx, q, t.ID, t.AccountID, t.LicenseID, t.DesktopDeviceID, t.ExpiresAt, nilIfZero(t.ConsumedAt), t.ResultPairID)
	return mapErr(err)
}

func (s *Store) GetPairingToken(ctx context.Context, id string) (authstore.PairingToken, error) {
	const q = `SELECT id, account_id, license_id, desktop_device_id, expires_at, consumed_at, result_pair_id FROM pairing_tokens WHERE id=$1`
	var t authstore.PairingToken
	var consumed *time.Time
	if err := s.pool.QueryRow(ctx, q, id).Scan(&t.ID, &t.AccountID, &t.LicenseID, &t.DesktopDeviceID, &t.ExpiresAt, &consumed, &t.ResultPairID); err != nil {
		return authstore.PairingToken{}, mapErr(err)
	}
	t.ConsumedAt = deref(consumed)
	return t, nil
}

func (s *Store) ConsumePairingToken(ctx context.Context, id, resultPairID string, consumedAt time.Time) error {
	// Atomic single-use: only the row that is still pending is updated.
	tag, err := s.pool.Exec(ctx,
		`UPDATE pairing_tokens SET consumed_at=$2, result_pair_id=$3 WHERE id=$1 AND consumed_at IS NULL`,
		id, consumedAt, resultPairID)
	if err != nil {
		return mapErr(err)
	}
	if tag.RowsAffected() == 0 {
		// Distinguish missing (ErrNotFound) from already-consumed (ErrConflict).
		var exists bool
		if err := s.pool.QueryRow(ctx, `SELECT true FROM pairing_tokens WHERE id=$1`, id).Scan(&exists); err != nil {
			return mapErr(err)
		}
		return authstore.ErrConflict
	}
	return nil
}

// --- Checkout claims ---

const claimCols = `nonce, stripe_session_id, redirect_uri, claim_code_hash, account_id, license_id, subscription_id, status, created_at, expires_at, consumed_at`

func scanClaim(row pgx.Row) (authstore.CheckoutClaim, error) {
	var c authstore.CheckoutClaim
	var status string
	var consumed *time.Time
	if err := row.Scan(&c.Nonce, &c.StripeSessionID, &c.RedirectURI, &c.ClaimCodeHash,
		&c.AccountID, &c.LicenseID, &c.SubscriptionID, &status, &c.CreatedAt, &c.ExpiresAt, &consumed); err != nil {
		return authstore.CheckoutClaim{}, mapErr(err)
	}
	c.Status = authstore.ClaimStatus(status)
	c.ConsumedAt = deref(consumed)
	return c, nil
}

func (s *Store) CreateCheckoutClaim(ctx context.Context, c authstore.CheckoutClaim) error {
	const q = `INSERT INTO checkout_claims (` + claimCols + `)
		VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11)`
	_, err := s.pool.Exec(ctx, q, c.Nonce, c.StripeSessionID, c.RedirectURI, c.ClaimCodeHash,
		c.AccountID, c.LicenseID, c.SubscriptionID, string(c.Status), c.CreatedAt, c.ExpiresAt, nilIfZero(c.ConsumedAt))
	return mapErr(err)
}

func (s *Store) GetCheckoutClaim(ctx context.Context, nonce string) (authstore.CheckoutClaim, error) {
	return scanClaim(s.pool.QueryRow(ctx, `SELECT `+claimCols+` FROM checkout_claims WHERE nonce=$1`, nonce))
}

func (s *Store) GetCheckoutClaimByCode(ctx context.Context, claimCodeHash string) (authstore.CheckoutClaim, error) {
	if claimCodeHash == "" {
		return authstore.CheckoutClaim{}, authstore.ErrNotFound
	}
	return scanClaim(s.pool.QueryRow(ctx, `SELECT `+claimCols+` FROM checkout_claims WHERE claim_code_hash=$1`, claimCodeHash))
}

func (s *Store) MarkCheckoutClaimReady(ctx context.Context, nonce, accountID, licenseID, subscriptionID, sessionID string) error {
	// Idempotent under Stripe retries: only a still-pending row is updated; a
	// second delivery (already ready/consumed) is a no-op rather than an error.
	_, err := s.pool.Exec(ctx,
		`UPDATE checkout_claims
			SET account_id=$2, license_id=$3, subscription_id=$4,
				stripe_session_id=COALESCE(NULLIF($5,''), stripe_session_id), status='ready'
		  WHERE nonce=$1 AND status='pending'`,
		nonce, accountID, licenseID, subscriptionID, sessionID)
	return mapErr(err)
}

func (s *Store) SetCheckoutClaimCode(ctx context.Context, nonce, claimCodeHash string) error {
	tag, err := s.pool.Exec(ctx,
		`UPDATE checkout_claims SET claim_code_hash=$2 WHERE nonce=$1 AND status='ready'`,
		nonce, claimCodeHash)
	if err != nil {
		return mapErr(err)
	}
	if tag.RowsAffected() == 0 {
		return authstore.ErrNotFound
	}
	return nil
}

func (s *Store) ConsumeCheckoutClaim(ctx context.Context, nonce string, consumedAt time.Time) (authstore.CheckoutClaim, error) {
	// Atomic single-use: only a row still in 'ready' is flipped to 'consumed'.
	c, err := scanClaim(s.pool.QueryRow(ctx,
		`UPDATE checkout_claims SET status='consumed', consumed_at=$2
		  WHERE nonce=$1 AND status='ready'
		RETURNING `+claimCols, nonce, consumedAt))
	if errors.Is(err, authstore.ErrNotFound) {
		// Distinguish already-consumed (ErrConflict) from missing/pending.
		var status string
		if e := s.pool.QueryRow(ctx, `SELECT status FROM checkout_claims WHERE nonce=$1`, nonce).Scan(&status); e == nil && status == "consumed" {
			return authstore.CheckoutClaim{}, authstore.ErrConflict
		}
	}
	return c, err
}

func (s *Store) DeleteExpiredCheckoutClaims(ctx context.Context, before time.Time) (int, error) {
	tag, err := s.pool.Exec(ctx, `DELETE FROM checkout_claims WHERE expires_at < $1`, before)
	if err != nil {
		return 0, mapErr(err)
	}
	return int(tag.RowsAffected()), nil
}

// --- Webhook events ---

func (s *Store) InsertWebhookEventIfAbsent(ctx context.Context, e authstore.WebhookEvent) (bool, error) {
	const q = `INSERT INTO webhook_events (id, type, status, attempts, payload, received_at, processed_at)
		VALUES ($1,$2,$3,$4,$5, COALESCE($6, now()), $7)
		ON CONFLICT (id) DO NOTHING`
	tag, err := s.pool.Exec(ctx, q, e.ID, e.Type, string(e.Status), e.Attempts, e.Payload, nilIfZero(e.ReceivedAt), nilIfZero(e.ProcessedAt))
	if err != nil {
		return false, mapErr(err)
	}
	return tag.RowsAffected() == 1, nil
}

func (s *Store) SetWebhookStatus(ctx context.Context, id string, status authstore.WebhookStatus, attempts int, processedAt time.Time) error {
	tag, err := s.pool.Exec(ctx, `UPDATE webhook_events SET status=$2, attempts=$3, processed_at=$4 WHERE id=$1`,
		id, string(status), attempts, nilIfZero(processedAt))
	if err != nil {
		return mapErr(err)
	}
	if tag.RowsAffected() == 0 {
		return authstore.ErrNotFound
	}
	return nil
}

func (s *Store) ListWebhookEventsByStatus(ctx context.Context, status authstore.WebhookStatus, limit int) ([]authstore.WebhookEvent, error) {
	q := `SELECT id, type, status, attempts, payload, received_at, processed_at FROM webhook_events WHERE status=$1 ORDER BY received_at`
	args := []any{string(status)}
	if limit > 0 {
		q += ` LIMIT $2`
		args = append(args, limit)
	}
	rows, err := s.pool.Query(ctx, q, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []authstore.WebhookEvent
	for rows.Next() {
		var e authstore.WebhookEvent
		var st string
		var processed *time.Time
		if err := rows.Scan(&e.ID, &e.Type, &st, &e.Attempts, &e.Payload, &e.ReceivedAt, &processed); err != nil {
			return nil, err
		}
		e.Status = authstore.WebhookStatus(st)
		e.ProcessedAt = deref(processed)
		out = append(out, e)
	}
	return out, rows.Err()
}

// --- Operational ---

func (s *Store) HealthCheck(ctx context.Context) error { return s.pool.Ping(ctx) }
func (s *Store) Close() error                          { s.pool.Close(); return nil }
