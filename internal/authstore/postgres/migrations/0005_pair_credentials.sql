-- Security L2: per-pair credential. The phone has no subscription of its own, so
-- before this it adopted the desktop's shared ACCOUNT secret out of the pairing QR
-- (anyone who photographed the QR obtained the account credential). Instead the
-- gateway now mints a credential scoped to a single pairing at completion; the
-- phone issues/refreshes connection tokens and unpairs with THAT, never the
-- account secret, which stays entirely on the desktop and off the QR.
--
-- Keyed by pair_id: at most one active credential per pairing. Re-pairing (FR-2.4)
-- upserts a fresh secret for the new mobile device, so the evicted device's old
-- credential stops authenticating. secret_hash is the hex SHA-256 of the secret
-- (mirrors accounts.secret_hash / refresh_tokens.id); the secret itself is never
-- stored. revoked_at is set on unpair (FR-2.5).

CREATE TABLE IF NOT EXISTS pair_credentials (
    pair_id          TEXT PRIMARY KEY,
    account_id       TEXT NOT NULL,
    license_id       TEXT NOT NULL,
    mobile_device_id TEXT NOT NULL,
    secret_hash      TEXT NOT NULL,
    created_at       TIMESTAMPTZ NOT NULL,
    revoked_at       TIMESTAMPTZ
);
