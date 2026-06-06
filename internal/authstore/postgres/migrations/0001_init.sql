-- M2 Auth & License Service schema. The local database mirrors Stripe state
-- (PRD §6.1); it is never the source of truth for subscriptions.

CREATE TABLE IF NOT EXISTS accounts (
    id                 TEXT PRIMARY KEY,
    stripe_customer_id TEXT UNIQUE,
    secret_hash        TEXT NOT NULL DEFAULT '',
    created_at         TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE TABLE IF NOT EXISTS subscriptions (
    id                 TEXT PRIMARY KEY,
    account_id         TEXT NOT NULL,
    status             TEXT NOT NULL,
    max_pairs          INTEGER NOT NULL DEFAULT 1,
    current_period_end TIMESTAMPTZ,
    grace_until        TIMESTAMPTZ,
    updated_at         TIMESTAMPTZ NOT NULL DEFAULT now()
);
CREATE INDEX IF NOT EXISTS subscriptions_account_idx ON subscriptions (account_id);

CREATE TABLE IF NOT EXISTS licenses (
    id                   TEXT PRIMARY KEY,
    account_id           TEXT NOT NULL,
    subscription_id      TEXT NOT NULL,
    subscription_item_id TEXT NOT NULL DEFAULT '',
    status               TEXT NOT NULL,
    created_at           TIMESTAMPTZ NOT NULL DEFAULT now()
);
CREATE INDEX IF NOT EXISTS licenses_account_idx ON licenses (account_id);
CREATE INDEX IF NOT EXISTS licenses_subscription_idx ON licenses (subscription_id);

CREATE TABLE IF NOT EXISTS devices (
    id         TEXT PRIMARY KEY,
    account_id TEXT NOT NULL,
    role       TEXT NOT NULL,
    public_key BYTEA,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now()
);
CREATE INDEX IF NOT EXISTS devices_account_idx ON devices (account_id);

CREATE TABLE IF NOT EXISTS pairings (
    pair_id           TEXT PRIMARY KEY,
    license_id        TEXT NOT NULL,
    account_id        TEXT NOT NULL,
    mobile_device_id  TEXT NOT NULL,
    desktop_device_id TEXT NOT NULL,
    status            TEXT NOT NULL,
    created_at        TIMESTAMPTZ NOT NULL DEFAULT now()
);
CREATE INDEX IF NOT EXISTS pairings_license_idx ON pairings (license_id);
CREATE INDEX IF NOT EXISTS pairings_account_idx ON pairings (account_id);

CREATE TABLE IF NOT EXISTS refresh_tokens (
    id         TEXT PRIMARY KEY,
    device_id  TEXT NOT NULL,
    account_id TEXT NOT NULL,
    pair_id    TEXT NOT NULL,
    expires_at TIMESTAMPTZ NOT NULL,
    revoked_at TIMESTAMPTZ
);

CREATE TABLE IF NOT EXISTS webhook_events (
    id           TEXT PRIMARY KEY,
    type         TEXT NOT NULL,
    status       TEXT NOT NULL,
    attempts     INTEGER NOT NULL DEFAULT 0,
    payload      BYTEA,
    received_at  TIMESTAMPTZ NOT NULL DEFAULT now(),
    processed_at TIMESTAMPTZ
);
CREATE INDEX IF NOT EXISTS webhook_events_status_idx ON webhook_events (status);
