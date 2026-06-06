-- M3 QR pairing flow (FR-2.1): the one-time, short-lived pairing token the
-- desktop embeds in the QR code and the mobile redeems to complete pairing.
-- id is a hash of the secret; the secret itself is never stored.

CREATE TABLE IF NOT EXISTS pairing_tokens (
    id                TEXT PRIMARY KEY,
    account_id        TEXT NOT NULL,
    license_id        TEXT NOT NULL,
    desktop_device_id TEXT NOT NULL,
    expires_at        TIMESTAMPTZ NOT NULL,
    consumed_at       TIMESTAMPTZ,
    result_pair_id    TEXT NOT NULL DEFAULT ''
);
CREATE INDEX IF NOT EXISTS pairing_tokens_account_idx ON pairing_tokens (account_id);
