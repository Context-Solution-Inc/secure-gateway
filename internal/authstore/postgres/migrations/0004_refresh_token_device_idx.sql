-- SG-04 (FR-2.4): re-pairing must revoke the evicted device's refresh tokens.
-- RevokeRefreshTokensByDevice filters on device_id over still-active tokens, so
-- index the active (not-yet-revoked) rows by device for an efficient bulk revoke.

CREATE INDEX IF NOT EXISTS refresh_tokens_device_active_idx
    ON refresh_tokens (device_id)
    WHERE revoked_at IS NULL;
