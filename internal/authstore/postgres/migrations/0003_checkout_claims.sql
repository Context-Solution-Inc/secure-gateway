-- Desktop subscription onboarding (claim-token flow): binds a desktop-generated
-- nonce to the account/license/subscription provisioned by a Stripe Checkout, so
-- a freshly-paid desktop can claim its account credential exactly once. No secret
-- is stored here; claim_code_hash is the hash of the one-time code delivered over
-- the loopback redirect, and the account secret is minted at claim time.

CREATE TABLE IF NOT EXISTS checkout_claims (
    nonce             TEXT PRIMARY KEY,
    stripe_session_id TEXT        NOT NULL DEFAULT '',
    redirect_uri      TEXT        NOT NULL,
    claim_code_hash   TEXT        NOT NULL DEFAULT '',
    account_id        TEXT        NOT NULL DEFAULT '',
    license_id        TEXT        NOT NULL DEFAULT '',
    subscription_id   TEXT        NOT NULL DEFAULT '',
    status            TEXT        NOT NULL,
    created_at        TIMESTAMPTZ NOT NULL,
    expires_at        TIMESTAMPTZ NOT NULL,
    consumed_at       TIMESTAMPTZ
);
CREATE INDEX IF NOT EXISTS checkout_claims_code_idx    ON checkout_claims (claim_code_hash);
CREATE INDEX IF NOT EXISTS checkout_claims_expires_idx ON checkout_claims (expires_at);
