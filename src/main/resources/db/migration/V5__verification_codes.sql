-- IAM-10: short-lived codes for email verification + password reset.
-- Hashed via argon2id (same encoder as provisioning tokens) so a DB
-- leak doesn't hand attackers valid codes.
--
-- Single-consume semantics: {@code consumed_at} is set atomically on
-- successful verify — a replayed code hits a WHERE consumed_at IS NULL
-- filter and returns "already used".
--
-- The (email, purpose, created_at DESC) index covers the most common
-- lookup (verify the latest code sent to this email for this purpose)
-- and also the rate-limit window scan (how many codes have we issued
-- to this email in the last N seconds).

CREATE TABLE verification_codes (
    id            UUID           PRIMARY KEY DEFAULT gen_random_uuid(),
    code_hash     VARCHAR(255)   NOT NULL,
    purpose       VARCHAR(32)    NOT NULL,   -- EMAIL_VERIFY | PASSWORD_RESET
    realm         VARCHAR(64)    NOT NULL,
    email         VARCHAR(255)   NOT NULL,
    attempts      INTEGER        NOT NULL DEFAULT 0,
    expires_at    TIMESTAMPTZ    NOT NULL,
    consumed_at   TIMESTAMPTZ,
    created_at    TIMESTAMPTZ    NOT NULL DEFAULT CURRENT_TIMESTAMP
);

CREATE INDEX idx_verif_codes_email_purpose_created
    ON verification_codes (email, purpose, created_at DESC);

CREATE INDEX idx_verif_codes_expires_at
    ON verification_codes (expires_at);
