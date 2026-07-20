-- IAM-11: append-only audit trail for identity mutations.
-- Every provisioning apply, user-management write, and auth event of
-- interest lands here. Nothing UPDATEs or DELETEs a row (aside from the
-- retention job); this is the one table where "the past is truth".
--
-- Design choices:
--   target_type is VARCHAR (Java enum backed) not a Postgres ENUM so we
--   can add TargetType.WHATEVER without a migration.
--
--   detail is JSONB so downstream queries can inspect a change diff
--   without touching parsing code. Keys only — never PII values (see
--   PiiMasker + AuditEvent#redactAttributeValues in code).
--
--   The (target_type, target_id) index covers "everything that happened
--   to user X" queries; the occurred_at index covers window queries
--   and the retention DELETE.

CREATE TABLE audit_log (
    id            UUID           PRIMARY KEY DEFAULT gen_random_uuid(),
    occurred_at   TIMESTAMPTZ    NOT NULL DEFAULT CURRENT_TIMESTAMP,
    caller        VARCHAR(128)   NOT NULL,
    realm         VARCHAR(64),
    target_type   VARCHAR(32)    NOT NULL,
    target_id     VARCHAR(255),
    operation     VARCHAR(64)    NOT NULL,
    detail        JSONB          NOT NULL DEFAULT '{}'::jsonb,
    success       BOOLEAN        NOT NULL
);

CREATE INDEX idx_audit_log_occurred_at_desc
    ON audit_log (occurred_at DESC);

CREATE INDEX idx_audit_log_target
    ON audit_log (target_type, target_id);

CREATE INDEX idx_audit_log_realm_occurred
    ON audit_log (realm, occurred_at DESC);
