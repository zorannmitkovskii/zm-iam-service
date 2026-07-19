-- IAM-04: history of successful manifest applies, one row per version.
--
-- UNIQUE(service_id, version) is defence-in-depth against two apply
-- callers racing past the pg_advisory_xact_lock: the second commits
-- will surface as a constraint violation instead of silently double-
-- writing.
--
-- manifest_hash lets us reject "same version, mutated body" — a client
-- bug we must fail loudly on instead of silently accepting the new
-- bytes.
--
-- manifest_json + changes stay as JSONB so we can inspect diffs and
-- feed the mapper reconciler's delete-only-if-previously-declared
-- decision without re-parsing raw text.

CREATE EXTENSION IF NOT EXISTS pgcrypto;

CREATE TABLE applied_manifests (
    id             UUID           PRIMARY KEY DEFAULT gen_random_uuid(),
    service_id     VARCHAR(64)    NOT NULL,
    version        INTEGER        NOT NULL,
    manifest_hash  CHAR(64)       NOT NULL,
    manifest_json  JSONB          NOT NULL,
    changes        JSONB          NOT NULL DEFAULT '[]'::jsonb,
    applied_at     TIMESTAMPTZ    NOT NULL DEFAULT CURRENT_TIMESTAMP,
    CONSTRAINT applied_manifests_svc_ver_uk UNIQUE (service_id, version)
);

CREATE INDEX idx_applied_manifests_svc_ver_desc
    ON applied_manifests (service_id, version DESC);
