-- IAM-06: tracks which service "owns" each Keycloak resource. First
-- declarant wins; foreign resources are refused with a 409 before any
-- Keycloak write. Roles are shared — no ownership tracked for them.
--
-- (resource_type, realm, resource_name) is unique because the same
-- name can legitimately exist in different realms (a "eventFE" client
-- in event-app and another "eventFE" in some-other-realm are distinct
-- resources).

CREATE TABLE resource_ownership (
    id             UUID           PRIMARY KEY DEFAULT gen_random_uuid(),
    resource_type  VARCHAR(16)    NOT NULL,   -- REALM | CLIENT | IDP
    realm          VARCHAR(64)    NOT NULL,
    resource_name  VARCHAR(255)   NOT NULL,
    owner_service  VARCHAR(64)    NOT NULL,
    created_at     TIMESTAMPTZ    NOT NULL DEFAULT CURRENT_TIMESTAMP,
    CONSTRAINT resource_ownership_type_realm_name_uk
        UNIQUE (resource_type, realm, resource_name)
);

-- Debug endpoint reads by realm; keep that fast.
CREATE INDEX idx_resource_ownership_realm
    ON resource_ownership (realm);
