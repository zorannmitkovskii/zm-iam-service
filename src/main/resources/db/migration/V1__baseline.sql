-- V1__baseline.sql
--
-- Empty baseline migration. Tables land in subsequent tickets:
--   V2 → applied_manifests + resource_ownership  (IAM-02)
--   V3 → verification_codes                       (IAM-03/IAM-04)
--   V4 → audit_log                                (IAM-05)
--   V5 → rate_limit_buckets                       (IAM-06)
--
-- Kept intentionally empty so Flyway has a recorded baseline row from day
-- one, and subsequent migrations can assume a Flyway-managed schema.

SELECT 1;
