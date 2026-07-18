-- ============================================================
-- IAM database — runs ONLY on a fresh zm-postgres volume.
-- Filename pattern: NN-<service>.sql (NN determines execution order).
--
-- Existing volumes SKIP this file. For an already-running zm-postgres,
-- use the idempotent step in the service's deploy workflow, OR run
-- the equivalent DO $$ ... $$ block manually via `docker exec`.
--
-- Change `CHANGE_ME_iam_pass` to match iam.env → DB_PASSWORD.
-- ============================================================

CREATE USER iam_user WITH PASSWORD 'CHANGE_ME_iam_pass';
CREATE DATABASE iam_db OWNER iam_user;
GRANT ALL PRIVILEGES ON DATABASE iam_db TO iam_user;
