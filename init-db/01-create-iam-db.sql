-- Runs once, on first postgres container boot, via Postgres's
-- /docker-entrypoint-initdb.d/ convention. Creates the IAM database and its
-- dedicated user.

CREATE USER iam_user WITH PASSWORD 'iam_pass';
CREATE DATABASE iam_db OWNER iam_user;
GRANT ALL PRIVILEGES ON DATABASE iam_db TO iam_user;
