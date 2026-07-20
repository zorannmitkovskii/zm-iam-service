#!/usr/bin/env bash
# generate-provisioning-token.sh — creates one (plaintext, argon2 hash) pair
# for a service's IAM provisioning bootstrap credential.
#
# Usage:
#   ./generate-provisioning-token.sh <serviceId>
#
# Output goes to stdout with two labelled blocks:
#   PLAINTEXT_TOKEN=... (goes on the SERVICE side — never on IAM)
#   IAM_PROVISIONING_TOKEN_<SERVICEID>=... (goes on the IAM side — never on the service)
#
# The plaintext token is a URL-safe 32-byte random string. The hash is
# argon2id at Spring Security's default v5.8 parameters (saltLen=16,
# hashLen=32, parallelism=1, memory=16MiB, iterations=2) so IAM's
# Argon2PasswordEncoder.defaultsForSpringSecurity_v5_8() can verify.
#
# Requires: argon2 CLI (Linux: apt-get install argon2 / brew install argon2)
#           openssl (for random bytes)

set -euo pipefail

if [ $# -ne 1 ]; then
  echo "Usage: $0 <serviceId>" >&2
  exit 1
fi

SERVICE_ID="$1"

if ! command -v argon2 >/dev/null 2>&1; then
  cat <<EOF >&2
argon2 CLI not found. Install it first:
  - macOS:        brew install argon2
  - Debian/Ubuntu: apt-get install argon2
  - Alpine:       apk add argon2
EOF
  exit 1
fi

# 32 raw bytes → base64url, no padding, no linebreaks
PLAINTEXT="$(openssl rand -base64 32 | tr '+/' '-_' | tr -d '=' | tr -d '\n')"

# argon2 CLI reads plaintext from stdin, needs a salt on the command line.
# We use a fresh 16-byte random salt per call.
SALT_HEX="$(openssl rand -hex 16)"

# Spring Security 5.8 defaults: t=2, m=16384 KiB, p=1, hashLen=32
HASH="$(printf '%s' "$PLAINTEXT" \
    | argon2 "$SALT_HEX" -id -t 2 -m 14 -p 1 -l 32 -e)"

# Env-var name convention: uppercase, dashes→underscores
ENV_NAME="IAM_PROVISIONING_TOKEN_$(echo "$SERVICE_ID" | tr '[:lower:]-' '[:upper:]_')"

cat <<EOF
────────────────────────────────────────────────────────────────
SERVICE-side env (put in the calling service's env file):

  PROVISIONING_TOKEN=${PLAINTEXT}

IAM-side env (put in IAM's env file — hash only, never the plaintext):

  ${ENV_NAME}=${HASH}

Rotation: append more hashes comma-separated to the IAM env value; both
old and new plaintext tokens work until you remove the old hash.
────────────────────────────────────────────────────────────────
EOF
