#!/usr/bin/env bash
# SPDX-FileCopyrightText: 2026 Sebastien Rousseau
# SPDX-License-Identifier: Apache-2.0 OR MIT
#
# Everything against a server this script starts and stops: crypto-server
# from a built checkout of the commit in ci/server.ref, on loopback, with
# a synthetic API key and JWT secret. Runs the conformance kit, the live
# tests, every example, every README block and the benchmark smoke run,
# then stops the server it started (by PID, nothing else).
#
#   CRYPTO_SERVICE_SERVER_DIR=/path/to/crypto-service scripts/regression.sh
#
# Without CRYPTO_SERVICE_SERVER_DIR it clones and builds the pinned
# commit into a temporary directory (needs git, Node 24 and pnpm).
# REGRESSION_PORT picks the port (default 3102).
set -euo pipefail

cd "$(dirname "$0")/.."

port="${REGRESSION_PORT:-3102}"
ref="$(tr -d '[:space:]' < ci/server.ref)"
if ! [[ "$ref" =~ ^[0-9a-f]{40}$ ]]; then
  echo "regression: ci/server.ref must hold a full 40-character commit SHA" >&2
  exit 1
fi
server="${CRYPTO_SERVICE_SERVER_DIR:-}"
tmp="$(mktemp -d)"
pid=""
cleanup() {
  if [ -n "$pid" ]; then kill "$pid" 2>/dev/null || true; fi
  rm -rf "$tmp"
}
trap cleanup EXIT

if [ -z "$server" ]; then
  server="$tmp/crypto-service"
  git clone --quiet https://github.com/sebastienrousseau/crypto-service "$server"
  git -C "$server" checkout --quiet "$ref"
  (cd "$server" && pnpm install --frozen-lockfile && pnpm -r run build)
fi

key="regression-key-$(od -An -N12 -tx1 /dev/urandom | tr -d ' \n')"
secret="regression-jwt-$(od -An -N24 -tx1 /dev/urandom | tr -d ' \n')"
(
  cd "$server/packages/crypto-server"
  PORT="$port" HOST=127.0.0.1 CRYPTO_API_KEY="$key" JWT_SECRET="$secret" \
    RATE_LIMIT_MAX=100000 NODE_ENV=development \
    exec node dist/index.js
) > "$tmp/server.log" 2>&1 &
pid=$!

for _ in $(seq 1 60); do
  if curl -fsS "http://127.0.0.1:$port/health" > /dev/null 2>&1; then break; fi
  sleep 1
done
curl -fsS "http://127.0.0.1:$port/health" > /dev/null || { cat "$tmp/server.log"; exit 1; }

export CRYPTO_SERVICE_URL="http://127.0.0.1:$port"
export CRYPTO_SERVICE_API_KEY="$key"
export CRYPTO_SERVICE_JWT_SECRET="$secret"
make conformance
make bench-smoke
echo "regression: passed against crypto-server $ref"
