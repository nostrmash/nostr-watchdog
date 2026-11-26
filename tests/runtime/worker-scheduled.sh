#!/bin/sh
# Local workerd rehearsal. Uses wrangler.rust-local.toml and its local D1 id.
# It does not deploy and it does not read production state.
set -eu
root=$(CDPATH= cd -- "$(dirname "$0")/../.." && pwd)
cd "$root"
if ! command -v worker-build >/dev/null 2>&1; then
  echo "worker-build is not installed. cargo install worker-build --locked" >&2
  exit 1
fi
worker-build --dev --no-opt --out-dir build crates/watchdog-worker
npx --yes wrangler@4 d1 migrations apply nostr-watchdog-rust-local --local --config wrangler.rust-local.toml
npx --yes wrangler@4 dev --test-scheduled --config wrangler.rust-local.toml --port 8788 --ip 127.0.0.1 &
pid=$!
trap 'kill "$pid" 2>/dev/null || true' EXIT
i=0
while [ "$i" -lt 30 ]; do
  if curl -fsS http://127.0.0.1:8788/healthz >/dev/null 2>&1; then
    break
  fi
  i=$((i + 1))
  sleep 1
done
curl -fsS http://127.0.0.1:8788/healthz
echo
curl -fsS http://127.0.0.1:8788/readyz
echo
curl -fsS "http://127.0.0.1:8788/__scheduled?cron=*+*+*+*+*"
echo
