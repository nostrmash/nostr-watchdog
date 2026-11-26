#!/bin/sh
# Prepare an isolated native test. This does not send a message and does not
# read production keys. The phone steps stay with the operator.
set -eu

root=$(CDPATH= cd -- "$(dirname "$0")/.." && pwd)
helper="$root/crates/watchdog-marmot/target/release/watchdog-marmot"
watchdog="$root/target/release/nostr-watchdog"
odin="${ODIN:-$HOME/.local/odin-dev-2026-10/odin}"
state="${WATCHDOG_ACCEPTANCE_ROOT:-$root/data/whitenoise-acceptance}"

if [ ! -x "$odin" ]; then
  echo "Odin dev-2026-10 revision 84bc3fc is required at $odin" >&2
  echo "Official archive: https://github.com/odin-lang/Odin/releases/download/dev-2026-10/odin-macos-arm64-dev-2026-10.tar.gz" >&2
  exit 1
fi
"$odin" version

if [ ! -x "$helper" ] || [ ! -x "$watchdog" ]; then
  echo "Build both executables first:" >&2
  echo "  ODIN=$odin cargo build --manifest-path crates/watchdog-marmot/Cargo.toml --release" >&2
  echo "  cargo build --release -p watchdog-native" >&2
  exit 1
fi

if [ -z "${OPERATOR_TOKEN:-}" ]; then
  echo "Set OPERATOR_TOKEN to a fresh local secret before starting the watchdog." >&2
  exit 1
fi

mkdir -p "$state/db" "$state/marmot"
chmod 700 "$state" "$state/db" "$state/marmot"

cat <<EOF
Isolated state: $state
Helper: $helper
Watchdog: $watchdog

WhiteNoise-operated relays from the pinned MDK deployment, not a social relay:
  wss://relay.eu.whitenoise.chat
  wss://relay.us.whitenoise.chat

Export this environment in the same shell. Replace the two identity values
with a new sender nsec and the test phone's public key. Do not use
SFS_BOT_NSEC, NOSTRMASH_BOT_NSEC, or a daily-driver account.

  export OPERATOR_TOKEN
  export WATCHDOG_DB=$state/db/watchdog.sqlite
  export MARMOT_ROOT=$state/marmot
  export MARMOT_HELPER=$helper
  export ENABLE_MARMOT=true
  export ENABLE_NIP17=false
  export ALERTS_ENABLED=true
  export WATCHDOG_ENABLED=true
  export BOOTSTRAP_RELAYS=wss://relay.eu.whitenoise.chat,wss://relay.us.whitenoise.chat
  export SFS_BOT_NSEC=<new test sender nsec>
  export ADMIN_NPUB=<test phone public key, hex or npub>
  $watchdog

Then:
  curl -sS -X POST http://127.0.0.1:8787/v1/diagnostics/test-alert \\
    -H "authorization: Bearer \$OPERATOR_TOKEN" \\
    -H "content-type: application/json" \\
    -d '{"projectId":"smartflowsocial","transport":"marmot"}'
  curl -sS http://127.0.0.1:8787/v1/diagnostics/marmot?project=smartflowsocial \\
    -H "authorization: Bearer \$OPERATOR_TOKEN"

Accept the conversation in WhiteNoise, confirm the test phone has registered
for notifications, lock the screen, and send a second alert. A relay-accepted
message is not a lock-screen notification. If the cached sender or recipient
must change, stop the process, set MARMOT_REONBOARD=smartflowsocial for one
start, and unset it afterward. Do not delete the MDK directory to force a
second conversation.
EOF
