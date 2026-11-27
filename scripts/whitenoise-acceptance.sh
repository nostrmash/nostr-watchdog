#!/bin/sh
# Isolated WhiteNoise acceptance for one test phone.
# This script never sends an alert unless you run alert-foreground or
# alert-background or alert-locked yourself. It does not read the parent shell's secrets.
set -eu

root=$(CDPATH= cd -- "$(dirname "$0")/.." && pwd)
helper="$root/crates/watchdog-marmot/target/release/watchdog-marmot"
watchdog="$root/target/release/nostr-watchdog"
odin="${ODIN:-$HOME/.local/odin-dev-2026-10/odin}"
state="${WATCHDOG_ACCEPTANCE_ROOT:-$root/data/whitenoise-acceptance}"
listen="${WATCHDOG_ACCEPTANCE_ADDR:-127.0.0.1:8791}"
relays="wss://relay.eu.whitenoise.chat,wss://relay.us.whitenoise.chat"
project="smartflowsocial"
operation="initial:${project}"

usage() {
  cat <<EOF
Usage: scripts/whitenoise-acceptance.sh <command>

  prepare <recipient>   Fresh database, MDK directory, sender, and operator token.
                        The recipient is a hex key or npub for the test phone.
                        Nothing is sent.
  start                 Start the isolated helper, then the isolated watchdog.
  init                  Import the generated sender. Idempotent.
  conversation          Establish the direct conversation. Idempotent.
  status                Show group and token readiness. No token bytes.
  alert-foreground      Send one test alert while the phone is unlocked.
  alert-background      Confirm the app is in the background, then send one alert.
  alert-locked          Confirm the phone is locked, then send one alert.
  restart               Stop both processes and start them again. Nothing is sent.
  stop                  Stop the isolated watchdog and its helper.

State directory: $state
Listen address:  http://$listen
The script ignores inherited Telegram credentials, production sender keys,
monitor settings, and WATCHDOG_CONFIG.
EOF
}

require_binaries() {
  if [ ! -x "$odin" ]; then
    echo "Odin dev-2026-10 revision 84bc3fc is required at $odin" >&2
    exit 1
  fi
  if [ ! -x "$helper" ] || [ ! -x "$watchdog" ]; then
    echo "Build both executables first:" >&2
    echo "  ODIN=$odin cargo build --locked --manifest-path crates/watchdog-marmot/Cargo.toml --release" >&2
    echo "  cargo build --locked --release -p watchdog-native" >&2
    exit 1
  fi
}

load_state() {
  if [ ! -f "$state/env" ]; then
    echo "Run prepare <recipient> before $1." >&2
    exit 1
  fi
  operator=""
  sender=""
  recipient=""
  while IFS= read -r line || [ -n "$line" ]; do
    case "$line" in
      OPERATOR_TOKEN=*) operator=${line#OPERATOR_TOKEN=} ;;
      SENDER_NSEC=*) sender=${line#SENDER_NSEC=} ;;
      RECIPIENT=*) recipient=${line#RECIPIENT=} ;;
    esac
  done < "$state/env"
  if [ -z "$operator" ] || [ -z "$sender" ] || [ -z "$recipient" ]; then
    echo "The acceptance env file is incomplete. Run prepare again in a new directory." >&2
    exit 1
  fi
}

write_secret() {
  path=$1
  value=$2
  umask 077
  mkdir -p "$(dirname "$path")"
  printf '%s\n' "$value" > "$path"
  chmod 600 "$path"
}

prepare() {
  recipient=${1:-}
  if [ -z "$recipient" ]; then
    echo "prepare requires the test phone's public key. There is no default recipient." >&2
    exit 2
  fi
  case "$recipient" in
    nsec*) echo "The recipient must be a public key, not a secret." >&2; exit 2 ;;
  esac
  require_binaries
  recipient=$("$helper" --normalize-pubkey "$recipient") || exit 2
  if [ -e "$state" ]; then
    echo "Refusing to reuse $state. Remove it yourself or set WATCHDOG_ACCEPTANCE_ROOT." >&2
    exit 1
  fi
  mkdir -p "$state/db" "$state/marmot"
  chmod 700 "$state" "$state/db" "$state/marmot"
  token=$(openssl rand -hex 32)
  sender_pub=$("$helper" --write-identity "$state/sender.nsec")
  chmod 600 "$state/sender.nsec"
  sender=$(tr -d '[:space:]' < "$state/sender.nsec")
  write_secret "$state/env" "OPERATOR_TOKEN=$token
SENDER_NSEC=$sender
RECIPIENT=$recipient"
  printf '%s\n' "$sender_pub" > "$state/sender.pub"
  chmod 600 "$state/sender.pub"
  echo "Prepared an isolated acceptance directory."
  echo "Sender public key: $sender_pub"
  echo "Recipient was stored. The operator token and sender secret were not printed."
  echo "Next: scripts/whitenoise-acceptance.sh start"
}

running() {
  [ -f "$state/watchdog.pid" ] && kill -0 "$(cat "$state/watchdog.pid")" 2>/dev/null
}

helper_healthy() {
  python3 - "$state/marmot/health.sock" <<'PY'
import json, socket, sys
path = sys.argv[1]
sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
try:
    sock.settimeout(1)
    sock.connect(path)
    data = b""
    while b"\n" not in data:
        chunk = sock.recv(4096)
        if not chunk:
            break
        data += chunk
    payload = json.loads(data.decode() or "{}")
    raise SystemExit(0 if payload.get("ok") is True else 1)
except Exception:
    raise SystemExit(1)
PY
}

start_helper() {
  if helper_healthy; then
    return
  fi
  mkdir -p "$state/marmot"
  chmod 700 "$state/marmot"
  # The watchdog spawns this process on the first delivery. Init and status
  # need it earlier. No --allow-loopback: these are the public WhiteNoise relays.
  env -i \
    PATH="$PATH" \
    HOME="$HOME" \
    TMPDIR="${TMPDIR:-/tmp}" \
    "$helper" \
    --root "$state/marmot" \
    --socket "$state/marmot/watchdog.sock" \
    --relay "wss://relay.eu.whitenoise.chat" \
    --relay "wss://relay.us.whitenoise.chat" \
    >> "$state/helper.log" 2>&1 &
  echo $! > "$state/helper.pid"
  i=0
  while [ "$i" -lt 150 ]; do
    if helper_healthy; then
      return
    fi
    if [ -f "$state/helper.pid" ] && ! kill -0 "$(cat "$state/helper.pid")" 2>/dev/null; then
      echo "The helper exited. See $state/helper.log" >&2
      exit 1
    fi
    sleep 0.2
    i=$((i + 1))
  done
  echo "The helper did not open its socket. See $state/helper.log" >&2
  exit 1
}

start_watchdog() {
  load_state start
  require_binaries
  if running; then
    echo "The isolated watchdog is already running."
    start_helper
    return
  fi
  if curl -fsS --max-time 1 "http://$listen/healthz" >/dev/null 2>&1; then
    echo "$listen is already in use. Stop that process before starting this test." >&2
    exit 1
  fi
  mkdir -p "$state/db" "$state/marmot"
  chmod 700 "$state/marmot"
  start_helper
  # env -i drops inherited production configuration. The values below are the
  # whole environment the test process receives.
  env -i \
    PATH="$PATH" \
    HOME="$HOME" \
    USER="${USER:-}" \
    TMPDIR="${TMPDIR:-/tmp}" \
    LANG="${LANG:-C}" \
    OPERATOR_TOKEN="$operator" \
    DATABASE_PATH="$state/db/watchdog.sqlite" \
    LISTEN_ADDR="$listen" \
    MARMOT_ROOT="$state/marmot" \
    MARMOT_SOCKET="$state/marmot/watchdog.sock" \
    MARMOT_HELPER="$helper" \
    ENABLE_MARMOT=true \
    ENABLE_NIP17=false \
    ALERTS_ENABLED=true \
    WATCHDOG_ENABLED=true \
    BOOTSTRAP_RELAYS="$relays" \
    SFS_BOT_NSEC="$sender" \
    ADMIN_NPUB="$recipient" \
    "$watchdog" >> "$state/watchdog.log" 2>&1 &
  echo $! > "$state/watchdog.pid"
  i=0
  while [ "$i" -lt 50 ]; do
    if curl -fsS --max-time 1 "http://$listen/healthz" >/dev/null 2>&1; then
      echo "Isolated watchdog is listening on http://$listen"
      echo "No alert has been sent."
      return
    fi
    if ! running; then
      echo "The watchdog exited. See $state/watchdog.log" >&2
      exit 1
    fi
    sleep 0.2
    i=$((i + 1))
  done
  echo "The watchdog did not open $listen. See $state/watchdog.log" >&2
  exit 1
}

owns_acceptance_process() {
  pid=$1
  expected=$2
  comm=$(ps -p "$pid" -o comm= 2>/dev/null | awk '{$1=$1; print}')
  comm=${comm##*/}
  if [ "$comm" != "$expected" ]; then
    return 1
  fi
  if ! command -v lsof >/dev/null 2>&1; then
    echo "lsof is required before this script will signal a process." >&2
    return 1
  fi
  case "$expected" in
    nostr-watchdog)
      lsof -nP -a -p "$pid" -iTCP:"${listen##*:}" -sTCP:LISTEN >/dev/null 2>&1
      ;;
    watchdog-marmot)
      lsof -nP -a -p "$pid" "$state/marmot/watchdog.sock" >/dev/null 2>&1 \
        || lsof -nP -a -p "$pid" "$state/marmot/health.sock" >/dev/null 2>&1
      ;;
    *)
      return 1
      ;;
  esac
}

stop_pid() {
  file=$1
  expected=$2
  if [ ! -f "$file" ]; then
    return
  fi
  pid=$(cat "$file")
  if ! kill -0 "$pid" 2>/dev/null; then
    rm -f "$file"
    return
  fi
  if ! owns_acceptance_process "$pid" "$expected"; then
    echo "Refusing to signal pid $pid from $file. It is not the isolated $expected for this state directory." >&2
    rm -f "$file"
    return
  fi
  kill "$pid" 2>/dev/null || true
  i=0
  while kill -0 "$pid" 2>/dev/null && [ "$i" -lt 50 ]; do
    sleep 0.1
    i=$((i + 1))
  done
  if kill -0 "$pid" 2>/dev/null; then
    kill -9 "$pid" 2>/dev/null || true
  fi
  rm -f "$file"
}

stop_watchdog() {
  stop_pid "$state/watchdog.pid" nostr-watchdog
  stop_pid "$state/helper.pid" watchdog-marmot
}

helper_call() {
  load_state "$1"
  python3 - "$state/marmot/watchdog.sock" "$state/env" "$2" "$relays" "$operation" <<'PY'
import json, socket, sys
path, env_path, mode, relays, operation = sys.argv[1:]
values = {}
for line in open(env_path):
    if "=" in line:
        key, value = line.rstrip("\n").split("=", 1)
        values[key] = value
request = {"op": mode}
if mode in ("onboard", "onboard_status"):
    request["operation_id"] = operation
if mode == "onboard":
    request.update({
        "nsec": values["SENDER_NSEC"],
        "relays": relays.split(","),
        "recipient": values["RECIPIENT"],
        "replace": False,
    })
sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
sock.connect(path)
sock.sendall((json.dumps(request) + "\n").encode())
data = b""
while b"\n" not in data:
    chunk = sock.recv(65536)
    if not chunk:
        break
    data += chunk
sock.close()
payload = json.loads(data.decode())
if mode == "readiness":
    identity = payload.get("identity") or {}
    print(json.dumps({
        "ok": payload.get("ok"),
        "error": payload.get("error"),
        "step": identity.get("step"),
        "recipient_devices": payload.get("recipient_devices"),
        "active_recipient_tokens": payload.get("active_recipient_tokens"),
        "group_available": identity.get("group_available"),
    }))
else:
    account = payload.get("account") or ""
    group = payload.get("group") or ""
    print(json.dumps({
        "ok": payload.get("ok"),
        "error": payload.get("error"),
        "phase": payload.get("phase"),
        "reused": payload.get("reused"),
        "account_prefix": account[:12],
        "group": group,
    }))
PY
}

wait_socket() {
  i=0
  while [ ! -S "$state/marmot/watchdog.sock" ] && [ "$i" -lt 50 ]; do
    sleep 0.2
    i=$((i + 1))
  done
  if [ ! -S "$state/marmot/watchdog.sock" ]; then
    echo "The helper socket is not ready. Start the watchdog and wait for it." >&2
    exit 1
  fi
}

onboard() {
  wait_socket
  i=0
  while [ "$i" -lt 15 ]; do
    result=$(helper_call onboard onboard)
    error=$(printf '%s' "$result" | python3 -c 'import json,sys; print(json.load(sys.stdin).get("error") or "")')
    if [ "$error" != "conversation_index_not_ready" ]; then
      printf '%s\n' "$result"
      return
    fi
    helper_call sync sync >/dev/null || true
    sleep 2
    i=$((i + 1))
  done
  echo "The conversation index is still not ready. Leave both processes running and retry conversation." >&2
  exit 1
}

send_alert() {
  load_state alert
  curl -sS -X POST "http://$listen/v1/diagnostics/test-alert" \
    -H "authorization: Bearer $operator" \
    -H "content-type: application/json" \
    -d "{\"projectId\":\"$project\",\"transport\":\"marmot\"}"
  echo
  echo "Queue state is not phone delivery. Inspect status before treating push as verified."
}

command=${1:-help}
shift || true
case "$command" in
  prepare) prepare "${1:-}" ;;
  start) start_watchdog ;;
  init) onboard ;;
  conversation) onboard ;;
  status)
    wait_socket
    onboard_result=$(helper_call status onboard_status)
    printf '%s\n' "$onboard_result"
    group=$(printf '%s' "$onboard_result" | python3 -c 'import json,sys; print(json.load(sys.stdin).get("group") or "")')
    if [ -n "$group" ]; then
      python3 - "$state/marmot/watchdog.sock" "$state/env" "$state/sender.pub" "$group" <<'PY'
import json, socket, sys
path, env_path, public_path, group = sys.argv[1:]
values = {}
for line in open(env_path):
    if "=" in line:
        key, value = line.rstrip("\n").split("=", 1)
        values[key] = value
account = open(public_path).read().strip()
request = {
    "op": "readiness",
    "account": account,
    "recipient": values["RECIPIENT"],
    "group": group,
}
sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
sock.connect(path)
sock.sendall((json.dumps(request) + "\n").encode())
data = b""
while b"\n" not in data:
    chunk = sock.recv(65536)
    if not chunk:
        break
    data += chunk
payload = json.loads(data.decode())
identity = payload.get("identity") or {}
print(json.dumps({
    "ok": payload.get("ok"),
    "error": payload.get("error"),
    "step": identity.get("step"),
    "group_available": identity.get("group_available"),
    "recipient_devices": payload.get("recipient_devices"),
    "active_recipient_tokens": payload.get("active_recipient_tokens"),
}))
PY
    fi
    ;;
  alert-foreground) send_alert ;;
  alert-background|alert-locked)
    if [ ! -t 0 ]; then
      echo "$1 must be run from a terminal." >&2
      exit 1
    fi
    case "$1" in
      alert-background) echo "Put WhiteNoise in the background on the test phone." ;;
      alert-locked) echo "Lock the test phone." ;;
    esac
    echo "Type send to publish one alert, or anything else to stop."
    read -r answer
    if [ "$answer" != "send" ]; then
      echo "No alert was sent."
      exit 1
    fi
    send_alert
    ;;
  restart)
    stop_watchdog
    start_watchdog
    ;;
  stop) stop_watchdog; echo "Stopped." ;;
  help|-h|--help) usage ;;
  *) usage; exit 2 ;;
esac
