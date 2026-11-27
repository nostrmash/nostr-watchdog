#!/bin/sh
# Workerd integration suite. Isolated D1, isolated config, local fixture only.
# Production network policy is unchanged. A failing assertion exits non-zero.
set -eu
root=$(CDPATH= cd -- "$(dirname "$0")/../.." && pwd)
cd "$root"
if ! command -v worker-build >/dev/null 2>&1; then
  echo "worker-build is not installed. cargo install worker-build --locked" >&2
  exit 1
fi
if ! command -v python3 >/dev/null 2>&1 || ! command -v npx >/dev/null 2>&1; then
  echo "python3 and npx are required" >&2
  exit 1
fi

persist=$(mktemp -d)
slow="$persist/slow"
fixture_host=$(python3 - <<'PY'
import re, subprocess
text = ""
for cmd in (["ifconfig"], ["ip", "-4", "-o", "addr"]):
    try:
        text += subprocess.check_output(cmd, text=True, stderr=subprocess.DEVNULL)
    except Exception:
        pass
addrs = re.findall(r"inet\s+(\d+\.\d+\.\d+\.\d+)", text)
def rank(ip):
    if ip.startswith("127."):
        return 9
    if ip.startswith("192.168.") or ip.startswith("172."):
        return 0
    if ip.startswith("10."):
        return 2
    return 1
usable = [ip for ip in addrs if not ip.startswith("127.")]
print(sorted(set(usable), key=rank)[0] if usable else "127.0.0.1")
PY
)
worker_port=$(python3 -c 'import socket; s=socket.socket(); s.bind(("127.0.0.1", 0)); print(s.getsockname()[1]); s.close()')
cleanup() {
  if [ -f "${persist:-}/wrangler.log" ]; then
    cp "$persist/wrangler.log" /tmp/wd-last-wrangler.log 2>/dev/null || true
  fi
  if [ -n "${worker_pid:-}" ]; then
    kill "$worker_pid" 2>/dev/null || true
    wait "$worker_pid" 2>/dev/null || true
  fi
  if [ -n "${fixture_pid:-}" ]; then
    kill "$fixture_pid" 2>/dev/null || true
    wait "$fixture_pid" 2>/dev/null || true
  fi
  if [ "${KEEP_RUNTIME_PERSIST:-}" = "1" ]; then
    echo "kept $persist" >/tmp/wd-persist-path
  else
    rm -rf "$persist"
  fi
}
trap cleanup EXIT
python3 - "$slow" "$persist/fixture.port" <<'PY' &
import json, sys, time
from pathlib import Path
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
slow = sys.argv[1]
port_path = sys.argv[2]
race = Path(port_path).with_name("reminder-race")
hits = {"n": 0}
class Handler(BaseHTTPRequestHandler):
    def do_GET(self):
        if self.path.split("?", 1)[0] != "/healthcheck":
            self.send_response(404)
            self.end_headers()
            return
        hits["n"] += 1
        if open(slow).read().strip() == "1" if __import__("os").path.exists(slow) else False:
            time.sleep(5)
        if race.exists():
            race.with_suffix(".entered").touch()
            until = time.monotonic() + 5
            while race.exists() and time.monotonic() < until:
                time.sleep(0.01)
        if hits["n"] <= 2 or race.with_suffix(".entered").exists():
            body = b'{"status":"down"}'
            status = 500
        else:
            body = b'{"status":"ok"}'
            status = 200
        self.send_response(status)
        self.send_header("content-type", "application/json")
        self.send_header("content-length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)
    def do_POST(self):
        if self.path != "/telegram":
            self.send_response(404)
            self.end_headers()
            return
        message = json.loads(self.rfile.read(int(self.headers.get("content-length", "0"))))
        body = json.dumps({"ok": message.get("chat_id") == "1" and bool(message.get("text"))}).encode()
        self.send_response(200)
        self.send_header("content-type", "application/json")
        self.end_headers()
        self.wfile.write(body)
    def log_message(self, fmt, *args):
        return
server = ThreadingHTTPServer(("0.0.0.0", 0), Handler)
with open(port_path, "w", encoding="utf-8") as handle:
    handle.write(str(server.server_address[1]))
    handle.write("\n")
server.serve_forever()
PY
fixture_pid=$!
i=0
while [ ! -s "$persist/fixture.port" ]; do
  i=$((i + 1))
  if [ "$i" -gt 50 ] || ! kill -0 "$fixture_pid" 2>/dev/null; then
    echo "fixture did not bind an ephemeral port" >&2
    exit 1
  fi
  sleep 0.1
done
fixture_port=$(tr -d '[:space:]' <"$persist/fixture.port")
config="$persist/wrangler.toml"
sed \
  -e "s#http://127.0.0.1:8765/healthcheck#http://${fixture_host}:${fixture_port}/healthcheck#" \
  -e "s#migrations_dir = \"migrations\"#migrations_dir = \"${root}/migrations\"#" \
  -e "s#main = \"crates/watchdog-worker/build/worker/shim.mjs\"#main = \"${root}/crates/watchdog-worker/build/worker/shim.mjs\"#" \
  wrangler.runtime-test.toml >"$config"
printf 'WATCHDOG_TEST_TELEGRAM_ENDPOINT = "http://127.0.0.1:%s/telegram"\n' "$fixture_port" >> "$config"
db=nostr-watchdog-runtime-test
echo "fixture http://${fixture_host}:${fixture_port}/healthcheck"

echo "building the worker bundle"
if ! worker-build --dev --no-opt --out-dir build crates/watchdog-worker; then
  # worker-build renames its staging directory into place. On this macOS
  # volume that rename can fail with EDEADLK after the bundle is written.
  staged="crates/watchdog-worker/build/.tmp/worker/shim.mjs"
  if [ ! -f "$staged" ]; then
    echo "worker bundle was not produced" >&2
    exit 1
  fi
  rm -rf crates/watchdog-worker/build/worker
  cp -R crates/watchdog-worker/build/.tmp/worker crates/watchdog-worker/build/worker
fi
test -f crates/watchdog-worker/build/worker/shim.mjs

echo "applying D1 migrations"
npx --yes wrangler@4.166.0 d1 migrations apply "$db" --local --persist-to "$persist" --config "$config"

npx --yes wrangler@4.166.0 dev --test-scheduled --config "$config" --port "$worker_port" --ip 127.0.0.1 --persist-to "$persist" >"$persist/wrangler.log" 2>&1 &
worker_pid=$!

i=0
while [ "$i" -lt 60 ]; do
  if curl -fsS "http://127.0.0.1:${worker_port}/healthz" >/dev/null 2>&1; then
    break
  fi
  if ! kill -0 "$worker_pid" 2>/dev/null; then
    echo "workerd exited during startup" >&2
    cat "$persist/wrangler.log" >&2
    exit 1
  fi
  i=$((i + 1))
  sleep 1
done
curl -fsS "http://127.0.0.1:${worker_port}/healthz" | grep -F '"live":true'

ready=$(curl -sS -o "$persist/ready-before.json" -w "%{http_code}" "http://127.0.0.1:${worker_port}/readyz")
test "$ready" = "503"
python3 - "$persist/ready-before.json" <<'PY'
import json, sys
body = json.load(open(sys.argv[1]))
assert body["ready"] is False
assert body["scheduler"] == "uninitialized"
PY

d1() {
  npx --yes wrangler@4.166.0 d1 execute "$db" --local --persist-to "$persist" --config "$config" --json --command "$1"
}

# The catalog interval is 60s. Rewinding the stored check time makes the next
# scheduled invocation probe again without waiting out the production interval.
echo "opening an incident"
curl -fsS --max-time 25 "http://127.0.0.1:${worker_port}/__scheduled?cron=*+*+*+*+*" >/dev/null
d1 "UPDATE monitor_state SET last_check_at = 0" >/dev/null
curl -fsS --max-time 25 "http://127.0.0.1:${worker_port}/__scheduled?cron=*+*+*+*+*" >/dev/null

python3 - "$persist" "$config" <<'PY'
import json, subprocess, sys
persist, config = sys.argv[1], sys.argv[2]
def query(sql):
    raw = subprocess.check_output([
        "npx", "--yes", "wrangler@4.166.0", "d1", "execute", "nostr-watchdog-runtime-test",
        "--local", "--persist-to", persist, "--config", config,
        "--json", "--command", sql,
    ], text=True)
    parsed = json.loads(raw)
    return parsed[0]["results"]
rows = query("SELECT status FROM monitor_state WHERE monitor_id = 'sfs-web'")
assert rows and rows[0]["status"] == "down", rows
open_rows = query("SELECT id, status, kind FROM incidents WHERE monitor_id = 'sfs-web' AND status = 'open'")
assert len(open_rows) == 1, open_rows
assert open_rows[0]["kind"] == "outage"
print("incident", open_rows[0]["id"])
open(persist + "/incident", "w").write(open_rows[0]["id"])
PY

echo "acknowledging an incident while a scheduled reminder is in flight"
incident=$(cat "$persist/incident")
d1 "UPDATE incidents SET opened_at = opened_at - 60000 WHERE id = '${incident}'; UPDATE monitor_state SET last_check_at = 0 WHERE monitor_id = 'sfs-web';" >/dev/null
touch "$persist/reminder-race"
curl -fsS --max-time 25 "http://127.0.0.1:${worker_port}/__scheduled?cron=*+*+*+*+*" >"$persist/reminder-tick.json" &
reminder_pid=$!
i=0
while [ ! -f "$persist/reminder-race.entered" ]; do
  i=$((i + 1))
  if [ "$i" -gt 150 ] || ! kill -0 "$reminder_pid" 2>/dev/null; then
    echo "the reminder probe did not reach the fixture" >&2
    exit 1
  fi
  sleep 0.02
done
curl -fsS --max-time 3 -X POST -H "authorization: Bearer runtime-operator-token" \
  "http://127.0.0.1:${worker_port}/v1/incidents/${incident}/ack" | grep -F '"status":"acked"'
rm "$persist/reminder-race"
wait "$reminder_pid"
rm "$persist/reminder-race.entered"
d1 "SELECT reminder_count, acked_at, (SELECT COUNT(*) FROM alert_outbox WHERE incident_id = '${incident}' AND alert_class = 'reminder') AS reminders,
           (SELECT status FROM monitor_state WHERE monitor_id = 'sfs-web') AS monitor_status
    FROM incidents WHERE id = '${incident}'" >"$persist/reminder-fence.json"
python3 - "$persist/reminder-fence.json" <<'RACE'
import json, sys
row = json.load(open(sys.argv[1]))[0]["results"][0]
assert row["reminder_count"] == row["reminders"] == 0 and row["acked_at"], row
assert row["monitor_status"] == "down", row
RACE

echo "seeding delivery rows"
now=$(python3 -c 'import time; print(int(time.time()*1000))')
d1 "INSERT INTO alert_outbox (
  id, alert_class, incident_id, monitor_id, project_id, dedupe_key, destination, severity,
  state, payload_text, next_attempt_at, created_at, updated_at, logical_id
) VALUES (
  'alt_new', 'outage', '${incident}', 'sfs-web', 'smartflowsocial', 'incident:new:open:marmot',
  'marmot', 'critical', 'queued', 'down', 0, ${now}, ${now}, 'incident:new:open'
);" >/dev/null
d1 "INSERT INTO alert_outbox (
  id, alert_class, incident_id, monitor_id, project_id, dedupe_key, destination, severity,
  state, payload_text, next_attempt_at, created_at, updated_at, logical_id
) VALUES (
  'alt_dup', 'outage', '${incident}', 'sfs-web', 'smartflowsocial', 'incident:dup:open:marmot',
  'marmot', 'critical', 'queued', 'down', 0, ${now}, ${now}, 'incident:dup:open'
);" >/dev/null
d1 "INSERT INTO alert_outbox (
  id, alert_class, incident_id, monitor_id, project_id, dedupe_key, destination, severity,
  state, payload_text, next_attempt_at, created_at, updated_at, logical_id
) VALUES (
  'alt_dup_telegram', 'outage', '${incident}', 'sfs-web', 'smartflowsocial', 'fallback:incident:dup:open',
  'telegram', 'critical', 'relay_accepted', 'already', 0, ${now}, ${now}, 'fallback:incident:dup:open'
);" >/dev/null
d1 "INSERT INTO alert_outbox (
  id, alert_class, incident_id, monitor_id, project_id, dedupe_key, destination, severity,
  state, payload_text, next_attempt_at, created_at, updated_at, claim_until, claim_token, claim_owner
) VALUES (
  'alt_stale', 'outage', '${incident}', 'sfs-web', 'smartflowsocial', 'incident:stale:open:marmot',
  'marmot', 'critical', 'retrying', 'held', 0, ${now}, ${now}, 4102444800000, 'held-token', 'other-runtime'
);" >/dev/null

curl -fsS --max-time 25 "http://127.0.0.1:${worker_port}/__scheduled?cron=*+*+*+*+*" >/dev/null

python3 - "$persist" "$config" <<'PY'
import json, subprocess, sys
persist, config = sys.argv[1], sys.argv[2]
def query(sql):
    raw = subprocess.check_output([
        "npx", "--yes", "wrangler@4.166.0", "d1", "execute", "nostr-watchdog-runtime-test",
        "--local", "--persist-to", persist, "--config", config,
        "--json", "--command", sql,
    ], text=True)
    return json.loads(raw)[0]["results"]
new = query("SELECT id, state, last_error, logical_id FROM alert_outbox WHERE id = 'alt_new'")[0]
assert new["state"] == "failed" and new["last_error"] == "transport_disabled", new
created = query("SELECT id, state, logical_id FROM alert_outbox WHERE destination = 'telegram' AND logical_id = 'fallback:incident:new:open'")
everything = query("SELECT id, destination, state, last_error, logical_id FROM alert_outbox")
assert len(created) == 1, {"created": created, "new": new, "all": everything}
dup = query("SELECT id FROM alert_outbox WHERE destination = 'telegram' AND logical_id = 'fallback:incident:dup:open'")
assert [row["id"] for row in dup] == ["alt_dup_telegram"], dup
stale = query("SELECT state, claim_token, claim_owner FROM alert_outbox WHERE id = 'alt_stale'")[0]
assert stale["state"] == "retrying" and stale["claim_token"] == "held-token", stale
assert stale["claim_owner"] == "other-runtime", stale
assert query("SELECT COUNT(*) AS n FROM alert_outbox WHERE logical_id = 'fallback:incident:stale:open'")[0]["n"] == 0
print("fallback", created[0]["id"], created[0]["state"])
open(persist + "/fallback", "w").write(created[0]["id"])
PY

fallback=$(cat "$persist/fallback")
d1 "UPDATE alert_outbox SET state = 'relay_accepted', claim_token = NULL, claim_until = NULL WHERE destination = 'telegram';" >/dev/null

code=$(curl -sS -o "$persist/alert.json" -w "%{http_code}" -H "authorization: Bearer runtime-operator-token" "http://127.0.0.1:${worker_port}/v1/outbox/${fallback}")
test "$code" = "200"
python3 - "$persist/alert.json" <<'PY'
import json, sys
body = json.load(open(sys.argv[1]))
for key in ("messageState", "pushState", "messageAttempts", "pushPublications", "operationId", "settledAt"):
    assert key in body, body
assert "payload" not in body and "payload_text" not in body
assert "nsec" not in json.dumps(body)
PY

echo "recovering"
d1 "UPDATE monitor_state SET last_check_at = 0" >/dev/null
curl -fsS --max-time 25 "http://127.0.0.1:${worker_port}/__scheduled?cron=*+*+*+*+*" >/dev/null
d1 "UPDATE monitor_state SET last_check_at = 0" >/dev/null
curl -fsS --max-time 25 "http://127.0.0.1:${worker_port}/__scheduled?cron=*+*+*+*+*" >/dev/null
python3 - "$persist" "$config" <<'PY'
import json, subprocess, sys
persist, config = sys.argv[1], sys.argv[2]
def query(sql):
    raw = subprocess.check_output([
        "npx", "--yes", "wrangler@4.166.0", "d1", "execute", "nostr-watchdog-runtime-test",
        "--local", "--persist-to", persist, "--config", config,
        "--json", "--command", sql,
    ], text=True)
    return json.loads(raw)[0]["results"]
state = query("SELECT status FROM monitor_state WHERE monitor_id = 'sfs-web'")[0]["status"]
assert state == "healthy", state
open_rows = query("SELECT id FROM incidents WHERE monitor_id = 'sfs-web' AND status = 'open'")
assert open_rows == [], open_rows
PY

ready=$(curl -sS -o "$persist/ready-after.json" -w "%{http_code}" "http://127.0.0.1:${worker_port}/readyz")
test "$ready" = "200"
python3 - "$persist/ready-after.json" <<'PY'
import json, sys
body = json.load(open(sys.argv[1]))
assert body["ready"] is True, body
assert body["scheduler"] == "fresh"
PY

echo "status signature"
status_code=$(curl -sS -D "$persist/status.headers" -o "$persist/status.json" -w "%{http_code}" -H "authorization: Bearer runtime-status-token" "http://127.0.0.1:${worker_port}/v1/status")
# The fixture's failed Marmot rows are retained dead letters, so the public
# status is degraded and the signature still covers those exact bytes.
test "$status_code" = "503"
python3 - "$persist/status.json" "$persist/status.headers" <<'PY'
import hashlib, hmac, json, sys
body = open(sys.argv[1], "rb").read()
headers = open(sys.argv[2], "r", errors="replace").read().lower()
signature = ""
for line in headers.splitlines():
    if line.startswith("x-watchdog-signature:"):
        signature = line.split(":", 1)[1].strip()
expected = hmac.new(b"runtime-signing-secret-32chars-min", body, hashlib.sha256).hexdigest()
assert signature == expected, (signature, expected)
parsed = json.loads(body)
assert parsed["contract"] == "watchdog-status-v1"
assert parsed["status"] == "degraded", parsed["status"]
assert b"nsec" not in body
PY

missing=$(curl -sS -o /dev/null -w "%{http_code}" -X POST "http://127.0.0.1:${worker_port}/v1/diagnostics/marmot/onboard" -H "content-type: application/json" --data '{"projectId":"smartflowsocial","operationId":"op-1"}')
test "$missing" = "401"
invalid=$(curl -sS -o /dev/null -w "%{http_code}" -X POST "http://127.0.0.1:${worker_port}/v1/diagnostics/marmot/onboard" -H "authorization: Bearer wrong" -H "content-type: application/json" --data '{"projectId":"smartflowsocial","operationId":"op-1"}')
test "$invalid" = "401"
oversized=$(curl -sS -o /dev/null -w "%{http_code}" -X POST "http://127.0.0.1:${worker_port}/v1/heartbeats/sfs-worker" -H "content-type: application/json" --data "$(python3 -c 'print("{" + "a"*20000 + "}")')")
test "$oversized" = "413"

python3 - "$worker_port" <<'PY'
import hashlib, hmac, sys, time, urllib.error, urllib.request
from concurrent.futures import ThreadPoolExecutor
port = sys.argv[1]
key = b"0123456789abcdef0123456789abcdef"
def post(body, ts, nonce):
    raw = body.encode()
    canon = f"{ts}\n{nonce}\nPOST\n/v1/heartbeats/sfs-worker\n{hashlib.sha256(raw).hexdigest()}"
    sig = hmac.new(key, canon.encode(), hashlib.sha256).hexdigest()
    req = urllib.request.Request(
        f"http://127.0.0.1:{port}/v1/heartbeats/sfs-worker",
        data=raw,
        method="POST",
        headers={
            "content-type": "application/json",
            "x-watchdog-timestamp": ts,
            "x-watchdog-nonce": nonce,
            "x-watchdog-signature": sig,
        },
    )
    try:
        with urllib.request.urlopen(req) as response:
            return response.status, response.read()
    except urllib.error.HTTPError as error:
        return error.code, error.read()
now = str(int(time.time()))
with ThreadPoolExecutor(max_workers=2) as requests:
    replies = list(requests.map(
        lambda _: post('{"progress":"cursor-b"}', now, "nonce-runtime-0000001"),
        range(2)
    ))
assert sorted(code for code, _ in replies) == [200, 401], replies
assert any(code == 401 and b"replay" in body for code, body in replies), replies
status, body = post('{"progress":"cursor-equal"}', now, "nonce-runtime-0000002")
assert status == 409 and b"stale" in body, (status, body)
older = str(int(time.time()) - 30)
status, body = post('{"progress":"cursor-a"}', older, "nonce-runtime-0000003")
assert status == 409 and b"stale" in body, (status, body)
PY

echo "d1 adapter fences"
curl -fsS --max-time 20 -H "authorization: Bearer runtime-operator-token" -H "content-type: application/json" -X POST "http://127.0.0.1:${worker_port}/v1/diagnostics/runtime-fence" -o "$persist/fence.json"
python3 - "$persist/fence.json" <<'PY'
import json, sys
body = json.load(open(sys.argv[1]))
assert body["winner"] is True, body
assert body["loser"] is False, body
assert body["telegramRows"] == 1, body
assert body["rolledBack"] is True, body
assert body["rollbackPreserved"] is True, body
assert body["updateInterrupted"] is True, body
assert body["fallbackPersisted"] is True, body
assert body["retryWon"] is True, body
assert body["retryPreserved"] is True, body
assert body["retryFallbackCount"] == 1, body
assert body["generationFirst"] is True, body
assert body["generationSecond"] is False, body
assert body["settled"] is True, body
assert body["settledAgain"] is False, body
assert body["settlementTelegram"] == 1, body
assert body["settlementPreserved"] is True, body
assert body["settlementBlocked"] is True, body
assert body["settlementBlockedPreserved"] is True, body
PY
unauth=$(curl -sS -o /dev/null -w "%{http_code}" -X POST "http://127.0.0.1:${worker_port}/v1/diagnostics/runtime-fence")
test "$unauth" = "401"

echo "probe deadline"
printf '1\n' >"$slow"
d1 "UPDATE monitor_state SET last_check_at = 0" >/dev/null
started=$(python3 -c 'import time; print(time.time())')
curl -fsS --max-time 20 "http://127.0.0.1:${worker_port}/__scheduled?cron=*+*+*+*+*" >/dev/null
python3 - "$started" <<'PY'
import sys, time
# The fixture sleeps 5s. A 2s probe budget must return well before that.
assert time.time() - float(sys.argv[1]) < 4, "scheduled probe ignored the timeout"
PY

echo "workerd suite passed"
