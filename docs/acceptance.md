# WhiteNoise acceptance

This procedure is for a person with a test phone. It is not something CI can pass. Do not run it against the production sender keys or the operator's existing WhiteNoise account. Automated tests in this repository do not prove that an iPhone displayed a notification.

Status: the helper has been built and has exchanged one encrypted alert with an official `MarmotApp` runtime on a loopback relay. A physical device test has not been performed. Do not mark that test passed from the fixture result.

## Build

The helper is a second executable with its own Cargo workspace. It links official `marmot-app` at `ca52a04718628f08ed76b777df9c444594074182`. The watchdog operational database stays plaintext SQLite in a different process. `marmot-markdown` is a hard dependency of `marmot-app`. Its build script requires Odin `dev-2026-10` revision `84bc3fc`.

```bash
export ODIN="$HOME/.local/odin-dev-2026-10/odin"
"$ODIN" version
cargo build --manifest-path crates/watchdog-marmot/Cargo.toml --release
cargo build --release -p watchdog-native
```

Expected binaries:

- `crates/watchdog-marmot/target/release/watchdog-marmot`
- `target/release/nostr-watchdog`

The helper process uses an 8 MiB Tokio worker stack. MDK futures overflow the default 2 MiB worker stack.

## Identities

Use a new sender and a WhiteNoise account that is not a daily driver. Do not reuse production `SFS_BOT_NSEC` or `NOSTRMASH_BOT_NSEC`.

```bash
export MARMOT_ROOT="$PWD/data/marmot-test"
export MARMOT_SOCKET="$MARMOT_ROOT/watchdog.sock"
export MARMOT_HELPER="$PWD/crates/watchdog-marmot/target/release/watchdog-marmot"
export ENABLE_MARMOT=true
export ENABLE_NIP17=false
export ALERTS_ENABLED=true
export WATCHDOG_ENABLED=true
export SFS_BOT_NSEC="<test sender nsec>"
export ADMIN_NPUB="<test recipient hex or npub>"
export BOOTSTRAP_RELAYS="wss://relay.example"
mkdir -p "$MARMOT_ROOT"
chmod 700 "$MARMOT_ROOT"
./target/release/nostr-watchdog
```

The watchdog starts the helper, clears the helper environment, and checks health with an IPC ping. A socket file left behind by an exited helper is not treated as healthy.

## Onboarding and one message

1. The first Marmot alert imports the project sender and publishes its key package through official account setup.
2. Group creation asks MDK for an existing reusable direct conversation before creating one, and stores the group id in the helper journal.
3. Send one test alert:

```bash
curl -sS -X POST http://127.0.0.1:8787/v1/diagnostics/test-alert \
  -H "authorization: Bearer $OPERATOR_TOKEN" \
  -H "content-type: application/json" \
  -d '{"projectId":"smartflowsocial","transport":"marmot"}'
```

Expected queue state after dispatch is `relay_accepted` only when a relay accepted the group message. `accepted_pending` means MDK still owns publication. `completion_unknown` means the helper must not encrypt that alert id again. None of those states means the phone displayed a notification.

4. Open WhiteNoise and confirm the ciphertext is in the test conversation.
5. Lock the iPhone, send a second alert, and record whether a push appears. This step is pending until the device owner runs it.
6. Restart both processes and send again. The stored group id must be reused. A second conversation is a failure.

## Troubleshooting

- `marmot_helper_unavailable`: the helper did not answer a ping. Check `MARMOT_HELPER`, `MARMOT_ROOT` mode `0700`, and that Odin was present at build time.
- `marmot_helper_busy`: the helper process is alive and a command is in progress. That is not a dead process. Do not start a second helper against the same root.
- `--allow-loopback` exists only for a loopback fixture relay. The watchdog does not pass it. WhiteNoise onboarding uses public `wss` relays.
- `recipient_absent` or `sender_absent`: the group does not contain both configured accounts. Do not send.
- `membership_rejected`: an account other than the sender and recipient is in the group.
- `recipient_push_token_unavailable`: MDK has no active push-token record for a current member. The group message can still be accepted. Push was not attempted.
- `push_disposition_unknown`: a token record exists. This build does not treat message publication as evidence that a push trigger was accepted.
- `DirectConversationIndexNotReady`: MDK has not finished its conversation index. Retry after the helper stays up; do not create a second group by hand.
- Relay `AUTH` that the sender cannot satisfy is an error, not an empty inbox.

## Targets, not guarantees

These are the bars for calling the transport ready. They are not a claim about this branch.

- At least 100 controlled sends under ordinary connectivity.
- At least 99 of those observed on the device.
- Median time under 5 seconds and 95th percentile under 15 seconds, measured on the device.
- No duplicate notification for one stored publication during normal operation.
- No MLS state that fails to open after a restart.
- No manual repair between the sends after the initial join.

Foreground, background, locked-screen, and force-quit are four different results. Relay `OK` alone is not a pass. A pass still does not mean v1.0.0.
