//! One disposable kind 0 published to the public WhiteNoise EU relay.
//!
//! The key is generated in this process and is not a project identity.
//! The test is opt-in because it writes one small profile event to a public relay.

use std::process::Command;

use nostr::event::FinalizeEvent;
use nostr::prelude::{EventBuilder, Keys, Kind, Tag, Timestamp};

#[tokio::test]
#[ignore = "publishes one disposable profile to wss://relay.eu.whitenoise.chat"]
async fn whitenoise_eu_accepts_one_disposable_profile() {
    let keys = Keys::generate();
    let event = EventBuilder::new(
        Kind::Metadata,
        r#"{"name":"marmot-worker-probe","about":"disposable interoperability probe"}"#,
    )
    .custom_created_at(Timestamp::now())
    .finalize(&keys)
    .expect("sign disposable profile");
    event.verify().expect("profile verifies");
    let inbox = EventBuilder::new(Kind::Custom(10050), "")
        .tags([Tag::custom(
            "relay",
            ["wss://relay.eu.whitenoise.chat".to_owned()],
        )])
        .custom_created_at(Timestamp::now())
        .finalize(&keys)
        .expect("sign disposable inbox list");
    inbox.verify().expect("inbox list verifies");
    let pubkey = event.pubkey.to_string();
    let payload = serde_json::to_string(&serde_json::json!([event, inbox])).expect("event json");
    let script = r#"
import WebSocket from "ws";
const events = JSON.parse(process.env.PROBE_EVENT);
const url = "wss://relay.eu.whitenoise.chat";
const ws = new WebSocket(url);
const pending = new Set(events.map((event) => event.id));
const timer = setTimeout(() => { console.log("timeout " + [...pending].join(",")); process.exit(2); }, 8000);
ws.on("open", () => {
  for (const event of events) ws.send(JSON.stringify(["EVENT", event]));
});
ws.on("message", (data) => {
  const frame = JSON.parse(data.toString());
  if (frame[0] !== "OK") return;
  console.log(JSON.stringify({ id: frame[1], accepted: frame[2] === true, message: frame[3] || "" }));
  if (frame[2] !== true) process.exit(3);
  pending.delete(frame[1]);
  if (pending.size === 0) {
    clearTimeout(timer);
    ws.close();
    process.exit(0);
  }
});
ws.on("error", (error) => { console.log(String(error)); process.exit(1); });
"#;
    let worker = std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../worker");
    let output = Command::new("node")
        .current_dir(&worker)
        .args(["--input-type=module", "-e", script])
        .env("PROBE_EVENT", payload)
        .output()
        .expect("node websocket");
    let text = format!(
        "{}{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    assert!(
        output.status.success(),
        "pubkey={pubkey} status={:?} {text}",
        output.status.code()
    );
    assert!(text.matches("\"accepted\":true").count() == 2, "{text}");
}
