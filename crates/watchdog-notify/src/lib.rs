//! Notification transports.
#![allow(clippy::too_many_arguments, clippy::result_unit_err)]
//!
//! NIP-17 uses the same `nostr` revision MDK pins, via `GiftWrapBuilder`.
//! Telegram is an independent HTTPS call. Marmot message encryption and push
//! triggers stay in the official MDK; this crate records why that engine is
//! not linked into the Cloudflare build and validates only non-secret routing
//! metadata.

mod inbox;
mod nip17;
mod nip17_flow;

pub use inbox::{
    select_inbox, sign_inbox, validate_inbox_relays, verify_inbox_event, VerifiedInbox,
};
pub use nip17::{
    build_gift_wrap, event_json, open_gift_wrap, parse_event, public_key_hex, recipient_pubkey,
    Nip17Error,
};
pub use nip17_flow::{
    auth_frame, definitive_negative, discovery_relays, fold_discovery, interpret_cache,
    parse_relay_frame, partial_failure, publication_relays, verify_frames, CacheDecision,
    DiscoveryFold, InboxFrames, RelayControl, MAX_DISCOVERY_RELAYS,
};

pub const MARMOT_ENGINE_STATUS: &str = "native_mdk_not_linked";

pub fn marmot_blocker() -> &'static str {
    "Native delivery uses the watchdog-marmot helper. The Worker does not link marmot-app. The only MDK StorageProvider at this revision is storage-sqlite on rusqlite 0.40 with bundled-sqlcipher-vendored-openssl. Push-trigger publication inside submit_text is best-effort and its relay result is not returned, so a published message stays push_disposition_unknown until reconciliation reaches an explicit terminal state."
}
