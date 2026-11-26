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
    "Official Marmot messaging and push triggers live in marmot-app, which requires SQLCipher, OpenSSL, a filesystem, and Tokio. cgka-engine itself compiles, but its StorageProvider implementation in storage-sqlite does not build for wasm32-unknown-unknown. This build will not publish a homemade MLS ciphertext."
}
