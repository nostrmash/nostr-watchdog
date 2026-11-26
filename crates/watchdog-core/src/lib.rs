//! Platform-independent Nostr Watchdog domain logic.
#![allow(clippy::too_many_arguments, clippy::result_unit_err)]
//!
//! Check decisions, incident transitions, alert text, URL policy, and status
//! derivation live here. Cloudflare and the native binary both call this crate.
//! Nothing in this crate opens a socket or a database.

pub mod catalog;
pub mod classify;
pub mod crypto;
pub mod domain;
pub mod format;
pub mod heartbeat;
pub mod http_judge;
pub mod json_pointer;
pub mod redact;
pub mod security_feed;
pub mod semver;
pub mod settings;
pub mod status;
pub mod transition;
pub mod url_policy;

pub use domain::*;
