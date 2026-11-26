//! One Durable Object per project sender.
//!
//! The object loads the sealed MDK snapshot, runs one official engine
//! operation, and writes the new snapshot before anything is published.
//! Application errors stay inside `Ok` so the runtime does not reset the object.

#[cfg(target_arch = "wasm32")]
mod durable;

#[cfg(target_arch = "wasm32")]
pub use durable::MarmotSender;
