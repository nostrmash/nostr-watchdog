//! Forces the pinned `cgka-engine` crate to be type-checked.
//!
//! This probe does not send messages. It exists to record whether the official
//! MLS engine builds for the native host and for `wasm32-unknown-unknown`.

/// Referencing a public constant pulls the pinned engine into the compilation.
/// `Engine<S>` additionally requires a `StorageProvider`; constructing one is a
/// separate adapter, not a compile probe.
pub fn pinned_engine_symbols() -> usize {
    cgka_engine::DEFAULT_MAX_PAST_EPOCHS
}
