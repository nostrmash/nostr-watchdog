//! Names the only `StorageProvider` implementation in the pinned MDK tree.
//! Building this crate for wasm32 is the reproducible check that the official
//! provider is not a Worker target.

pub fn provider_name() -> &'static str {
    std::any::type_name::<storage_sqlite::SqliteAccountStorage>()
}
