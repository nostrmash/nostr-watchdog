//! Cloudflare entrypoint.
#![cfg_attr(target_arch = "wasm32", allow(unused_must_use))]
//!
//! The shared monitoring engine is not linked here. The native SQLite store
//! uses rusqlite, which does not compile to `wasm32-unknown-unknown`, and the
//! official MDK session store needs SQLCipher. This Worker proves the
//! workers-rs fetch and scheduled entrypoints on the staging name. It does not
//! publish alerts and it does not touch the production D1 database.

#[cfg(target_arch = "wasm32")]
use worker::*;

#[cfg(target_arch = "wasm32")]
#[event(fetch)]
pub async fn fetch(req: Request, _env: Env, _ctx: Context) -> Result<Response> {
    let path = req.path();
    if req.method() == Method::Get && path == "/healthz" {
        return Response::from_json(&serde_json::json!({
            "status": "ok",
            "service": "nostr-watchdog",
            "runtime": "cloudflare",
            "marmot": "blocked",
            "blocker": "cgka-engine compiles for wasm32-unknown-unknown. marmot-app and storage-sqlite require SQLCipher, OpenSSL, and Tokio. This staging Worker does not publish alerts."
        }));
    }
    if req.method() == Method::Get && path == "/v1/diagnostics/marmot" {
        return Response::from_json(&serde_json::json!({
            "engineStatus": "wasm_storage_unsupported",
            "pushTokenAvailable": false,
            "note": "Relay acceptance is not phone delivery. No push token is stored or returned."
        }));
    }
    Response::error("not_found", 404)
}

#[cfg(target_arch = "wasm32")]
#[event(scheduled)]
pub async fn scheduled(_event: ScheduledEvent, _env: Env, _ctx: ScheduleContext) -> Result<()> {
    console_log!(
        "scheduled tick skipped: durable Marmot state is not available in this wasm build"
    );
    Ok(())
}

#[cfg(not(target_arch = "wasm32"))]
pub fn cloudflare_target_only() -> &'static str {
    "build with --target wasm32-unknown-unknown"
}
