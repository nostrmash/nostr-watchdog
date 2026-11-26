//! Cloudflare entrypoint.
#![cfg_attr(target_arch = "wasm32", allow(unused_must_use))]
//!
//! Monitoring uses the shared engine and a D1 store. Marmot sessions stay on
//! the native MDK crate; this Worker does not invent MLS ciphertext.

#[cfg(target_arch = "wasm32")]
mod d1_store;
#[cfg(target_arch = "wasm32")]
mod runtime;

#[cfg(target_arch = "wasm32")]
use worker::*;

#[cfg(target_arch = "wasm32")]
#[event(fetch)]
pub async fn fetch(req: Request, env: Env, _ctx: Context) -> Result<Response> {
    runtime::fetch(req, env).await
}

#[cfg(target_arch = "wasm32")]
#[event(scheduled)]
pub async fn scheduled(event: ScheduledEvent, env: Env, _ctx: ScheduleContext) -> Result<()> {
    runtime::scheduled(event, env).await
}

#[cfg(not(target_arch = "wasm32"))]
pub fn cloudflare_target_only() -> &'static str {
    "build with --target wasm32-unknown-unknown"
}
