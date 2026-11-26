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

// nostr uses universal-time. On wasm32-unknown-unknown the cdylib has to
// provide the clock; Date.now is the Workers clock.
#[cfg(all(target_arch = "wasm32", target_os = "unknown"))]
mod wasm_time {
    use core::time::Duration;

    use universal_time::{Instant, MonotonicClock, SystemTime, WallClock};

    struct WorkerClock;

    impl WallClock for WorkerClock {
        fn system_time(&self) -> SystemTime {
            SystemTime::from_unix_duration(Duration::from_millis(js_sys::Date::now() as u64))
        }
    }

    impl MonotonicClock for WorkerClock {
        fn instant(&self) -> Instant {
            Instant::from_ticks(Duration::from_millis(js_sys::Date::now() as u64))
        }
    }

    // The link name is the diagnostic string universal-time looks up. `used`
    // keeps the static in the cdylib when this crate never calls it directly.
    #[used]
    #[export_name = "\n\nerror: a time provider is required.\n       Use `define_time_provider!(YourProvider)` in your binary crate.\n       See: https://github.com/shadowylab/universal-time\n"]
    static WORKER_TIME_PROVIDER: &dyn universal_time::TimeProvider = &WorkerClock;
}

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
