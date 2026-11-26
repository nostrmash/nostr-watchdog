//! One Durable Object per project sender.
//!
//! Cryptographic mutations run inside `blockConcurrencyWhile` and commit with
//! a compare-and-swap on the account row. Relay I/O happens after that commit.

mod cas;

#[cfg(target_arch = "wasm32")]
mod durable;
#[cfg(target_arch = "wasm32")]
mod relay;

#[cfg(target_arch = "wasm32")]
pub use durable::MarmotSender;

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

    #[used]
    #[export_name = "\n\nerror: a time provider is required.\n       Use `define_time_provider!(YourProvider)` in your binary crate.\n       See: https://github.com/shadowylab/universal-time\n"]
    static WORKER_TIME_PROVIDER: &dyn universal_time::TimeProvider = &WorkerClock;
}

#[cfg(not(target_arch = "wasm32"))]
pub fn cloudflare_target_only() -> &'static str {
    "build with --target wasm32-unknown-unknown"
}
