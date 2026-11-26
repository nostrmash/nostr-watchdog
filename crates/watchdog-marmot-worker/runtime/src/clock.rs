//! Portable clock for native tests and `wasm32-unknown-unknown`.
//!
//! `std::time::SystemTime` does not advance on the Workers target, so leases,
//! Nostr timestamps, and Marmot convergence would stall. Native code uses the
//! system clock. Workers use `Date.now`, the same source as the watchdog Worker.

use std::sync::Arc;
use std::time::Duration;

use cgka_engine::{ConvergenceClock, ConvergenceTime};
use cgka_traits::maintenance::{MaintenanceRandom, MonotonicClock, WallClock};
use cgka_traits::Timestamp;

pub fn unix_ms() -> u64 {
    #[cfg(all(target_arch = "wasm32", target_os = "unknown"))]
    {
        js_sys::Date::now() as u64
    }
    #[cfg(not(all(target_arch = "wasm32", target_os = "unknown")))]
    {
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|duration| duration.as_millis() as u64)
            .unwrap_or(0)
    }
}

pub fn unix_secs() -> u64 {
    unix_ms() / 1000
}

#[derive(Clone, Copy, Debug, Default)]
pub struct PortableWallClock;

impl WallClock for PortableWallClock {
    fn now(&self) -> Timestamp {
        Timestamp(unix_secs())
    }

    fn now_ms(&self) -> u64 {
        unix_ms()
    }
}

#[derive(Debug)]
pub struct PortableMonotonic {
    origin_ms: u64,
}

impl PortableMonotonic {
    pub fn new() -> Self {
        Self {
            origin_ms: unix_ms(),
        }
    }
}

impl MonotonicClock for PortableMonotonic {
    fn elapsed(&self) -> Duration {
        Duration::from_millis(unix_ms().saturating_sub(self.origin_ms))
    }
}

#[derive(Debug)]
pub struct PortableConvergence {
    origin_ms: u64,
}

impl PortableConvergence {
    pub fn new() -> Self {
        Self {
            origin_ms: unix_ms(),
        }
    }
}

impl ConvergenceClock for PortableConvergence {
    fn now(&self) -> ConvergenceTime {
        let wall_ms = unix_ms();
        ConvergenceTime {
            monotonic_ms: wall_ms.saturating_sub(self.origin_ms),
            wall_ms,
        }
    }
}

#[derive(Debug, Default)]
pub struct PortableRandom;

impl MaintenanceRandom for PortableRandom {
    fn next_u64(&self) -> u64 {
        let mut bytes = [0u8; 8];
        let _ = getrandom::getrandom(&mut bytes);
        u64::from_le_bytes(bytes)
    }
}

pub fn engine_clocks() -> (
    Arc<PortableWallClock>,
    Arc<PortableRandom>,
    Arc<PortableMonotonic>,
    Arc<PortableConvergence>,
) {
    (
        Arc::new(PortableWallClock),
        Arc::new(PortableRandom),
        Arc::new(PortableMonotonic::new()),
        Arc::new(PortableConvergence::new()),
    )
}
