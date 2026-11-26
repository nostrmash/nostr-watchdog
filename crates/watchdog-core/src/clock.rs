//! Portable clock. `std::time::SystemTime` is not a usable clock on
//! `wasm32-unknown-unknown`: it does not advance, so leases and retries would
//! collapse to zero. Native code uses the system clock. Cloudflare uses
//! `Date.now`. Tests use [`ManualClock`].

use std::sync::atomic::{AtomicI64, Ordering};

pub trait Clock {
    fn unix_ms(&self) -> i64;
}

#[derive(Clone, Copy, Debug, Default)]
pub struct SystemClock;

impl Clock for SystemClock {
    fn unix_ms(&self) -> i64 {
        system_unix_ms()
    }
}

impl Clock for &SystemClock {
    fn unix_ms(&self) -> i64 {
        system_unix_ms()
    }
}

#[derive(Debug)]
pub struct ManualClock {
    ms: AtomicI64,
}

impl ManualClock {
    pub fn new(ms: i64) -> Self {
        Self {
            ms: AtomicI64::new(ms),
        }
    }

    pub fn set(&self, ms: i64) {
        self.ms.store(ms, Ordering::Relaxed);
    }

    pub fn advance(&self, by: i64) {
        self.ms.fetch_add(by, Ordering::Relaxed);
    }
}

impl Clock for ManualClock {
    fn unix_ms(&self) -> i64 {
        self.ms.load(Ordering::Relaxed)
    }
}

impl Clock for &ManualClock {
    fn unix_ms(&self) -> i64 {
        (*self).unix_ms()
    }
}

pub fn system_unix_ms() -> i64 {
    #[cfg(all(target_arch = "wasm32", target_os = "unknown"))]
    {
        js_sys::Date::now() as i64
    }
    #[cfg(not(all(target_arch = "wasm32", target_os = "unknown")))]
    {
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|duration| duration.as_millis() as i64)
            .unwrap_or(0)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn manual_clock_is_deterministic() {
        let clock = ManualClock::new(1_000);
        assert_eq!(clock.unix_ms(), 1_000);
        clock.advance(25);
        assert_eq!(clock.unix_ms(), 1_025);
        clock.set(5);
        assert_eq!(Clock::unix_ms(&clock), 5);
    }

    #[test]
    fn system_clock_is_after_the_unix_epoch() {
        assert!(system_unix_ms() > 1_700_000_000_000);
    }
}
