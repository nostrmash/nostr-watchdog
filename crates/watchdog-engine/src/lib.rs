//! Shared monitoring loop. Platform crates supply HTTP and notification I/O.
#![allow(clippy::too_many_arguments, clippy::result_unit_err)]

mod cycle;
mod http_api;
mod nip17;
mod probes;
mod updates;

pub use cycle::{dispatch_due, run_check_cycle, DeliveryOutcome, Notifier};
pub use nip17::{deliver_nip17, InboxFrames, RelayIo};
pub use http_api::{handle, ApiError, ApiRequest, ApiResponse};
pub use probes::{HttpClient, ProbeRequest, ProbeResponse};
pub use updates::run_update_cycle;
