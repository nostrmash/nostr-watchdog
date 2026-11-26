use std::net::SocketAddr;
use std::time::Duration;

use watchdog_core::url_policy::resolved_addresses_allowed;

/// Resolve `host` and return one address that passed the destination policy.
/// The caller connects to this address while TLS still uses the original name.
pub async fn resolve_pinned(
    host: &str,
    port: u16,
    allow_private: bool,
) -> Result<SocketAddr, String> {
    let mut addresses = Vec::new();
    let lookup = tokio::time::timeout(Duration::from_secs(5), tokio::net::lookup_host((host, port)))
        .await
        .map_err(|_| "dns_timeout".to_string())?
        .map_err(|_| "dns_failed".to_string())?;
    for address in lookup {
        addresses.push(address.ip());
    }
    if !resolved_addresses_allowed(&addresses, allow_private) {
        return Err("destination_blocked".to_string());
    }
    let ip = addresses
        .into_iter()
        .next()
        .ok_or_else(|| "destination_blocked".to_string())?;
    Ok(SocketAddr::new(ip, port))
}
