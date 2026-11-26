//! Checks for relays this helper is configured to use.
//!
//! Official MDK classifies a relay URL before dialing. A domain is accepted
//! without a DNS lookup, so a name that later resolves to a private address
//! is not blocked by the pinned relay plane. This module checks the relays
//! the operator configured. It does not sit on MDK's dial path, and it does
//! not see group relays or notification-server hints discovered later.
//! Resolving a name and then letting MDK resolve it again is not a pin: the
//! address can change between the two lookups.

use std::net::ToSocketAddrs;
use std::time::Duration;

use url::Url;
use watchdog_core::url_policy::resolved_addresses_allowed;

pub fn validate_configured_relays(relays: &[String], allow_loopback: bool) -> Result<(), String> {
    if relays.is_empty() {
        return Err("relay_missing".to_string());
    }
    for relay in relays {
        validate_one(relay, allow_loopback)?;
    }
    Ok(())
}

fn validate_one(raw: &str, allow_loopback: bool) -> Result<(), String> {
    let url = Url::parse(raw.trim()).map_err(|_| "relay_invalid".to_string())?;
    if !url.username().is_empty() || url.password().is_some() {
        return Err("relay_invalid".to_string());
    }
    let host = url
        .host_str()
        .unwrap_or("")
        .trim_end_matches('.')
        .to_ascii_lowercase();
    if host.is_empty()
        || host == "metadata.google.internal"
        || host == "metadata.internal"
        || host == "metadata"
        || host.ends_with(".local")
        || host.ends_with(".localhost")
        || host.ends_with(".internal")
        || host.ends_with(".home.arpa")
    {
        return Err("relay_destination_blocked".to_string());
    }
    let loopback = is_loopback_host(&host);
    match url.scheme() {
        "ws" if allow_loopback && loopback => {}
        "wss" if !loopback => {
            if url.port().is_some_and(|port| port != 443) {
                return Err("relay_invalid".to_string());
            }
        }
        _ => return Err("relay_invalid".to_string()),
    }
    if looks_like_ip(&host) && !resolved_addresses_allowed(&parse_literal(&host), allow_loopback) {
        return Err("relay_destination_blocked".to_string());
    }
    if !loopback {
        // One lookup of the configured name. MDK looks it up again when it
        // dials, so this is not a rebinding defense for that connection.
        resolve_public(&host, url.port().unwrap_or(443))?;
    }
    Ok(())
}

fn is_loopback_host(host: &str) -> bool {
    host == "localhost" || host == "127.0.0.1" || host == "::1"
}

fn looks_like_ip(host: &str) -> bool {
    host.parse::<std::net::IpAddr>().is_ok()
}

fn parse_literal(host: &str) -> Vec<std::net::IpAddr> {
    host.parse().into_iter().collect()
}

fn resolve_public(host: &str, port: u16) -> Result<(), String> {
    let host = host.to_string();
    let (tx, rx) = std::sync::mpsc::channel();
    std::thread::spawn(move || {
        let _ = tx.send((host.as_str(), port).to_socket_addrs());
    });
    let addresses = rx
        .recv_timeout(Duration::from_secs(5))
        .map_err(|_| "relay_dns_failed".to_string())?
        .map_err(|_| "relay_dns_failed".to_string())?;
    let ips: Vec<_> = addresses.map(|address| address.ip()).collect();
    if resolved_addresses_allowed(&ips, false) {
        Ok(())
    } else {
        Err("relay_destination_blocked".to_string())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn loopback_is_rejected_unless_the_fixture_flag_is_set() {
        assert!(validate_one("ws://127.0.0.1:1", false).is_err());
        assert!(validate_one("ws://127.0.0.1:9", true).is_ok());
        assert!(validate_one("ws://10.0.0.1:9", true).is_err());
        assert!(validate_one("wss://user:pass@relay.example", false).is_err());
        assert!(validate_one("https://relay.example", false).is_err());
        assert!(validate_one("wss://169.254.169.254", false).is_err());
    }
}
