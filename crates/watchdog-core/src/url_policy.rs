use std::fmt;

use url::Url;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct UrlPolicyError {
    pub message: &'static str,
}

impl fmt::Display for UrlPolicyError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.message)
    }
}

impl std::error::Error for UrlPolicyError {}

pub struct UrlPolicy<'a> {
    pub allow_hosts: &'a [&'a str],
    pub private_network: bool,
}

const BLOCKED_HOSTS: &[&str] = &[
    "localhost",
    "localhost.localdomain",
    "metadata.google.internal",
    "metadata.internal",
    "metadata",
];

pub fn assert_probe_url(raw: &str, policy: UrlPolicy<'_>) -> Result<Url, UrlPolicyError> {
    let url = Url::parse(raw).map_err(|_| UrlPolicyError {
        message: "The probe URL is not a valid absolute URL.",
    })?;
    if !url.username().is_empty() || url.password().is_some() {
        return Err(UrlPolicyError {
            message: "The probe URL must not include credentials.",
        });
    }
    let https = url.scheme() == "https";
    let http_private = policy.private_network && url.scheme() == "http";
    if !https && !http_private {
        return Err(UrlPolicyError {
            message: "The probe URL must use HTTPS.",
        });
    }
    let host = url
        .host_str()
        .unwrap_or("")
        .trim_end_matches('.')
        .to_ascii_lowercase();
    if host.is_empty() {
        return Err(UrlPolicyError {
            message: "The probe URL is missing a host.",
        });
    }
    if !policy
        .allow_hosts
        .iter()
        .any(|item| item.eq_ignore_ascii_case(&host))
    {
        return Err(UrlPolicyError {
            message: "The probe host is not on the configured allowlist.",
        });
    }
    // Public probes stay on 443. The private profile is an explicit opt-in
    // and may name the service port. Production configs do not set it.
    if url.port().is_some() && !policy.private_network {
        return Err(UrlPolicyError {
            message: "The probe URL uses a non-default port.",
        });
    }
    let special = BLOCKED_HOSTS.contains(&host.as_str())
        || host.ends_with(".local")
        || host.ends_with(".localhost")
        || host.ends_with(".internal")
        || host.ends_with(".home.arpa");
    if special && !policy.private_network {
        return Err(UrlPolicyError {
            message: "The probe host is not a public destination.",
        });
    }
    if is_blocked_address(&host) && !policy.private_network {
        return Err(UrlPolicyError {
            message: "The probe address is a private, link-local, or metadata destination.",
        });
    }
    if looks_like_address(&host) && parse_address(&host) == AddressClass::Invalid {
        return Err(UrlPolicyError {
            message: "The probe address could not be validated.",
        });
    }
    Ok(url)
}

pub fn assert_wss_url(raw: &str) -> Result<Url, UrlPolicyError> {
    let url = Url::parse(raw).map_err(|_| UrlPolicyError {
        message: "The relay URL is invalid.",
    })?;
    if url.scheme() != "wss" || !url.username().is_empty() || url.password().is_some() {
        return Err(UrlPolicyError {
            message: "Relay URLs must be wss and must not include credentials.",
        });
    }
    if url.port().is_some() {
        return Err(UrlPolicyError {
            message: "Relay URLs must use the default TLS port.",
        });
    }
    let host = url.host_str().unwrap_or("").to_ascii_lowercase();
    if is_blocked_address(&host)
        || BLOCKED_HOSTS.contains(&host.as_str())
        || host.ends_with(".local")
        || host.ends_with(".internal")
    {
        return Err(UrlPolicyError {
            message: "The relay host is not a public destination.",
        });
    }
    Ok(url)
}

/// Cloudflare's fetch upgrade accepts `https://`, not `wss://`.
/// Configuration stays `wss://` on port 443. `ws://` is never produced.
pub fn workers_websocket_url(wss_url: &str) -> Result<String, UrlPolicyError> {
    let mut url = assert_wss_url(wss_url)?;
    let _ = url.set_scheme("https");
    Ok(url.to_string())
}

/// Every resolved address must be acceptable. A mixed public and private
/// answer is rejected for public destinations. `allow_private` is only for a
/// monitor that was explicitly placed in the private-network profile.
pub fn resolved_addresses_allowed(addresses: &[std::net::IpAddr], allow_private: bool) -> bool {
    !addresses.is_empty()
        && addresses.iter().all(|address| {
            let rendered = address.to_string();
            if is_blocked_address(&rendered) {
                allow_private && !is_unspecified_or_multicast(address)
            } else {
                true
            }
        })
}

fn is_unspecified_or_multicast(address: &std::net::IpAddr) -> bool {
    match address {
        std::net::IpAddr::V4(ip) => ip.is_unspecified() || ip.is_multicast() || ip.is_broadcast(),
        std::net::IpAddr::V6(ip) => ip.is_unspecified() || ip.is_multicast(),
    }
}

pub fn is_blocked_address(hostname: &str) -> bool {
    !matches!(
        parse_address(hostname),
        AddressClass::Public | AddressClass::Name
    )
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum AddressClass {
    Public,
    Blocked,
    Invalid,
    Name,
}

fn looks_like_address(hostname: &str) -> bool {
    hostname.contains(':')
        || hostname
            .split('.')
            .all(|part| !part.is_empty() && part.chars().all(|ch| ch.is_ascii_digit()))
        || hostname
            .strip_prefix("0x")
            .or_else(|| hostname.strip_prefix("0X"))
            .is_some_and(|rest| rest.chars().all(|ch| ch.is_ascii_hexdigit()) && !rest.is_empty())
}

fn parse_address(hostname: &str) -> AddressClass {
    if hostname.contains(':') {
        return match parse_ipv6(hostname) {
            None => AddressClass::Invalid,
            Some(value) if ipv6_blocked(value) => AddressClass::Blocked,
            Some(_) => AddressClass::Public,
        };
    }
    let hex = hostname
        .strip_prefix("0x")
        .or_else(|| hostname.strip_prefix("0X"));
    if hex.is_some_and(|rest| !rest.is_empty() && rest.chars().all(|ch| ch.is_ascii_hexdigit()))
        || hostname.chars().all(|ch| ch.is_ascii_digit()) && !hostname.is_empty()
    {
        return AddressClass::Blocked;
    }
    match ipv4_to_u32(hostname) {
        None if hostname.split('.').count() > 1
            && hostname
                .split('.')
                .all(|part| !part.is_empty() && part.chars().all(|ch| ch.is_ascii_digit())) =>
        {
            AddressClass::Invalid
        }
        None => AddressClass::Name,
        Some(value) if private_v4(value) => AddressClass::Blocked,
        Some(_) => AddressClass::Public,
    }
}

pub fn ipv4_to_u32(hostname: &str) -> Option<u32> {
    let parts: Vec<&str> = hostname.split('.').collect();
    if parts.len() != 4 {
        return None;
    }
    let mut value: u32 = 0;
    for part in parts {
        if part.is_empty() || part.len() > 3 || !part.chars().all(|ch| ch.is_ascii_digit()) {
            return None;
        }
        if part.len() > 1 && part.starts_with('0') {
            return None;
        }
        let octet: u32 = part.parse().ok()?;
        if octet > 255 {
            return None;
        }
        value = value * 256 + octet;
    }
    Some(value)
}

fn private_v4(value: u32) -> bool {
    let a = (value >> 24) & 255;
    let b = (value >> 16) & 255;
    if a == 0 || a == 10 || a == 127 {
        return true;
    }
    if a == 100 && (64..=127).contains(&b) {
        return true;
    }
    if a == 169 && b == 254 {
        return true;
    }
    if a == 172 && (16..=31).contains(&b) {
        return true;
    }
    if a == 192 && (b == 168 || b == 0) {
        return true;
    }
    if a == 198 && (b == 18 || b == 19 || b == 51) {
        return true;
    }
    if a == 203 && b == 0 {
        return true;
    }
    a >= 224
}

fn parse_ipv6(input: &str) -> Option<u128> {
    let mut value = input.to_ascii_lowercase();
    if let Some(zone) = value.find('%') {
        value.truncate(zone);
    }
    if let Some(index) = value.rfind(':') {
        let tail = &value[index + 1..];
        if tail.contains('.') {
            let v4 = ipv4_to_u32(tail)?;
            let hi = format!("{:x}", (v4 >> 16) & 0xffff);
            let lo = format!("{:x}", v4 & 0xffff);
            value = format!("{}{hi}:{lo}", &value[..index + 1]);
        }
    }
    let halves: Vec<&str> = value.split("::").collect();
    if halves.len() > 2 {
        return None;
    }
    let left: Vec<&str> = if halves[0].is_empty() {
        Vec::new()
    } else {
        halves[0].split(':').collect()
    };
    let right: Vec<&str> = if halves.len() == 2 && !halves[1].is_empty() {
        halves[1].split(':').collect()
    } else {
        Vec::new()
    };
    if halves.len() == 1 && left.len() != 8 {
        return None;
    }
    let missing = 8isize - left.len() as isize - right.len() as isize;
    if halves.len() == 2 && missing < 1 {
        return None;
    }
    if missing < 0 {
        return None;
    }
    let mut groups = left;
    groups.extend(std::iter::repeat_n("0", missing as usize));
    groups.extend(right);
    if groups.len() != 8 {
        return None;
    }
    let mut out = 0u128;
    for group in groups {
        if group.is_empty() || group.len() > 4 || !group.chars().all(|ch| ch.is_ascii_hexdigit()) {
            return None;
        }
        let part = u128::from_str_radix(group, 16).ok()?;
        out = (out << 16) + part;
    }
    Some(out)
}

fn ipv6_blocked(value: u128) -> bool {
    if value == 0 || value == 1 {
        return true;
    }
    let first = ((value >> 112) & 0xffff) as u16;
    if first & 0xfe00 == 0xfc00 {
        return true;
    }
    if first & 0xffc0 == 0xfe80 {
        return true;
    }
    if first & 0xff00 == 0xff00 {
        return true;
    }
    if value >> 96 == 0x2001_0db8 {
        return true;
    }
    if value >> 32 == 0xffff {
        return private_v4(value as u32);
    }
    if first == 0x2002 {
        return private_v4(((value >> 80) & 0xffff_ffff) as u32);
    }
    false
}

#[cfg(test)]
mod tests {
    use super::*;

    macro_rules! allow {
        ($host:expr, $private:expr) => {
            UrlPolicy {
                allow_hosts: &[$host],
                private_network: $private,
            }
        };
    }

    #[test]
    fn accepts_allowlisted_https() {
        let url = assert_probe_url(
            "https://app.example/healthcheck",
            allow!("app.example", false),
        )
        .unwrap();
        assert_eq!(url.path(), "/healthcheck");
    }

    #[test]
    fn rejects_credentials_http_ports_and_other_hosts() {
        assert!(assert_probe_url(
            "https://user:pw@app.example/health",
            allow!("app.example", false)
        )
        .is_err());
        assert!(assert_probe_url(
            "http://app.example/healthcheck",
            allow!("app.example", false)
        )
        .is_err());
        assert!(assert_probe_url(
            "https://app.example:8443/health",
            allow!("app.example", false)
        )
        .is_err());
        assert!(assert_probe_url(
            "https://other.example/healthcheck",
            allow!("app.example", false)
        )
        .is_err());
    }

    #[test]
    fn blocks_private_and_metadata_literals() {
        assert!(is_blocked_address("127.0.0.1"));
        assert!(is_blocked_address("10.1.2.3"));
        assert!(is_blocked_address("169.254.169.254"));
        assert!(is_blocked_address("192.168.1.1"));
        assert!(is_blocked_address("2130706433"));
        assert!(is_blocked_address("::1"));
        assert!(is_blocked_address("::ffff:127.0.0.1"));
        assert!(is_blocked_address("2001:db8::1"));
        assert!(!is_blocked_address("1.1.1.1"));
        assert!(assert_probe_url("https://127.0.0.1/health", allow!("127.0.0.1", false)).is_err());
    }

    #[test]
    fn private_profile_allows_an_explicit_private_destination() {
        let url = assert_probe_url("http://10.1.2.3/health", allow!("10.1.2.3", true)).unwrap();
        assert_eq!(url.host_str(), Some("10.1.2.3"));
        assert!(
            assert_probe_url("http://10.1.2.3:8765/health", allow!("10.1.2.3", false)).is_err()
        );
        let fixture =
            assert_probe_url("http://10.1.2.3:8765/health", allow!("10.1.2.3", true)).unwrap();
        assert_eq!(fixture.port(), Some(8765));
        assert!(assert_probe_url(
            "https://app.example:8443/health",
            allow!("app.example", false)
        )
        .is_err());
    }

    #[test]
    fn mixed_resolution_is_rejected_unless_the_monitor_allows_private_addresses() {
        use std::net::{IpAddr, Ipv4Addr};
        let public = IpAddr::V4(Ipv4Addr::new(1, 1, 1, 1));
        let private = IpAddr::V4(Ipv4Addr::new(10, 1, 2, 3));
        assert!(resolved_addresses_allowed(&[public], false));
        assert!(!resolved_addresses_allowed(&[private], false));
        assert!(resolved_addresses_allowed(&[private], true));
        assert!(!resolved_addresses_allowed(&[public, private], false));
        assert!(resolved_addresses_allowed(&[public, private], true));
        assert!(!resolved_addresses_allowed(&[], true));
    }

    #[test]
    fn relays_must_be_public_wss() {
        assert_eq!(
            assert_wss_url("wss://relay.example").unwrap().scheme(),
            "wss"
        );
        assert!(assert_wss_url("ws://relay.example").is_err());
        assert!(assert_wss_url("wss://127.0.0.1").is_err());
        assert!(workers_websocket_url("wss://relay.example/")
            .unwrap()
            .starts_with("https://"));
    }
}
