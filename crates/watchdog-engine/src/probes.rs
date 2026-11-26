use std::collections::HashMap;
use std::time::Duration;

use async_trait::async_trait;
use serde_json::Value;
use watchdog_core::classify::{
    classify_alby, classify_btcpay, parse_alarms, parse_alby_info, parse_node_ready,
    parse_server_info, parse_synchronized,
};
use watchdog_core::domain::{
    misconfigured, network_failure, unknown_result, CheckResult, HttpCheckSpec, MonitorDefinition,
    MonitorStatus,
};
use watchdog_core::heartbeat::{evaluate_heartbeat, HeartbeatRow};
use watchdog_core::http_judge::{judge_http, HttpObservation};
use watchdog_core::redact::safe_version;
use watchdog_core::url_policy::{assert_probe_url, UrlPolicy};
use watchdog_store::HeartbeatStored;

#[async_trait]
pub trait HttpClient: Send + Sync {
    async fn send(&self, request: ProbeRequest) -> Result<ProbeResponse, String>;
}

#[derive(Clone, Debug)]
pub struct ProbeRequest {
    pub method: &'static str,
    pub url: String,
    pub headers: HashMap<String, String>,
    pub timeout: Duration,
    pub max_bytes: usize,
    /// Configured monitors may use the private-network profile. Discovered
    /// relays never set this.
    pub allow_private: bool,
}

#[derive(Clone, Debug)]
pub struct ProbeResponse {
    pub status: u16,
    pub headers: HashMap<String, String>,
    pub body: Vec<u8>,
    pub too_large: bool,
}

pub async fn probe_monitor(
    monitor: &MonitorDefinition,
    get: &impl Fn(&str) -> String,
    private_network: bool,
    timeout_ms: i64,
    now: i64,
    stale_seconds: i64,
    progress_seconds: i64,
    heartbeat: Option<&HeartbeatStored>,
    http: &dyn HttpClient,
) -> CheckResult {
    match monitor.kind {
        watchdog_core::CheckKind::HttpJson => {
            let Some(spec) = &monitor.http else {
                return unknown_result("This monitor kind is not implemented.", "schema", None);
            };
            if let Some(secret) = spec.bearer_secret {
                if get(secret).is_empty() {
                    return misconfigured("The health probe token is not configured.", None);
                }
            }
            run_http(
                spec,
                &get(spec.url_var),
                private_network,
                timeout_ms,
                &get,
                http,
            )
            .await
        }
        watchdog_core::CheckKind::SignedHeartbeat => evaluate_heartbeat(
            heartbeat
                .map(|row| HeartbeatRow {
                    received_at: row.received_at,
                    progress_token: row.progress_token.clone(),
                    progress_changed_at: row.progress_changed_at,
                    idle: row.idle,
                    loop_at: row.loop_at,
                })
                .as_ref(),
            now,
            stale_seconds,
            progress_seconds,
        ),
        watchdog_core::CheckKind::AlbyHub => {
            run_alby(
                &get("ALBY_BASE_URL"),
                &get("ALBY_ROUTING_PROFILE"),
                &get("ALBY_HUB_NAME"),
                &get("ALBY_HUB_REGION"),
                &get("ALBY_AUTH_TOKEN"),
                private_network,
                timeout_ms,
                http,
            )
            .await
        }
        watchdog_core::CheckKind::Btcpay => {
            run_btcpay(
                &get("BTCPAY_BASE_URL"),
                &get("BTCPAY_API_KEY"),
                private_network,
                timeout_ms,
                http,
            )
            .await
        }
    }
}

async fn run_http(
    spec: &HttpCheckSpec,
    url: &str,
    private_network: bool,
    timeout_ms: i64,
    get: &impl Fn(&str) -> String,
    http: &dyn HttpClient,
) -> CheckResult {
    if url.is_empty() {
        return misconfigured("The readiness URL is not configured.", None);
    }
    let host = url::Url::parse(url).map(|item| item.host_str().unwrap_or("").to_string());
    let Ok(host) = host else {
        return misconfigured("The readiness URL failed the outbound policy.", None);
    };
    let Ok(target) = assert_probe_url(
        url,
        UrlPolicy {
            allow_hosts: &[host.as_str()],
            private_network,
        },
    ) else {
        return misconfigured("The readiness URL failed the outbound policy.", None);
    };
    if target.path() != spec.expected_path {
        return misconfigured(
            format!("The readiness URL must use {}.", spec.expected_path),
            None,
        );
    }
    let bearer = spec.bearer_secret.map(get).unwrap_or_default();
    fetch_checked(spec, target, private_network, timeout_ms, &bearer, http, 0).await
}

async fn fetch_checked(
    spec: &HttpCheckSpec,
    target: url::Url,
    private_network: bool,
    timeout_ms: i64,
    bearer: &str,
    http: &dyn HttpClient,
    hop: u8,
) -> CheckResult {
    let started = std::time::Instant::now();
    let mut headers = HashMap::from([
        ("accept".to_string(), "application/json".to_string()),
        ("cache-control".to_string(), "no-cache".to_string()),
    ]);
    if !bearer.is_empty() {
        headers.insert("authorization".to_string(), format!("Bearer {bearer}"));
    }
    let response = match http
        .send(ProbeRequest {
            method: "GET",
            url: target.to_string(),
            headers,
            timeout: Duration::from_millis(timeout_ms as u64),
            max_bytes: spec.max_bytes,
            allow_private: private_network,
        })
        .await
    {
        Ok(response) => response,
        Err(error) => return network_failure(&error, "", started.elapsed().as_millis() as i64),
    };
    let latency = started.elapsed().as_millis() as i64;
    if (300..400).contains(&response.status) {
        if !bearer.is_empty() {
            return misconfigured(
                "The readiness endpoint redirected. The authenticated probe did not follow it.",
                Some(latency),
            );
        }
        if hop >= 2 {
            return misconfigured(
                "The readiness endpoint redirected too many times.",
                Some(latency),
            );
        }
        let Some(location) = response.headers.get("location") else {
            return misconfigured(
                "The readiness endpoint returned a redirect without a location.",
                Some(latency),
            );
        };
        let Ok(next) = target.join(location) else {
            return misconfigured(
                "The readiness endpoint redirected outside its allowlist.",
                Some(latency),
            );
        };
        let host = target.host_str().unwrap_or("");
        let Ok(next) = assert_probe_url(
            next.as_str(),
            UrlPolicy {
                allow_hosts: &[host],
                private_network,
            },
        ) else {
            return misconfigured(
                "The readiness endpoint redirected outside its allowlist.",
                Some(latency),
            );
        };
        return Box::pin(fetch_checked(
            spec,
            next,
            private_network,
            timeout_ms,
            bearer,
            http,
            hop + 1,
        ))
        .await;
    }
    if response.too_large {
        return judge_http(
            spec,
            &HttpObservation {
                status: response.status,
                body: None,
                too_large: true,
                not_json: false,
                latency_ms: latency,
            },
        );
    }
    let text = String::from_utf8_lossy(&response.body);
    let (body, not_json) = if text.trim().is_empty() {
        (None, false)
    } else {
        match serde_json::from_str::<Value>(&text) {
            Ok(value) => (Some(value), false),
            Err(_) => (None, true),
        }
    };
    judge_http(
        spec,
        &HttpObservation {
            status: response.status,
            body,
            too_large: false,
            not_json,
            latency_ms: latency,
        },
    )
}

async fn run_alby(
    base_url: &str,
    routing_profile: &str,
    hub_name: &str,
    hub_region: &str,
    token: &str,
    private_network: bool,
    timeout_ms: i64,
    http: &dyn HttpClient,
) -> CheckResult {
    if base_url.is_empty() {
        return misconfigured("The Alby Hub base URL is not configured.", None);
    }
    let Ok(parsed) = url::Url::parse(base_url) else {
        return misconfigured("The Alby Hub URL failed the outbound policy.", None);
    };
    let host = parsed.host_str().unwrap_or("").to_string();
    let Ok(target) = assert_probe_url(
        base_url,
        UrlPolicy {
            allow_hosts: &[host.as_str()],
            private_network,
        },
    ) else {
        return misconfigured("The Alby Hub URL failed the outbound policy.", None);
    };
    if host == "my.albyhub.com" && routing_profile != "alby_cloud" {
        return misconfigured(
            "The shared Alby Cloud origin requires routing profile alby_cloud.",
            None,
        );
    }
    if routing_profile == "alby_cloud" && hub_name.is_empty() {
        return misconfigured("Alby Cloud routing requires ALBY_HUB_NAME.", None);
    }
    if !routing_profile.is_empty()
        && routing_profile != "self_hosted"
        && routing_profile != "alby_cloud"
    {
        return misconfigured(
            "ALBY_ROUTING_PROFILE must be self_hosted or alby_cloud.",
            None,
        );
    }
    let mut headers = HashMap::from([("accept".to_string(), "application/json".to_string())]);
    if routing_profile == "alby_cloud" {
        headers.insert("AlbyHub-Name".to_string(), hub_name.to_string());
        if !hub_region.is_empty() {
            headers.insert("AlbyHub-Region".to_string(), hub_region.to_string());
        }
    }
    if !token.is_empty() {
        headers.insert("authorization".to_string(), format!("Bearer {token}"));
    }
    let info_url = target.join("/api/info").unwrap_or(target.clone());
    let started = std::time::Instant::now();
    let info = match vendor_get(
        http,
        info_url.as_str(),
        headers.clone(),
        timeout_ms,
        32_768,
        private_network,
    )
    .await
    {
        Ok(response) => response,
        Err(error) => return vendor_error(&error, started.elapsed().as_millis() as i64),
    };
    let latency = started.elapsed().as_millis() as i64;
    if matches!(info.status, 401 | 403) {
        return misconfigured("The Alby Hub rejected the read-only token.", Some(latency));
    }
    let info_json = parse_body(&info);
    if info.too_large || info_json.is_err() || !(200..300).contains(&info.status) {
        if !(200..300).contains(&info.status) && info_json.is_ok() {
            return watchdog_core::check_result(
                MonitorStatus::Down,
                Some("http_status"),
                "The Alby Hub info endpoint failed.",
                Some(latency),
                None,
            );
        }
        return unknown_result(
            "The Alby Hub info response did not match the expected schema.",
            "schema",
            Some(latency),
        );
    }
    let info_value = info_json.unwrap_or(Value::Null);
    let Some(parsed_info) = parse_alby_info(&info_value) else {
        return unknown_result(
            "The Alby Hub info response did not match the expected schema.",
            "schema",
            Some(latency),
        );
    };
    let version = safe_version(Some(&parsed_info.version));
    if token.is_empty() {
        let mut result = misconfigured(
            "The Alby Hub read-only token is not configured, so node health was not checked.",
            Some(latency),
        );
        result.observed_version = version;
        return result;
    }
    let health_url = target.join("/api/health").unwrap_or(target.clone());
    let node_url = target.join("/api/node/status").unwrap_or(target.clone());
    let health = vendor_get(
        http,
        health_url.as_str(),
        headers.clone(),
        timeout_ms,
        16_384,
        private_network,
    )
    .await;
    let node = vendor_get(
        http,
        node_url.as_str(),
        headers,
        timeout_ms,
        16_384,
        private_network,
    )
    .await;
    let done = started.elapsed().as_millis() as i64;
    let (Ok(health), Ok(node)) = (health, node) else {
        return vendor_error("network", done);
    };
    if matches!(health.status, 401 | 403) || matches!(node.status, 401 | 403) {
        let mut result = misconfigured(
            "The Alby Hub read-only token was rejected or has expired.",
            Some(done),
        );
        result.error_class = Some("unauthorized".to_string());
        result.observed_version = version;
        return result;
    }
    let (Ok(health_body), Ok(node_body)) = (parse_body(&health), parse_body(&node)) else {
        return unknown_result(
            "The Alby Hub health response did not match the expected schema.",
            "schema",
            Some(done),
        );
    };
    if !(200..300).contains(&health.status) || !(200..300).contains(&node.status) {
        return watchdog_core::check_result(
            MonitorStatus::Degraded,
            Some("http_status"),
            "The Alby Hub API responded, but the health or node status endpoint failed.",
            Some(done),
            version,
        );
    }
    let Ok(alarms) = parse_alarms(&health_body) else {
        return unknown_result(
            "The Alby Hub health response did not match the expected schema.",
            "schema",
            Some(done),
        );
    };
    let Ok(node_ready) = parse_node_ready(&node_body) else {
        return unknown_result(
            "The Alby Hub node status response did not match the expected schema.",
            "schema",
            Some(done),
        );
    };
    classify_alby(&parsed_info, &alarms, node_ready, done)
}

async fn run_btcpay(
    base_url: &str,
    api_key: &str,
    private_network: bool,
    timeout_ms: i64,
    http: &dyn HttpClient,
) -> CheckResult {
    if base_url.is_empty() {
        return misconfigured("The BTCPay base URL is not configured.", None);
    }
    let Ok(parsed) = url::Url::parse(base_url) else {
        return misconfigured("The BTCPay URL failed the outbound policy.", None);
    };
    let host = parsed.host_str().unwrap_or("").to_string();
    let Ok(target) = assert_probe_url(
        base_url,
        UrlPolicy {
            allow_hosts: &[host.as_str()],
            private_network,
        },
    ) else {
        return misconfigured("The BTCPay URL failed the outbound policy.", None);
    };
    let started = std::time::Instant::now();
    let health_url = target.join("/api/v1/health").unwrap_or(target.clone());
    let health = match vendor_get(
        http,
        health_url.as_str(),
        json_headers(None),
        timeout_ms,
        16_384,
        private_network,
    )
    .await
    {
        Ok(response) => response,
        Err(error) => return vendor_error(&error, started.elapsed().as_millis() as i64),
    };
    let health_latency = started.elapsed().as_millis() as i64;
    if matches!(health.status, 401 | 403) {
        return misconfigured(
            "The BTCPay health endpoint rejected the request.",
            Some(health_latency),
        );
    }
    let Ok(health_body) = parse_body(&health) else {
        return unknown_result(
            "The BTCPay health response did not match the expected schema.",
            "schema",
            Some(health_latency),
        );
    };
    if !(200..300).contains(&health.status) {
        return watchdog_core::check_result(
            MonitorStatus::Down,
            Some("http_status"),
            "The BTCPay health endpoint failed.",
            Some(health_latency),
            None,
        );
    }
    let Ok(synchronized) = parse_synchronized(&health_body) else {
        return unknown_result(
            "The BTCPay health response did not match the expected schema.",
            "schema",
            Some(health_latency),
        );
    };
    if api_key.is_empty() {
        return watchdog_core::check_result(
            MonitorStatus::Degraded,
            Some(if synchronized {
                "coverage_incomplete"
            } else {
                "unsynchronized"
            }),
            if synchronized {
                "BTCPay public health passed. Version, sync detail, and payment-processor status were not checked because no read-only key is configured."
            } else {
                "BTCPay public health says the server is not synchronized. Server info was not checked because no read-only key is configured."
            },
            Some(health_latency),
            None,
        );
    }
    let info_url = target.join("/api/v1/server/info").unwrap_or(target);
    let mut headers = json_headers(None);
    headers.insert("authorization".to_string(), format!("token {api_key}"));
    let info = match vendor_get(
        http,
        info_url.as_str(),
        headers,
        timeout_ms,
        32_768,
        private_network,
    )
    .await
    {
        Ok(response) => response,
        Err(error) => return vendor_error(&error, started.elapsed().as_millis() as i64),
    };
    let latency = started.elapsed().as_millis() as i64;
    if matches!(info.status, 401 | 403) {
        return watchdog_core::check_result(
            MonitorStatus::Misconfigured,
            Some("unauthorized"),
            if synchronized {
                "BTCPay is up, but the server info key was rejected or lacks access."
            } else {
                "BTCPay is up but not synchronized, and the server info key was rejected."
            },
            Some(latency),
            None,
        );
    }
    let Ok(info_body) = parse_body(&info) else {
        return unknown_result(
            "The BTCPay server info response did not match the expected schema.",
            "schema",
            Some(latency),
        );
    };
    if !(200..300).contains(&info.status) {
        return unknown_result(
            "The BTCPay server info response did not match the expected schema.",
            "schema",
            Some(latency),
        );
    }
    let Some(info) = parse_server_info(&info_body) else {
        return unknown_result(
            "The BTCPay server info response did not match the expected schema.",
            "schema",
            Some(latency),
        );
    };
    classify_btcpay(synchronized, &info, latency)
}

fn json_headers(extra: Option<(&str, String)>) -> HashMap<String, String> {
    let mut headers = HashMap::from([("accept".to_string(), "application/json".to_string())]);
    if let Some((key, value)) = extra {
        headers.insert(key.to_string(), value);
    }
    headers
}

async fn vendor_get(
    http: &dyn HttpClient,
    url: &str,
    headers: HashMap<String, String>,
    timeout_ms: i64,
    max_bytes: usize,
    allow_private: bool,
) -> Result<ProbeResponse, String> {
    let response = http
        .send(ProbeRequest {
            method: "GET",
            url: url.to_string(),
            headers,
            timeout: Duration::from_millis(timeout_ms as u64),
            max_bytes,
            allow_private,
        })
        .await?;
    if (300..400).contains(&response.status) {
        return Err("vendor redirect refused".to_string());
    }
    Ok(response)
}

fn parse_body(response: &ProbeResponse) -> Result<Value, ()> {
    if response.too_large || response.body.is_empty() {
        return Err(());
    }
    serde_json::from_slice(&response.body).map_err(|_| ())
}

fn vendor_error(error: &str, latency_ms: i64) -> CheckResult {
    if error.contains("redirect") {
        misconfigured(
            "The vendor endpoint redirected. The probe did not follow it.",
            Some(latency_ms),
        )
    } else {
        network_failure(error, "", latency_ms)
    }
}
