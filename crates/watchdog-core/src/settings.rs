use crate::domain::clamp_i64;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum TelegramMode {
    Dual,
    NostrFallback,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Settings {
    pub enabled: bool,
    pub alerts_enabled: bool,
    pub concurrency: i64,
    pub timeout_ms: i64,
    pub failure_threshold: Option<i64>,
    pub recovery_threshold: Option<i64>,
    pub relay_ttl_seconds: i64,
    pub skew_seconds: i64,
    pub max_body: i64,
    pub stale_seconds: i64,
    pub progress_seconds: i64,
    pub reminder_seconds: i64,
    pub unknown_threshold: i64,
    pub delivery_claim_ms: i64,
    pub scheduler_stale_seconds: i64,
    pub telegram_mode: TelegramMode,
    pub bootstrap: Vec<String>,
    pub github_api: String,
    pub private_network: bool,
    pub runbook_base: Option<String>,
    pub environment: String,
    pub marmot_enabled: bool,
    pub nip17_enabled: bool,
    pub sync_interval_seconds: i64,
}

pub fn load_settings(get: impl Fn(&str) -> String) -> Settings {
    let failure = get("FAILURE_THRESHOLD");
    let recovery = get("RECOVERY_THRESHOLD");
    let mode = get("TELEGRAM_CRITICAL_MODE");
    Settings {
        enabled: get("WATCHDOG_ENABLED") != "false",
        alerts_enabled: get("ALERTS_ENABLED") != "false",
        concurrency: clamp_i64(read_int(&get, "CHECK_CONCURRENCY", 4), 1, 6),
        timeout_ms: clamp_i64(read_int(&get, "CHECK_TIMEOUT_MS", 5000), 1000, 15000),
        failure_threshold: if failure.is_empty() {
            None
        } else {
            Some(clamp_i64(read_int(&get, "FAILURE_THRESHOLD", 2), 1, 10))
        },
        recovery_threshold: if recovery.is_empty() {
            None
        } else {
            Some(clamp_i64(read_int(&get, "RECOVERY_THRESHOLD", 2), 1, 10))
        },
        relay_ttl_seconds: clamp_i64(read_int(&get, "RELAY_LIST_TTL_SECONDS", 3600), 60, 86_400),
        skew_seconds: clamp_i64(read_int(&get, "HEARTBEAT_MAX_SKEW_SECONDS", 300), 30, 900),
        max_body: clamp_i64(
            read_int(&get, "HEARTBEAT_MAX_BODY_BYTES", 4096),
            256,
            16_384,
        ),
        stale_seconds: clamp_i64(read_int(&get, "HEARTBEAT_STALE_SECONDS", 180), 30, 86_400),
        progress_seconds: clamp_i64(
            read_int(&get, "HEARTBEAT_PROGRESS_SECONDS", 600),
            30,
            86_400,
        ),
        reminder_seconds: clamp_i64(read_int(&get, "CRITICAL_REMINDER_SECONDS", 0), 0, 604_800),
        unknown_threshold: clamp_i64(read_int(&get, "UNKNOWN_THRESHOLD", 5), 2, 100),
        delivery_claim_ms: clamp_i64(
            read_int(&get, "DELIVERY_CLAIM_MS", 120_000),
            30_000,
            300_000,
        ),
        scheduler_stale_seconds: clamp_i64(
            read_int(&get, "SCHEDULER_STALE_SECONDS", 180),
            90,
            3600,
        ),
        telegram_mode: if mode == "nostr_fallback" {
            TelegramMode::NostrFallback
        } else {
            TelegramMode::Dual
        },
        bootstrap: get("BOOTSTRAP_RELAYS")
            .split(',')
            .map(str::trim)
            .filter(|item| !item.is_empty())
            .map(str::to_string)
            .collect(),
        github_api: {
            let value = get("GITHUB_API_BASE");
            if value.is_empty() {
                "https://api.github.com".to_string()
            } else {
                value
            }
        },
        private_network: get("PRIVATE_NETWORK_PROFILE") == "true",
        runbook_base: https_origin(&get("RUNBOOK_BASE_URL")),
        environment: {
            let value = get("ENVIRONMENT");
            if value.is_empty() {
                "development".to_string()
            } else {
                value
            }
        },
        marmot_enabled: get("ENABLE_MARMOT") == "true",
        nip17_enabled: get("ENABLE_NIP17") != "false",
        sync_interval_seconds: clamp_i64(read_int(&get, "MARMOT_SYNC_SECONDS", 60), 30, 3600),
    }
}

fn read_int(get: &impl Fn(&str) -> String, key: &str, fallback: i64) -> i64 {
    let raw = get(key);
    if raw.is_empty() {
        return fallback;
    }
    raw.parse::<i64>().unwrap_or(fallback)
}

fn https_origin(value: &str) -> Option<String> {
    if value.is_empty() {
        return None;
    }
    let url = url::Url::parse(value).ok()?;
    if url.scheme() != "https" || !url.username().is_empty() || url.password().is_some() {
        return None;
    }
    Some(url.as_str().trim_end_matches('/').to_string())
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct TransportRoute {
    pub marmot: bool,
    pub nip17: bool,
    pub telegram: bool,
}

/// Severity routing. Marmot and NIP-17 are independent. Telegram remains critical-only.
pub fn route_for(settings: &Settings, severity: crate::domain::Severity) -> TransportRoute {
    let warning_or_worse = matches!(
        severity,
        crate::domain::Severity::Warning | crate::domain::Severity::Critical
    );
    TransportRoute {
        marmot: settings.marmot_enabled && warning_or_worse,
        nip17: settings.nip17_enabled,
        telegram: severity == crate::domain::Severity::Critical,
    }
}
