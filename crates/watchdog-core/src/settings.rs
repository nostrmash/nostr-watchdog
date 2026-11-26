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
    /// Emergency stops. These override project and severity routing.
    pub emergency_disable_nip17: bool,
    pub emergency_disable_marmot: bool,
    pub emergency_disable_telegram: bool,
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
        emergency_disable_nip17: truthy(&get("EMERGENCY_DISABLE_NIP17")),
        emergency_disable_marmot: truthy(&get("EMERGENCY_DISABLE_MARMOT")),
        emergency_disable_telegram: truthy(&get("EMERGENCY_DISABLE_TELEGRAM")),
    }
}

fn truthy(value: &str) -> bool {
    matches!(
        value.trim().to_ascii_lowercase().as_str(),
        "true" | "1" | "yes" | "on"
    )
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

/// Severity routing. Global flags are defaults. `NOTIFY_<PROJECT>_<TRANSPORT>`
/// overrides one project. An empty override keeps the global default. `false`
/// disables that transport. `true` allows every severity. A comma-separated
/// list allows only those severities. `EMERGENCY_DISABLE_*` stops a transport
/// even when a project override asks for it. Queued rows are finalized on the
/// next dispatch instead of being retried forever.
/// Configuration names read by the engine, the catalog, and the runtimes.
/// Both the Worker and the native process load this list. Production names
/// stay as they are on the TypeScript Worker. The two historical Worker typos
/// are accepted only as aliases of the canonical names.
pub const CONFIG_KEYS: &[&str] = &[
    "WATCHDOG_ENABLED",
    "ALERTS_ENABLED",
    "ENABLE_MARMOT",
    "ENABLE_NIP17",
    "CHECK_CONCURRENCY",
    "CHECK_TIMEOUT_MS",
    "FAILURE_THRESHOLD",
    "RECOVERY_THRESHOLD",
    "RELAY_LIST_TTL_SECONDS",
    "HEARTBEAT_MAX_SKEW_SECONDS",
    "HEARTBEAT_MAX_BODY_BYTES",
    "HEARTBEAT_STALE_SECONDS",
    "HEARTBEAT_PROGRESS_SECONDS",
    "CRITICAL_REMINDER_SECONDS",
    "UNKNOWN_THRESHOLD",
    "DELIVERY_CLAIM_MS",
    "SCHEDULER_STALE_SECONDS",
    "TELEGRAM_CRITICAL_MODE",
    "BOOTSTRAP_RELAYS",
    "GITHUB_API_BASE",
    "GITHUB_TOKEN",
    "PRIVATE_NETWORK_PROFILE",
    "RUNBOOK_BASE_URL",
    "ENVIRONMENT",
    "MARMOT_SYNC_SECONDS",
    "EMERGENCY_DISABLE_NIP17",
    "EMERGENCY_DISABLE_MARMOT",
    "EMERGENCY_DISABLE_TELEGRAM",
    "PROJECT_RECIPIENTS",
    "ADMIN_NPUB",
    "SFS_BOT_NSEC",
    "NOSTRMASH_BOT_NSEC",
    "TELEGRAM_BOT_TOKEN",
    "TELEGRAM_CHAT_IDS",
    "OPERATOR_TOKEN",
    "STATUS_READ_TOKEN",
    "STATUS_SIGNING_SECRET",
    "HEARTBEAT_KEYS",
    "HEARTBEAT_KEYS_PREVIOUS",
    "ENABLE_SFS_WEB",
    "SFS_WEB_READY_URL",
    "ENABLE_SFS_WORKER",
    "ENABLE_SFS_BLOSSOM",
    "SFS_BLOSSOM_READY_URL",
    "ENABLE_SFS_BLASTR",
    "SFS_BLASTR_READY_URL",
    "ENABLE_SFS_ALBY",
    "ALBY_BASE_URL",
    "ALBY_ROUTING_PROFILE",
    "ALBY_HUB_NAME",
    "ALBY_HUB_REGION",
    "ALBY_AUTH_TOKEN",
    "ENABLE_SFS_BTCPAY",
    "BTCPAY_BASE_URL",
    "BTCPAY_API_KEY",
    "ENABLE_NOSTRMASH_API",
    "NOSTRMASH_API_READY_URL",
    "ENABLE_NOSTRMASH_INGESTOR",
    "ENABLE_NOSTRMASH_WORKER",
    "ENABLE_NOSTRMASH_READ_GATEWAY",
    "NOSTRMASH_READ_GATEWAY_URL",
    "ENABLE_NOSTRMASH_PUBLISH_GATEWAY",
    "NOSTRMASH_PUBLISH_GATEWAY_URL",
    "ENABLE_NOSTRMASH_READ_GATEWAY_DEEP",
    "NOSTRMASH_READ_GATEWAY_DEEP_URL",
    "READ_GATEWAY_HEALTH_TOKEN",
    "ENABLE_NOSTRMASH_PUBLISH_GATEWAY_DEEP",
    "NOSTRMASH_PUBLISH_GATEWAY_DEEP_URL",
    "PUBLISH_GATEWAY_HEALTH_TOKEN",
    "NOTIFY_SMARTFLOWSOCIAL_MARMOT",
    "NOTIFY_SMARTFLOWSOCIAL_NIP17",
    "NOTIFY_SMARTFLOWSOCIAL_TELEGRAM",
    "NOTIFY_NOSTRMASH_MARMOT",
    "NOTIFY_NOSTRMASH_NIP17",
    "NOTIFY_NOSTRMASH_TELEGRAM",
    "DATABASE_PATH",
    "LISTEN_ADDR",
    "MARMOT_SOCKET",
    "MARMOT_ROOT",
    "MARMOT_HELPER",
];

/// Older Worker builds loaded these names. They are not a second configuration.
pub fn config_alias(key: &str) -> Option<&'static str> {
    match key {
        "STATUS_READER_TOKEN" => Some("STATUS_READ_TOKEN"),
        "STATUS_SIGNING_KEY" => Some("STATUS_SIGNING_SECRET"),
        _ => None,
    }
}

/// Drop the transport suffix so two failed transports share one fallback key.
pub fn logical_notification_key(dedupe_key: &str) -> &str {
    match dedupe_key.rsplit_once(':') {
        Some((head, tail))
            if matches!(tail, "nostr" | "marmot" | "telegram") && !head.is_empty() =>
        {
            head
        }
        _ => dedupe_key,
    }
}

pub fn route_for(
    settings: &Settings,
    get: &impl Fn(&str) -> String,
    project_id: &str,
    severity: crate::domain::Severity,
) -> TransportRoute {
    let project = project_id.to_ascii_uppercase().replace('-', "_");
    TransportRoute {
        marmot: transport_choice(
            get,
            &project,
            "MARMOT",
            settings.marmot_enabled,
            severity,
            TransportDefault::WarningOrCritical,
        ),
        nip17: transport_choice(
            get,
            &project,
            "NIP17",
            settings.nip17_enabled,
            severity,
            TransportDefault::All,
        ),
        telegram: transport_choice(
            get,
            &project,
            "TELEGRAM",
            true,
            severity,
            TransportDefault::CriticalOnly,
        ),
    }
}

enum TransportDefault {
    All,
    WarningOrCritical,
    CriticalOnly,
}

fn transport_choice(
    get: &impl Fn(&str) -> String,
    project: &str,
    transport: &str,
    enabled: bool,
    severity: crate::domain::Severity,
    default: TransportDefault,
) -> bool {
    let override_value = get(&format!("NOTIFY_{project}_{transport}"));
    if override_value.is_empty() {
        if !enabled {
            return false;
        }
        return match default {
            TransportDefault::All => true,
            TransportDefault::WarningOrCritical => matches!(
                severity,
                crate::domain::Severity::Warning | crate::domain::Severity::Critical
            ),
            TransportDefault::CriticalOnly => severity == crate::domain::Severity::Critical,
        };
    }
    match override_value.to_ascii_lowercase().as_str() {
        "false" | "off" | "disabled" => false,
        "true" | "all" => true,
        list => list.split(',').any(|item| item.trim() == severity.as_str()),
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum TransportAvailability {
    Ready,
    TemporarilyUnavailable,
    NotConfigured,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum QueuedTransport {
    Deliver,
    Suppress,
    SuppressWithFallback,
    Defer,
}

/// One policy for every queued notification. Test alerts never create a
/// fallback incident or a second transport. Critical NIP-17 and Marmot rows
/// create one Telegram fallback only in `nostr_fallback` mode.
pub fn queued_transport(
    settings: &Settings,
    get: &impl Fn(&str) -> String,
    project_id: &str,
    destination: &str,
    severity: crate::domain::Severity,
    alert_class: &str,
    availability: TransportAvailability,
) -> QueuedTransport {
    let emergency = match destination {
        "nostr" => settings.emergency_disable_nip17,
        "marmot" => settings.emergency_disable_marmot,
        "telegram" => settings.emergency_disable_telegram,
        _ => true,
    };
    if alert_class == "test" {
        if emergency || explicitly_disabled(get, project_id, destination) {
            return QueuedTransport::Suppress;
        }
        let configured = match destination {
            "nostr" => settings.nip17_enabled,
            "marmot" => settings.marmot_enabled,
            "telegram" => availability != TransportAvailability::NotConfigured,
            _ => false,
        };
        if !configured || availability == TransportAvailability::NotConfigured {
            return QueuedTransport::Suppress;
        }
        if availability == TransportAvailability::TemporarilyUnavailable {
            return QueuedTransport::Defer;
        }
        return QueuedTransport::Deliver;
    }
    if emergency || availability == TransportAvailability::NotConfigured {
        return if fallback_wanted(
            settings,
            get,
            project_id,
            destination,
            severity,
            alert_class,
        ) {
            QueuedTransport::SuppressWithFallback
        } else {
            QueuedTransport::Suppress
        };
    }
    let allowed = match destination {
        "nostr" => route_for(settings, get, project_id, severity).nip17,
        "marmot" => route_for(settings, get, project_id, severity).marmot,
        "telegram" => route_for(settings, get, project_id, severity).telegram,
        _ => false,
    };
    if !allowed {
        return if fallback_wanted(
            settings,
            get,
            project_id,
            destination,
            severity,
            alert_class,
        ) {
            QueuedTransport::SuppressWithFallback
        } else {
            QueuedTransport::Suppress
        };
    }
    if availability == TransportAvailability::TemporarilyUnavailable {
        QueuedTransport::Defer
    } else {
        QueuedTransport::Deliver
    }
}

fn explicitly_disabled(get: &impl Fn(&str) -> String, project_id: &str, destination: &str) -> bool {
    let transport = match destination {
        "nostr" => "NIP17",
        "marmot" => "MARMOT",
        "telegram" => "TELEGRAM",
        _ => return true,
    };
    let project = project_id.to_ascii_uppercase().replace('-', "_");
    matches!(
        get(&format!("NOTIFY_{project}_{transport}"))
            .trim()
            .to_ascii_lowercase()
            .as_str(),
        "false" | "off" | "disabled"
    )
}

pub fn fallback_wanted(
    settings: &Settings,
    get: &impl Fn(&str) -> String,
    project_id: &str,
    destination: &str,
    severity: crate::domain::Severity,
    alert_class: &str,
) -> bool {
    alert_class != "test"
        && matches!(destination, "nostr" | "marmot")
        && severity == crate::domain::Severity::Critical
        && settings.telegram_mode == TelegramMode::NostrFallback
        && !settings.emergency_disable_telegram
        && route_for(settings, get, project_id, severity).telegram
}

pub fn fallback_required(
    outcome_accepted: bool,
    hold_attempt: bool,
    message_state: Option<&str>,
    push_state: Option<&str>,
    destination: &str,
    severity: crate::domain::Severity,
) -> bool {
    if destination == "telegram" || severity != crate::domain::Severity::Critical {
        return false;
    }
    let pending = matches!(message_state, Some("accepted_pending"));
    let push_unknown = destination == "marmot"
        && matches!(
            push_state,
            None | Some("unknown")
                | Some("unobservable")
                | Some("pending")
                | Some("expired")
                | Some("token_unavailable")
                | Some("not_attempted")
        )
        && matches!(
            message_state,
            Some("accepted" | "accepted_pending" | "relay_accepted")
        );
    !outcome_accepted || pending || (hold_attempt && pending) || push_unknown
}

#[cfg(test)]
mod tests {
    use super::*;

    fn settings(marmot: bool, nip17: bool) -> Settings {
        load_settings(|key| match key {
            "ENABLE_MARMOT" => marmot.to_string(),
            "ENABLE_NIP17" => {
                if nip17 {
                    String::new()
                } else {
                    "false".to_string()
                }
            }
            _ => String::new(),
        })
    }

    #[test]
    fn project_override_disables_nip17_without_changing_the_global_default() {
        let settings = settings(true, true);
        let get = |key: &str| {
            if key == "NOTIFY_SMARTFLOWSOCIAL_NIP17" {
                "false".to_string()
            } else {
                String::new()
            }
        };
        let smartflow = route_for(
            &settings,
            &get,
            "smartflowsocial",
            crate::domain::Severity::Critical,
        );
        let nostrmash = route_for(
            &settings,
            &|_| String::new(),
            "nostrmash",
            crate::domain::Severity::Critical,
        );
        assert!(!smartflow.nip17);
        assert!(smartflow.marmot);
        assert!(nostrmash.nip17);
    }

    #[test]
    fn logical_key_collapses_transport_suffixes_and_catalog_names_are_registered() {
        assert_eq!(
            logical_notification_key("incident:inc_1:open:nostr"),
            "incident:inc_1:open"
        );
        assert_eq!(
            logical_notification_key("incident:inc_1:open:marmot"),
            "incident:inc_1:open"
        );
        assert_eq!(logical_notification_key("test:plain"), "test:plain");
        assert_eq!(
            config_alias("STATUS_READER_TOKEN"),
            Some("STATUS_READ_TOKEN")
        );
        assert_eq!(
            config_alias("STATUS_SIGNING_KEY"),
            Some("STATUS_SIGNING_SECRET")
        );
        for monitor in crate::catalog::monitors() {
            assert!(
                CONFIG_KEYS.contains(&monitor.enable_var),
                "{}",
                monitor.enable_var
            );
            if let Some(http) = &monitor.http {
                assert!(CONFIG_KEYS.contains(&http.url_var), "{}", http.url_var);
                if let Some(secret) = http.bearer_secret {
                    assert!(CONFIG_KEYS.contains(&secret), "{secret}");
                }
            }
        }
        for project in crate::catalog::PROJECTS {
            assert!(CONFIG_KEYS.contains(&project.sender_secret));
        }
        assert!(CONFIG_KEYS.contains(&"STATUS_READ_TOKEN"));
        assert!(CONFIG_KEYS.contains(&"STATUS_SIGNING_SECRET"));
    }
}
