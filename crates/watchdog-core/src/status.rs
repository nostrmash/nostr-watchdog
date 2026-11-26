use serde_json::{json, Value};

use crate::catalog::{monitors, PROJECTS};
use crate::domain::{CheckKind, MonitorStatus};
use crate::settings::Settings;

pub const KNOWN_ERRORS: &[&str] = &[
    "sender_key_missing",
    "sender_key_invalid",
    "recipient_missing",
    "recipient_invalid",
    "recipient_inbox_missing",
    "bootstrap_relays_missing",
    "inbox_discovery_failed",
    "relay_rejected",
    "partial_relay_acceptance",
    "envelope_invalid",
    "delivery_failed",
    "telegram_failed",
    "telegram_unavailable",
    "project_invalid",
    "claim_lost",
    "marmot_engine_unavailable",
    "marmot_group_missing",
    "push_token_unavailable",
    "push_trigger_rejected",
    "message_not_accepted",
    "unauthorized_membership",
];

#[derive(Clone, Debug, Default)]
pub struct StatusSnapshot {
    pub states: Vec<StateView>,
    pub heartbeats: Vec<HeartbeatView>,
    pub runs: Vec<RunView>,
    pub vendor_checks: Vec<VendorView>,
    pub outbox_by_monitor: Vec<OutboxCount>,
    pub open_incident_monitor_ids: Vec<String>,
    pub errors_by_monitor: Vec<ErrorCount>,
}

#[derive(Clone, Debug)]
pub struct StateView {
    pub monitor_id: String,
    pub status: String,
    pub last_check_at: Option<i64>,
}

#[derive(Clone, Debug)]
pub struct HeartbeatView {
    pub monitor_id: String,
    pub received_at: i64,
}

#[derive(Clone, Debug)]
pub struct RunView {
    pub name: String,
    pub started_at: Option<i64>,
    pub finished_at: Option<i64>,
    pub success_at: Option<i64>,
    pub error: Option<String>,
}

#[derive(Clone, Debug)]
pub struct VendorView {
    pub monitor_id: String,
    pub vendor: String,
    pub attempted_at: Option<i64>,
    pub succeeded_at: Option<i64>,
    pub partial_succeeded_at: Option<i64>,
    pub releases_checked_at: Option<i64>,
    pub advisories_checked_at: Option<i64>,
    pub releases_stale: bool,
    pub advisories_stale: bool,
    pub releases_state: String,
    pub advisories_state: String,
    pub coverage: String,
    pub error_code: Option<String>,
    pub consecutive_failures: i64,
    pub releases_failures: i64,
    pub advisories_failures: i64,
    /// Conditional-commit fence. Zero means the row has not been written.
    pub generation: i64,
}

#[derive(Clone, Debug)]
pub struct OutboxCount {
    pub monitor_id: String,
    pub state: String,
    pub count: i64,
}

#[derive(Clone, Debug)]
pub struct ErrorCount {
    pub monitor_id: String,
    pub error: String,
    pub count: i64,
}

#[derive(Clone, Debug)]
pub struct DestinationFlags {
    pub nostr_ready: bool,
    pub telegram_configured: bool,
}

pub struct DerivedStatus {
    pub status: &'static str,
    pub http_status: u16,
    pub body: Value,
}

const UPDATE_OVERDUE_MS: i64 = 2 * 3_600_000;
const UPDATE_UNHEALTHY_MS: i64 = 6 * 3_600_000;
const SOURCE_FAILURE_GRACE: i64 = 3;

pub fn derive_operational_status(
    settings: &Settings,
    now: i64,
    snapshot: &StatusSnapshot,
    enabled: &[crate::domain::MonitorDefinition],
    destinations: DestinationFlags,
) -> DerivedStatus {
    let enabled_ids: std::collections::HashSet<&str> =
        enabled.iter().map(|monitor| monitor.id).collect();
    let mut counts = std::collections::BTreeMap::from([
        ("healthy", 0_i64),
        ("degraded", 0),
        ("down", 0),
        ("unknown", 0),
        ("misconfigured", 0),
    ]);
    let mut stale_heartbeats = 0;
    let mut missing_heartbeats = 0;
    let mut stale_monitor_results = 0;
    for monitor in enabled {
        let state = snapshot
            .states
            .iter()
            .find(|item| item.monitor_id == monitor.id);
        let status = state.and_then(|item| MonitorStatus::parse(&item.status));
        let key = status.map(MonitorStatus::as_str).unwrap_or("unknown");
        *counts.entry(key).or_insert(0) += 1;
        let result_limit = settings
            .scheduler_stale_seconds
            .max(monitor.interval_seconds.saturating_mul(3));
        if state
            .and_then(|item| item.last_check_at)
            .is_none_or(|at| now - at > result_limit * 1000)
        {
            stale_monitor_results += 1;
        }
        if monitor.kind == CheckKind::SignedHeartbeat {
            match snapshot
                .heartbeats
                .iter()
                .find(|item| item.monitor_id == monitor.id)
            {
                None => missing_heartbeats += 1,
                Some(beat) if now - beat.received_at > settings.stale_seconds * 1000 => {
                    stale_heartbeats += 1
                }
                Some(_) => {}
            }
        }
    }
    let checks = run_of(snapshot, "checks");
    let updates = run_of(snapshot, "updates");
    let (delivery_counts, inactive_dead) = delivery_counts(snapshot, &enabled_ids);
    let pending = *delivery_counts.get("queued").unwrap_or(&0);
    let retrying = *delivery_counts.get("retrying").unwrap_or(&0);
    let dead_letters = *delivery_counts.get("failed").unwrap_or(&0);
    let (active_incidents, inactive_incidents) = incident_counts(snapshot, &enabled_ids);
    let mut errors = serde_json::Map::new();
    for row in snapshot
        .errors_by_monitor
        .iter()
        .filter(|row| enabled_ids.contains(row.monitor_id.as_str()))
    {
        if KNOWN_ERRORS.contains(&row.error.as_str()) {
            let entry = errors.entry(row.error.clone()).or_insert(json!(0));
            *entry = json!(entry.as_i64().unwrap_or(0) + row.count);
        }
    }
    let check_age = checks.finished_at.map(|at| now - at);
    let scheduler_stale = !enabled.is_empty()
        && check_age.is_none_or(|age| age > settings.scheduler_stale_seconds * 1000);
    let scheduler_failed = checks
        .error
        .as_deref()
        .is_some_and(|error| error != "disabled");
    let repeated_delivery_failures = dead_letters > 0 || retrying > 3;
    let version_monitors = enabled
        .iter()
        .filter(|monitor| monitor.version_vendor.is_some())
        .count();
    let vendor_checks: Vec<&VendorView> = snapshot
        .vendor_checks
        .iter()
        .filter(|row| enabled_ids.contains(row.monitor_id.as_str()))
        .collect();
    let update_age = updates.success_at.map(|at| now - at);
    let updates_required = version_monitors > 0;
    let update_overdue = updates_required && update_age.is_none_or(|age| age > UPDATE_OVERDUE_MS);
    let update_unhealthy =
        updates_required && update_age.is_some_and(|age| age > UPDATE_UNHEALTHY_MS);
    let update_failed = updates_required
        && updates.error.as_deref().is_some_and(|error| {
            !matches!(error, "disabled" | "coverage_partial" | "rate_limited")
        });
    let vendor_failing = vendor_checks
        .iter()
        .any(|row| row.consecutive_failures >= 3);
    let source_gap = vendor_checks.iter().any(|row| source_overdue(row, now));
    let coverage_gap = vendor_checks
        .iter()
        .any(|row| row.coverage == "incomplete" || row.coverage == "unavailable");
    let check_unhealthy = scheduler_stale
        && check_age.is_none_or(|age| age > settings.scheduler_stale_seconds * 3 * 1000);
    let degraded = (scheduler_stale && !check_unhealthy)
        || scheduler_failed
        || repeated_delivery_failures
        || stale_monitor_results > 0
        || (update_overdue && !update_unhealthy)
        || update_failed
        || vendor_failing
        || source_gap
        || coverage_gap;
    let status = if !settings.enabled {
        "disabled"
    } else if enabled.is_empty() {
        "not_configured"
    } else if (!destinations.nostr_ready && settings.alerts_enabled) || counts["misconfigured"] > 0
    {
        "misconfigured"
    } else if check_unhealthy || update_unhealthy {
        "unhealthy"
    } else if degraded {
        "degraded"
    } else if !settings.alerts_enabled {
        "alerts_disabled"
    } else {
        "healthy"
    };
    let body = json!({
        "contract": "watchdog-status-v1",
        "status": status,
        "environment": settings.environment,
        "checkedAt": crate::format::format_unix_ms(now),
        "monitoringEnabled": settings.enabled,
        "alertsEnabled": settings.alerts_enabled,
        "monitors": {
            "configured": monitors().len(),
            "enabled": enabled.len(),
            "healthy": counts["healthy"],
            "degraded": counts["degraded"],
            "down": counts["down"],
            "unknown": counts["unknown"],
            "misconfigured": counts["misconfigured"],
        },
        "lastSuccessfulCheckAt": checks.success_at.map(crate::format::format_unix_ms),
        "lastSuccessfulUpdateAt": updates.success_at.map(crate::format::format_unix_ms),
        "lastCycleAgeMs": check_age,
        "scheduler": {
            "checks": public_run(&checks, scheduler_stale, None),
            "updates": public_run(&updates, update_overdue, Some(vendor_checks.iter().filter(|row| row.consecutive_failures > 0).count())),
        },
        "securityChecks": vendor_checks.iter().map(|row| json!({
            "monitorId": row.monitor_id,
            "vendor": row.vendor,
            "attemptedAt": row.attempted_at.map(crate::format::format_unix_ms),
            "succeededAt": row.succeeded_at.map(crate::format::format_unix_ms),
            "releasesCheckedAt": row.releases_checked_at.map(crate::format::format_unix_ms),
            "advisoriesCheckedAt": row.advisories_checked_at.map(crate::format::format_unix_ms),
            "releasesStale": row.releases_stale,
            "advisoriesStale": row.advisories_stale,
            "releasesState": row.releases_state,
            "advisoriesState": row.advisories_state,
            "coverage": row.coverage,
            "errorCode": row.error_code,
            "consecutiveFailures": row.consecutive_failures,
            "releasesFailures": row.releases_failures,
            "advisoriesFailures": row.advisories_failures,
            "partialSucceededAt": row.partial_succeeded_at.map(crate::format::format_unix_ms),
        })).collect::<Vec<_>>(),
        "openIncidents": active_incidents,
        "inactiveOpenIncidents": inactive_incidents,
        "staleMonitorResults": stale_monitor_results,
        "pendingAlerts": pending,
        "retryingAlerts": retrying,
        "deadLetters": dead_letters,
        "inactiveDeadLetters": inactive_dead,
        "heartbeats": { "stale": stale_heartbeats, "missing": missing_heartbeats },
        "delivery": {
            "destinationsConfigured": {
                "nostr": destinations.nostr_ready,
                "telegram": destinations.telegram_configured,
                "marmot": settings.marmot_enabled,
            },
            "recentErrors": errors,
        },
        "projects": PROJECTS.iter().map(|project| project.id).collect::<Vec<_>>(),
    });
    DerivedStatus {
        status,
        http_status: if status == "healthy" { 200 } else { 503 },
        body,
    }
}

fn source_overdue(row: &VendorView, now: i64) -> bool {
    feed_overdue(
        row.releases_stale,
        row.releases_checked_at,
        row.releases_failures,
        now,
    ) || feed_overdue(
        row.advisories_stale,
        row.advisories_checked_at,
        row.advisories_failures,
        now,
    )
}

fn feed_overdue(stale: bool, checked_at: Option<i64>, failures: i64, now: i64) -> bool {
    if !stale {
        return false;
    }
    if failures >= SOURCE_FAILURE_GRACE {
        return true;
    }
    checked_at.is_some_and(|at| now - at > UPDATE_OVERDUE_MS)
}

fn delivery_counts(
    snapshot: &StatusSnapshot,
    enabled_ids: &std::collections::HashSet<&str>,
) -> (std::collections::BTreeMap<String, i64>, i64) {
    let mut counts = std::collections::BTreeMap::new();
    let mut inactive = 0;
    for row in &snapshot.outbox_by_monitor {
        if !enabled_ids.contains(row.monitor_id.as_str()) {
            if row.state == "failed" {
                inactive += row.count;
            }
            continue;
        }
        *counts.entry(row.state.clone()).or_insert(0) += row.count;
    }
    (counts, inactive)
}

fn incident_counts(
    snapshot: &StatusSnapshot,
    enabled_ids: &std::collections::HashSet<&str>,
) -> (i64, i64) {
    let mut active = 0;
    let mut inactive = 0;
    for id in &snapshot.open_incident_monitor_ids {
        if enabled_ids.contains(id.as_str()) {
            active += 1;
        } else {
            inactive += 1;
        }
    }
    (active, inactive)
}

fn run_of(snapshot: &StatusSnapshot, name: &str) -> RunView {
    snapshot
        .runs
        .iter()
        .find(|item| item.name == name)
        .cloned()
        .unwrap_or(RunView {
            name: name.to_string(),
            started_at: None,
            finished_at: None,
            success_at: None,
            error: None,
        })
}

fn public_run(run: &RunView, overdue: bool, failed_vendors: Option<usize>) -> Value {
    let mut value = json!({
        "lastStartedAt": run.started_at.map(crate::format::format_unix_ms),
        "lastFinishedAt": run.finished_at.map(crate::format::format_unix_ms),
        "lastSuccessAt": run.success_at.map(crate::format::format_unix_ms),
        "lastError": run.error,
        "overdue": overdue,
    });
    if let Some(count) = failed_vendors {
        value["failedVendors"] = json!(count);
    }
    value
}
