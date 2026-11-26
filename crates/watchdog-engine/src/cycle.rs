use std::collections::HashMap;

use futures_util::future::join_all;
use uuid::Uuid;
use watchdog_core::catalog::{project_by_id, telegram_chat, PROJECTS};
use watchdog_core::clock::Clock;
use watchdog_core::domain::{
    next_delivery_state, AlertClass, AlertDraft, CheckResult, DeliveryState, Destination,
    MonitorDefinition, Notice, NoticeEvent, Severity,
};
use watchdog_core::format::{format_incident_message, IncidentMessage};
use watchdog_core::settings::{logical_notification_key, route_for, Settings, TelegramMode};
use watchdog_core::transition::{transition, TransitionInput};
use watchdog_notify::marmot_blocker;
use watchdog_store::{OperationalStore, OutboxRow};

use crate::probes::{probe_monitor, HttpClient};

#[derive(Clone, Debug)]
pub struct DeliveryOutcome {
    pub accepted: bool,
    pub terminal: bool,
    /// Keep the current attempt count and try again later. Used when a Marmot
    /// message is already submitted and a later retry must reconcile it instead
    /// of burning the attempt budget or encrypting it again.
    pub hold_attempt: bool,
    pub error: Option<String>,
    pub accepted_relays: Vec<String>,
    pub failed_relays: Vec<String>,
    pub message_phase: Option<String>,
    pub push_phase: Option<String>,
    pub message_event_id: Option<String>,
    pub push_envelope: Option<String>,
}

pub trait Notifier {
    fn deliver_nostr(
        &self,
        row: &OutboxRow,
        claim: &str,
    ) -> impl std::future::Future<Output = DeliveryOutcome>;
    fn deliver_telegram(
        &self,
        row: &OutboxRow,
    ) -> impl std::future::Future<Output = DeliveryOutcome>;
    fn deliver_marmot(
        &self,
        row: &OutboxRow,
        claim: &str,
    ) -> impl std::future::Future<Output = DeliveryOutcome>;
}

pub async fn run_check_cycle<S: OperationalStore, H: HttpClient, N: Notifier, C: Clock>(
    store: &S,
    settings: &Settings,
    get: &impl Fn(&str) -> String,
    http: &H,
    notifier: &N,
    now: i64,
    clock: &C,
) -> Result<(), watchdog_store::StoreError> {
    if !settings.enabled {
        store
            .mark_run("checks", Some(now), Some(now), Some("disabled"), None)
            .await?;
        return Ok(());
    }
    let owner = Uuid::new_v4().to_string();
    let monitor_count = watchdog_core::catalog::enabled_monitors(get).len() as i64;
    let width_for_lease = settings.concurrency.max(1);
    let waves = (monitor_count + width_for_lease - 1) / width_for_lease;
    let lease_ms =
        (settings.timeout_ms.saturating_mul(waves.max(1)) + 20_000).clamp(50_000, 180_000);
    if !store
        .acquire_lease("checks", &owner, now + lease_ms, now)
        .await?
    {
        return Ok(());
    }
    let mut cycle_error: Option<String> = None;
    let due = due_monitors(store, get, now).await?;
    let width = settings.concurrency.max(1) as usize;
    for chunk in due.chunks(width) {
        let probed = join_all(chunk.iter().map(|monitor| async move {
            let before = store.load_memory(monitor.id).await.ok();
            let heartbeat = if monitor.kind == watchdog_core::CheckKind::SignedHeartbeat {
                store.read_heartbeat(monitor.id).await.ok().flatten()
            } else {
                None
            };
            let result = probe_monitor(
                monitor,
                get,
                settings.private_network,
                settings.timeout_ms,
                now,
                settings.stale_seconds,
                settings.progress_seconds,
                heartbeat.as_ref(),
                http,
            )
            .await;
            (monitor, before, result)
        }))
        .await;
        for (monitor, before, result) in probed {
            if let Some(before) = before.as_ref() {
                if let Ok(current) = store.load_memory(monitor.id).await {
                    if current.generation != before.generation {
                        continue;
                    }
                }
            }
            if apply_probe(store, settings, get, monitor, &result, now)
                .await
                .is_err()
            {
                cycle_error = Some("monitor_commit_failed".to_string());
            }
        }
    }
    let _ = store.prune(now).await;
    let _ = notifier;
    store
        .release_lease("checks", &owner, clock.unix_ms())
        .await?;
    store
        .mark_run(
            "checks",
            Some(now),
            Some(now),
            cycle_error.as_deref(),
            cycle_error.is_none().then_some(now),
        )
        .await?;
    Ok(())
}

pub async fn dispatch_due<S: OperationalStore, N: Notifier, C: Clock>(
    store: &S,
    settings: &Settings,
    get: &impl Fn(&str) -> String,
    notifier: &N,
    clock: &C,
) -> Result<(), watchdog_store::StoreError> {
    if !settings.alerts_enabled {
        return Ok(());
    }
    for destination in ["telegram", "marmot", "nostr"] {
        if destination == "nostr" && !settings.nip17_enabled {
            continue;
        }
        if destination == "marmot" && !settings.marmot_enabled {
            continue;
        }
        if destination == "telegram" && get("TELEGRAM_BOT_TOKEN").is_empty() {
            continue;
        }
        let claimed_at = clock.unix_ms();
        let rows = store
            .claim_outbox(
                claimed_at,
                claimed_at + settings.delivery_claim_ms,
                Some(destination),
                4,
            )
            .await?;
        let mut critical = 0;
        let mut other = 0;
        for row in rows {
            let token = row.claim_token.clone().unwrap_or_default();
            let is_critical = row.severity == "critical";
            let admit = if is_critical { critical < 2 } else { other < 1 };
            if !admit {
                let now = clock.unix_ms();
                let _ = store
                    .finish_delivery(
                        &row.id,
                        &token,
                        DeliveryState::Queued,
                        row.attempt_count,
                        now,
                        None,
                        None,
                        None,
                        None,
                        None,
                        None,
                        None,
                        now,
                    )
                    .await;
                continue;
            }
            if is_critical {
                critical += 1;
            } else {
                other += 1;
            }
            let now = clock.unix_ms();
            if !transport_enabled(settings, get, &row) {
                let _ = store
                    .finish_delivery(
                        &row.id,
                        &token,
                        DeliveryState::Queued,
                        row.attempt_count,
                        now + 300_000,
                        Some("transport_disabled"),
                        None,
                        None,
                        None,
                        None,
                        None,
                        None,
                        now,
                    )
                    .await;
                continue;
            }
            if !store
                .extend_claim(&row.id, &token, now + settings.delivery_claim_ms, now)
                .await
                .unwrap_or(false)
            {
                continue;
            }
            let outcome = match Destination::parse(&row.destination) {
                Some(Destination::Telegram) => notifier.deliver_telegram(&row).await,
                Some(Destination::Marmot) => notifier.deliver_marmot(&row, &token).await,
                Some(Destination::Nostr) => notifier.deliver_nostr(&row, &token).await,
                None => DeliveryOutcome {
                    accepted: false,
                    terminal: true,
                    hold_attempt: false,
                    error: Some("project_invalid".to_string()),
                    accepted_relays: Vec::new(),
                    failed_relays: Vec::new(),
                    message_phase: None,
                    push_phase: None,
                    message_event_id: None,
                    push_envelope: None,
                },
            };
            let finished = clock.unix_ms();
            let attempt = if outcome.hold_attempt {
                row.attempt_count
            } else {
                row.attempt_count + 1
            };
            let state = if outcome.accepted {
                DeliveryState::RelayAccepted
            } else if outcome.hold_attempt {
                DeliveryState::Retrying
            } else {
                next_delivery_state(attempt, outcome.terminal)
            };
            let next_attempt = if outcome.hold_attempt {
                finished + 60_000
            } else {
                finished + watchdog_core::backoff_ms(attempt)
            };
            let owned = store
                .finish_delivery(
                    &row.id,
                    &token,
                    state,
                    attempt,
                    next_attempt,
                    outcome.error.as_deref(),
                    Some(
                        &serde_json::to_string(&outcome.accepted_relays)
                            .unwrap_or_else(|_| "[]".to_string()),
                    ),
                    Some(
                        &serde_json::to_string(&outcome.failed_relays)
                            .unwrap_or_else(|_| "[]".to_string()),
                    ),
                    outcome.message_phase.as_deref(),
                    outcome.push_phase.as_deref(),
                    outcome.message_event_id.as_deref(),
                    outcome.push_envelope.as_deref(),
                    finished,
                )
                .await?;
            let redundancy = outcome.hold_attempt
                && matches!(
                    outcome.message_phase.as_deref(),
                    Some("relay_accepted" | "completion_unknown")
                );
            if owned
                && !outcome.accepted
                && (redundancy || !outcome.hold_attempt)
                && settings.telegram_mode == TelegramMode::NostrFallback
                && matches!(row.destination.as_str(), "nostr" | "marmot")
            {
                enqueue_fallback(store, settings, get, &row, finished).await?;
            }
        }
    }
    Ok(())
}

fn transport_enabled(settings: &Settings, get: &impl Fn(&str) -> String, row: &OutboxRow) -> bool {
    let Some(severity) = Severity::parse(&row.severity) else {
        return false;
    };
    if row.alert_class == "test" {
        return match row.destination.as_str() {
            "nostr" => settings.nip17_enabled,
            "marmot" => settings.marmot_enabled,
            "telegram" => !get("TELEGRAM_BOT_TOKEN").is_empty(),
            _ => false,
        };
    }
    let route = route_for(settings, get, &row.project_id, severity);
    match row.destination.as_str() {
        "nostr" => route.nip17,
        "marmot" => route.marmot,
        "telegram" => route.telegram,
        _ => false,
    }
}

async fn due_monitors<S: OperationalStore>(
    store: &S,
    get: &impl Fn(&str) -> String,
    now: i64,
) -> Result<Vec<MonitorDefinition>, watchdog_store::StoreError> {
    let last: HashMap<_, _> = store.last_checks().await?.into_iter().collect();
    Ok(watchdog_core::catalog::enabled_monitors(get)
        .into_iter()
        .filter(|monitor| match last.get(monitor.id) {
            None | Some(None) => true,
            Some(Some(at)) => now - at >= monitor.interval_seconds * 1000,
        })
        .collect())
}

async fn apply_probe<S: OperationalStore>(
    store: &S,
    settings: &Settings,
    get: &impl Fn(&str) -> String,
    monitor: &MonitorDefinition,
    check: &CheckResult,
    now: i64,
) -> Result<(), watchdog_store::StoreError> {
    let loaded = store.load_memory(monitor.id).await?;
    let incident_id = format!("inc_{}", Uuid::new_v4());
    let integrity_id = format!("inc_{}", Uuid::new_v4());
    let next = transition(TransitionInput {
        memory: &loaded.memory,
        result: check,
        now,
        failure_threshold: settings
            .failure_threshold
            .unwrap_or(monitor.failure_threshold),
        recovery_threshold: settings
            .recovery_threshold
            .unwrap_or(monitor.recovery_threshold),
        severity: monitor.severity,
        incident_on_degraded: monitor.incident_on_degraded,
        unknown_threshold: settings.unknown_threshold,
        reminder_seconds: settings.reminder_seconds,
        new_incident_id: &incident_id,
        new_integrity_incident_id: &integrity_id,
    });
    let alerts = next
        .notices
        .iter()
        .flat_map(|notice| incident_alerts(settings, get, monitor, notice, check, now))
        .collect::<Vec<_>>();
    let outcome = store
        .commit_check(
            monitor.id,
            monitor.project_id,
            loaded.generation,
            &next.memory,
            check,
            now,
            &next.notices,
            &alerts,
        )
        .await?;
    let _ = outcome.committed;
    Ok(())
}

fn incident_alerts(
    settings: &Settings,
    get: &impl Fn(&str) -> String,
    monitor: &MonitorDefinition,
    notice: &Notice,
    check: &CheckResult,
    now: i64,
) -> Vec<AlertDraft> {
    let Some(project) = project_by_id(monitor.project_id) else {
        return Vec::new();
    };
    let runbook = settings
        .runbook_base
        .as_ref()
        .map(|base| format!("{base}{}", monitor.runbook_path));
    let text = format_incident_message(IncidentMessage {
        project_name: project.display_name,
        display_name: monitor.display_name,
        severity: notice.severity,
        kind: notice.kind,
        event: notice.event,
        state: notice.monitor_status.as_str(),
        incident_id: &notice.incident_id,
        occurred_at: notice.occurred_at,
        reason: &notice.reason,
        observed_version: check.observed_version.as_deref(),
        runbook_url: runbook.as_deref(),
    });
    let bucket = if settings.reminder_seconds > 0 {
        now / (settings.reminder_seconds * 1000)
    } else {
        now
    };
    let suffix = match notice.event {
        NoticeEvent::Remind => format!("remind:{bucket}"),
        NoticeEvent::Open => "open".to_string(),
        NoticeEvent::Close => "close".to_string(),
    };
    let route = route_for(settings, get, monitor.project_id, notice.severity);
    let mut drafts = Vec::new();
    if route.nip17 {
        drafts.push(draft(
            monitor,
            notice,
            Destination::Nostr,
            &format!("{suffix}:nostr"),
            &text,
        ));
    }
    if route.marmot {
        drafts.push(draft(
            monitor,
            notice,
            Destination::Marmot,
            &format!("{suffix}:marmot"),
            &text,
        ));
    }
    if route.telegram
        && settings.telegram_mode == TelegramMode::Dual
        && telegram_chat(&get("TELEGRAM_CHAT_IDS"), monitor.project_id).is_some()
    {
        drafts.push(draft(
            monitor,
            notice,
            Destination::Telegram,
            &format!("{suffix}:telegram"),
            &text,
        ));
    }
    let _ = marmot_blocker();
    let _ = PROJECTS;
    drafts
}

fn draft(
    monitor: &MonitorDefinition,
    notice: &Notice,
    destination: Destination,
    suffix: &str,
    text: &str,
) -> AlertDraft {
    let class = match notice.event {
        NoticeEvent::Close => AlertClass::Recovery,
        NoticeEvent::Remind => AlertClass::Reminder,
        NoticeEvent::Open => AlertClass::Outage,
    };
    AlertDraft {
        id: format!("alt_{}", Uuid::new_v4()),
        alert_class: class,
        incident_id: Some(notice.incident_id.clone()),
        monitor_id: monitor.id.to_string(),
        project_id: monitor.project_id.to_string(),
        dedupe_key: format!("incident:{}:{suffix}", notice.incident_id),
        destination,
        severity: notice.severity,
        text: text.to_string(),
    }
}

async fn enqueue_fallback<S: OperationalStore>(
    store: &S,
    settings: &Settings,
    get: &impl Fn(&str) -> String,
    row: &OutboxRow,
    now: i64,
) -> Result<(), watchdog_store::StoreError> {
    if project_by_id(&row.project_id).is_none() {
        return Ok(());
    }
    let Some(severity) = Severity::parse(&row.severity) else {
        return Ok(());
    };
    if !route_for(settings, get, &row.project_id, severity).telegram {
        return Ok(());
    }
    if telegram_chat(&get("TELEGRAM_CHAT_IDS"), &row.project_id).is_none()
        || get("TELEGRAM_BOT_TOKEN").is_empty()
    {
        return Ok(());
    }
    store
        .insert_alert(
            &AlertDraft {
                id: format!("alt_{}", Uuid::new_v4()),
                alert_class: AlertClass::parse(&row.alert_class).unwrap_or(AlertClass::Outage),
                incident_id: row.incident_id.clone(),
                monitor_id: row.monitor_id.clone(),
                project_id: row.project_id.clone(),
                dedupe_key: format!("fallback:{}", logical_notification_key(&row.dedupe_key)),
                destination: Destination::Telegram,
                severity,
                text: row.payload_text.clone(),
            },
            now,
        )
        .await
}
