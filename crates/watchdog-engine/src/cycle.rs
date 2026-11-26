use std::collections::HashMap;

use futures_util::future::join_all;
use uuid::Uuid;
use watchdog_core::catalog::{project_by_id, telegram_chat, PROJECTS};
use watchdog_core::clock::Clock;
use watchdog_core::domain::{
    AlertClass, AlertDraft, CheckResult, DeliveryState, Destination, MonitorDefinition, Notice,
    NoticeEvent, Severity,
};
use watchdog_core::format::{format_incident_message, format_telegram_notice, IncidentMessage};
use watchdog_core::settings::{
    fallback_required, logical_notification_key, queued_transport, route_for, Settings,
    TelegramMode, TransportAvailability,
};
use watchdog_core::transition::{transition, TransitionInput};
use watchdog_notify::marmot_blocker;
use watchdog_store::LoadedMemory;
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
    pub operation: Option<watchdog_core::delivery::OperationResult>,
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
    deadline_ms: i64,
) -> Result<(), watchdog_store::StoreError> {
    if !settings.enabled {
        let finished = clock.unix_ms();
        store
            .mark_run(
                "checks",
                "disabled",
                Some(now),
                Some(finished),
                Some("disabled"),
                None,
            )
            .await?;
        return Ok(());
    }
    let owner = Uuid::new_v4().to_string();
    let started = now;
    let monitor_count = watchdog_core::catalog::enabled_monitors(get).len() as i64;
    let width_for_lease = settings.concurrency.max(1);
    let waves = (monitor_count + width_for_lease - 1) / width_for_lease;
    let lease_ms =
        (settings.timeout_ms.saturating_mul(waves.max(1)) + 20_000).clamp(50_000, 180_000);
    if !store
        .acquire_lease("checks", &owner, started + lease_ms, started)
        .await?
    {
        return Ok(());
    }
    let mut cycle_error: Option<String> = None;
    let work = async {
        store
            .mark_run("checks", &owner, Some(started), None, None, None)
            .await?;
        let due = due_monitors(store, get, started).await?;
        let width = settings.concurrency.max(1) as usize;
        for chunk in due.chunks(width) {
            let renew_at = clock.unix_ms();
            if renew_at >= deadline_ms {
                cycle_error = Some("budget_exhausted".to_string());
                break;
            }
            let remaining = (deadline_ms - renew_at).clamp(1_000, settings.timeout_ms);
            if !store
                .renew_lease("checks", &owner, renew_at + lease_ms, renew_at)
                .await?
            {
                cycle_error = Some("lease_lost".to_string());
                break;
            }
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
                    remaining,
                    started,
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
                let Some(before) = before else {
                    cycle_error = Some("monitor_load_failed".to_string());
                    continue;
                };
                match apply_probe(store, settings, get, monitor, &before, &result, started).await {
                    Ok(outcome) => {
                        if !outcome.committed {
                            // A newer generation won. The stale observation is discarded.
                        }
                    }
                    Err(_) => cycle_error = Some("monitor_commit_failed".to_string()),
                }
            }
        }
        let _ = store.prune(clock.unix_ms()).await;
        Ok::<(), watchdog_store::StoreError>(())
    }
    .await;
    let finished = clock.unix_ms();
    let _ = store.release_lease("checks", &owner, finished).await;
    if work.is_err() {
        cycle_error = Some("check_cycle_failed".to_string());
    }
    store
        .mark_run(
            "checks",
            &owner,
            Some(started),
            Some(finished),
            cycle_error.as_deref(),
            cycle_error.is_none().then_some(finished),
        )
        .await?;
    let _ = notifier;
    work
}

pub async fn settle_due<S: OperationalStore, C: Clock>(
    store: &S,
    settings: &Settings,
    get: &impl Fn(&str) -> String,
    clock: &C,
) -> Result<(), watchdog_store::StoreError> {
    let now = clock.unix_ms();
    let ids = store.settlement_ids(now).await?;
    for id in ids {
        let Some(row) = store.read_alert(&id).await? else {
            continue;
        };
        let Some(severity) = Severity::parse(&row.severity) else {
            let _ = store.settle_one(&id, now, None).await?;
            continue;
        };
        let wants_fallback = watchdog_core::settings::fallback_wanted(
            settings,
            get,
            &row.project_id,
            &row.destination,
            severity,
            &row.alert_class,
        ) && fallback_required(
            matches!(
                row.message_state.as_deref(),
                Some("relay_accepted" | "accepted")
            ),
            false,
            row.message_state.as_deref(),
            row.push_state.as_deref(),
            &row.destination,
            severity,
        );
        let fallback = if wants_fallback {
            fallback_draft(settings, get, &row, now)
        } else {
            None
        };
        let _ = store.settle_one(&id, now, fallback.as_ref()).await?;
    }
    Ok(())
}

pub async fn dispatch_due<S: OperationalStore, N: Notifier, C: Clock>(
    store: &S,
    settings: &Settings,
    get: &impl Fn(&str) -> String,
    notifier: &N,
    clock: &C,
    runtime_id: &str,
) -> Result<(), watchdog_store::StoreError> {
    let started = clock.unix_ms();
    let deadline = started + 15_000;
    settle_due(store, settings, get, clock).await?;
    dispatch_transport(
        store, settings, get, notifier, clock, "telegram", 2, 1, deadline, "delivery", runtime_id,
    )
    .await?;
    dispatch_transport(
        store, settings, get, notifier, clock, "nostr", 2, 1, deadline, "delivery", runtime_id,
    )
    .await?;
    dispatch_transport(
        store, settings, get, notifier, clock, "marmot", 1, 1, deadline, "delivery", runtime_id,
    )
    .await?;
    dispatch_transport(
        store, settings, get, notifier, clock, "marmot", 1, 0, deadline, "push", runtime_id,
    )
    .await?;
    Ok(())
}

pub async fn dispatch_transport<S: OperationalStore, N: Notifier, C: Clock>(
    store: &S,
    settings: &Settings,
    get: &impl Fn(&str) -> String,
    notifier: &N,
    clock: &C,
    destination: &str,
    max_critical: usize,
    max_other: usize,
    deadline_ms: i64,
    kind: &str,
    runtime_id: &str,
) -> Result<(), watchdog_store::StoreError> {
    if !settings.alerts_enabled || deadline_ms.saturating_sub(clock.unix_ms()) < 1_500 {
        return Ok(());
    }
    settle_due(store, settings, get, clock).await?;
    if emergency_disabled(settings, destination) {
        let _ = store
            .expedite_destination(destination, clock.unix_ms())
            .await;
    }
    let claim_kind = if kind == "push" {
        "push"
    } else {
        "delivery-critical"
    };
    deliver_claimed(
        store,
        settings,
        get,
        notifier,
        clock,
        destination,
        claim_kind,
        max_critical as i64,
        deadline_ms,
        runtime_id,
    )
    .await?;
    if kind != "push" && max_other > 0 && clock.unix_ms() < deadline_ms {
        deliver_claimed(
            store,
            settings,
            get,
            notifier,
            clock,
            destination,
            "delivery-other",
            max_other as i64,
            deadline_ms,
            runtime_id,
        )
        .await?;
    }
    Ok(())
}

fn emergency_disabled(settings: &Settings, destination: &str) -> bool {
    match destination {
        "nostr" => settings.emergency_disable_nip17,
        "marmot" => settings.emergency_disable_marmot,
        "telegram" => settings.emergency_disable_telegram,
        _ => false,
    }
}

async fn deliver_claimed<S: OperationalStore, N: Notifier, C: Clock>(
    store: &S,
    settings: &Settings,
    get: &impl Fn(&str) -> String,
    notifier: &N,
    clock: &C,
    destination: &str,
    kind: &str,
    limit: i64,
    deadline_ms: i64,
    runtime_id: &str,
) -> Result<(), watchdog_store::StoreError> {
    if limit <= 0 || clock.unix_ms() >= deadline_ms {
        return Ok(());
    }
    let claimed_at = clock.unix_ms();
    let rows = store
        .claim_outbox(
            claimed_at,
            claimed_at
                + settings
                    .delivery_claim_ms
                    .min(deadline_ms - claimed_at)
                    .max(1_000),
            Some(destination),
            limit,
            kind,
            claimed_at - 7 * 86_400_000,
            runtime_id,
        )
        .await?;
    for row in rows {
        if clock.unix_ms() >= deadline_ms {
            release_unstarted(store, &row, clock.unix_ms()).await?;
            continue;
        }
        deliver_one(store, settings, get, notifier, clock, &row).await?;
    }
    Ok(())
}

async fn release_unstarted<S: OperationalStore>(
    store: &S,
    row: &OutboxRow,
    now: i64,
) -> Result<(), watchdog_store::StoreError> {
    let token = row.claim_token.clone().unwrap_or_default();
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
    Ok(())
}

async fn deliver_one<S: OperationalStore, N: Notifier, C: Clock>(
    store: &S,
    settings: &Settings,
    get: &impl Fn(&str) -> String,
    notifier: &N,
    clock: &C,
    row: &OutboxRow,
) -> Result<(), watchdog_store::StoreError> {
    let token = row.claim_token.clone().unwrap_or_default();
    let now = clock.unix_ms();
    let Some(severity) = Severity::parse(&row.severity) else {
        return finish_terminal(store, row, &token, "project_invalid", now).await;
    };
    let availability = availability_for(get, &row.destination);
    let policy = queued_transport(
        settings,
        get,
        &row.project_id,
        &row.destination,
        severity,
        &row.alert_class,
        availability,
    );
    match policy {
        watchdog_core::settings::QueuedTransport::Suppress => {
            return finish_terminal(store, row, &token, "transport_disabled", now).await;
        }
        watchdog_core::settings::QueuedTransport::SuppressWithFallback => {
            let fallback = fallback_draft(settings, get, row, now);
            let _ = store
                .finish_with_fallback(
                    &row.id,
                    &token,
                    DeliveryState::Failed,
                    row.attempt_count,
                    now,
                    Some("transport_disabled"),
                    None,
                    None,
                    None,
                    None,
                    None,
                    None,
                    Some(&logical_notification_key(&row.dedupe_key)),
                    fallback.as_ref(),
                    &watchdog_core::delivery::AuthoritativeCounters::unknown(),
                    now,
                )
                .await?;
            return Ok(());
        }
        watchdog_core::settings::QueuedTransport::Defer => {
            let _ = store
                .finish_delivery(
                    &row.id,
                    &token,
                    DeliveryState::Retrying,
                    row.attempt_count,
                    now + 60_000,
                    Some("transport_unavailable"),
                    None,
                    None,
                    None,
                    None,
                    None,
                    None,
                    now,
                )
                .await?;
            return Ok(());
        }
        watchdog_core::settings::QueuedTransport::Deliver => {}
    }
    if !store
        .extend_claim(&row.id, &token, now + settings.delivery_claim_ms, now)
        .await
        .unwrap_or(false)
    {
        return Ok(());
    }
    let outcome = match Destination::parse(&row.destination) {
        Some(Destination::Telegram) => notifier.deliver_telegram(row).await,
        Some(Destination::Marmot)
            if row.message_state.as_deref() == Some("accepted")
                || row.message_state.as_deref() == Some("accepted_pending") =>
        {
            notifier.deliver_marmot(row, &token).await
        }
        Some(Destination::Marmot) => notifier.deliver_marmot(row, &token).await,
        Some(Destination::Nostr) => notifier.deliver_nostr(row, &token).await,
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
            operation: None,
        },
    };
    let finished = clock.unix_ms();
    let started_at = outcome
        .operation
        .as_ref()
        .and_then(|operation| operation.started_at_ms)
        .or(row.operation_started_at)
        .unwrap_or(row.created_at);
    let counters = outcome
        .operation
        .as_ref()
        .map(|operation| operation.counters)
        .unwrap_or_else(watchdog_core::delivery::AuthoritativeCounters::unknown);
    let message_phase = outcome.operation.as_ref().and_then(|operation| {
        operation
            .message
            .map(watchdog_core::delivery::MessageState::as_str)
    });
    let push_phase = outcome.operation.as_ref().and_then(|operation| {
        operation
            .push
            .map(watchdog_core::delivery::PushState::as_str)
    });
    let report = watchdog_core::delivery::interpret(watchdog_core::delivery::LifecycleInput {
        destination: &row.destination,
        message_phase: message_phase.or(outcome.message_phase.as_deref()),
        push_phase: push_phase.or(outcome.push_phase.as_deref()),
        counters,
        age_ms: finished.saturating_sub(started_at),
        hold: outcome.hold_attempt,
        terminal: outcome.terminal,
        accepted: outcome.accepted,
        ordinary_attempts: row.attempt_count,
        disposition: outcome
            .operation
            .as_ref()
            .map(|operation| operation.disposition),
        retry_after_ms: outcome
            .operation
            .as_ref()
            .and_then(|operation| operation.retry_after_ms),
        permanent_push_uncertainty: outcome
            .operation
            .as_ref()
            .is_some_and(|operation| operation.permanent_push_uncertainty),
    });
    let reconciling = matches!(
        report.decision,
        watchdog_core::delivery::LifecycleDecision::Reconcile { .. }
    );
    let attempt = if reconciling {
        row.attempt_count
    } else {
        row.attempt_count.saturating_add(1)
    };
    let state = match report.decision {
        watchdog_core::delivery::LifecycleDecision::Reconcile { .. }
        | watchdog_core::delivery::LifecycleDecision::Retry { .. } => DeliveryState::Retrying,
        watchdog_core::delivery::LifecycleDecision::Accept => DeliveryState::RelayAccepted,
        watchdog_core::delivery::LifecycleDecision::Fail => DeliveryState::Failed,
    };
    let error = if report.incompatible {
        Some("unknown_transport_state".to_string())
    } else if matches!(
        report.decision,
        watchdog_core::delivery::LifecycleDecision::Fail
    ) && outcome.error.is_none()
    {
        Some("reconciliation_window".to_string())
    } else {
        outcome.error.clone()
    };
    let next_attempt = match report.decision {
        watchdog_core::delivery::LifecycleDecision::Reconcile { retry_ms }
        | watchdog_core::delivery::LifecycleDecision::Retry { retry_ms } => finished + retry_ms,
        _ => finished,
    };
    let message_phase = if report.incompatible {
        None
    } else {
        report
            .message
            .map(watchdog_core::delivery::MessageState::as_str)
    };
    let push_phase = if report.incompatible {
        None
    } else {
        report.push.map(watchdog_core::delivery::PushState::as_str)
    };
    let still_open = matches!(
        report.decision,
        watchdog_core::delivery::LifecycleDecision::Reconcile { .. }
            | watchdog_core::delivery::LifecycleDecision::Retry { .. }
    );
    let needs_fallback = !still_open
        && watchdog_core::settings::fallback_wanted(
            settings,
            get,
            &row.project_id,
            &row.destination,
            severity,
            &row.alert_class,
        )
        && fallback_required(
            matches!(
                report.decision,
                watchdog_core::delivery::LifecycleDecision::Accept
            ),
            false,
            message_phase,
            push_phase,
            &row.destination,
            severity,
        );
    let fallback = if needs_fallback {
        fallback_draft(settings, get, row, finished)
    } else {
        None
    };
    let _owned = store
        .finish_with_fallback(
            &row.id,
            &token,
            state,
            attempt,
            next_attempt,
            error.as_deref(),
            Some(
                &serde_json::to_string(&outcome.accepted_relays)
                    .unwrap_or_else(|_| "[]".to_string()),
            ),
            Some(
                &serde_json::to_string(&outcome.failed_relays).unwrap_or_else(|_| "[]".to_string()),
            ),
            message_phase,
            push_phase,
            outcome.message_event_id.as_deref(),
            outcome.push_envelope.as_deref(),
            Some(&logical_notification_key(&row.dedupe_key)),
            fallback.as_ref(),
            &report.counters,
            finished,
        )
        .await?;
    Ok(())
}

fn availability_for(get: &impl Fn(&str) -> String, destination: &str) -> TransportAvailability {
    match destination {
        "telegram" if get("TELEGRAM_BOT_TOKEN").is_empty() => TransportAvailability::NotConfigured,
        "marmot" => TransportAvailability::Ready,
        _ => TransportAvailability::Ready,
    }
}

async fn finish_terminal<S: OperationalStore>(
    store: &S,
    row: &OutboxRow,
    token: &str,
    error: &str,
    now: i64,
) -> Result<(), watchdog_store::StoreError> {
    let _ = store
        .finish_delivery(
            &row.id,
            token,
            DeliveryState::Failed,
            row.attempt_count,
            now,
            Some(error),
            None,
            None,
            None,
            None,
            None,
            None,
            now,
        )
        .await?;
    Ok(())
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
    before: &LoadedMemory,
    check: &CheckResult,
    now: i64,
) -> Result<watchdog_store::CommitOutcome, watchdog_store::StoreError> {
    let loaded = before;
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
    Ok(outcome)
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
        && !settings.emergency_disable_telegram
        && telegram_chat(&get("TELEGRAM_CHAT_IDS"), monitor.project_id).is_some()
    {
        drafts.push(draft(
            monitor,
            notice,
            Destination::Telegram,
            &format!("{suffix}:telegram"),
            &format_telegram_notice(
                project.display_name,
                monitor.display_name,
                notice.severity,
                notice.event,
                &notice.incident_id,
            ),
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

fn fallback_draft(
    settings: &Settings,
    get: &impl Fn(&str) -> String,
    row: &OutboxRow,
    _now: i64,
) -> Option<AlertDraft> {
    if project_by_id(&row.project_id).is_none() || row.alert_class == "test" {
        return None;
    }
    let severity = Severity::parse(&row.severity)?;
    if !route_for(settings, get, &row.project_id, severity).telegram {
        return None;
    }
    if telegram_chat(&get("TELEGRAM_CHAT_IDS"), &row.project_id).is_none()
        || get("TELEGRAM_BOT_TOKEN").is_empty()
    {
        return None;
    }
    let event = match row.alert_class.as_str() {
        "recovery" => watchdog_core::domain::NoticeEvent::Close,
        "reminder" => watchdog_core::domain::NoticeEvent::Remind,
        _ => watchdog_core::domain::NoticeEvent::Open,
    };
    Some(AlertDraft {
        id: format!("alt_{}", Uuid::new_v4()),
        alert_class: AlertClass::parse(&row.alert_class).unwrap_or(AlertClass::Outage),
        incident_id: row.incident_id.clone(),
        monitor_id: row.monitor_id.clone(),
        project_id: row.project_id.clone(),
        dedupe_key: format!("fallback:{}", logical_notification_key(&row.dedupe_key)),
        destination: Destination::Telegram,
        severity,
        text: format_telegram_notice(
            project_by_id(&row.project_id)
                .map(|project| project.display_name)
                .unwrap_or(row.project_id.as_str()),
            &row.monitor_id,
            severity,
            event,
            row.incident_id.as_deref().unwrap_or(&row.id),
        ),
    })
}
