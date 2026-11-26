//! Hourly vendor release and advisory checks.
//!
//! One vendor failure does not stop the others. Cached feeds are kept when
//! GitHub is unavailable. An empty advisory list is not treated as "secure".

use std::time::Duration;

use regex::Regex;
use serde_json::Value;
use uuid::Uuid;
use watchdog_core::catalog::{project_by_id, telegram_chat};
use watchdog_core::domain::{
    AlertClass, AlertDraft, Destination, MonitorDefinition, Severity, VendorId,
};
use watchdog_core::format::{format_security_message, format_version_message};
use watchdog_core::security_feed::{
    assess_security, official_github_url, AdvisoryRef, SecurityStatus,
};
use watchdog_core::semver::{latest_stable, update_available, ReleaseRef};
use watchdog_core::settings::{route_for, Settings, TelegramMode};
use watchdog_core::status::VendorView;
use watchdog_store::{OperationalStore, UpstreamRow, VersionRow};

use crate::cycle::{dispatch_due, Notifier};
use crate::probes::{HttpClient, ProbeRequest, ProbeResponse};

struct Feed<T> {
    value: Option<T>,
    fresh: bool,
    error_code: Option<&'static str>,
}

pub async fn run_update_cycle<S: OperationalStore, H: HttpClient, N: Notifier>(
    store: &S,
    settings: &Settings,
    get: &impl Fn(&str) -> String,
    http: &H,
    notifier: &N,
    now: i64,
) -> Result<(), watchdog_store::StoreError> {
    if !settings.enabled {
        return Ok(());
    }
    let owner = Uuid::new_v4().to_string();
    if !store
        .acquire_lease("updates", &owner, now + 600_000, now)
        .await?
    {
        return Ok(());
    }
    store
        .mark_run("updates", Some(now), None, None, None)
        .await?;
    let mut failed = 0;
    let mut incomplete = 0;
    let mut rate_limited = 0;
    let mut partial = 0;
    for monitor in watchdog_core::catalog::enabled_monitors(get) {
        let Some(vendor) = monitor.version_vendor else {
            continue;
        };
        let outcome = match check_vendor(store, settings, get, http, &monitor, vendor, now).await {
            Ok(outcome) => outcome,
            Err(_) => Outcome {
                monitor_id: monitor.id.to_string(),
                vendor: vendor.as_str().to_string(),
                succeeded: false,
                releases_state: "unavailable",
                advisories_state: "unavailable",
                coverage: "unavailable",
                error_code: Some("vendor_check_failed"),
                releases_rate_limited: false,
                advisories_rate_limited: false,
                checked_at: now,
            },
        };
        match outcome.coverage {
            "complete" => {}
            "incomplete" => incomplete += 1,
            "unavailable" => {
                if outcome.error_code == Some("rate_limited") {
                    rate_limited += 1;
                } else {
                    failed += 1;
                }
            }
            _ => {
                if outcome.error_code == Some("rate_limited") {
                    rate_limited += 1;
                } else {
                    partial += 1;
                }
            }
        }
        record_vendor(store, get, &monitor, &outcome).await?;
    }
    let _ = dispatch_due(store, settings, get, notifier, now).await;
    let error = if failed > 0 {
        Some("vendor_checks_failed")
    } else if rate_limited > 0 {
        Some("rate_limited")
    } else if incomplete > 0 {
        Some("coverage_incomplete")
    } else if partial > 0 {
        Some("coverage_partial")
    } else {
        None
    };
    store
        .mark_run(
            "updates",
            None,
            Some(now),
            error,
            error.is_none().then_some(now),
        )
        .await?;
    store.release_lease("updates", &owner, now).await?;
    Ok(())
}

struct Outcome {
    monitor_id: String,
    vendor: String,
    succeeded: bool,
    releases_state: &'static str,
    advisories_state: &'static str,
    coverage: &'static str,
    error_code: Option<&'static str>,
    releases_rate_limited: bool,
    advisories_rate_limited: bool,
    checked_at: i64,
}

async fn check_vendor<S: OperationalStore, H: HttpClient>(
    store: &S,
    settings: &Settings,
    get: &impl Fn(&str) -> String,
    http: &H,
    monitor: &MonitorDefinition,
    vendor: VendorId,
    now: i64,
) -> Result<Outcome, watchdog_store::StoreError> {
    let (owner, repo) = vendor.github();
    let installed = store.installed_version(monitor.id).await?;
    let releases = load_feed(
        store,
        http,
        settings,
        &format!("releases:{}", vendor.as_str()),
        owner,
        repo,
        "releases?per_page=20",
        &get("GITHUB_TOKEN"),
        now,
        parse_releases,
    )
    .await?;
    let advisories = load_feed(
        store,
        http,
        settings,
        &format!("advisories:{}", vendor.as_str()),
        owner,
        repo,
        "security-advisories?per_page=30&state=published",
        &get("GITHUB_TOKEN"),
        now,
        parse_advisories,
    )
    .await?;
    let previous = store.read_version(monitor.id).await?;
    let release_state = source_state(&releases);
    let advisory_state = source_state(&advisories);
    let release_fresh = release_state == "fresh";
    let advisory_fresh = advisory_state == "fresh";
    let latest = if release_fresh {
        releases
            .value
            .as_deref()
            .and_then(|items| latest_stable(items, false))
    } else {
        None
    };
    let comparison = installed
        .as_deref()
        .zip(latest)
        .and_then(|(installed, latest)| update_available(installed, &latest.tag));
    let assessment = assess_security(
        vendor,
        installed.as_deref(),
        if advisory_fresh {
            advisories.value.as_deref()
        } else {
            None
        },
        if release_fresh {
            releases.value.as_deref()
        } else {
            None
        },
    );
    let mut status = assessment.status;
    let mut fingerprint = assessment.fingerprint;
    let mut summary = assessment.summary;
    let mut advisory_url = assessment.advisory_url;
    if installed.is_none() {
        status = if release_fresh || advisory_fresh {
            SecurityStatus::VersionUnavailable
        } else {
            SecurityStatus::Unknown
        };
        fingerprint = "version-unavailable".to_string();
        summary = "No installed version has been observed, so update and security coverage is incomplete. The server was not marked safe or vulnerable.".to_string();
        advisory_url = None;
    } else if status == SecurityStatus::Unknown {
        if let Some(previous) = previous.as_ref() {
            if matches!(
                previous.security_status.as_str(),
                "affected" | "review_recommended"
            ) {
                status = SecurityStatus::parse(&previous.security_status).unwrap_or(status);
                fingerprint = previous.advisory_fingerprint.clone().unwrap_or(fingerprint);
                summary = "A previously confirmed security finding was kept because a newer feed was unavailable.".to_string();
                advisory_url = previous.latest_url.clone();
            }
        }
    }
    let coverage = coverage_for(installed.is_some(), release_fresh, advisory_fresh, status);
    let mut notice = previous
        .as_ref()
        .and_then(|row| row.notice_fingerprint.clone());
    let mut alerts = Vec::new();
    if release_fresh && comparison == Some(true) {
        if let Some(latest) = latest {
            let changed = previous.as_ref().and_then(|row| row.latest.as_deref())
                != Some(latest.tag.as_str());
            if changed {
                alerts.push(version_alert(
                    monitor,
                    installed.as_deref().unwrap_or(""),
                    &latest.tag,
                    &latest.url,
                    now,
                ));
                notice = Some(format!("update:{}", latest.tag));
            }
        }
    }
    let can_alert = status == SecurityStatus::Affected
        || ((status == SecurityStatus::ReviewRecommended
            || status == SecurityStatus::VersionUnavailable)
            && (release_fresh || advisory_fresh));
    let mut reminded = previous.as_ref().and_then(|row| row.security_reminded_at);
    let initial = can_alert
        && previous
            .as_ref()
            .and_then(|row| row.advisory_fingerprint.as_deref())
            != Some(fingerprint.as_str());
    let remind = !initial
        && status == SecurityStatus::Affected
        && previous
            .as_ref()
            .and_then(|row| row.advisory_fingerprint.as_deref())
            == Some(fingerprint.as_str())
        && settings.reminder_seconds > 0
        && reminded.is_some_and(|at| now - at >= settings.reminder_seconds * 1000);
    if initial {
        reminded = Some(now);
        alerts.extend(security_alerts(
            settings,
            get,
            monitor,
            status,
            &fingerprint,
            installed.as_deref(),
            &summary,
            advisory_url.as_deref(),
            now,
            "",
            AlertClass::Security,
        ));
    } else if remind {
        reminded = Some(now);
        let reason = format!("This confirmed finding is still open. {summary}");
        alerts.extend(security_alerts(
            settings,
            get,
            monitor,
            status,
            &fingerprint,
            installed.as_deref(),
            &reason,
            advisory_url.as_deref(),
            now,
            &format!("remind:{now}:"),
            AlertClass::Reminder,
        ));
    }
    if status != SecurityStatus::Affected {
        reminded = None;
    }
    let latest_kept = latest
        .map(|item| item.tag.clone())
        .or_else(|| previous.as_ref().and_then(|row| row.latest.clone()));
    let latest_url = latest
        .map(|item| item.url.clone())
        .or_else(|| previous.as_ref().and_then(|row| row.latest_url.clone()));
    store
        .write_version(
            monitor.id,
            &VersionRow {
                installed: installed.clone(),
                latest: latest_kept,
                latest_url,
                security_status: status.as_str().to_string(),
                advisory_fingerprint: Some(if status == SecurityStatus::Unknown {
                    previous
                        .and_then(|row| row.advisory_fingerprint)
                        .unwrap_or(fingerprint.clone())
                } else {
                    fingerprint.clone()
                }),
                notice_fingerprint: notice,
                security_reminded_at: reminded,
            },
            now,
        )
        .await?;
    for alert in &alerts {
        store.insert_alert(alert, now).await?;
    }
    let error_code = vendor_error(
        coverage,
        release_state,
        advisory_state,
        &releases,
        &advisories,
    );
    Ok(Outcome {
        monitor_id: monitor.id.to_string(),
        vendor: vendor.as_str().to_string(),
        succeeded: coverage == "complete",
        releases_state: release_state,
        advisories_state: advisory_state,
        coverage,
        error_code,
        releases_rate_limited: releases.error_code == Some("rate_limited"),
        advisories_rate_limited: advisories.error_code == Some("rate_limited"),
        checked_at: now,
    })
}

async fn record_vendor<S: OperationalStore>(
    store: &S,
    get: &impl Fn(&str) -> String,
    monitor: &MonitorDefinition,
    outcome: &Outcome,
) -> Result<(), watchdog_store::StoreError> {
    let previous = store.read_vendor(&outcome.monitor_id).await?;
    let rate_limited = outcome.error_code == Some("rate_limited");
    let hard_failure = outcome.coverage == "unavailable" && !rate_limited;
    let consecutive = if outcome.succeeded {
        0
    } else if hard_failure {
        previous
            .as_ref()
            .map(|row| row.consecutive_failures)
            .unwrap_or(0)
            + 1
    } else {
        previous
            .as_ref()
            .map(|row| row.consecutive_failures)
            .unwrap_or(0)
    };
    let releases_failures = source_failures(
        outcome.releases_state,
        outcome.releases_rate_limited,
        previous
            .as_ref()
            .map(|row| row.releases_failures)
            .unwrap_or(0),
    );
    let advisories_failures = source_failures(
        outcome.advisories_state,
        outcome.advisories_rate_limited,
        previous
            .as_ref()
            .map(|row| row.advisories_failures)
            .unwrap_or(0),
    );
    let partial = outcome.coverage == "partial" || outcome.coverage == "policy_only";
    store
        .write_vendor(
            &VendorView {
                monitor_id: outcome.monitor_id.clone(),
                vendor: outcome.vendor.clone(),
                attempted_at: Some(outcome.checked_at),
                succeeded_at: outcome.succeeded.then_some(outcome.checked_at),
                partial_succeeded_at: partial.then_some(outcome.checked_at),
                releases_checked_at: (outcome.releases_state == "fresh")
                    .then_some(outcome.checked_at),
                advisories_checked_at: (outcome.advisories_state == "fresh")
                    .then_some(outcome.checked_at),
                releases_stale: outcome.releases_state != "fresh",
                advisories_stale: outcome.advisories_state != "fresh",
                releases_state: outcome.releases_state.to_string(),
                advisories_state: outcome.advisories_state.to_string(),
                coverage: outcome.coverage.to_string(),
                error_code: outcome.error_code.map(str::to_string),
                consecutive_failures: consecutive,
                releases_failures,
                advisories_failures,
            },
            outcome.checked_at,
        )
        .await?;
    if hard_failure && consecutive == 3 {
        let Some(project) = project_by_id(monitor.project_id) else {
            return Ok(());
        };
        let previous_success = previous.and_then(|row| row.succeeded_at).unwrap_or(0);
        store.insert_alert(
            &AlertDraft {
                id: format!("alt_{}", Uuid::new_v4()),
                alert_class: AlertClass::Integrity,
                incident_id: None,
                monitor_id: monitor.id.to_string(),
                project_id: monitor.project_id.to_string(),
                dedupe_key: format!("integrity:{}:vendor:{previous_success}", monitor.id),
                destination: Destination::Nostr,
                severity: Severity::Warning,
                text: format!(
                    "{} {} security checks failed {consecutive} times ({}). Cached advisories were kept.",
                    project.display_name,
                    monitor.display_name,
                    outcome.error_code.unwrap_or("unavailable")
                ),
            },
            outcome.checked_at,
        ).await?;
        let _ = get;
    }
    Ok(())
}

fn source_failures(state: &str, rate_limited: bool, previous: i64) -> i64 {
    if state == "fresh" {
        0
    } else if rate_limited {
        previous
    } else {
        previous + 1
    }
}

fn source_state<T>(feed: &Feed<T>) -> &'static str {
    if feed.fresh && feed.value.is_some() {
        "fresh"
    } else if feed.error_code == Some("rate_limited") {
        if feed.value.is_some() {
            "stale"
        } else {
            "unavailable"
        }
    } else if feed.value.is_some() {
        "cached"
    } else {
        "unavailable"
    }
}

fn coverage_for(
    installed: bool,
    release_fresh: bool,
    advisory_fresh: bool,
    status: SecurityStatus,
) -> &'static str {
    if !installed {
        return if release_fresh || advisory_fresh {
            "incomplete"
        } else {
            "unavailable"
        };
    }
    if release_fresh && advisory_fresh {
        "complete"
    } else if release_fresh || advisory_fresh {
        "partial"
    } else if status == SecurityStatus::Affected {
        "policy_only"
    } else {
        "unavailable"
    }
}

fn vendor_error<T, U>(
    coverage: &str,
    releases: &str,
    advisories: &str,
    release_feed: &Feed<T>,
    advisory_feed: &Feed<U>,
) -> Option<&'static str> {
    if coverage == "incomplete" {
        return Some("coverage_incomplete");
    }
    if coverage == "complete" {
        return None;
    }
    if release_feed.error_code == Some("rate_limited")
        || advisory_feed.error_code == Some("rate_limited")
    {
        return Some("rate_limited");
    }
    if coverage == "policy_only" || coverage == "unavailable" {
        return Some(
            if releases == "unavailable" && advisories == "unavailable" {
                "feeds_unavailable"
            } else {
                "feeds_not_fresh"
            },
        );
    }
    if releases != "fresh" {
        return Some(release_feed.error_code.unwrap_or("releases_cached"));
    }
    if advisories != "fresh" {
        return Some(advisory_feed.error_code.unwrap_or("advisories_cached"));
    }
    None
}

async fn load_feed<T, S: OperationalStore, H: HttpClient>(
    store: &S,
    http: &H,
    settings: &Settings,
    key: &str,
    owner: &str,
    repo: &str,
    query: &str,
    token: &str,
    now: i64,
    parse: fn(&Value) -> Option<T>,
) -> Result<Feed<T>, watchdog_store::StoreError>
where
    T: serde::Serialize + serde::de::DeserializeOwned,
{
    let cache = store.read_upstream(key).await?;
    if cache
        .as_ref()
        .and_then(|row| row.rate_limited_until)
        .is_some_and(|until| until > now)
    {
        return Ok(Feed {
            value: cache
                .as_ref()
                .and_then(|row| decode(row.payload_json.as_deref())),
            fresh: false,
            error_code: Some("rate_limited"),
        });
    }
    let path = format!("/repos/{owner}/{repo}/{query}");
    let fetched = request_github(
        &settings.github_api,
        &path,
        token,
        cache.as_ref().and_then(|row| row.etag.as_deref()),
        settings.timeout_ms,
        http,
    )
    .await;
    match fetched {
        Github::NotModified => Ok(Feed {
            value: cache
                .as_ref()
                .and_then(|row| decode(row.payload_json.as_deref())),
            fresh: cache
                .as_ref()
                .and_then(|row| row.payload_json.as_ref())
                .is_some(),
            error_code: None,
        }),
        Github::RateLimited(retry_at) => {
            store
                .write_upstream(
                    key,
                    &UpstreamRow {
                        etag: cache.as_ref().and_then(|row| row.etag.clone()),
                        payload_json: cache.as_ref().and_then(|row| row.payload_json.clone()),
                        fetched_at: cache.as_ref().map(|row| row.fetched_at).unwrap_or(now),
                        rate_limited_until: retry_at,
                    },
                )
                .await?;
            Ok(Feed {
                value: cache.and_then(|row| decode(row.payload_json.as_deref())),
                fresh: false,
                error_code: Some("rate_limited"),
            })
        }
        Github::Unavailable => Ok(Feed {
            value: cache.and_then(|row| decode(row.payload_json.as_deref())),
            fresh: false,
            error_code: Some("unavailable"),
        }),
        Github::Ok { etag, body } => {
            let Some(parsed) = parse(&body) else {
                return Ok(Feed {
                    value: cache.and_then(|row| decode(row.payload_json.as_deref())),
                    fresh: false,
                    error_code: Some("unavailable"),
                });
            };
            store
                .write_upstream(
                    key,
                    &UpstreamRow {
                        etag,
                        payload_json: serde_json::to_string(&parsed).ok(),
                        fetched_at: now,
                        rate_limited_until: None,
                    },
                )
                .await?;
            Ok(Feed {
                value: Some(parsed),
                fresh: true,
                error_code: None,
            })
        }
    }
}

enum Github {
    Ok { etag: Option<String>, body: Value },
    NotModified,
    RateLimited(Option<i64>),
    Unavailable,
}

async fn request_github<H: HttpClient>(
    api_base: &str,
    path: &str,
    token: &str,
    etag: Option<&str>,
    timeout_ms: i64,
    http: &H,
) -> Github {
    let base = if api_base.ends_with('/') {
        api_base.to_string()
    } else {
        format!("{api_base}/")
    };
    let Ok(url) = url::Url::parse(&base).and_then(|base| base.join(path.trim_start_matches('/')))
    else {
        return Github::Unavailable;
    };
    let host = url.host_str().unwrap_or("");
    if url.scheme() != "https" || (host != "api.github.com" && !host.ends_with(".github.com")) {
        return Github::Unavailable;
    }
    let mut headers = std::collections::HashMap::from([
        (
            "accept".to_string(),
            "application/vnd.github+json".to_string(),
        ),
        ("user-agent".to_string(), "nostr-watchdog".to_string()),
        ("x-github-api-version".to_string(), "2022-11-28".to_string()),
    ]);
    if let Some(etag) = etag {
        headers.insert("if-none-match".to_string(), etag.to_string());
    }
    if !token.is_empty() {
        headers.insert("authorization".to_string(), format!("Bearer {token}"));
    }
    let Ok(response) = http
        .send(ProbeRequest {
            method: "GET",
            url: url.to_string(),
            headers,
            timeout: Duration::from_millis(timeout_ms as u64),
            max_bytes: 262_144,
            allow_private: false,
        })
        .await
    else {
        return Github::Unavailable;
    };
    classify_github(response)
}

fn classify_github(response: ProbeResponse) -> Github {
    if response.status == 304 {
        return Github::NotModified;
    }
    if (300..400).contains(&response.status) || response.too_large {
        return Github::Unavailable;
    }
    if response.status == 403 || response.status == 429 {
        let retry_at = response
            .headers
            .get("x-ratelimit-reset")
            .and_then(|value| value.parse::<i64>().ok())
            .map(|seconds| seconds * 1000);
        return Github::RateLimited(retry_at);
    }
    if !(200..300).contains(&response.status) {
        return Github::Unavailable;
    }
    match serde_json::from_slice::<Value>(&response.body) {
        Ok(body) => Github::Ok {
            etag: response.headers.get("etag").cloned(),
            body,
        },
        Err(_) => Github::Unavailable,
    }
}

fn parse_releases(body: &Value) -> Option<Vec<ReleaseRef>> {
    let items = body.as_array()?;
    let mut releases = Vec::new();
    for item in items {
        let tag = item.get("tag_name")?.as_str()?;
        let url = official_github_url(item.get("html_url").and_then(Value::as_str).unwrap_or(""))?;
        let name = item.get("name").and_then(Value::as_str).unwrap_or("");
        let text = item.get("body").and_then(Value::as_str).unwrap_or("");
        releases.push(ReleaseRef {
            tag: tag.to_string(),
            url,
            prerelease: item
                .get("prerelease")
                .and_then(Value::as_bool)
                .unwrap_or(false),
            draft: item.get("draft").and_then(Value::as_bool).unwrap_or(false),
            security_related: security_hint(&format!(
                "{name}\n{}",
                text.chars().take(8_000).collect::<String>()
            )),
        });
    }
    Some(releases)
}

fn parse_advisories(body: &Value) -> Option<Vec<AdvisoryRef>> {
    let items = body.as_array()?;
    let mut advisories = Vec::new();
    for item in items {
        let id = item.get("ghsa_id")?.as_str()?;
        if item
            .get("state")
            .and_then(Value::as_str)
            .is_some_and(|state| state != "published")
        {
            continue;
        }
        let url = official_github_url(item.get("html_url").and_then(Value::as_str).unwrap_or(""))?;
        let mut ranges = Vec::new();
        if let Some(vulnerabilities) = item.get("vulnerabilities").and_then(Value::as_array) {
            for vulnerability in vulnerabilities {
                if let Some(range) = vulnerability
                    .get("vulnerable_version_range")
                    .and_then(Value::as_str)
                {
                    if !range.trim().is_empty() {
                        ranges.push(range.trim().to_string());
                    }
                }
            }
        }
        advisories.push(AdvisoryRef {
            id: id.to_string(),
            url,
            severity: item
                .get("severity")
                .and_then(Value::as_str)
                .map(str::to_string),
            ranges,
        });
    }
    Some(advisories)
}

fn security_hint(text: &str) -> bool {
    Regex::new(r"(?i)\b(security|vulnerabilit(?:y|ies)|cve-\d{4}-\d+|ghsa-[0-9a-z-]+|advisory)\b")
        .is_ok_and(|pattern| pattern.is_match(text))
}

fn decode<T: serde::de::DeserializeOwned>(payload: Option<&str>) -> Option<T> {
    serde_json::from_str(payload?).ok()
}

fn version_alert(
    monitor: &MonitorDefinition,
    installed: &str,
    latest: &str,
    url: &str,
    now: i64,
) -> AlertDraft {
    let project = project_by_id(monitor.project_id)
        .map(|item| item.display_name)
        .unwrap_or(monitor.project_id);
    AlertDraft {
        id: format!("alt_{}", Uuid::new_v4()),
        alert_class: AlertClass::Update,
        incident_id: None,
        monitor_id: monitor.id.to_string(),
        project_id: monitor.project_id.to_string(),
        dedupe_key: format!("update:{}:{latest}:nostr", monitor.id),
        destination: Destination::Nostr,
        severity: Severity::Info,
        text: format_version_message(project, monitor.display_name, installed, latest, url, now),
    }
}

fn security_alerts(
    settings: &Settings,
    get: &impl Fn(&str) -> String,
    monitor: &MonitorDefinition,
    status: SecurityStatus,
    fingerprint: &str,
    installed: Option<&str>,
    summary: &str,
    url: Option<&str>,
    now: i64,
    suffix: &str,
    class: AlertClass,
) -> Vec<AlertDraft> {
    let project = project_by_id(monitor.project_id)
        .map(|item| item.display_name)
        .unwrap_or(monitor.project_id);
    let severity = if status == SecurityStatus::Affected {
        Severity::Critical
    } else {
        Severity::Warning
    };
    let text = format_security_message(
        project,
        monitor.display_name,
        severity,
        installed,
        summary,
        url,
        now,
        Some(status.as_str()),
    );
    let route = route_for(settings, get, monitor.project_id, severity);
    let mut drafts = Vec::new();
    if route.nip17 {
        drafts.push(security_draft(
            monitor,
            severity,
            fingerprint,
            Destination::Nostr,
            &text,
            suffix,
            class,
        ));
    }
    if route.marmot {
        drafts.push(security_draft(
            monitor,
            severity,
            fingerprint,
            Destination::Marmot,
            &text,
            suffix,
            class,
        ));
    }
    if severity == Severity::Critical
        && settings.telegram_mode == TelegramMode::Dual
        && telegram_chat(&get("TELEGRAM_CHAT_IDS"), monitor.project_id).is_some()
    {
        drafts.push(security_draft(
            monitor,
            severity,
            fingerprint,
            Destination::Telegram,
            &text,
            suffix,
            class,
        ));
    }
    drafts
}

fn security_draft(
    monitor: &MonitorDefinition,
    severity: Severity,
    fingerprint: &str,
    destination: Destination,
    text: &str,
    suffix: &str,
    class: AlertClass,
) -> AlertDraft {
    AlertDraft {
        id: format!("alt_{}", Uuid::new_v4()),
        alert_class: class,
        incident_id: None,
        monitor_id: monitor.id.to_string(),
        project_id: monitor.project_id.to_string(),
        dedupe_key: format!(
            "security:{}:{fingerprint}:{suffix}{}",
            monitor.id,
            destination.as_str()
        ),
        destination,
        severity,
        text: text.to_string(),
    }
}

#[cfg(test)]
mod tests {
    use std::collections::HashMap;

    use watchdog_core::settings::load_settings;
    use watchdog_store::{OutboxRow, SqliteStore};

    use super::*;
    use crate::cycle::DeliveryOutcome;
    use crate::probes::{HttpClient, ProbeRequest, ProbeResponse};

    struct Scripted;

    impl HttpClient for Scripted {
        async fn send(&self, request: ProbeRequest) -> Result<ProbeResponse, String> {
            let body = if request.url.contains("security-advisories") {
                b"[]".to_vec()
            } else if request.url.contains("releases") {
                br#"[{"tag_name":"v2.4.2","html_url":"https://github.com/btcpayserver/btcpayserver/releases/tag/v2.4.2","prerelease":false,"draft":false,"name":"2.4.2","body":""}]"#.to_vec()
            } else {
                return Err("unexpected url".to_string());
            };
            Ok(ProbeResponse {
                status: 200,
                headers: HashMap::new(),
                body,
                too_large: false,
            })
        }
    }

    struct Silent;

    fn pending() -> DeliveryOutcome {
        DeliveryOutcome {
            accepted: false,
            terminal: false,
            error: Some("delivery_deferred".to_string()),
            accepted_relays: Vec::new(),
            failed_relays: Vec::new(),
            message_phase: None,
            push_phase: None,
            message_event_id: None,
            push_envelope: None,
        }
    }

    impl Notifier for Silent {
        async fn deliver_nostr(&self, _row: &OutboxRow, _claim: &str) -> DeliveryOutcome {
            pending()
        }
        async fn deliver_telegram(&self, _row: &OutboxRow) -> DeliveryOutcome {
            pending()
        }
        async fn deliver_marmot(&self, _row: &OutboxRow, _claim: &str) -> DeliveryOutcome {
            pending()
        }
    }

    #[tokio::test]
    async fn missing_installed_version_is_not_reported_as_secure() {
        let store = SqliteStore::memory().unwrap();
        let get = |key: &str| match key {
            "ENABLE_SFS_BTCPAY" => "true".to_string(),
            "WATCHDOG_ENABLED" => "true".to_string(),
            _ => String::new(),
        };
        let settings = load_settings(get);
        run_update_cycle(&store, &settings, &get, &Scripted, &Silent, 1_000)
            .await
            .unwrap();
        let version = store.read_version("sfs-btcpay").unwrap().unwrap();
        assert_eq!(version.security_status, "version_unavailable");
        assert_eq!(version.latest.as_deref(), Some("v2.4.2"));
        let vendor = store.read_vendor("sfs-btcpay").unwrap().unwrap();
        assert_eq!(vendor.coverage, "incomplete");
        assert_ne!(vendor.error_code.as_deref(), Some("secure"));
    }
}
