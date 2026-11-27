//! Readiness is stricter than a database ping.
//!
//! A disabled optional transport is healthy. An enabled transport this runtime
//! cannot provide is not ready. Unknown Marmot or push-token state is reported
//! as unknown and does not, by itself, fail readiness. Historical dead letters
//! do not fail readiness. A mandatory transport that is known to be unavailable
//! does.

use serde_json::{json, Value};

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ReadinessInput {
    pub database_ok: bool,
    pub schema_ok: bool,
    pub configuration_ok: bool,
    pub monitors_enabled: bool,
    pub scheduler_age_ms: Option<i64>,
    pub scheduler_stale_after_ms: i64,
    pub nip17_enabled: bool,
    pub nip17_ready: bool,
    pub telegram_enabled: bool,
    pub telegram_ready: bool,
    pub marmot_enabled: bool,
    /// `disabled`, `ready`, `unavailable`, `degraded`, or `unknown`.
    pub marmot_state: &'static str,
    /// `disabled`, `ready`, `missing`, or `unknown`.
    pub push_tokens: &'static str,
    pub projects_ready: bool,
    pub pending_recovery: i64,
    pub recent_retrying: i64,
    /// True only during the documented startup window before the first success.
    pub startup_grace: bool,
}

pub fn evaluate_readiness(input: &ReadinessInput) -> (bool, Value) {
    let scheduler = if !input.monitors_enabled {
        "idle"
    } else if input
        .scheduler_age_ms
        .is_some_and(|age| age <= input.scheduler_stale_after_ms)
    {
        "fresh"
    } else if input.scheduler_age_ms.is_none() && input.startup_grace {
        "starting"
    } else if input.scheduler_age_ms.is_none() {
        "uninitialized"
    } else {
        "stale"
    };
    let marmot_blocks =
        input.marmot_enabled && matches!(input.marmot_state, "unavailable" | "unconfigured");
    let nip17_blocks = input.nip17_enabled && !input.nip17_ready;
    let telegram_blocks = input.telegram_enabled && !input.telegram_ready;
    let scheduler_blocks = scheduler == "stale" || scheduler == "uninitialized";
    let ready = input.database_ok
        && input.schema_ok
        && input.configuration_ok
        && input.projects_ready
        && !marmot_blocks
        && !nip17_blocks
        && !telegram_blocks
        && !scheduler_blocks;
    let body = json!({
        "ready": ready,
        "database": if input.database_ok { "ok" } else { "unavailable" },
        "schema": if input.schema_ok { "ok" } else { "not_ready" },
        "configuration": if input.configuration_ok { "ok" } else { "invalid" },
        "scheduler": scheduler,
        "projects": if input.projects_ready { "ok" } else { "incomplete" },
        "transports": {
            "nip17": transport_label(input.nip17_enabled, input.nip17_ready),
            "telegram": transport_label(input.telegram_enabled, input.telegram_ready),
            "marmot": input.marmot_state,
        },
        "pushTokens": input.push_tokens,
        "pendingRecovery": input.pending_recovery,
        "recentRetrying": input.recent_retrying,
        "policy": "Disabled optional transports are ignored. Unknown Marmot and push-token state do not fail readiness. An enabled mandatory transport that is unavailable does. A scheduler that has never succeeded is not ready after the startup grace. Historical dead letters do not.",
    });
    (ready, body)
}

fn transport_label(enabled: bool, ready: bool) -> &'static str {
    if !enabled {
        "disabled"
    } else if ready {
        "ready"
    } else {
        "unavailable"
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn base() -> ReadinessInput {
        ReadinessInput {
            database_ok: true,
            schema_ok: true,
            configuration_ok: true,
            monitors_enabled: true,
            scheduler_age_ms: Some(1_000),
            scheduler_stale_after_ms: 180_000,
            nip17_enabled: true,
            nip17_ready: true,
            telegram_enabled: false,
            telegram_ready: false,
            marmot_enabled: false,
            marmot_state: "disabled",
            push_tokens: "unknown",
            projects_ready: true,
            pending_recovery: 0,
            recent_retrying: 0,
            startup_grace: false,
        }
    }

    #[test]
    fn disabled_optional_transport_stays_ready_and_unknown_marmot_does_not_fail() {
        let (ready, body) = evaluate_readiness(&base());
        assert!(ready);
        assert_eq!(body["transports"]["telegram"], "disabled");
        assert_eq!(body["pushTokens"], "unknown");
        let mut unknown = base();
        unknown.marmot_enabled = true;
        unknown.marmot_state = "unknown";
        assert!(evaluate_readiness(&unknown).0);
        unknown.marmot_state = "unavailable";
        assert!(!evaluate_readiness(&unknown).0);
    }

    #[test]
    fn stale_scheduler_and_historical_retries_follow_the_policy() {
        let mut stale = base();
        stale.scheduler_age_ms = Some(500_000);
        assert!(!evaluate_readiness(&stale).0);
        let mut history = base();
        history.pending_recovery = 40;
        history.recent_retrying = 2;
        let (ready, body) = evaluate_readiness(&history);
        assert!(ready);
        assert_eq!(body["pendingRecovery"], 40);
    }
}
