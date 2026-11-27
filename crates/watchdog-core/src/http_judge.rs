use serde_json::Value;

use crate::domain::{
    check_result, misconfigured, unknown_result, CheckResult, HttpCheckSpec, MonitorStatus,
};
use crate::json_pointer::read_pointer;

#[derive(Clone, Debug)]
pub struct HttpObservation {
    pub status: u16,
    pub body: Option<Value>,
    pub too_large: bool,
    pub not_json: bool,
    pub latency_ms: i64,
}

pub fn judge_http(spec: &HttpCheckSpec, observation: &HttpObservation) -> CheckResult {
    let latency = Some(observation.latency_ms);
    if observation.too_large {
        return unknown_result(
            "The readiness response exceeded the size limit.",
            "schema",
            latency,
        );
    }
    if matches!(observation.status, 401 | 403) {
        return misconfigured("The readiness endpoint rejected the request.", latency);
    }
    if observation.status == 404 {
        return misconfigured("The readiness endpoint was not found.", latency);
    }
    if observation.status == 429 {
        return unknown_result(
            "The readiness endpoint was rate limited.",
            "rate_limit",
            latency,
        );
    }
    if observation.not_json {
        return unknown_result("The readiness response was not JSON.", "schema", latency);
    }
    if let Some(map) = &spec.status_from_body {
        return status_from_body(observation, spec, map).unwrap_or_else(|| {
            check_result(
                MonitorStatus::Down,
                Some("predicate"),
                "The readiness response did not match its status contract.",
                latency,
                None,
            )
        });
    }
    if !spec.expected_statuses.contains(&observation.status) {
        return check_result(
            MonitorStatus::Down,
            Some("http_status"),
            "The readiness endpoint returned an unexpected status.",
            latency,
            None,
        );
    }
    let body = observation.body.as_ref().unwrap_or(&Value::Null);
    for predicate in &spec.predicates {
        if read_pointer(body, predicate.pointer) != Some(&predicate.equals) {
            return check_result(
                MonitorStatus::Down,
                Some("predicate"),
                "The readiness response did not match its success contract.",
                latency,
                None,
            );
        }
    }
    check_result(
        MonitorStatus::Healthy,
        None,
        "The readiness contract passed.",
        latency,
        None,
    )
}

fn status_from_body(
    observation: &HttpObservation,
    spec: &HttpCheckSpec,
    map: &crate::domain::HttpStatusMap,
) -> Option<CheckResult> {
    let body = observation.body.as_ref()?;
    let value = read_pointer(body, map.pointer)?.as_str()?;
    let latency = Some(observation.latency_ms);
    if value == map.healthy && spec.expected_statuses.contains(&observation.status) {
        return Some(check_result(
            MonitorStatus::Healthy,
            None,
            "The readiness contract passed.",
            latency,
            None,
        ));
    }
    if map.degraded == Some(value) && observation.status == 200 {
        return Some(check_result(
            MonitorStatus::Degraded,
            Some("partial"),
            "The endpoint is only partly available.",
            latency,
            None,
        ));
    }
    if map.down == Some(value) {
        return Some(check_result(
            MonitorStatus::Down,
            Some("http_status"),
            "The endpoint reported that it is down.",
            latency,
            None,
        ));
    }
    if map.misconfigured == Some(value) {
        return Some(misconfigured(
            "The endpoint reported that it is misconfigured.",
            latency,
        ));
    }
    None
}
