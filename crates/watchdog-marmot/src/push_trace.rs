//! Diagnostic capture of MDK push warnings.
//!
//! `publish_notification_trigger_best_effort` logs a warning and discards the
//! event id. Background workers can emit that warning for a different message
//! while this process is submitting. Those warnings stay diagnostic. They do
//! not select an alert's push state.

use std::sync::atomic::{AtomicU64, Ordering};

use tracing::field::{Field, Visit};
use tracing::Subscriber;
use tracing_subscriber::layer::Context;
use tracing_subscriber::Layer;

static DIAGNOSTICS: AtomicU64 = AtomicU64::new(0);

pub fn install() {
    use std::sync::Once;
    static ONCE: Once = Once::new();
    ONCE.call_once(|| {
        use tracing_subscriber::layer::SubscriberExt;
        use tracing_subscriber::util::SubscriberInitExt;
        let _ = tracing_subscriber::registry()
            .with(PushPublishCapture)
            .try_init();
    });
}

/// Warnings observed since process start. Not keyed to an operation.
#[allow(dead_code)]
pub fn diagnostic_warnings() -> u64 {
    DIAGNOSTICS.load(Ordering::Relaxed)
}

/// No warning from this layer is evidence about a particular alert.
pub fn operation_push_failure() -> Option<String> {
    None
}

struct PushPublishCapture;

impl<S> Layer<S> for PushPublishCapture
where
    S: Subscriber,
{
    fn on_event(&self, event: &tracing::Event<'_>, _ctx: Context<'_, S>) {
        if event.metadata().target() != "marmot_app::notifications"
            || *event.metadata().level() != tracing::Level::WARN
        {
            return;
        }
        let mut visitor = KindVisitor::default();
        event.record(&mut visitor);
        if visitor.failed {
            DIAGNOSTICS.fetch_add(1, Ordering::Relaxed);
            let _ = visitor.kind;
        }
    }
}

#[derive(Default)]
struct KindVisitor {
    failed: bool,
    kind: Option<String>,
}

impl Visit for KindVisitor {
    fn record_str(&mut self, field: &Field, value: &str) {
        self.note(field.name(), value);
    }

    fn record_debug(&mut self, field: &Field, value: &dyn std::fmt::Debug) {
        self.note(field.name(), &format!("{value:?}"));
    }
}

impl KindVisitor {
    fn note(&mut self, name: &str, value: &str) {
        let value = value.trim_matches('"');
        match name {
            "message" if value.contains("notification trigger publish failed") => {
                self.failed = true;
            }
            "error_kind" => {
                self.kind = Some(sanitize_error_kind(value));
            }
            _ => {}
        }
    }
}

pub fn sanitize_error_kind(value: &str) -> String {
    let trimmed = value.trim_matches('"');
    let lower = trimmed.to_ascii_lowercase();
    if lower.contains("nsec") || lower.contains("token") || trimmed.contains("nsec1") {
        return "publish_failed".to_string();
    }
    let cleaned: String = trimmed
        .chars()
        .filter(|ch| ch.is_ascii_alphanumeric() || matches!(*ch, '_' | '-' | ':'))
        .take(48)
        .collect();
    if cleaned.is_empty() {
        "publish_failed".to_string()
    } else {
        cleaned
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn error_kinds_drop_secrets_and_stay_short() {
        assert_eq!(sanitize_error_kind("Transport"), "Transport");
        assert_eq!(sanitize_error_kind("nsec1secret"), "publish_failed");
        assert_eq!(sanitize_error_kind("device token abc"), "publish_failed");
        assert_eq!(sanitize_error_kind("a b"), "ab");
    }

    #[test]
    fn a_warning_is_not_an_operation_result() {
        assert!(operation_push_failure().is_none());
        let _ = diagnostic_warnings();
    }
}
