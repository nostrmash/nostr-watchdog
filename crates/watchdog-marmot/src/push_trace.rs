//! Records the one push-publish failure MDK actually logs.
//!
//! `publish_notification_trigger_best_effort` swallows the error after a
//! `tracing` warning. Success is not logged and the event id is discarded.
//! This layer keeps the privacy-safe `error_kind` only.

use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Mutex;

use tracing::field::{Field, Visit};
use tracing::Subscriber;
use tracing_subscriber::layer::Context;
use tracing_subscriber::Layer;

static FAILURES: Mutex<Vec<(u64, String)>> = Mutex::new(Vec::new());
static GENERATION: AtomicU64 = AtomicU64::new(1);

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

/// Starts one submission's observation window. Later warnings keep this id,
/// so a refresh can see a failure that MDK logs after `submit_text` returns.
pub fn begin_submit() -> u64 {
    let generation = GENERATION.fetch_add(1, Ordering::Relaxed) + 1;
    if let Ok(mut failures) = FAILURES.lock() {
        failures.retain(|(id, _)| generation.saturating_sub(*id) < 8);
    }
    generation
}

pub fn observed_for(generation: u64) -> Option<String> {
    FAILURES.lock().ok().and_then(|failures| {
        failures
            .iter()
            .rev()
            .find(|(id, _)| *id == generation)
            .map(|(_, kind)| kind.clone())
    })
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
            if let Ok(mut failures) = FAILURES.lock() {
                let generation = GENERATION.load(Ordering::Relaxed);
                failures.push((
                    generation,
                    visitor.kind.unwrap_or_else(|| "publish_failed".to_string()),
                ));
            }
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
}
