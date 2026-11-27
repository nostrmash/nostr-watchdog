use regex::Regex;
use std::sync::OnceLock;

fn patterns() -> &'static [Regex] {
    static PATTERNS: OnceLock<Vec<Regex>> = OnceLock::new();
    PATTERNS.get_or_init(|| {
        [
            r"(?i)nsec1[0-9a-z]+",
            r"(?i)npub1[0-9a-z]+",
            r"(?i)bearer\s+\S+",
            r"(?i)\b(?:token|secret|password|authorization)\b\s*[:=]\s*\S+",
            r"(?i)[a-f0-9]{32,}",
            r"(?i)[a-z]+://[^/\s:@]+:[^/\s@]+@",
        ]
        .into_iter()
        .map(|pattern| Regex::new(pattern).expect("redaction pattern"))
        .collect()
    })
}

pub fn sanitize_text(value: &str, max: usize) -> String {
    let mut text = value.split_whitespace().collect::<Vec<_>>().join(" ");
    for pattern in patterns() {
        text = pattern.replace_all(&text, "[redacted]").into_owned();
    }
    if text.chars().count() > max {
        let mut truncated: String = text.chars().take(max.saturating_sub(1)).collect();
        truncated.push('…');
        return truncated;
    }
    text
}

pub fn safe_version(value: Option<&str>) -> Option<String> {
    let trimmed = value?.trim();
    if (1..=40).contains(&trimmed.len())
        && trimmed
            .chars()
            .all(|ch| ch.is_ascii_alphanumeric() || matches!(ch, '.' | '_' | '+' | '-'))
    {
        Some(trimmed.to_string())
    } else {
        None
    }
}

pub fn redact_log_key(key: &str) -> bool {
    let key = key.to_ascii_lowercase();
    [
        "token",
        "secret",
        "nsec",
        "authorization",
        "password",
        "seed",
        "api_key",
        "api-key",
        "apikey",
        "credential",
        "cookie",
        "push",
    ]
    .iter()
    .any(|needle| key.contains(needle))
}
