use crate::domain::Severity;
use crate::domain::VendorId;
use crate::semver::{parse_semver, satisfies_range, update_available, ReleaseRef};

#[derive(Clone, Debug, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct AdvisoryRef {
    pub id: String,
    pub url: String,
    pub severity: Option<String>,
    pub ranges: Vec<String>,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum SecurityStatus {
    Unknown,
    VersionUnavailable,
    ReviewRecommended,
    Affected,
    NoPublishedAdvisories,
    OutsidePublishedRanges,
}

impl SecurityStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Unknown => "unknown",
            Self::VersionUnavailable => "version_unavailable",
            Self::ReviewRecommended => "review_recommended",
            Self::Affected => "affected",
            Self::NoPublishedAdvisories => "no_published_advisories",
            Self::OutsidePublishedRanges => "outside_published_ranges",
        }
    }

    pub fn parse(value: &str) -> Option<Self> {
        Some(match value {
            "unknown" => Self::Unknown,
            "version_unavailable" => Self::VersionUnavailable,
            "review_recommended" => Self::ReviewRecommended,
            "affected" => Self::Affected,
            "no_published_advisories" => Self::NoPublishedAdvisories,
            "outside_published_ranges" => Self::OutsidePublishedRanges,
            _ => return None,
        })
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SecurityAssessment {
    pub status: SecurityStatus,
    pub fingerprint: String,
    pub advisory_url: Option<String>,
    pub summary: String,
}

#[derive(Clone, Debug)]
pub struct ConfirmedAdvisory {
    pub id: &'static str,
    pub vendor_id: VendorId,
    pub url: &'static str,
    pub summary: &'static str,
    pub ranges: &'static [&'static str],
    pub verified_on: &'static str,
    pub source_note: &'static str,
}

pub static VENDOR_POLICY: &[ConfirmedAdvisory] = &[
    ConfirmedAdvisory {
        id: "btcpay-2026-08-lnd-macaroon",
        vendor_id: VendorId::BtcpayServer,
        url: "https://blog.btcpayserver.org/security-advisory-btcpay-server-2-4-2/",
        summary: "BTCPay Server versions before 2.4.2, including 2.4.2 release candidates, contain the vulnerability fixed in 2.4.2. The vendor says LND credential theft is the exploited case and still asks every earlier version to update.",
        ranges: &["< 2.4.2"],
        verified_on: "2026-11-22",
        source_note: "Official BTCPay Server blog post published 2026-08-07, cross-checked with the v2.4.2 GitHub release. This does not say whether a particular server uses LND.",
    },
    ConfirmedAdvisory {
        id: "btcpay-2026-11-incident",
        vendor_id: VendorId::BtcpayServer,
        url: "https://blog.btcpayserver.org/btcpay-server-security-incident-2-4-1-and-earlier/",
        summary: "The November 2026 BTCPay Server incident affected 2.4.1 and earlier. The vendor reported no thefts against servers already on 2.4.2 or later. Updating a previously exposed server does not undo a compromise.",
        ranges: &["<= 2.4.1"],
        verified_on: "2026-11-22",
        source_note: "Official BTCPay Server blog post published 2026-11-02. Checked again on 2026-11-22. The watchdog reports version exposure only.",
    },
];

pub fn policy_for(vendor_id: VendorId) -> Vec<&'static ConfirmedAdvisory> {
    VENDOR_POLICY
        .iter()
        .filter(|entry| entry.vendor_id == vendor_id)
        .collect()
}

pub fn assess_security(
    vendor_id: VendorId,
    installed: Option<&str>,
    advisories: Option<&[AdvisoryRef]>,
    releases: Option<&[ReleaseRef]>,
) -> SecurityAssessment {
    let policy = policy_for(vendor_id);
    let Some(installed) = installed else {
        return SecurityAssessment {
            status: SecurityStatus::VersionUnavailable,
            fingerprint: "version-unavailable".to_string(),
            advisory_url: None,
            summary: "No installed version has been observed, so security applicability cannot be decided. This is not a healthy security check.".to_string(),
        };
    };
    let definite = definite_matches(installed, advisories, &policy);
    if !definite.is_empty() {
        let mut ids: Vec<&str> = definite.iter().map(|(id, _)| *id).collect();
        ids.sort_unstable();
        return SecurityAssessment {
            status: SecurityStatus::Affected,
            fingerprint: format!("affected:{installed}:{}", ids.join(",")),
            advisory_url: definite.first().map(|(_, url)| (*url).to_string()),
            summary: format!(
                "Installed version {installed} matches a confirmed affected range for {}.",
                ids.join(", ")
            ),
        };
    }
    let security_release = newest_security_release(releases, installed);
    let unparsed = has_unparsed_advisory(installed, advisories);
    if security_release.is_some() || unparsed {
        let mut ids: Vec<String> = advisories
            .unwrap_or(&[])
            .iter()
            .map(|item| item.id.clone())
            .chain(policy.iter().map(|item| item.id.to_string()))
            .collect();
        if let Some(release) = &security_release {
            ids.push(format!("release:{}", release.tag));
        }
        ids.sort();
        let summary = if let Some(release) = &security_release {
            format!(
                "Security-related release {} is newer than {installed}, and no verified affected range confirms impact. Review the release notes before treating this as a vulnerability.",
                release.tag
            )
        } else {
            "Security information exists, but impact on the installed version could not be confirmed. Security review is recommended.".to_string()
        };
        return SecurityAssessment {
            status: SecurityStatus::ReviewRecommended,
            fingerprint: format!("review:{installed}:{}", ids.join(",")),
            advisory_url: security_release
                .map(|release| release.url.clone())
                .or_else(|| {
                    advisories.and_then(|items| items.first().map(|item| item.url.clone()))
                }),
            summary,
        };
    }
    if advisories.is_none()
        && releases.is_none_or(|items| !items.iter().any(|item| item.security_related))
    {
        return SecurityAssessment {
            status: SecurityStatus::Unknown,
            fingerprint: "feed-unavailable".to_string(),
            advisory_url: None,
            summary: "Upstream security information was unavailable. The installed version was not marked safe or vulnerable.".to_string(),
        };
    }
    assess_advisories(Some(installed), advisories)
}

fn definite_matches<'a>(
    installed: &str,
    advisories: Option<&'a [AdvisoryRef]>,
    policy: &[&'a ConfirmedAdvisory],
) -> Vec<(&'a str, &'a str)> {
    let Some(version) = parse_semver(installed) else {
        return Vec::new();
    };
    let mut matched = Vec::new();
    for advisory in advisories.unwrap_or(&[]) {
        if advisory.ranges.is_empty() {
            continue;
        }
        if advisory
            .ranges
            .iter()
            .any(|range| satisfies_range(&version, range) == Some(true))
        {
            matched.push((advisory.id.as_str(), advisory.url.as_str()));
        }
    }
    for entry in policy {
        if entry
            .ranges
            .iter()
            .any(|range| satisfies_range(&version, range) == Some(true))
        {
            matched.push((entry.id, entry.url));
        }
    }
    matched
}

fn has_unparsed_advisory(installed: &str, advisories: Option<&[AdvisoryRef]>) -> bool {
    let Some(advisories) = advisories else {
        return false;
    };
    let Some(version) = parse_semver(installed) else {
        return !advisories.is_empty();
    };
    advisories.iter().any(|advisory| {
        advisory.ranges.is_empty()
            || advisory
                .ranges
                .iter()
                .any(|range| satisfies_range(&version, range).is_none())
    })
}

fn newest_security_release<'a>(
    releases: Option<&'a [ReleaseRef]>,
    installed: &str,
) -> Option<&'a ReleaseRef> {
    let releases = releases?;
    let mut best: Option<&ReleaseRef> = None;
    for release in releases {
        if !release.security_related || release.draft || release.prerelease {
            continue;
        }
        if update_available(installed, &release.tag) != Some(true) {
            continue;
        }
        if best
            .as_ref()
            .is_none_or(|current| update_available(&current.tag, &release.tag) == Some(true))
        {
            best = Some(release);
        }
    }
    best
}

pub fn assess_advisories(
    installed: Option<&str>,
    advisories: Option<&[AdvisoryRef]>,
) -> SecurityAssessment {
    let Some(advisories) = advisories else {
        return SecurityAssessment {
            status: SecurityStatus::Unknown,
            fingerprint: "feed-unavailable".to_string(),
            advisory_url: None,
            summary:
                "Security advisory status is unknown because the official feed was unavailable."
                    .to_string(),
        };
    };
    if advisories.is_empty() {
        return SecurityAssessment {
            status: SecurityStatus::NoPublishedAdvisories,
            fingerprint: "none".to_string(),
            advisory_url: None,
            summary: "No published GitHub Security Advisories were returned. This is not a claim that the software is secure.".to_string(),
        };
    }
    let version = installed.and_then(parse_semver);
    let mut affected = Vec::new();
    let mut unparsed = false;
    for advisory in advisories {
        if advisory.ranges.is_empty() {
            unparsed = true;
            continue;
        }
        let Some(version) = version.as_ref() else {
            unparsed = true;
            continue;
        };
        let mut matched = false;
        for range in &advisory.ranges {
            match satisfies_range(version, range) {
                None => unparsed = true,
                Some(true) => matched = true,
                Some(false) => {}
            }
        }
        if matched {
            affected.push(advisory);
        }
    }
    if !affected.is_empty() {
        let mut ids: Vec<&str> = affected.iter().map(|item| item.id.as_str()).collect();
        ids.sort_unstable();
        return SecurityAssessment {
            status: SecurityStatus::Affected,
            fingerprint: format!(
                "affected:{}:{}",
                installed.unwrap_or("unknown"),
                ids.join(",")
            ),
            advisory_url: affected.first().map(|item| item.url.clone()),
            summary: format!(
                "Installed version {} is in the affected range for {}.",
                installed.unwrap_or("unknown"),
                ids.join(", ")
            ),
        };
    }
    if unparsed || version.is_none() {
        let mut ids: Vec<&str> = advisories.iter().map(|item| item.id.as_str()).collect();
        ids.sort_unstable();
        return SecurityAssessment {
            status: SecurityStatus::ReviewRecommended,
            fingerprint: format!("review:{}:{}", installed.unwrap_or("unknown"), ids.join(",")),
            advisory_url: advisories.first().map(|item| item.url.clone()),
            summary: "A published advisory exists, but impact on the installed version could not be confirmed. Security review is recommended.".to_string(),
        };
    }
    let mut ids: Vec<&str> = advisories.iter().map(|item| item.id.as_str()).collect();
    ids.sort_unstable();
    SecurityAssessment {
        status: SecurityStatus::OutsidePublishedRanges,
        fingerprint: format!("outside:{}:{}", installed.unwrap_or("unknown"), ids.join(",")),
        advisory_url: None,
        summary: "Published advisories were checked and the installed version is outside their parsed affected ranges. This is not a claim that the software is secure.".to_string(),
    }
}

pub fn alert_severity(status: SecurityStatus) -> Option<Severity> {
    match status {
        SecurityStatus::Affected => Some(Severity::Critical),
        SecurityStatus::ReviewRecommended
        | SecurityStatus::VersionUnavailable
        | SecurityStatus::Unknown => Some(Severity::Warning),
        _ => None,
    }
}

pub fn official_github_url(value: &str) -> Option<String> {
    let url = url::Url::parse(value).ok()?;
    if url.scheme() != "https" {
        return None;
    }
    if url.host_str() != Some("github.com") && url.host_str() != Some("www.github.com") {
        return None;
    }
    Some(url.to_string())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::domain::VendorId;

    #[test]
    fn btcpay_policy_marks_2_4_1_affected_and_2_4_2_clear_of_that_range() {
        let old = assess_security(VendorId::BtcpayServer, Some("2.4.1"), Some(&[]), Some(&[]));
        assert_eq!(old.status, SecurityStatus::Affected);
        assert!(old.fingerprint.contains("btcpay-2026-11-incident"));
        let current = assess_security(VendorId::BtcpayServer, Some("2.4.2"), Some(&[]), Some(&[]));
        assert_eq!(current.status, SecurityStatus::NoPublishedAdvisories);
    }
}
