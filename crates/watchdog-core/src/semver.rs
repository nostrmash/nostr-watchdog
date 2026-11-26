#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SemVer {
    pub major: u64,
    pub minor: u64,
    pub patch: u64,
    pub prerelease: Vec<String>,
}

pub fn parse_semver(input: &str) -> Option<SemVer> {
    let trimmed = input.trim();
    let trimmed = trimmed
        .strip_prefix('v')
        .or_else(|| trimmed.strip_prefix('V'))
        .unwrap_or(trimmed);
    let (core, prerelease) = match trimmed.split_once('-') {
        Some((core, pre)) => {
            let pre = pre.split('+').next().unwrap_or(pre);
            (core, Some(pre))
        }
        None => (trimmed.split('+').next().unwrap_or(trimmed), None),
    };
    let mut parts = core.split('.');
    let major = parts.next()?.parse().ok()?;
    let minor = parts.next()?.parse().ok()?;
    let patch = parts.next()?.parse().ok()?;
    if parts.next().is_some() {
        return None;
    }
    let core_ok = core.split('.').all(|part| {
        !part.is_empty()
            && part.chars().all(|ch| ch.is_ascii_digit())
            && !(part.len() > 1 && part.starts_with('0'))
    });
    if !core_ok {
        return None;
    }
    let prerelease = match prerelease {
        None => Vec::new(),
        Some(value) => {
            let items: Vec<String> = value.split('.').map(str::to_string).collect();
            if items.iter().any(|item| {
                item.is_empty()
                    || !item
                        .chars()
                        .all(|ch| ch.is_ascii_alphanumeric() || ch == '-')
            }) {
                return None;
            }
            items
        }
    };
    Some(SemVer {
        major,
        minor,
        patch,
        prerelease,
    })
}

pub fn compare_semver(left: &SemVer, right: &SemVer) -> i32 {
    if left.major != right.major {
        return if left.major > right.major { 1 } else { -1 };
    }
    if left.minor != right.minor {
        return if left.minor > right.minor { 1 } else { -1 };
    }
    if left.patch != right.patch {
        return if left.patch > right.patch { 1 } else { -1 };
    }
    if left.prerelease.is_empty() && right.prerelease.is_empty() {
        return 0;
    }
    if left.prerelease.is_empty() {
        return 1;
    }
    if right.prerelease.is_empty() {
        return -1;
    }
    let length = left.prerelease.len().max(right.prerelease.len());
    for index in 0..length {
        let Some(a) = left.prerelease.get(index) else {
            return -1;
        };
        let Some(b) = right.prerelease.get(index) else {
            return 1;
        };
        let a_num = a.chars().all(|ch| ch.is_ascii_digit());
        let b_num = b.chars().all(|ch| ch.is_ascii_digit());
        if a_num && b_num && a != b {
            let a_n: u64 = a.parse().unwrap_or(0);
            let b_n: u64 = b.parse().unwrap_or(0);
            return if a_n > b_n { 1 } else { -1 };
        }
        if a_num != b_num {
            return if a_num { -1 } else { 1 };
        }
        if a != b {
            return if a > b { 1 } else { -1 };
        }
    }
    0
}

pub fn satisfies_range(version: &SemVer, range: &str) -> Option<bool> {
    let trimmed = range.trim();
    if trimmed.is_empty() || trimmed.contains("||") {
        return None;
    }
    let parts: Vec<&str> = trimmed
        .split(',')
        .map(str::trim)
        .filter(|part| !part.is_empty())
        .collect();
    if parts.is_empty() {
        return None;
    }
    for part in parts {
        let (operator, rest) = if let Some(rest) = part.strip_prefix("<=") {
            ("<=", rest)
        } else if let Some(rest) = part.strip_prefix(">=") {
            (">=", rest)
        } else if let Some(rest) = part.strip_prefix('<') {
            ("<", rest)
        } else if let Some(rest) = part.strip_prefix('>') {
            (">", rest)
        } else if let Some(rest) = part.strip_prefix('=') {
            ("=", rest)
        } else {
            ("=", part)
        };
        let boundary = parse_semver(rest.trim())?;
        let order = compare_semver(version, &boundary);
        let ok = match operator {
            "=" => order == 0,
            "<" => order < 0,
            "<=" => order <= 0,
            ">" => order > 0,
            ">=" => order >= 0,
            _ => return None,
        };
        if !ok {
            return Some(false);
        }
    }
    Some(true)
}

#[derive(Clone, Debug, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct ReleaseRef {
    pub tag: String,
    pub url: String,
    pub prerelease: bool,
    pub draft: bool,
    pub security_related: bool,
}

pub fn latest_stable(releases: &[ReleaseRef], include_prerelease: bool) -> Option<&ReleaseRef> {
    let mut best: Option<(&ReleaseRef, SemVer)> = None;
    for release in releases {
        if release.draft || (release.prerelease && !include_prerelease) {
            continue;
        }
        let Some(version) = parse_semver(&release.tag) else {
            continue;
        };
        if !version.prerelease.is_empty() && !include_prerelease {
            continue;
        }
        if best
            .as_ref()
            .is_none_or(|(_, current)| compare_semver(&version, current) > 0)
        {
            best = Some((release, version));
        }
    }
    best.map(|(release, _)| release)
}

pub fn update_available(installed: &str, latest: &str) -> Option<bool> {
    let current = parse_semver(installed)?;
    let upstream = parse_semver(latest)?;
    if !upstream.prerelease.is_empty() {
        return None;
    }
    Some(compare_semver(&current, &upstream) < 0)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn orders_stable_and_prerelease() {
        let a = parse_semver("v1.2.3").unwrap();
        let b = parse_semver("1.2.4-rc.1").unwrap();
        let c = parse_semver("1.2.4").unwrap();
        assert!(compare_semver(&a, &c) < 0);
        assert!(compare_semver(&b, &c) < 0);
        assert_eq!(satisfies_range(&a, "< 2.4.2"), Some(true));
        assert_eq!(satisfies_range(&c, "<= 1.2.3"), Some(false));
        assert_eq!(update_available("2.4.1", "2.4.2"), Some(true));
        assert_eq!(update_available("2.4.2", "2.4.2"), Some(false));
    }
}
