use anyhow::Result;
use serde::Serialize;
use std::collections::{HashMap, HashSet};
use ::rusty_wappalyzer::AnalysisResult;

#[derive(Debug, Serialize, Clone)]
pub struct VersionChange {
    pub technology: String,
    pub was: Option<String>,
    pub now: Option<String>,
}

#[derive(Debug, Serialize, Clone)]
pub struct TechEntry {
    pub name: String,
    pub version: Option<String>,
}

/// Diff of current tech stack vs one historical snapshot.
#[derive(Debug, Serialize, Clone)]
pub struct SnapshotComparison {
    pub snapshot_timestamp: String,
    pub snapshot_date: String,
    pub snapshot_url: String,
    pub historical: Vec<TechEntry>,
    /// Technologies present now but absent in the snapshot
    pub added: Vec<String>,
    /// Technologies present in the snapshot but gone now
    pub removed: Vec<String>,
    pub version_changes: Vec<VersionChange>,
}

#[derive(Debug, Serialize)]
pub struct WaybackComparison {
    pub url: String,
    pub current: Vec<TechEntry>,
    /// Snapshot ~365 days ago (None if not found)
    pub snapshot_365: Option<SnapshotComparison>,
    /// Snapshot ~735 days ago (None if not found)
    pub snapshot_735: Option<SnapshotComparison>,
}

pub fn days_ago_yyyymmdd(days: i64) -> String {
    use std::time::{SystemTime, UNIX_EPOCH};
    let secs = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs() as i64;
    let target_secs = secs - days * 86400;
    // Convert Unix timestamp to YYYYMMDD using the Euclidean civil-from-days algorithm.
    let z = target_secs / 86400 + 719468;
    let era = z.div_euclid(146097);
    let doe = z - era * 146097;
    let yoe = (doe - doe / 1460 + doe / 36524 - doe / 146096) / 365;
    let y = yoe + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = doy - (153 * mp + 2) / 5 + 1;
    let m = if mp < 10 { mp + 3 } else { mp - 9 };
    let y = if m <= 2 { y + 1 } else { y };
    format!("{:04}{:02}{:02}", y, m, d)
}

/// Strip scheme and trailing slash for CDX URL matching.
fn strip_scheme(url: &str) -> &str {
    url.trim_start_matches("https://")
        .trim_start_matches("http://")
        .trim_end_matches('/')
}

/// Find the closest available Wayback snapshot within ±7 days of `lookback_days` ago.
/// Returns `(timestamp, archive_url)` or `None` if no snapshot is found.
pub async fn find_snapshot(url: &str, lookback_days: u32) -> Result<Option<(String, String)>> {
    let bare = strip_scheme(url);
    let bare_encoded: String = url::form_urlencoded::byte_serialize(bare.as_bytes()).collect();
    // Search a ±7-day window centered on the target date
    let from_date = days_ago_yyyymmdd((lookback_days + 7) as i64);
    let to_date   = days_ago_yyyymmdd(lookback_days.saturating_sub(7) as i64);

    let cdx_url = format!(
        "https://web.archive.org/cdx/search/cdx?url={}&output=json&fl=timestamp,statuscode&filter=statuscode:200&limit=1&from={}&to={}999999",
        bare_encoded, from_date, to_date
    );

    let client = reqwest::Client::builder()
        .timeout(std::time::Duration::from_secs(45))
        .user_agent("Mozilla/5.0")
        .build()?;

    let resp = client.get(&cdx_url).send().await?;
    let data: serde_json::Value = resp.json().await?;

    let rows = match data.as_array() {
        Some(r) if r.len() >= 2 => r,
        _ => return Ok(None),
    };

    let row = match rows.get(1).and_then(|r| r.as_array()) {
        Some(r) => r,
        None => return Ok(None),
    };
    let ts = match row.get(0).and_then(|v| v.as_str()) {
        Some(s) => s.to_string(),
        None => return Ok(None),
    };

    let archive_url = format!("https://web.archive.org/web/{}/{}", ts, url);
    Ok(Some((ts, archive_url)))
}

/// Diff current vs one historical `AnalysisResult` and produce a `SnapshotComparison`.
pub fn compare_snapshot(
    current: &AnalysisResult,
    historical: &AnalysisResult,
    snapshot_ts: &str,
    snapshot_url: &str,
) -> SnapshotComparison {
    let current_map: HashMap<&str, Option<&str>> = current
        .technologies
        .iter()
        .map(|t| (t.name.as_str(), t.version.as_deref()))
        .collect();

    let hist_map: HashMap<&str, Option<&str>> = historical
        .technologies
        .iter()
        .map(|t| (t.name.as_str(), t.version.as_deref()))
        .collect();

    let current_names: HashSet<&str> = current_map.keys().copied().collect();
    let hist_names: HashSet<&str> = hist_map.keys().copied().collect();

    let mut added: Vec<String> = current_names
        .difference(&hist_names)
        .map(|s| s.to_string())
        .collect();
    let mut removed: Vec<String> = hist_names
        .difference(&current_names)
        .map(|s| s.to_string())
        .collect();
    added.sort();
    removed.sort();

    let mut version_changes: Vec<VersionChange> = current_names
        .intersection(&hist_names)
        .filter_map(|name| {
            let now = current_map[name];
            let was = hist_map[name];
            if now != was {
                Some(VersionChange {
                    technology: name.to_string(),
                    was: was.map(|s| s.to_string()),
                    now: now.map(|s| s.to_string()),
                })
            } else {
                None
            }
        })
        .collect();
    version_changes.sort_by(|a, b| a.technology.cmp(&b.technology));

    let snapshot_date = if snapshot_ts.len() >= 8 {
        format!(
            "{}-{}-{}",
            &snapshot_ts[0..4],
            &snapshot_ts[4..6],
            &snapshot_ts[6..8]
        )
    } else {
        snapshot_ts.to_string()
    };

    SnapshotComparison {
        snapshot_timestamp: snapshot_ts.to_string(),
        snapshot_date,
        snapshot_url: snapshot_url.to_string(),
        historical: historical
            .technologies
            .iter()
            .map(|t| TechEntry { name: t.name.clone(), version: t.version.clone() })
            .collect(),
        added,
        removed,
        version_changes,
    }
}
