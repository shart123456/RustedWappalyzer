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

/// Parse a CDX JSON body into the first snapshot timestamp, if any.
///
/// The CDX API returns `[["timestamp","statuscode"], ["20250813185136","200"]]`,
/// or an empty body when nothing matched. Anything that is not a well-formed
/// array with at least one data row is treated as "no snapshot" rather than an
/// error, since a caller cannot act on the difference.
pub fn parse_cdx_timestamp(body: &str) -> Option<String> {
    let trimmed = body.trim();
    if trimmed.is_empty() {
        return None;
    }
    let data: serde_json::Value = serde_json::from_str(trimmed).ok()?;
    let rows = data.as_array()?;
    // Row 0 is the field header; row 1 is the first match.
    let row = rows.get(1)?.as_array()?;
    let ts = row.first()?.as_str()?;
    if ts.is_empty() {
        None
    } else {
        Some(ts.to_string())
    }
}

/// Build the CDX query URL for a `±7`-day window centred `lookback_days` ago.
fn cdx_query_url(url: &str, lookback_days: u32) -> String {
    let bare = strip_scheme(url);
    let bare_encoded: String = url::form_urlencoded::byte_serialize(bare.as_bytes()).collect();
    let from_date = days_ago_yyyymmdd((lookback_days + 7) as i64);
    let to_date = days_ago_yyyymmdd(lookback_days.saturating_sub(7) as i64);
    format!(
        "https://web.archive.org/cdx/search/cdx?url={}&output=json&fl=timestamp,statuscode&filter=statuscode:200&limit=1&from={}&to={}999999",
        bare_encoded, from_date, to_date
    )
}

/// Number of attempts made against the CDX endpoint before giving up.
const CDX_ATTEMPTS: u32 = 3;

/// Find the closest available Wayback snapshot within ±7 days of `lookback_days` ago.
/// Returns `(timestamp, archive_url)` or `None` if no snapshot is found.
///
/// The CDX endpoint throttles aggressively: concurrent or rapid queries are
/// answered with `503` and an HTML error page, or by dropping the connection.
/// We therefore check the status before parsing (so an HTML error page is never
/// fed to the JSON parser) and retry transient failures with a linear backoff.
pub async fn find_snapshot(url: &str, lookback_days: u32) -> Result<Option<(String, String)>> {
    let cdx_url = cdx_query_url(url, lookback_days);

    let client = reqwest::Client::builder()
        .timeout(std::time::Duration::from_secs(45))
        .user_agent("Mozilla/5.0")
        .build()?;

    let mut last_err: Option<anyhow::Error> = None;

    for attempt in 1..=CDX_ATTEMPTS {
        if attempt > 1 {
            // Linear backoff: 1s, then 2s. Cheap, and enough to clear the
            // short-lived throttle the CDX endpoint applies.
            tokio::time::sleep(std::time::Duration::from_secs(attempt as u64 - 1)).await;
        }

        let resp = match client.get(&cdx_url).send().await {
            Ok(r) => r,
            Err(e) => {
                tracing::warn!(attempt, error = %e, "CDX request failed; retrying");
                last_err = Some(anyhow::anyhow!("CDX request failed: {}", e));
                continue;
            }
        };

        let status = resp.status();
        if !status.is_success() {
            // 429/5xx are the throttle responses and are worth retrying.
            // Everything else is a hard failure and is reported as such
            // instead of being misreported as a body-decoding problem.
            if status.as_u16() == 429 || status.is_server_error() {
                tracing::warn!(attempt, %status, "CDX endpoint throttled; retrying");
                last_err = Some(anyhow::anyhow!(
                    "CDX endpoint returned {} (rate limited)",
                    status
                ));
                continue;
            }
            return Err(anyhow::anyhow!("CDX endpoint returned {}", status));
        }

        let body = match resp.text().await {
            Ok(b) => b,
            Err(e) => {
                tracing::warn!(attempt, error = %e, "CDX body read failed; retrying");
                last_err = Some(anyhow::anyhow!("CDX body read failed: {}", e));
                continue;
            }
        };

        return Ok(parse_cdx_timestamp(&body).map(|ts| {
            let archive_url = format!("https://web.archive.org/web/{}/{}", ts, url);
            (ts, archive_url)
        }));
    }

    Err(last_err.unwrap_or_else(|| anyhow::anyhow!("CDX lookup failed after {} attempts", CDX_ATTEMPTS)))
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_first_data_row() {
        let body = "[[\"timestamp\",\"statuscode\"],\n[\"20250813185136\",\"200\"]]";
        assert_eq!(parse_cdx_timestamp(body).as_deref(), Some("20250813185136"));
    }

    #[test]
    fn empty_body_is_no_snapshot_not_an_error() {
        assert_eq!(parse_cdx_timestamp(""), None);
        assert_eq!(parse_cdx_timestamp("   \n"), None);
    }

    #[test]
    fn header_only_response_is_no_snapshot() {
        assert_eq!(parse_cdx_timestamp("[[\"timestamp\",\"statuscode\"]]"), None);
    }

    #[test]
    fn html_error_page_is_no_snapshot_not_a_panic() {
        // Regression: archive.org answers throttled requests with an HTML 503
        // page. This used to reach serde and surface as a misleading
        // "error decoding response body".
        let html = "<html><head><title>503 Service Unavailable</title></head></html>";
        assert_eq!(parse_cdx_timestamp(html), None);
    }

    #[test]
    fn malformed_json_is_no_snapshot() {
        assert_eq!(parse_cdx_timestamp("[[\"timestamp\""), None);
        assert_eq!(parse_cdx_timestamp("{\"not\":\"an array\"}"), None);
    }

    #[test]
    fn cdx_query_url_targets_a_seven_day_window() {
        let u = cdx_query_url("https://example.com/", 365);
        assert!(u.starts_with("https://web.archive.org/cdx/search/cdx?url=example.com&"));
        assert!(u.contains("output=json"));
        assert!(u.contains("filter=statuscode:200"));
        // from is 372 days ago, to is 358 days ago -> from must sort before to
        let from = u.split("&from=").nth(1).unwrap().split('&').next().unwrap();
        let to = u.split("&to=").nth(1).unwrap().trim_end_matches("999999");
        assert!(from < to, "from={} should precede to={}", from, to);
    }
}
