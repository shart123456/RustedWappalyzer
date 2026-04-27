use std::collections::HashMap;
use std::io::IsTerminal;
use indicatif::{ProgressBar, ProgressStyle};
use sha2::{Sha256, Digest};
use tokio::fs;

use crate::types::{
    Category, TechnologyDefinition, WappalyzerDatabase, WappalyzerError,
};

/// Returns the path to the wappalyzer cache file.
/// Uses the WAPPALYZER_CACHE env var if set, otherwise places the cache
/// next to the running binary.
pub(crate) fn cache_file_path() -> std::path::PathBuf {
    if let Ok(p) = std::env::var("WAPPALYZER_CACHE") {
        return std::path::PathBuf::from(p);
    }
    std::env::current_exe()
        .ok()
        .and_then(|p| p.parent().map(|d| d.join("wappalyzer_cache.json")))
        .unwrap_or_else(|| std::path::PathBuf::from("wappalyzer_cache.json"))
}

/// Favicon hash database embedded at compile time (data/favicon_hashes.json).
/// Eliminates the runtime file dependency — the binary carries the data itself.
const FAVICON_HASHES_JSON: &str = include_str!("../data/favicon_hashes.json");

/// Supplemental CPE overrides embedded at compile time (data/cpe_overrides.json).
/// Maps Wappalyzer technology name → CPE 2.3 string for technologies that already
/// extract a version but lack a CPE entry in the upstream Wappalyzer database.
/// Populated by scripts/nvd_cpe_lookup.py; takes priority over the DB value when
/// the DB has no CPE but never overrides a CPE that the DB already provides.
const CPE_OVERRIDES_JSON: &str = include_str!("../data/cpe_overrides.json");

/// Supplemental version extraction patches embedded at compile time (data/version_patches.json).
/// Maps tech name → field name → pattern value, adding version extraction to Segment C
/// technologies that have a CPE but no version pattern in the upstream database.
const VERSION_PATCHES_JSON: &str = include_str!("../data/version_patches.json");

/// Load favicon hash → tech name mapping from the embedded JSON blob.
/// Returns empty map silently if the data is malformed.
pub(crate) fn load_favicon_hashes() -> HashMap<i32, String> {
    match serde_json::from_str::<HashMap<String, String>>(FAVICON_HASHES_JSON) {
        Ok(map) => map.into_iter()
            .filter_map(|(k, v)| k.parse::<i32>().ok().map(|h| (h, v)))
            .collect(),
        Err(e) => {
            tracing::warn!("Failed to parse embedded favicon hashes: {} — favicon detection disabled", e);
            HashMap::new()
        }
    }
}

/// Load supplemental CPE override map from the embedded JSON blob.
/// Returns empty map silently on parse failure so the binary still starts.
pub(crate) fn load_cpe_overrides() -> HashMap<String, String> {
    match serde_json::from_str::<HashMap<String, String>>(CPE_OVERRIDES_JSON) {
        Ok(map) => {
            if !map.is_empty() {
                tracing::info!(count = map.len(), "CPE overrides loaded");
            }
            map
        }
        Err(e) => {
            tracing::warn!("Failed to parse CPE overrides: {} — override CPEs disabled", e);
            HashMap::new()
        }
    }
}

/// Load version extraction patches from the embedded JSON blob.
/// Returns empty map silently on parse failure so the binary still starts.
pub(crate) fn load_version_patches() -> std::collections::HashMap<String, std::collections::HashMap<String, serde_json::Value>> {
    match serde_json::from_str::<std::collections::HashMap<String, std::collections::HashMap<String, serde_json::Value>>>(VERSION_PATCHES_JSON) {
        Ok(map) => {
            if !map.is_empty() {
                tracing::info!(count = map.len(), "Version patches loaded");
            }
            map
        }
        Err(e) => {
            tracing::warn!("Failed to parse version patches: {} — version patches disabled", e);
            std::collections::HashMap::new()
        }
    }
}

/// Load database from cache or fetch from remote
pub(crate) async fn load_or_fetch_database() -> Result<WappalyzerDatabase, WappalyzerError> {
    let cache_file = cache_file_path();
    let checksum_file = {
        let mut p = cache_file.clone();
        let name = p.file_name()
            .map(|n| format!("{}.sha256", n.to_string_lossy()))
            .unwrap_or_else(|| "wappalyzer_cache.json.sha256".to_string());
        p.set_file_name(name);
        p
    };

    // Try to load from cache first
    if let Ok(cache_data) = fs::read_to_string(&cache_file).await {
        // Verify checksum if companion file exists
        let checksum_ok = if let Ok(stored_hash) = fs::read_to_string(&checksum_file).await {
            let computed_hash = format!("{:x}", Sha256::digest(cache_data.as_bytes()));
            if computed_hash != stored_hash.trim() {
                tracing::warn!("Cache checksum mismatch — re-fetching database");
                false
            } else {
                true
            }
        } else {
            // No checksum file — accept the cache as-is
            true
        };

        if checksum_ok {
            if let Ok(database) = serde_json::from_str::<WappalyzerDatabase>(&cache_data) {
                tracing::info!("Using cached Wappalyzer database");
                return Ok(database);
            }
        }
    }

    tracing::info!("Fetching latest Wappalyzer database");
    let database = fetch_latest_database().await?;

    // Cache the database using a write-then-rename pattern so that a crash
    // or kill during the write never leaves a corrupt cache file on disk.
    if let Ok(cache_data) = serde_json::to_string_pretty(&database) {
        let hash = format!("{:x}", Sha256::digest(cache_data.as_bytes()));
        let unique = std::process::id();
        let tmp_cache = cache_file.with_file_name(format!(
            "{}.{}.tmp",
            cache_file.file_name().unwrap_or_default().to_string_lossy(),
            unique
        ));
        let tmp_checksum = checksum_file.with_file_name(format!(
            "{}.{}.tmp",
            checksum_file.file_name().unwrap_or_default().to_string_lossy(),
            unique
        ));
        if fs::write(&tmp_cache, &cache_data).await.is_ok()
            && fs::rename(&tmp_cache, &cache_file).await.is_ok()
        {
            if fs::write(&tmp_checksum, &hash).await.is_ok() {
                let _ = fs::rename(&tmp_checksum, &checksum_file).await;
            }
            tracing::info!("Database cached successfully");
        } else {
            let _ = fs::remove_file(&tmp_cache).await;
            tracing::warn!("Failed to write database cache — next startup will re-fetch");
        }
    }

    Ok(database)
}

/// Fetch all 27 per-letter technology JSON files from `base_url` (a GitHub raw
/// content prefix ending with `/technologies/`). Logs warnings for individual
/// failures but continues. Returns an empty map when every file failed.
async fn fetch_tech_files(
    client: &reqwest::Client,
    base_url: &str,
    spinner_color: &str,
) -> HashMap<String, TechnologyDefinition> {
    let tech_letters = [
        'a', 'b', 'c', 'd', 'e', 'f', 'g', 'h', 'i', 'j', 'k', 'l', 'm',
        'n', 'o', 'p', 'q', 'r', 's', 't', 'u', 'v', 'w', 'x', 'y', 'z', '_',
    ];
    let mut all_technologies = HashMap::new();

    let is_interactive = std::io::stderr().is_terminal();
    let pb = if is_interactive {
        let template = format!(
            "{{spinner:.{}}} [{{elapsed_precise}}] [{{bar:40.cyan/blue}}] {{pos}}/{{len}} {{msg}}",
            spinner_color
        );
        let p = ProgressBar::new(tech_letters.len() as u64);
        p.set_style(ProgressStyle::default_bar().template(&template).unwrap());
        Some(p)
    } else {
        None
    };

    for letter in tech_letters {
        if let Some(ref p) = pb { p.set_message(format!("{}.json", letter)); }
        let url = format!("{}{}.json", base_url, letter);

        match client.get(&url).send().await {
            Ok(response) if response.status().is_success() => {
                match response.json::<HashMap<String, TechnologyDefinition>>().await {
                    Ok(tech_data) => { all_technologies.extend(tech_data); }
                    Err(e) => { tracing::warn!("Failed to parse {}.json: {}", letter, e); }
                }
            }
            Ok(response) => {
                tracing::warn!("HTTP {} for {}.json", response.status(), letter);
            }
            Err(e) => {
                tracing::warn!("Network error for {}.json: {}", letter, e);
            }
        }
        if let Some(ref p) = pb { p.inc(1); }
    }
    if let Some(p) = pb { p.finish_with_message("done"); }
    all_technologies
}

/// Fetch and normalise a categories JSON file from `url`.
/// Returns a fallback set when the fetch fails or the response cannot be parsed.
async fn fetch_categories(
    client: &reqwest::Client,
    url: &str,
) -> HashMap<String, Category> {
    match client.get(url).send().await {
        Ok(response) if response.status().is_success() => {
            match response.json::<HashMap<String, Category>>().await {
                Ok(cat_data) => {
                    let mut processed = HashMap::new();
                    for (key, mut category) in cat_data {
                        if let Ok(id) = key.parse::<u32>() {
                            category.id = id;
                        }
                        processed.insert(key, category);
                    }
                    processed
                }
                Err(e) => {
                    tracing::warn!("Failed to parse categories from {}: {}", url, e);
                    create_fallback_categories()
                }
            }
        }
        Ok(response) => {
            tracing::warn!("HTTP {} for categories from {}", response.status(), url);
            create_fallback_categories()
        }
        Err(e) => {
            tracing::warn!("Network error for categories from {}: {}", url, e);
            create_fallback_categories()
        }
    }
}

/// Fetch the latest Wappalyzer database from available sources.
///
/// The source base URL defaults to the `enthec/webappanalyzer` GitHub mirror but
/// can be overridden by setting the `WAPPALYZER_DB_URL` environment variable to
/// any base URL whose `technologies/` sub-path and `categories.json` follow the
/// same layout (e.g. a corporate proxy or private mirror).
async fn fetch_latest_database() -> Result<WappalyzerDatabase, WappalyzerError> {
    let client = reqwest::Client::builder()
        .user_agent("Standalone-Wappalyzer/1.0")
        .timeout(std::time::Duration::from_secs(30))
        .build()?;

    let enthec_base = std::env::var("WAPPALYZER_DB_URL")
        .unwrap_or_else(|_| "https://raw.githubusercontent.com/enthec/webappanalyzer/main/src".to_string());
    let tech_base = format!("{}/technologies/", enthec_base.trim_end_matches('/'));
    let categories_url = format!("{}/categories.json", enthec_base.trim_end_matches('/'));

    tracing::debug!("Fetching technology definitions from {}", tech_base);
    let all_technologies = fetch_tech_files(&client, &tech_base, "green").await;

    if all_technologies.is_empty() {
        tracing::warn!("Could not fetch from primary DB source, trying fallback");
        return fetch_from_fallback_sources().await;
    }

    let loaded = all_technologies.len();
    if loaded < 7_000 {
        tracing::warn!(loaded, "Fewer technologies than expected — some letter files may have failed");
    }
    tracing::info!(loaded, "Loaded technologies from primary source");

    tracing::debug!("Fetching categories from {}", categories_url);
    let categories = fetch_categories(&client, &categories_url).await;

    Ok(WappalyzerDatabase { technologies: all_technologies, categories })
}

/// Create fallback categories when remote fetch fails
fn create_fallback_categories() -> HashMap<String, Category> {
    tracing::debug!("Using fallback categories");
    let mut fallback = HashMap::new();
    let categories = vec![
        (1, "CMS"), (2, "Message Boards"), (3, "Database Managers"), (4, "Documentation"),
        (5, "Widgets"), (6, "Ecommerce"), (7, "Photo Galleries"), (8, "Wikis"),
        (9, "Hosting Panels"), (10, "Analytics"), (11, "Blogs"), (12, "JavaScript Frameworks"),
        (13, "Issue Trackers"), (14, "Video Players"), (15, "Comment Systems"), (16, "Security"),
        (17, "Font Scripts"), (18, "Web Frameworks"), (19, "Miscellaneous"), (20, "Editors"),
        (21, "LMS"), (22, "Web Servers"), (23, "Cache Tools"), (24, "Rich Text Editors"),
        (25, "JavaScript Graphics"), (26, "Mobile Frameworks"), (27, "Programming Languages"),
        (28, "Operating Systems"), (29, "Search Engines"), (30, "Web Mail"), (31, "CDN"),
        (32, "Marketing Automation"), (33, "Web Hosting"), (34, "Database"), (35, "Map"),
        (36, "Advertising"), (37, "Network Storage"), (38, "Media Servers"), (39, "Webcams"),
        (40, "Printers"), (41, "Payment Processors"), (42, "Tag Managers"), (43, "Paywalls"),
        (44, "Build/CI Systems"), (45, "SCADA"), (46, "Remote Access"), (47, "Development"),
        (48, "Network Devices"), (49, "Feed Readers"), (50, "Page Builders"),
    ];

    for (id, name) in categories {
        fallback.insert(id.to_string(), Category {
            name: name.to_string(),
            priority: Some(id),
            id
        });
    }
    fallback
}

/// Fallback to dochne/wappalyzer if enthec/webappanalyzer is unreachable.
async fn fetch_from_fallback_sources() -> Result<WappalyzerDatabase, WappalyzerError> {
    let client = reqwest::Client::builder()
        .user_agent("Standalone-Wappalyzer/1.0")
        .timeout(std::time::Duration::from_secs(30))
        .build()?;

    tracing::info!("Trying fallback: dochne/wappalyzer");
    let base = "https://raw.githubusercontent.com/dochne/wappalyzer/main/src/technologies/";
    let all_technologies = fetch_tech_files(&client, base, "yellow").await;

    if all_technologies.is_empty() {
        return Err(WappalyzerError::InvalidInput(
            "Could not fetch technology definitions from any source".to_string(),
        ));
    }

    tracing::info!(count = all_technologies.len(), "Loaded technologies from fallback sources");

    let categories_url = "https://raw.githubusercontent.com/dochne/wappalyzer/main/src/categories.json";
    let categories = fetch_categories(&client, categories_url).await;

    Ok(WappalyzerDatabase { technologies: all_technologies, categories })
}

/// Force-delete the cache file and re-fetch. Called by the `update` CLI subcommand.
pub async fn update_database() -> Result<WappalyzerDatabase, WappalyzerError> {
    let cache_file = cache_file_path();
    let _ = fs::remove_file(&cache_file).await;
    load_or_fetch_database().await
}
