use std::collections::HashMap;
use regex::Regex;
use serde::{Deserialize, Serialize};
use serde_json::Value;
use thiserror::Error;

/// Custom error types for the standalone Wappalyzer
#[derive(Error, Debug)]
pub enum WappalyzerError {
    #[error("Failed to fetch data: {0}")]
    FetchError(#[from] reqwest::Error),
    #[error("Failed to parse JSON: {0}")]
    JsonError(#[from] serde_json::Error),
    #[error("Regex compilation error: {0}")]
    RegexError(#[from] regex::Error),
    #[error("URL parsing error: {0}")]
    UrlError(#[from] url::ParseError),
    #[error("IO error: {0}")]
    IoError(#[from] std::io::Error),
    #[error("Invalid input: {0}")]
    InvalidInput(String),
}

/// Configuration for the Wappalyzer analyzer.
/// All timeout values are in seconds.
#[derive(Debug, Clone)]
pub struct WappalyzerConfig {
    /// Total HTTP request timeout in seconds (default: 30)
    pub http_timeout_secs: u64,
    /// HTTP connection timeout in seconds (default: 3).
    /// Kept low so parked / firewalled domains fail fast and don't dominate batch wall-time.
    pub connect_timeout_secs: u64,
    /// Timeout for fetching linked assets (JS/CSS) in seconds (default: 8)
    pub asset_timeout_secs: u64,
    /// Timeout for full-scan probe requests in seconds (default: 8)
    pub probe_timeout_secs: u64,
    /// Timeout for favicon fetching in seconds (default: 8)
    pub favicon_timeout_secs: u64,
    /// Timeout for source map fetching in seconds (default: 10)
    pub source_map_timeout_secs: u64,
    /// Max concurrent asset fetches (default: 10)
    pub asset_concurrency: usize,
    /// Max concurrent probe requests (default: 8)
    pub probe_concurrency: usize,
    /// User-Agent header sent with all outbound HTTP requests
    pub user_agent: String,
    /// Maximum number of URLs accepted by the batch API endpoint (default: 100)
    pub max_batch_size: usize,
    /// Enforce SSRF protection inside the HTTP client by validating resolved IPs
    /// at TCP-connection time via a custom DNS resolver.  Set to `true` in server
    /// mode to mitigate DNS rebinding attacks (default: false for CLI compatibility).
    pub ssrf_protection: bool,
    /// Maximum number of asset URLs held in the in-process asset-body cache (default: 500)
    pub asset_cache_size: u64,
    /// Time-to-live for asset cache entries in seconds (default: 300)
    pub asset_cache_ttl_secs: u64,
}

impl Default for WappalyzerConfig {
    fn default() -> Self {
        Self {
            http_timeout_secs: 30,
            connect_timeout_secs: 3,
            asset_timeout_secs: 8,
            probe_timeout_secs: 8,
            favicon_timeout_secs: 8,
            source_map_timeout_secs: 10,
            asset_concurrency: 10,
            probe_concurrency: 8,
            user_agent: "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/122.0.0.0 Safari/537.36".to_string(),
            max_batch_size: 100,
            ssrf_protection: false,
            asset_cache_size: 500,
            asset_cache_ttl_secs: 300,
        }
    }
}

/// Represents an HTTP response for analysis
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HttpResponse {
    pub url: String,
    pub headers: HashMap<String, String>,
    pub body: String,
    pub status_code: u16,
    pub response_time_ms: u64,
    /// Raw Set-Cookie header values, one per element (preserves multi-header semantics)
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub set_cookie_headers: Vec<String>,
}

/// A single detection signal contributing to a technology match
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Signal {
    pub signal_type: String, // "header", "html", "script", "script_src", "meta", "css", "cookie", "url", "dns_txt", "dns_mx", "probe", "source_map", "favicon", "implied"
    pub value: String,       // matched pattern/source description (truncated to 100 chars)
    pub weight: u8,          // 0-100
}

/// Internal detection accumulator — signals + best version found so far
#[derive(Debug, Clone)]
pub struct TechDetection {
    pub version: Option<String>,
    pub signals: Vec<Signal>,
}

/// Technology detection result
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Technology {
    pub name: String,
    pub confidence: u8,
    pub version: Option<String>,
    pub categories: Vec<String>,
    pub website: Option<String>,
    pub description: Option<String>,
    pub icon: Option<String>,
    pub cpe: Option<String>,
    pub saas: Option<bool>,
    pub pricing: Option<Vec<String>>,
    #[serde(skip_serializing_if = "Vec::is_empty", default)]
    pub signals: Vec<Signal>,
}

/// Analysis results for a URL
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AnalysisResult {
    pub url: String,
    pub technologies: Vec<Technology>,
    pub analysis_time_ms: u64,
    pub response_info: Option<HttpResponse>,
    pub error: Option<String>,
}

/// Technology detection pattern
#[derive(Debug, Clone)]
pub struct CompiledPattern {
    pub regex: Regex,
    pub confidence: u8,
    pub version: Option<String>,
}

/// A compiled JS global/property pattern for matching against HTML/inline-script content
#[derive(Debug, Clone)]
pub struct CompiledJsPattern {
    /// The full path to check for, e.g. "window.Shopify"
    pub path: String,
    /// None = presence-only (confidence 75); Some = value regex with version extraction
    pub pattern: Option<CompiledPattern>,
}

/// Technology definition from Wappalyzer database
#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct TechnologyDefinition {
    #[serde(default)]
    pub description: Option<String>,
    #[serde(default)]
    pub website: Option<String>,
    #[serde(default, rename = "cats")]
    pub categories: Vec<u32>,
    #[serde(default)]
    pub icon: Option<String>,
    #[serde(default)]
    pub cpe: Option<String>,
    #[serde(default)]
    pub saas: Option<bool>,
    #[serde(default)]
    pub pricing: Option<Vec<String>>,

    // Detection patterns
    #[serde(default)]
    pub url: Option<Value>,
    #[serde(default)]
    pub html: Option<Value>,
    #[serde(default)]
    pub css: Option<Value>,
    #[serde(default)]
    pub script: Option<Value>,
    #[serde(default, rename = "scriptSrc")]
    pub script_src: Option<Value>,
    #[serde(default)]
    pub scripts: Option<Value>,
    #[serde(default)]
    pub meta: Option<HashMap<String, Value>>,
    #[serde(default)]
    pub headers: Option<HashMap<String, Value>>,
    #[serde(default)]
    pub cookies: Option<HashMap<String, Value>>,
    #[serde(default)]
    pub dom: Option<Value>,
    #[serde(default)]
    pub js: Option<HashMap<String, Value>>,
    #[serde(default)]
    pub xhr: Option<Value>,
    #[serde(default)]
    pub text: Option<Value>,
    #[serde(default)]
    pub cert_issuer: Option<Value>,
    #[serde(default)]
    pub robots: Option<Value>,
    #[serde(default)]
    pub dns: Option<HashMap<String, Value>>,

    // Relationships
    #[serde(default)]
    pub implies: Option<Value>,
    #[serde(default)]
    pub excludes: Option<Value>,
    #[serde(default)]
    pub requires: Option<Value>,
    #[serde(default)]
    pub requires_category: Option<Value>,
}

/// Category definition from Wappalyzer database
#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct Category {
    #[serde(default)]
    pub name: String,
    #[serde(default)]
    pub priority: Option<u32>,
    #[serde(default)]
    pub id: u32,
}

/// Main Wappalyzer database structure
#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct WappalyzerDatabase {
    pub technologies: HashMap<String, TechnologyDefinition>,
    pub categories: HashMap<String, Category>,
}
