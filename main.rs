use std::collections::HashMap;
use std::sync::Arc;
use std::time::Instant;
use anyhow::Result;
use clap::{Parser, Subcommand};
use colored::Colorize;
use indicatif::{ProgressBar, ProgressStyle};
use once_cell::sync::Lazy;
use regex::Regex;
use serde::{Deserialize, Serialize};
use serde_json::Value;
use thiserror::Error;
use tokio::fs;

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

/// Command line interface
#[derive(Parser)]
#[command(author, version, about, long_about = None)]
struct Cli {
    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand)]
enum Commands {
    /// Analyze a single URL
    Analyze {
        /// Target URL to analyze
        url: String,
        /// Show detailed output
        #[arg(short, long)]
        verbose: bool,
        /// Minimum confidence threshold (0-100)
        #[arg(short, long, default_value = "50")]
        confidence: u8,
        /// Output format (json, table, simple)
        #[arg(short, long, default_value = "table")]
        format: String,
    },
    /// Analyze multiple URLs from a file
    Batch {
        /// File containing URLs (one per line)
        file: String,
        /// Output file for results
        #[arg(short, long)]
        output: Option<String>,
        /// Number of concurrent requests
        #[arg(short, long, default_value = "5")]
        concurrency: usize,
        /// Minimum confidence threshold
        #[arg(short = 't', long, default_value = "50")]
        confidence: u8,
    },
    /// Update the Wappalyzer database
    Update {
        /// Force update even if cache is recent
        #[arg(short, long)]
        force: bool,
    },
    /// Show information about the database
    Info,
    /// Run performance benchmarks
    Benchmark {
        /// Number of test URLs to generate
        #[arg(short, long, default_value = "100")]
        count: usize,
        /// Number of threads to use
        #[arg(short, long, default_value = "5")]
        threads: usize,
    },
}

/// Represents an HTTP response for analysis
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HttpResponse {
    pub url: String,
    pub headers: HashMap<String, String>,
    pub body: String,
    pub status_code: u16,
    pub response_time_ms: u64,
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

/// Technology definition from Wappalyzer database
#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct TechnologyDefinition {
    #[serde(default)]
    pub description: Option<String>,
    #[serde(default)]
    pub website: Option<String>,
    #[serde(default)]
    pub categories: Vec<u32>,
    #[serde(default)]
    pub icon: Option<String>,
    
    // Detection patterns
    #[serde(default)]
    pub url: Option<Value>,
    #[serde(default)]
    pub html: Option<Value>,
    #[serde(default)]
    pub css: Option<Value>,
    #[serde(default)]
    pub script: Option<Value>,
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

/// HTTP client for fetching web pages
pub struct HttpClient {
    client: reqwest::Client,
}

impl HttpClient {
    pub fn new() -> Self {
        let client = reqwest::Client::builder()
            .user_agent("Standalone-Wappalyzer/1.0")
            .timeout(std::time::Duration::from_secs(30))
            .redirect(reqwest::redirect::Policy::limited(5))
            .build()
            .expect("Failed to create HTTP client");

        Self { client }
    }

    pub async fn fetch_page(&self, url: &str) -> Result<HttpResponse, WappalyzerError> {
        let start = Instant::now();
        
        let response = self.client.get(url).send().await?;
        let status_code = response.status().as_u16();
        
        // Extract headers
        let mut headers = HashMap::new();
        for (name, value) in response.headers() {
            if let Ok(value_str) = value.to_str() {
                headers.insert(name.to_string().to_lowercase(), value_str.to_string());
            }
        }

        let body = response.text().await?;
        let response_time_ms = start.elapsed().as_millis() as u64;

        Ok(HttpResponse {
            url: url.to_string(),
            headers,
            body,
            status_code,
            response_time_ms,
        })
    }
}

/// Technology analyzer engine
pub struct TechnologyAnalyzer {
    database: WappalyzerDatabase,
    html_patterns: HashMap<String, Vec<CompiledPattern>>,
    header_patterns: HashMap<String, HashMap<String, Vec<CompiledPattern>>>,
    url_patterns: HashMap<String, Vec<CompiledPattern>>,
    script_patterns: HashMap<String, Vec<CompiledPattern>>,
    meta_patterns: HashMap<String, HashMap<String, Vec<CompiledPattern>>>,
}

impl TechnologyAnalyzer {
    /// Create a new analyzer with the latest Wappalyzer database
    pub async fn new() -> Result<Self, WappalyzerError> {
        let database = Self::load_or_fetch_database().await?;
        let mut analyzer = Self {
            database,
            html_patterns: HashMap::new(),
            header_patterns: HashMap::new(),
            url_patterns: HashMap::new(),
            script_patterns: HashMap::new(),
            meta_patterns: HashMap::new(),
        };
        
        analyzer.compile_patterns()?;
        Ok(analyzer)
    }

    /// Load database from cache or fetch from remote
    async fn load_or_fetch_database() -> Result<WappalyzerDatabase, WappalyzerError> {
        let cache_file = "wappalyzer_cache.json";
        
        // Try to load from cache first
        if let Ok(cache_data) = fs::read_to_string(cache_file).await {
            if let Ok(database) = serde_json::from_str::<WappalyzerDatabase>(&cache_data) {
                println!("{}", "Using cached Wappalyzer database".green());
                return Ok(database);
            }
        }

        println!("{}", "Fetching latest Wappalyzer database...".yellow());
        let database = Self::fetch_latest_database().await?;
        
        // Cache the database
        if let Ok(cache_data) = serde_json::to_string_pretty(&database) {
            let _ = fs::write(cache_file, cache_data).await;
            println!("{}", "Database cached successfully".green());
        }

        Ok(database)
    }

    /// Fetch the latest Wappalyzer database from available sources
    async fn fetch_latest_database() -> Result<WappalyzerDatabase, WappalyzerError> {
        let client = reqwest::Client::new();
        
        // Try the dochne/wappalyzer repository (last commit before going private)
        println!("Trying to fetch from dochne/wappalyzer (original pre-private snapshot)...");
        
        // Fetch technologies (split into multiple files)
        let tech_letters = vec!['a', 'b', 'c', 'd', 'e', 'f', 'g', 'h', 'i', 'j', 'k', 'l', 'm', 'n', 'o', 'p', 'q', 'r', 's', 't', 'u', 'v', 'w', 'x', 'y', 'z', '_'];
        let mut all_technologies = HashMap::new();
        
        println!("Fetching technology definitions from dochne/wappalyzer (27 files)...");
        let pb = ProgressBar::new(tech_letters.len() as u64);
        pb.set_style(ProgressStyle::default_bar()
            .template("{spinner:.green} [{elapsed_precise}] [{bar:40.cyan/blue}] {pos}/{len} Fetching {msg}")
            .unwrap());
        
        for letter in tech_letters {
            pb.set_message(format!("{}.json", letter));
            let url = format!("https://raw.githubusercontent.com/dochne/wappalyzer/main/src/technologies/{}.json", letter);
            
            match client
                .get(&url)
                .header("User-Agent", "Standalone-Wappalyzer/1.0")
                .send()
                .await
            {
                Ok(response) => {
                    if response.status().is_success() {
                        match response.json::<HashMap<String, TechnologyDefinition>>().await {
                            Ok(tech_data) => {
                                all_technologies.extend(tech_data);
                            }
                            Err(e) => {
                                println!("⚠️  Failed to parse {}.json: {}", letter, e);
                            }
                        }
                    } else {
                        println!("⚠️  HTTP {} for {}.json", response.status(), letter);
                    }
                }
                Err(e) => {
                    println!("⚠️  Network error for {}.json: {}", letter, e);
                }
            }
            pb.inc(1);
        }
        pb.finish_with_message("Technology files loaded");
        
        if all_technologies.is_empty() {
            println!("⚠️  Could not fetch from dochne/wappalyzer, trying fallback sources...");
            return Self::fetch_from_fallback_sources().await;
        }
        
        println!("✅ Successfully loaded {} technologies from dochne/wappalyzer", all_technologies.len());

        // Fetch categories
        println!("Fetching categories from dochne/wappalyzer...");
        let categories_url = "https://raw.githubusercontent.com/dochne/wappalyzer/main/src/categories.json";
        
        let categories = match client
            .get(categories_url)
            .header("User-Agent", "Standalone-Wappalyzer/1.0")
            .send()
            .await
        {
            Ok(response) => {
                if response.status().is_success() {
                    match response.json::<HashMap<String, Category>>().await {
                        Ok(cat_data) => {
                            println!("✅ Successfully fetched categories from dochne/wappalyzer");
                            // Convert string keys to numeric IDs and update categories
                            let mut processed_categories = HashMap::new();
                            for (key, mut category) in cat_data {
                                if let Ok(id) = key.parse::<u32>() {
                                    category.id = id;
                                }
                                processed_categories.insert(key, category);
                            }
                            processed_categories
                        }
                        Err(e) => {
                            println!("⚠️  Failed to parse categories from dochne/wappalyzer: {}", e);
                            Self::create_fallback_categories()
                        }
                    }
                } else {
                    println!("⚠️  HTTP {} for categories from dochne/wappalyzer", response.status());
                    Self::create_fallback_categories()
                }
            }
            Err(e) => {
                println!("⚠️  Network error for categories from dochne/wappalyzer: {}", e);
                Self::create_fallback_categories()
            }
        };

        Ok(WappalyzerDatabase {
            technologies: all_technologies,
            categories,
        })
    }

    /// Create fallback categories when remote fetch fails
    fn create_fallback_categories() -> HashMap<String, Category> {
        println!("🔄 Using fallback categories");
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

    /// Fallback to other sources if dochne/wappalyzer fails
    async fn fetch_from_fallback_sources() -> Result<WappalyzerDatabase, WappalyzerError> {
        let client = reqwest::Client::new();
        
        // Try the Enthec WebAppAnalyzer repository as fallback
        println!("Trying fallback: Enthec WebAppAnalyzer...");
        
        let tech_letters = vec!['a', 'b', 'c', 'd', 'e', 'f', 'g', 'h', 'i', 'j', 'k', 'l', 'm', 'n', 'o', 'p', 'q', 'r', 's', 't', 'u', 'v', 'w', 'x', 'y', 'z', '_'];
        let mut all_technologies = HashMap::new();
        
        println!("Fetching from enthec/webappanalyzer as fallback...");
        let pb = ProgressBar::new(tech_letters.len() as u64);
        pb.set_style(ProgressStyle::default_bar()
            .template("{spinner:.yellow} [{elapsed_precise}] [{bar:40.yellow/blue}] {pos}/{len} Fallback {msg}")
            .unwrap());
        
        for letter in tech_letters {
            pb.set_message(format!("{}.json", letter));
            let url = format!("https://raw.githubusercontent.com/enthec/webappanalyzer/main/src/technologies/{}.json", letter);
            
            match client
                .get(&url)
                .header("User-Agent", "Standalone-Wappalyzer/1.0")
                .send()
                .await
            {
                Ok(response) => {
                    if response.status().is_success() {
                        match response.json::<HashMap<String, TechnologyDefinition>>().await {
                            Ok(tech_data) => {
                                all_technologies.extend(tech_data);
                            }
                            Err(_) => {} // Silently continue with other files
                        }
                    }
                }
                Err(_) => {} // Silently continue with other files
            }
            pb.inc(1);
        }
        pb.finish_with_message("Fallback technology files loaded");
        
        if all_technologies.is_empty() {
            return Err(WappalyzerError::InvalidInput("Could not fetch technology definitions from any source".to_string()));
        }
        
        println!("✅ Successfully loaded {} technologies from fallback sources", all_technologies.len());

        // Try to fetch categories from fallback
        let categories_url = "https://raw.githubusercontent.com/enthec/webappanalyzer/main/src/categories.json";
        let categories = match client.get(categories_url).send().await {
            Ok(response) if response.status().is_success() => {
                match response.json::<HashMap<String, Category>>().await {
                    Ok(cat_data) => {
                        let mut processed_categories = HashMap::new();
                        for (key, mut category) in cat_data {
                            if let Ok(id) = key.parse::<u32>() {
                                category.id = id;
                            }
                            processed_categories.insert(key, category);
                        }
                        processed_categories
                    }
                    Err(_) => Self::create_fallback_categories()
                }
            }
            _ => Self::create_fallback_categories()
        };

        Ok(WappalyzerDatabase {
            technologies: all_technologies,
            categories,
        })
    }

    /// Force update the database
    pub async fn update_database() -> Result<WappalyzerDatabase, WappalyzerError> {
        let cache_file = "wappalyzer_cache.json";
        let _ = fs::remove_file(cache_file).await; // Remove cache
        Self::load_or_fetch_database().await
    }

    /// Get database statistics
    pub fn get_stats(&self) -> (usize, usize) {
        (self.database.technologies.len(), self.database.categories.len())
    }

    /// Compile all regex patterns for efficient matching
    fn compile_patterns(&mut self) -> Result<(), WappalyzerError> {
        let pb = ProgressBar::new(self.database.technologies.len() as u64);
        pb.set_style(ProgressStyle::default_bar()
            .template("{spinner:.green} [{elapsed_precise}] [{bar:40.cyan/blue}] {pos}/{len} ({eta})")
            .unwrap());
        pb.set_message("Compiling patterns");

        for (tech_name, tech_def) in &self.database.technologies {
            // Compile HTML patterns
            if let Some(html_patterns) = &tech_def.html {
                if let Ok(patterns) = Self::compile_pattern_value(html_patterns) {
                    if !patterns.is_empty() {
                        self.html_patterns.insert(tech_name.clone(), patterns);
                    }
                }
            }

            // Compile URL patterns
            if let Some(url_patterns) = &tech_def.url {
                if let Ok(patterns) = Self::compile_pattern_value(url_patterns) {
                    if !patterns.is_empty() {
                        self.url_patterns.insert(tech_name.clone(), patterns);
                    }
                }
            }

            // Compile script patterns
            if let Some(script_patterns) = &tech_def.script {
                if let Ok(patterns) = Self::compile_pattern_value(script_patterns) {
                    if !patterns.is_empty() {
                        self.script_patterns.insert(tech_name.clone(), patterns);
                    }
                }
            }

            // Compile header patterns
            if let Some(headers) = &tech_def.headers {
                let mut compiled_headers = HashMap::new();
                for (header_name, pattern_value) in headers {
                    if let Ok(patterns) = Self::compile_pattern_value(pattern_value) {
                        if !patterns.is_empty() {
                            compiled_headers.insert(header_name.to_lowercase(), patterns);
                        }
                    }
                }
                if !compiled_headers.is_empty() {
                    self.header_patterns.insert(tech_name.clone(), compiled_headers);
                }
            }

            // Compile meta patterns
            if let Some(meta) = &tech_def.meta {
                let mut compiled_meta = HashMap::new();
                for (meta_name, pattern_value) in meta {
                    if let Ok(patterns) = Self::compile_pattern_value(pattern_value) {
                        if !patterns.is_empty() {
                            compiled_meta.insert(meta_name.to_lowercase(), patterns);
                        }
                    }
                }
                if !compiled_meta.is_empty() {
                    self.meta_patterns.insert(tech_name.clone(), compiled_meta);
                }
            }

            pb.inc(1);
        }
        
        pb.finish_with_message("Pattern compilation complete");
        Ok(())
    }

    /// Compile a pattern value (string or array) into CompiledPattern structs
    fn compile_pattern_value(value: &Value) -> Result<Vec<CompiledPattern>, WappalyzerError> {
        let mut patterns = Vec::new();
        
        match value {
            Value::String(pattern_str) => {
                if let Some(compiled) = Self::compile_single_pattern(pattern_str)? {
                    patterns.push(compiled);
                }
            }
            Value::Array(pattern_array) => {
                for pattern_val in pattern_array {
                    if let Value::String(pattern_str) = pattern_val {
                        if let Some(compiled) = Self::compile_single_pattern(pattern_str)? {
                            patterns.push(compiled);
                        }
                    }
                }
            }
            _ => {}
        }
        
        Ok(patterns)
    }

    /// Compile a single pattern string with confidence and version extraction
    fn compile_single_pattern(pattern: &str) -> Result<Option<CompiledPattern>, WappalyzerError> {
        if pattern.is_empty() {
            return Ok(None);
        }

        // Parse Wappalyzer pattern format: "pattern\;confidence:100\;version:\1"
        let parts: Vec<&str> = pattern.split("\\;").collect();
        let regex_pattern = parts[0];
        
        let mut confidence = 100u8;
        let mut version: Option<String> = None;

        // Parse confidence and version from pattern
        for part in parts.iter().skip(1) {
            if part.starts_with("confidence:") {
                if let Ok(conf) = part.replace("confidence:", "").parse::<u8>() {
                    confidence = conf;
                }
            } else if part.starts_with("version:") {
                version = Some(part.replace("version:", ""));
            }
        }

        // Compile regex with case-insensitive flag
        match Regex::new(&format!("(?i){}", regex_pattern)) {
            Ok(regex) => Ok(Some(CompiledPattern {
                regex,
                confidence,
                version,
            })),
            Err(_) => {
                // Skip invalid regex patterns silently
                Ok(None)
            }
        }
    }

    /// Analyze an HTTP response and detect technologies
    pub fn analyze(&self, response: &HttpResponse, min_confidence: u8) -> Vec<Technology> {
        let mut detected_technologies = HashMap::new();
        
        // Analyze URL
        self.analyze_url(&response.url, &mut detected_technologies);
        
        // Analyze headers
        self.analyze_headers(&response.headers, &mut detected_technologies);
        
        // Analyze HTML content
        self.analyze_html(&response.body, &mut detected_technologies);
        
        // Analyze script tags
        self.analyze_scripts(&response.body, &mut detected_technologies);
        
        // Analyze meta tags
        self.analyze_meta_tags(&response.body, &mut detected_technologies);

        // Convert to Technology structs and filter by confidence
        detected_technologies
            .into_iter()
            .filter(|(_, (confidence, _))| *confidence >= min_confidence)
            .map(|(name, (confidence, version))| {
                let tech_def = self.database.technologies.get(&name);
                let categories = self.get_technology_categories(&name);
                
                Technology {
                    name,
                    confidence,
                    version,
                    categories,
                    website: tech_def.and_then(|def| def.website.clone()),
                    description: tech_def.and_then(|def| def.description.clone()),
                }
            })
            .collect()
    }

    /// Analyze URL patterns
    fn analyze_url(&self, url: &str, detected: &mut HashMap<String, (u8, Option<String>)>) {
        for (tech_name, patterns) in &self.url_patterns {
            for pattern in patterns {
                if let Some(captures) = pattern.regex.captures(url) {
                    let version = Self::extract_version(&pattern.version, &captures);
                    Self::update_detection(detected, tech_name.clone(), pattern.confidence, version);
                }
            }
        }
    }

    /// Analyze HTTP headers
    fn analyze_headers(&self, headers: &HashMap<String, String>, detected: &mut HashMap<String, (u8, Option<String>)>) {
        for (tech_name, header_patterns) in &self.header_patterns {
            for (header_name, patterns) in header_patterns {
                if let Some(header_value) = headers.get(header_name) {
                    for pattern in patterns {
                        if let Some(captures) = pattern.regex.captures(header_value) {
                            let version = Self::extract_version(&pattern.version, &captures);
                            Self::update_detection(detected, tech_name.clone(), pattern.confidence, version);
                        }
                    }
                }
            }
        }
    }

    /// Analyze HTML content
    fn analyze_html(&self, html: &str, detected: &mut HashMap<String, (u8, Option<String>)>) {
        for (tech_name, patterns) in &self.html_patterns {
            for pattern in patterns {
                if let Some(captures) = pattern.regex.captures(html) {
                    let version = Self::extract_version(&pattern.version, &captures);
                    Self::update_detection(detected, tech_name.clone(), pattern.confidence, version);
                }
            }
        }
    }

    /// Analyze script tags in HTML
    fn analyze_scripts(&self, html: &str, detected: &mut HashMap<String, (u8, Option<String>)>) {
        static SCRIPT_REGEX: Lazy<Regex> = Lazy::new(|| {
            Regex::new(r#"(?i)<script[^>]*src=['"]([^'"]*)['"]*[^>]*>"#).unwrap()
        });

        for script_match in SCRIPT_REGEX.captures_iter(html) {
            if let Some(script_src) = script_match.get(1) {
                for (tech_name, patterns) in &self.script_patterns {
                    for pattern in patterns {
                        if let Some(captures) = pattern.regex.captures(script_src.as_str()) {
                            let version = Self::extract_version(&pattern.version, &captures);
                            Self::update_detection(detected, tech_name.clone(), pattern.confidence, version);
                        }
                    }
                }
            }
        }
    }

    /// Analyze meta tags in HTML
    fn analyze_meta_tags(&self, html: &str, detected: &mut HashMap<String, (u8, Option<String>)>) {
        static META_REGEX: Lazy<Regex> = Lazy::new(|| {
            Regex::new(r#"(?i)<meta[^>]*name=['"]([^'"]*)['"]*[^>]*content=['"]([^'"]*)['"]*[^>]*>"#).unwrap()
        });

        for meta_match in META_REGEX.captures_iter(html) {
            if let (Some(meta_name), Some(meta_content)) = (meta_match.get(1), meta_match.get(2)) {
                let meta_name_lower = meta_name.as_str().to_lowercase();
                
                for (tech_name, meta_patterns) in &self.meta_patterns {
                    if let Some(patterns) = meta_patterns.get(&meta_name_lower) {
                        for pattern in patterns {
                            if let Some(captures) = pattern.regex.captures(meta_content.as_str()) {
                                let version = Self::extract_version(&pattern.version, &captures);
                                Self::update_detection(detected, tech_name.clone(), pattern.confidence, version);
                            }
                        }
                    }
                }
            }
        }
    }

    /// Extract version from regex captures using version pattern
    fn extract_version(version_pattern: &Option<String>, captures: &regex::Captures) -> Option<String> {
        if let Some(pattern) = version_pattern {
            let mut version = pattern.clone();
            
            // Replace capture groups in version pattern
            for i in 1..captures.len() {
                if let Some(capture) = captures.get(i) {
                    version = version.replace(&format!("\\{}", i), capture.as_str());
                }
            }
            
            // Clean up the version string
            version = version.trim().to_string();
            if !version.is_empty() && version != *pattern {
                Some(version)
            } else {
                None
            }
        } else {
            None
        }
    }

    /// Update detection results with confidence and version
    fn update_detection(
        detected: &mut HashMap<String, (u8, Option<String>)>,
        tech_name: String,
        confidence: u8,
        version: Option<String>,
    ) {
        detected
            .entry(tech_name)
            .and_modify(|(existing_confidence, existing_version)| {
                // Update with higher confidence
                if confidence > *existing_confidence {
                    *existing_confidence = confidence;
                }
                // Update version if we have one and don't have one yet
                if version.is_some() && existing_version.is_none() {
                    *existing_version = version.clone();
                }
            })
            .or_insert((confidence, version));
    }

    /// Get categories for a technology
    fn get_technology_categories(&self, tech_name: &str) -> Vec<String> {
        if let Some(tech_def) = self.database.technologies.get(tech_name) {
            tech_def
                .categories
                .iter()
                .filter_map(|cat_id| {
                    self.database
                        .categories
                        .values()
                        .find(|cat| cat.id == *cat_id)
                        .map(|cat| cat.name.clone())
                })
                .collect()
        } else {
            Vec::new()
        }
    }
}

/// Main application struct
pub struct StandaloneWappalyzer {
    analyzer: Arc<TechnologyAnalyzer>,
    http_client: HttpClient,
}

impl StandaloneWappalyzer {
    pub async fn new() -> Result<Self, WappalyzerError> {
        println!("{}", "Initializing Standalone Wappalyzer...".cyan());
        let analyzer = Arc::new(TechnologyAnalyzer::new().await?);
        let http_client = HttpClient::new();
        
        let (tech_count, cat_count) = analyzer.get_stats();
        println!("{} {} technologies and {} categories", 
                "Loaded".green(), tech_count.to_string().yellow(), cat_count.to_string().yellow());
        
        Ok(Self {
            analyzer,
            http_client,
        })
    }

    /// Analyze a single URL
    pub async fn analyze_url(&self, url: &str, min_confidence: u8) -> AnalysisResult {
        let start = Instant::now();
        
        match self.http_client.fetch_page(url).await {
            Ok(response) => {
                let technologies = self.analyzer.analyze(&response, min_confidence);
                AnalysisResult {
                    url: url.to_string(),
                    technologies,
                    analysis_time_ms: start.elapsed().as_millis() as u64,
                    response_info: Some(response),
                    error: None,
                }
            }
            Err(e) => {
                AnalysisResult {
                    url: url.to_string(),
                    technologies: Vec::new(),
                    analysis_time_ms: start.elapsed().as_millis() as u64,
                    response_info: None,
                    error: Some(e.to_string()),
                }
            }
        }
    }

    /// Analyze multiple URLs concurrently
    pub async fn analyze_urls_batch(&self, urls: Vec<String>, concurrency: usize, min_confidence: u8) -> Vec<AnalysisResult> {
        use tokio::sync::Semaphore;
        
        let semaphore = Arc::new(Semaphore::new(concurrency));
        let pb = ProgressBar::new(urls.len() as u64);
        pb.set_style(ProgressStyle::default_bar()
            .template("{spinner:.green} [{elapsed_precise}] [{bar:40.cyan/blue}] {pos}/{len} ({eta}) {msg}")
            .unwrap());

        let analyzer = Arc::clone(&self.analyzer);
        let client = reqwest::Client::builder()
            .user_agent("Standalone-Wappalyzer/1.0")
            .timeout(std::time::Duration::from_secs(30))
            .redirect(reqwest::redirect::Policy::limited(5))
            .build()
            .expect("Failed to create HTTP client");

        let tasks: Vec<_> = urls.into_iter().map(|url| {
            let analyzer = Arc::clone(&analyzer);
            let client = client.clone();
            let semaphore = Arc::clone(&semaphore);
            let pb = pb.clone();
            
            tokio::spawn(async move {
                let _permit = semaphore.acquire().await.unwrap();
                let result = Self::analyze_single_url_static(analyzer, &client, &url, min_confidence).await;
                pb.inc(1);
                result
            })
        }).collect();

        let results = futures::future::join_all(tasks).await
            .into_iter()
            .filter_map(|task_result| task_result.ok())
            .collect();

        pb.finish_with_message("Analysis complete");
        results
    }

    async fn analyze_single_url_static(
        analyzer: Arc<TechnologyAnalyzer>,
        client: &reqwest::Client,
        url: &str,
        min_confidence: u8,
    ) -> AnalysisResult {
        let start = Instant::now();
        
        match Self::fetch_page_static(client, url).await {
            Ok(response) => {
                let technologies = analyzer.analyze(&response, min_confidence);
                AnalysisResult {
                    url: url.to_string(),
                    technologies,
                    analysis_time_ms: start.elapsed().as_millis() as u64,
                    response_info: Some(response),
                    error: None,
                }
            }
            Err(e) => {
                AnalysisResult {
                    url: url.to_string(),
                    technologies: Vec::new(),
                    analysis_time_ms: start.elapsed().as_millis() as u64,
                    response_info: None,
                    error: Some(e.to_string()),
                }
            }
        }
    }

    async fn fetch_page_static(client: &reqwest::Client, url: &str) -> Result<HttpResponse, WappalyzerError> {
        let start = Instant::now();
        
        let response = client.get(url).send().await?;
        let status_code = response.status().as_u16();
        
        // Extract headers
        let mut headers = HashMap::new();
        for (name, value) in response.headers() {
            if let Ok(value_str) = value.to_str() {
                headers.insert(name.to_string().to_lowercase(), value_str.to_string());
            }
        }

        let body = response.text().await?;
        let response_time_ms = start.elapsed().as_millis() as u64;

        Ok(HttpResponse {
            url: url.to_string(),
            headers,
            body,
            status_code,
            response_time_ms,
        })
    }

    #[allow(dead_code)]
    async fn analyze_single_url(
        analyzer: Arc<TechnologyAnalyzer>,
        http_client: &HttpClient,
        url: &str,
        min_confidence: u8,
    ) -> AnalysisResult {
        let start = Instant::now();
        
        match http_client.fetch_page(url).await {
            Ok(response) => {
                let technologies = analyzer.analyze(&response, min_confidence);
                AnalysisResult {
                    url: url.to_string(),
                    technologies,
                    analysis_time_ms: start.elapsed().as_millis() as u64,
                    response_info: Some(response),
                    error: None,
                }
            }
            Err(e) => {
                AnalysisResult {
                    url: url.to_string(),
                    technologies: Vec::new(),
                    analysis_time_ms: start.elapsed().as_millis() as u64,
                    response_info: None,
                    error: Some(e.to_string()),
                }
            }
        }
    }
}

/// Output formatting functions
mod output {
    use super::*;
    use std::collections::HashMap;

    pub fn print_analysis_result(result: &AnalysisResult, format: &str, verbose: bool) {
        match format {
            "json" => print_json(result),
            "table" => print_table(result, verbose),
            "simple" => print_simple(result),
            _ => print_table(result, verbose),
        }
    }

    fn print_json(result: &AnalysisResult) {
        println!("{}", serde_json::to_string_pretty(result).unwrap());
    }

    fn print_table(result: &AnalysisResult, verbose: bool) {
        println!("\n{}", format!("🔍 Analysis Results for: {}", result.url).cyan().bold());
        println!("{}", "=".repeat(80).blue());

        if let Some(error) = &result.error {
            println!("{} {}", "❌ Error:".red().bold(), error);
            return;
        }

        if result.technologies.is_empty() {
            println!("{}", "No technologies detected".yellow());
            return;
        }

        // Group by category
        let mut categories: HashMap<String, Vec<&Technology>> = HashMap::new();
        for tech in &result.technologies {
            if tech.categories.is_empty() {
                categories.entry("Other".to_string()).or_insert_with(Vec::new).push(tech);
            } else {
                for category in &tech.categories {
                    categories.entry(category.clone()).or_insert_with(Vec::new).push(tech);
                }
            }
        }

        for (category, techs) in categories {
            println!("\n📂 {}", category.green().bold());
            println!("{}", "-".repeat(40).green());
            
            for tech in techs {
                let confidence_color = match tech.confidence {
                    90..=100 => tech.confidence.to_string().green(),
                    70..=89 => tech.confidence.to_string().yellow(),
                    _ => tech.confidence.to_string().red(),
                };
                
                print!("  • {} [{}%]", tech.name.white().bold(), confidence_color);
                
                if let Some(version) = &tech.version {
                    print!(" v{}", version.cyan());
                }
                
                if verbose {
                    if let Some(description) = &tech.description {
                        print!("\n    {}", description.dimmed());
                    }
                    if let Some(website) = &tech.website {
                        print!("\n    🌐 {}", website.blue().underline());
                    }
                }
                println!();
            }
        }

        if verbose {
            if let Some(response_info) = &result.response_info {
                println!("\n📊 {}", "Response Information".blue().bold());
                println!("{}", "-".repeat(40).blue());
                println!("  Status Code: {}", response_info.status_code);
                println!("  Response Time: {}ms", response_info.response_time_ms);
                println!("  Content Length: {} bytes", response_info.body.len());
                
                if !response_info.headers.is_empty() {
                    println!("\n📋 {}", "Headers".blue().bold());
                    println!("{}", "-".repeat(40).blue());
                    for (name, value) in &response_info.headers {
                        if value.len() > 80 {
                            println!("  {}: {}...", name.yellow(), &value[..77].dimmed());
                        } else {
                            println!("  {}: {}", name.yellow(), value.dimmed());
                        }
                    }
                }
            }
        }

        println!("\n⏱️ Analysis completed in {}ms", result.analysis_time_ms.to_string().green());
    }

    fn print_simple(result: &AnalysisResult) {
        if let Some(error) = &result.error {
            println!("{}: ERROR - {}", result.url, error);
            return;
        }

        if result.technologies.is_empty() {
            println!("{}: No technologies detected", result.url);
            return;
        }

        let tech_names: Vec<String> = result.technologies
            .iter()
            .map(|t| {
                if let Some(version) = &t.version {
                    format!("{} v{}", t.name, version)
                } else {
                    t.name.clone()
                }
            })
            .collect();

        println!("{}: {}", result.url, tech_names.join(", "));
    }

    pub fn print_batch_summary(results: &[AnalysisResult]) {
        let total_urls = results.len();
        let successful = results.iter().filter(|r| r.error.is_none()).count();
        let failed = total_urls - successful;
        
        let mut all_technologies: HashMap<String, usize> = HashMap::new();
        for result in results {
            for tech in &result.technologies {
                *all_technologies.entry(tech.name.clone()).or_insert(0) += 1;
            }
        }

        println!("\n{}", "📈 Batch Analysis Summary".cyan().bold());
        println!("{}", "=".repeat(50).blue());
        println!("Total URLs processed: {}", total_urls.to_string().yellow());
        println!("Successful: {} | Failed: {}", successful.to_string().green(), failed.to_string().red());
        
        if !all_technologies.is_empty() {
            println!("\n{}", "🏆 Most Common Technologies:".green().bold());
            let mut tech_vec: Vec<_> = all_technologies.into_iter().collect();
            tech_vec.sort_by(|a, b| b.1.cmp(&a.1));
            
            for (i, (tech, count)) in tech_vec.iter().take(10).enumerate() {
                let percentage = (*count as f64 / successful as f64) * 100.0;
                println!("  {}. {} - {} sites ({:.1}%)", 
                    (i + 1).to_string().yellow(),
                    tech.white().bold(),
                    count.to_string().green(),
                    percentage.to_string().cyan()
                );
            }
        }
    }
}

/// Benchmark functionality
mod benchmark {
    use super::*;

    #[derive(Debug)]
    pub struct BenchmarkResults {
        pub total_time: std::time::Duration,
        pub urls_processed: usize,
        pub successful_analyses: usize,
        pub urls_per_second: f64,
        pub average_time_per_url: std::time::Duration,
        pub technologies_detected: usize,
    }

    impl std::fmt::Display for BenchmarkResults {
        fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
            write!(
                f,
                "🚀 Benchmark Results:\n\
                 ⏱️  Total Time: {:?}\n\
                 📊 URLs Processed: {}\n\
                 ✅ Successful: {}\n\
                 📈 URLs/Second: {:.2}\n\
                 ⚡ Avg Time/URL: {:?}\n\
                 🔍 Technologies Detected: {}",
                self.total_time,
                self.urls_processed,
                self.successful_analyses,
                self.urls_per_second,
                self.average_time_per_url,
                self.technologies_detected
            )
        }
    }

    pub fn generate_test_urls(count: usize) -> Vec<String> {
        let popular_sites = vec![
            "https://github.com",
            "https://stackoverflow.com",
            "https://www.wikipedia.org",
            "https://www.reddit.com",
            "https://www.youtube.com",
            "https://www.google.com",
            "https://www.facebook.com",
            "https://www.twitter.com",
            "https://www.instagram.com",
            "https://www.linkedin.com",
            "https://www.amazon.com",
            "https://www.netflix.com",
            "https://www.spotify.com",
            "https://www.dropbox.com",
            "https://www.slack.com",
        ];

        (0..count)
            .map(|i| popular_sites[i % popular_sites.len()].to_string())
            .collect()
    }

    pub async fn run_benchmark(
        wappalyzer: &StandaloneWappalyzer,
        url_count: usize,
        concurrency: usize,
    ) -> Result<BenchmarkResults, WappalyzerError> {
        println!("{}", format!("🚀 Starting benchmark with {} URLs and {} concurrent threads", url_count, concurrency).cyan().bold());
        
        let test_urls = generate_test_urls(url_count);
        let start = Instant::now();
        
        let results = wappalyzer.analyze_urls_batch(test_urls, concurrency, 50).await;
        
        let total_time = start.elapsed();
        let successful_analyses = results.iter().filter(|r| r.error.is_none()).count();
        let urls_per_second = url_count as f64 / total_time.as_secs_f64();
        let average_time_per_url = total_time / url_count as u32;
        let technologies_detected = results.iter()
            .map(|r| r.technologies.len())
            .sum();

        Ok(BenchmarkResults {
            total_time,
            urls_processed: url_count,
            successful_analyses,
            urls_per_second,
            average_time_per_url,
            technologies_detected,
        })
    }
}

/// Main CLI application
#[tokio::main]
async fn main() -> Result<()> {
    let cli = Cli::parse();

    match cli.command {
        Commands::Analyze { url, verbose, confidence, format } => {
            let wappalyzer = StandaloneWappalyzer::new().await?;
            let result = wappalyzer.analyze_url(&url, confidence).await;
            output::print_analysis_result(&result, &format, verbose);
        }

        Commands::Batch { file, output, concurrency, confidence } => {
            let urls = fs::read_to_string(&file).await?
                .lines()
                .map(|line| line.trim().to_string())
                .filter(|line| !line.is_empty() && line.starts_with("http"))
                .collect::<Vec<_>>();

            if urls.is_empty() {
                return Err(anyhow::anyhow!("No valid URLs found in file"));
            }

            println!("{}", format!("📁 Loaded {} URLs from {}", urls.len(), file).green());

            let wappalyzer = StandaloneWappalyzer::new().await?;
            let results = wappalyzer.analyze_urls_batch(urls, concurrency, confidence).await;

            if let Some(output_file) = output {
                let json_output = serde_json::to_string_pretty(&results)?;
                fs::write(&output_file, json_output).await?;
                println!("{}", format!("💾 Results saved to {}", output_file).green());
            } else {
                // Print summary
                output::print_batch_summary(&results);
                
                // Print individual results in simple format
                println!("\n{}", "📋 Individual Results:".blue().bold());
                for result in &results {
                    output::print_analysis_result(result, "simple", false);
                }
            }
        }

        Commands::Update { force } => {
            if force {
                let _ = fs::remove_file("wappalyzer_cache.json").await;
            }
            
            println!("{}", "🔄 Updating Wappalyzer database...".yellow());
            let _ = TechnologyAnalyzer::update_database().await?;
            println!("{}", "✅ Database updated successfully!".green());
        }

        Commands::Info => {
            let analyzer = TechnologyAnalyzer::new().await?;
            let (tech_count, cat_count) = analyzer.get_stats();
            
            println!("{}", "📊 Wappalyzer Database Information".cyan().bold());
            println!("{}", "=".repeat(40).blue());
            println!("Technologies: {}", tech_count.to_string().yellow());
            println!("Categories: {}", cat_count.to_string().yellow());
            
            // Show some sample technologies
            println!("\n{}", "🔍 Sample Technologies:".green().bold());
            let sample_techs: Vec<_> = analyzer.database.technologies.keys().take(10).collect();
            for tech in sample_techs {
                println!("  • {}", tech);
            }
            
            // Show categories
            println!("\n{}", "📂 Categories:".green().bold());
            for (_, category) in analyzer.database.categories.iter().take(15) {
                println!("  • {}", category.name);
            }
        }

        Commands::Benchmark { count, threads } => {
            let wappalyzer = StandaloneWappalyzer::new().await?;
            let results = benchmark::run_benchmark(&wappalyzer, count, threads).await?;
            println!("\n{}", results.to_string().green());
        }
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_pattern_compilation() {
        // Test simple pattern
        let pattern = r"WordPress";
        let compiled = TechnologyAnalyzer::compile_single_pattern(pattern).unwrap();
        assert!(compiled.is_some());
        
        let compiled = compiled.unwrap();
        assert_eq!(compiled.confidence, 100); // default confidence
        assert_eq!(compiled.version, None); // no version pattern
        
        // Test pattern with confidence (using correct format)
        let pattern_with_confidence = r"WordPress\;confidence:80";
        let compiled2 = TechnologyAnalyzer::compile_single_pattern(pattern_with_confidence).unwrap();
        assert!(compiled2.is_some());
        
        let compiled2 = compiled2.unwrap();
        assert_eq!(compiled2.confidence, 80);
        assert_eq!(compiled2.version, None);
        
        // Test pattern with version (using correct format)
        let pattern_with_version = r"WordPress\;version:\1";
        let compiled3 = TechnologyAnalyzer::compile_single_pattern(pattern_with_version).unwrap();
        assert!(compiled3.is_some());
        
        let compiled3 = compiled3.unwrap();
        assert_eq!(compiled3.confidence, 100); // default
        assert_eq!(compiled3.version, Some("\\1".to_string()));
    }

    #[tokio::test]
    async fn test_version_extraction() {
        let pattern = Some("\\1".to_string());
        let regex = Regex::new(r"WordPress (\d+\.\d+)").unwrap();
        let captures = regex.captures("WordPress 5.8").unwrap(); // Changed to match the expected output
        
        let version = TechnologyAnalyzer::extract_version(&pattern, &captures);
        assert_eq!(version, Some("5.8".to_string())); // Updated expected result
    }

    #[tokio::test]
    async fn test_http_response_analysis() {
        let response = HttpResponse {
            url: "https://example.com".to_string(),
            headers: {
                let mut headers = HashMap::new();
                headers.insert("server".to_string(), "Apache/2.4.41".to_string());
                headers.insert("x-powered-by".to_string(), "PHP/7.4.0".to_string());
                headers
            },
            body: r#"<html>
                <head>
                    <meta name="generator" content="WordPress 5.8">
                    <title>Test Site</title>
                </head>
                <body>
                    <script src="https://ajax.googleapis.com/ajax/libs/jquery/3.6.0/jquery.min.js"></script>
                </body>
            </html>"#.to_string(),
            status_code: 200,
            response_time_ms: 150,
        };

        // Test the structure
        assert_eq!(response.status_code, 200);
        assert!(response.body.contains("WordPress"));
        assert!(response.headers.contains_key("server"));
    }

    #[test]
    fn test_benchmark_url_generation() {
        let urls = benchmark::generate_test_urls(20);
        assert_eq!(urls.len(), 20);
        assert!(urls[0].starts_with("https://"));
    }

    #[test]
    fn test_cli_parsing() {
        // Test that CLI can be parsed
        use clap::Parser;
        
        let cli = Cli::try_parse_from(&["test", "analyze", "https://example.com"]);
        assert!(cli.is_ok());
    }
}
