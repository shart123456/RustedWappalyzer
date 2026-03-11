use ::rusty_wappalyzer::*;
use anyhow::Result;
use clap::{Parser, Subcommand};
use colored::Colorize;
use tokio::fs;
use tracing::{info, error, debug};
use tracing_subscriber::{fmt, layer::SubscriberExt, util::SubscriberInitExt, EnvFilter};

mod output;
mod benchmark;
mod vuln;
mod poc;
mod alert;
mod wayback;
mod middleware;
mod server;

/// Allowed output formats for CLI commands.
#[derive(clap::ValueEnum, Clone, Debug, Default)]
enum OutputFormat {
    #[default]
    Table,
    Json,
    Simple,
}

impl std::fmt::Display for OutputFormat {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            OutputFormat::Table  => write!(f, "table"),
            OutputFormat::Json   => write!(f, "json"),
            OutputFormat::Simple => write!(f, "simple"),
        }
    }
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
        /// Output format
        #[arg(short, long, default_value = "table", value_enum)]
        format: OutputFormat,
        /// Disable SSL verification
        #[arg(short = 'k', long)]
        insecure: bool,
        /// Probe well-known endpoints for additional version information.
        /// Also runs automatically as a fallback when no technologies are detected.
        #[arg(long)]
        full_scan: bool,
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
        /// Disable SSL verification
        #[arg(short = 'k', long)]
        insecure: bool,
        /// Probe well-known endpoints for additional version information.
        /// Also runs automatically as a fallback when no technologies are detected.
        #[arg(long)]
        full_scan: bool,
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
    /// Start the HTTP API server
    Serve {
        /// Port to listen on
        #[arg(short, long, default_value = "3000")]
        port: u16,
        /// Disable SSL certificate verification
        #[arg(short = 'k', long)]
        insecure: bool,
    },
    /// Compare current tech stack against Wayback Machine snapshots (~1yr and ~2yr ago)
    Wayback {
        /// Target URL to analyze
        url: String,
        /// Minimum confidence threshold (0-100)
        #[arg(short, long, default_value = "50")]
        confidence: u8,
        /// Output format (json, table)
        #[arg(short, long, default_value = "table", value_enum)]
        format: OutputFormat,
        /// Disable SSL verification
        #[arg(short = 'k', long)]
        insecure: bool,
    },
}

/// Initialise tracing.
///
/// - CLI modes  → human-readable output on stderr only.
/// - Server mode → stderr **and** a daily rolling file under `logs/`.
///
/// The log level is controlled by the `RUST_LOG` env var (default: `info`).
fn init_logging(server_mode: bool) -> Option<tracing_appender::non_blocking::WorkerGuard> {
    let env_filter = EnvFilter::try_from_default_env()
        .unwrap_or_else(|_| EnvFilter::new("info"));

    if server_mode {
        let file_appender = tracing_appender::rolling::daily("logs", "wappalyzer.log");
        let (non_blocking, guard) = tracing_appender::non_blocking(file_appender);

        tracing_subscriber::registry()
            .with(env_filter)
            .with(fmt::layer().with_writer(std::io::stderr).with_ansi(true))
            .with(fmt::layer().with_writer(non_blocking).with_ansi(false))
            .init();

        Some(guard)
    } else {
        tracing_subscriber::registry()
            .with(env_filter)
            .with(fmt::layer().with_writer(std::io::stderr).with_ansi(true))
            .init();

        None
    }
}

/// Main CLI application
#[tokio::main]
async fn main() -> Result<()> {
    let cli = Cli::parse();

    match cli.command {
        Commands::Analyze { url, verbose, confidence, format, insecure, full_scan } => {
            let _guard = init_logging(false);
            // SSRF protection: reject URLs that resolve to private/internal addresses.
            if let Err(e) = is_safe_url(&url).await {
                eprintln!("Error: {}", e);
                std::process::exit(1);
            }
            info!(url = %url, confidence, full_scan, "Starting analysis");
            let wappalyzer = StandaloneWappalyzer::new(insecure).await?;
            if full_scan {
                println!("{}", "🔍 Full scan enabled: probing additional endpoints...".yellow());
            }
            let result = wappalyzer.analyze_url(&url, confidence, full_scan).await;
            if let Some(ref e) = result.error {
                error!(url = %url, error = %e, "Analysis failed");
            } else {
                info!(url = %url, tech_count = result.technologies.len(), "Analysis complete");
            }
            output::print_analysis_result(&result, &format.to_string(), verbose);
        }

        Commands::Batch { file, output, concurrency, confidence, insecure, full_scan } => {
            let _guard = init_logging(false);
            let urls = fs::read_to_string(&file).await?
                .lines()
                .map(|line| line.trim().to_string())
                .filter(|line| !line.is_empty() && line.starts_with("http"))
                .collect::<Vec<_>>();

            if urls.is_empty() {
                error!(file = %file, "No valid URLs found in file");
                return Err(anyhow::anyhow!("No valid URLs found in file"));
            }

            // SSRF protection: reject any URL that resolves to a private/internal address.
            for u in &urls {
                if let Err(e) = is_safe_url(u).await {
                    eprintln!("Error: {}", e);
                    std::process::exit(1);
                }
            }

            info!(file = %file, url_count = urls.len(), concurrency, full_scan, "Starting batch analysis");
            println!("{}", format!("📁 Loaded {} URLs from {}", urls.len(), file).green());
            if full_scan {
                println!("{}", "🔍 Full scan enabled: probing additional endpoints per URL...".yellow());
            }

            let wappalyzer = StandaloneWappalyzer::new(insecure).await?;
            let results = wappalyzer.analyze_urls_batch(urls, concurrency, confidence, full_scan).await?;
            let failed = results.iter().filter(|r| r.error.is_some()).count();
            info!(total = results.len(), failed, "Batch analysis complete");

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
            let _guard = init_logging(false);
            if force {
                debug!("Force flag set — removing cache file");
                let _ = fs::remove_file("wappalyzer_cache.json").await;
            }

            info!("Updating Wappalyzer database");
            println!("{}", "🔄 Updating Wappalyzer database...".yellow());
            let _ = TechnologyAnalyzer::update_database().await?;
            info!("Database updated successfully");
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
            let _guard = init_logging(false);
            info!(url_count = count, threads, "Starting benchmark");
            let wappalyzer = StandaloneWappalyzer::new(false).await?;
            let results = benchmark::run_benchmark(&wappalyzer, count, threads).await?;
            info!(urls_per_second = results.urls_per_second, "Benchmark complete");
            println!("\n{}", results.to_string().green());
        }

        Commands::Wayback { url, confidence, format, insecure } => {
            let _guard = init_logging(false);
            info!(url = %url, "Starting Wayback comparison (365d + 735d)");

            println!("Looking up Wayback Machine snapshots (~365 and ~735 days ago)...");

            let (snap365, snap735) = tokio::join!(
                wayback::find_snapshot(&url, 365),
                wayback::find_snapshot(&url, 735),
            );

            let snap365 = snap365.map_err(|e| anyhow::anyhow!("CDX lookup failed (365d): {}", e))?;
            let snap735 = snap735.map_err(|e| anyhow::anyhow!("CDX lookup failed (735d): {}", e))?;

            match &snap365 {
                Some((ts, u)) => println!("  365d snapshot : {} -> {}", ts, u),
                None => println!("  365d snapshot : not found"),
            }
            match &snap735 {
                Some((ts, u)) => println!("  735d snapshot : {} -> {}", ts, u),
                None => println!("  735d snapshot : not found"),
            }

            println!("Analyzing current site and historical snapshots...");

            let wappalyzer = StandaloneWappalyzer::new(insecure).await?;
            let current = wappalyzer.analyze_url(&url, confidence, true).await;

            let snapshot_365 = if let Some((ts, archive_url)) = &snap365 {
                let hist = wappalyzer.analyze_url(archive_url, confidence, false).await;
                Some(wayback::compare_snapshot(&current, &hist, ts, archive_url))
            } else {
                None
            };

            let snapshot_735 = if let Some((ts, archive_url)) = &snap735 {
                let hist = wappalyzer.analyze_url(archive_url, confidence, false).await;
                Some(wayback::compare_snapshot(&current, &hist, ts, archive_url))
            } else {
                None
            };

            let comparison = wayback::WaybackComparison {
                url: url.clone(),
                current: current.technologies.iter()
                    .map(|t| wayback::TechEntry { name: t.name.clone(), version: t.version.clone() })
                    .collect(),
                snapshot_365,
                snapshot_735,
            };

            match format {
                OutputFormat::Json => println!("{}", serde_json::to_string_pretty(&comparison)?),
                _ => output::print_wayback_comparison(&comparison),
            }
        }

        Commands::Serve { port, insecure } => {
            // Keep the guard alive for the duration of the server process.
            let _guard = init_logging(true);
            info!(port, insecure, "Starting HTTP API server");
            server::run(port, insecure).await?;
        }
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_benchmark_url_generation() {
        let urls = benchmark::generate_test_urls(20);
        assert_eq!(urls.len(), 20);
        assert!(urls[0].starts_with("https://"));
    }

    #[test]
    fn test_cli_parsing() {
        use clap::Parser;
        let cli = Cli::try_parse_from(&["test", "analyze", "https://example.com"]);
        assert!(cli.is_ok());
    }

    // ── is_safe_url ──────────────────────────────────────────────────────────

    #[tokio::test]
    async fn test_is_safe_url_rejects_loopback() {
        // We can't easily force a hostname to resolve to 127.0.0.1 in a unit test,
        // but we can verify that a direct IP literal URL is rejected.
        // (url::Url treats bare IPv4 as host — no DNS lookup needed)
        assert!(is_safe_url("http://127.0.0.1/").await.is_err());
    }

    #[tokio::test]
    async fn test_is_safe_url_rejects_private_10() {
        assert!(is_safe_url("http://10.0.0.1/").await.is_err());
    }

    #[tokio::test]
    async fn test_is_safe_url_rejects_private_172() {
        assert!(is_safe_url("http://172.16.0.1/").await.is_err());
        assert!(is_safe_url("http://172.31.255.255/").await.is_err());
        // 172.32.0.1 is NOT in the private range
        assert!(is_safe_url("http://172.32.0.1/").await.is_ok());
    }

    #[tokio::test]
    async fn test_is_safe_url_rejects_private_192_168() {
        assert!(is_safe_url("http://192.168.1.1/").await.is_err());
    }

    #[tokio::test]
    async fn test_is_safe_url_rejects_link_local() {
        assert!(is_safe_url("http://169.254.0.1/").await.is_err());
    }

    #[tokio::test]
    async fn test_is_safe_url_rejects_ipv6_loopback() {
        assert!(is_safe_url("http://[::1]/").await.is_err());
    }

    #[tokio::test]
    async fn test_is_safe_url_rejects_ipv6_ula() {
        assert!(is_safe_url("http://[fc00::1]/").await.is_err());
        assert!(is_safe_url("http://[fd00::1]/").await.is_err());
    }

    #[tokio::test]
    async fn test_is_safe_url_rejects_ipv6_link_local() {
        assert!(is_safe_url("http://[fe80::1]/").await.is_err());
    }

    #[tokio::test]
    async fn test_is_safe_url_rejects_ipv4_mapped_private() {
        // ::ffff:127.0.0.1 is the IPv4-mapped loopback
        assert!(is_safe_url("http://[::ffff:127.0.0.1]/").await.is_err());
        assert!(is_safe_url("http://[::ffff:10.0.0.1]/").await.is_err());
        assert!(is_safe_url("http://[::ffff:192.168.1.1]/").await.is_err());
    }

    #[tokio::test]
    async fn test_is_safe_url_rejects_invalid() {
        assert!(is_safe_url("not-a-url").await.is_err());
    }

    // ── RateLimiter ──────────────────────────────────────────────────────────

    #[test]
    fn test_rate_limiter_allows_under_limit() {
        let rl = middleware::RateLimiter::new(5, 60);
        for _ in 0..5 {
            assert!(rl.check("test-ip"));
        }
    }

    #[test]
    fn test_rate_limiter_blocks_over_limit() {
        let rl = middleware::RateLimiter::new(3, 60);
        assert!(rl.check("ip"));
        assert!(rl.check("ip"));
        assert!(rl.check("ip"));
        assert!(!rl.check("ip")); // 4th request should be blocked
    }

    #[test]
    fn test_rate_limiter_independent_keys() {
        let rl = middleware::RateLimiter::new(1, 60);
        assert!(rl.check("ip-a"));
        assert!(rl.check("ip-b")); // different key — should be allowed
        assert!(!rl.check("ip-a")); // same key, now blocked
    }
}
