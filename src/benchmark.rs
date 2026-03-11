use std::time::Instant;
use colored::Colorize;
use ::rusty_wappalyzer::{StandaloneWappalyzer, WappalyzerError};

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

    let results = wappalyzer.analyze_urls_batch(test_urls, concurrency, 50, false).await?;

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
