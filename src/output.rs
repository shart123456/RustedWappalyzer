use std::collections::HashMap;
use colored::Colorize;
use ::rusty_wappalyzer::{AnalysisResult, Technology};

pub fn print_analysis_result(result: &AnalysisResult, format: &str, verbose: bool) {
    match format {
        "json" => print_json(result),
        "table" => print_table(result, verbose),
        "simple" => print_simple(result),
        _ => print_table(result, verbose),
    }
}

fn print_json(result: &AnalysisResult) {
    match serde_json::to_string_pretty(result) {
        Ok(json) => println!("{}", json),
        Err(e) => eprintln!("Error serializing result: {}", e),
    }
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
                if let Some(saas) = tech.saas {
                    if saas {
                        print!("\n    ☁️  SaaS");
                    }
                }
                if let Some(pricing) = &tech.pricing {
                    print!("\n    💰 Pricing: {}", pricing.join(", ").yellow());
                }
                if let Some(cpe) = &tech.cpe {
                    print!("\n    🔒 CPE: {}", cpe.dimmed());
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
                    if value.chars().count() > 80 {
                        let truncated: String = value.chars().take(77).collect();
                        println!("  {}: {}...", name.yellow(), truncated.dimmed());
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

pub fn print_wayback_comparison(cmp: &crate::wayback::WaybackComparison) {
    println!("\n{}", format!("Wayback Comparison: {}", cmp.url).cyan().bold());
    println!("{}", "=".repeat(80).blue());

    println!("\n{}", "Current technologies:".green().bold());
    if cmp.current.is_empty() {
        println!("  (none detected)");
    }
    for t in &cmp.current {
        print!("  + {}", t.name.white().bold());
        if let Some(v) = &t.version { print!(" v{}", v.cyan()); }
        println!();
    }

    for (label, snap_opt) in [
        ("~365 days ago", &cmp.snapshot_365),
        ("~735 days ago", &cmp.snapshot_735),
    ] {
        println!("\n{}", format!("--- Snapshot {} ---", label).cyan().bold());
        match snap_opt {
            None => println!("  (no snapshot found)"),
            Some(snap) => {
                println!("  Date        : {} ({})", snap.snapshot_date.yellow(), snap.snapshot_timestamp.dimmed());
                println!("  Archive URL : {}", snap.snapshot_url.blue());

                println!("\n{}", format!("  Historical technologies ({}):", label).green().bold());
                if snap.historical.is_empty() {
                    println!("    (none detected)");
                }
                for t in &snap.historical {
                    print!("    + {}", t.name.white().bold());
                    if let Some(v) = &t.version { print!(" v{}", v.cyan()); }
                    println!();
                }

                if !snap.added.is_empty() {
                    println!("\n  {}", "Added since snapshot (new in current):".green().bold());
                    for name in &snap.added {
                        println!("    + {}", name.green());
                    }
                }

                if !snap.removed.is_empty() {
                    println!("\n  {}", "Removed since snapshot (gone from current):".red().bold());
                    for name in &snap.removed {
                        println!("    - {}", name.red());
                    }
                }

                if !snap.version_changes.is_empty() {
                    println!("\n  {}", "Version changes:".yellow().bold());
                    for vc in &snap.version_changes {
                        let was = vc.was.as_deref().unwrap_or("?");
                        let now = vc.now.as_deref().unwrap_or("?");
                        println!("    {} : {} -> {}", vc.technology.white().bold(), was.red(), now.green());
                    }
                }

                if snap.added.is_empty() && snap.removed.is_empty() && snap.version_changes.is_empty() {
                    println!("\n  {}", "No changes detected vs this snapshot.".green());
                }
            }
        }
    }
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
            let percentage = if successful > 0 {
                (*count as f64 / successful as f64) * 100.0
            } else {
                0.0
            };
            println!("  {}. {} - {} sites ({:.1}%)",
                (i + 1).to_string().yellow(),
                tech.white().bold(),
                count.to_string().green(),
                percentage.to_string().cyan()
            );
        }
    }
}
