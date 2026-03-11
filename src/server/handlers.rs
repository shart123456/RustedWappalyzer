use actix_web::{web, HttpResponse};
use futures::future::join_all;
use serde::{Deserialize, Serialize};
use std::sync::Arc;
use subtle::ConstantTimeEq;
use ::rusty_wappalyzer::{StandaloneWappalyzer, AnalysisResult, Signal, is_safe_url};
use crate::vuln;
use crate::poc;
use crate::alert;

type ResponseCache = Arc<moka::sync::Cache<String, Arc<AnalysisResult>>>;

#[derive(Serialize)]
struct TechEntry {
    technology: String,
    confidence: u8,
    version: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    cpe: Option<String>,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    cves: Vec<vuln::CveEntry>,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pocs: Vec<poc::PocEntry>,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    kev: Vec<alert::KevEntry>,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    advisories: Vec<alert::GhsaEntry>,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    signals: Vec<Signal>,
}

#[derive(Serialize)]
struct AnalyzeResponse {
    url: String,
    technologies: Vec<TechEntry>,
    #[serde(skip_serializing_if = "Option::is_none")]
    error: Option<String>,
}

#[derive(Deserialize)]
pub struct AnalyzeRequest {
    pub url: String,
    pub confidence: Option<u8>,
    pub insecure: Option<bool>,
    pub full_scan: Option<bool>,
    /// Set to `true` to silently re-run with full_scan when any technology
    /// lacks a version.  Defaults to `false` because it doubles request cost.
    pub auto_escalate: Option<bool>,
}

#[derive(Deserialize)]
pub struct BatchRequest {
    pub urls: Vec<String>,
    pub concurrency: Option<usize>,
    pub confidence: Option<u8>,
    pub full_scan: Option<bool>,
}

#[derive(Deserialize)]
pub struct WaybackRequest {
    pub url: String,
    pub confidence: Option<u8>,
    pub full_scan: Option<bool>,
}

/// Convert an `AnalysisResult` into an `AnalyzeResponse`, enriching each versioned
/// technology with CVE data from VulnVault, PoC links from PocVault, and
/// KEV/GHSA data from AlertVault when available.
async fn enrich_result(
    result: AnalysisResult,
    vault: Arc<Option<vuln::VulnVault>>,
    poc_vault: Arc<Option<poc::PocVault>>,
    alert_vault: Arc<Option<alert::AlertVault>>,
) -> AnalyzeResponse {
    let futures: Vec<_> = result.technologies.into_iter().map(|t| {
        let v = Arc::clone(&vault);
        let pv = Arc::clone(&poc_vault);
        let av = Arc::clone(&alert_vault);
        async move {
            let cves = if let Some(vault) = v.as_ref() {
                if let Some(ver) = t.version.as_deref() {
                    vault.lookup(ver, t.cpe.as_deref()).await
                } else if let Some(cpe) = t.cpe.as_deref() {
                    vault.lookup_unversioned(cpe).await
                } else {
                    vec![]
                }
            } else {
                vec![]
            };
            // PoC enrichment: primary path uses found CVE IDs, fallback uses CPE prefix.
            let pocs = if let Some(poc_vault) = pv.as_ref() {
                let cve_ids: Vec<&str> = cves.iter().map(|c| c.id.as_str()).collect();
                if !cve_ids.is_empty() {
                    poc_vault.lookup_by_cves(&cve_ids).await
                } else if let Some(cpe) = t.cpe.as_deref() {
                    poc_vault.lookup_by_cpe(cpe).await
                } else {
                    vec![]
                }
            } else {
                vec![]
            };
            // AlertVault enrichment: KEV catalog + GHSA advisories.
            let (kev, advisories) = if let Some(av) = av.as_ref() {
                let cve_ids: Vec<&str> = cves.iter().map(|c| c.id.as_str()).collect();
                let kev = if !cve_ids.is_empty() {
                    av.kev_by_cves(&cve_ids).await
                } else {
                    vec![]
                };
                let mut adv = if !cve_ids.is_empty() {
                    av.ghsa_by_cves(&cve_ids).await
                } else {
                    vec![]
                };
                // Supplement with package-based GHSA lookup.
                if let Some((ecosystem, pkg)) = alert::tech_package_lookup(&t.name) {
                    let pkg_adv = av.ghsa_by_package(pkg, ecosystem).await;
                    for a in pkg_adv {
                        if !adv.iter().any(|x| x.id == a.id) {
                            adv.push(a);
                        }
                    }
                }
                (kev, adv)
            } else {
                (vec![], vec![])
            };
            TechEntry {
                technology: t.name,
                confidence: t.confidence,
                version: t.version,
                cpe: t.cpe,
                cves,
                pocs,
                kev,
                advisories,
                signals: t.signals,
            }
        }
    }).collect();

    AnalyzeResponse {
        url: result.url,
        technologies: join_all(futures).await,
        error: result.error,
    }
}

/// Shared auth + rate-limit guard.  Returns `Err(response)` when the request
/// should be rejected, allowing callers to `return` it immediately.
fn check_auth_and_rate_limit(
    req: &actix_web::HttpRequest,
    rate_limiter: &crate::middleware::RateLimiter,
    api_key: &Option<String>,
) -> Result<(), HttpResponse> {
    let ip = req
        .peer_addr()
        .map(|a| a.ip().to_string())
        .unwrap_or_else(|| "unknown".to_string());
    if !rate_limiter.check(&ip) {
        return Err(HttpResponse::TooManyRequests().json(serde_json::json!({
            "error": "Rate limit exceeded. Max 60 requests per minute."
        })));
    }
    if let Some(required_key) = api_key.as_deref() {
        let provided = req
            .headers()
            .get("Authorization")
            .and_then(|v| v.to_str().ok())
            .and_then(|v| v.strip_prefix("Bearer "));
        let authorized = provided
            .map(|p| {
                // Use constant-time comparison to prevent timing-based key recovery.
                // ConstantTimeEq requires equal-length inputs; different lengths are
                // always rejected without leaking which byte diverged.
                p.len() == required_key.len()
                    && bool::from(p.as_bytes().ct_eq(required_key.as_bytes()))
            })
            .unwrap_or(false);
        if !authorized {
            return Err(HttpResponse::Unauthorized().json(serde_json::json!({
                "error": "Invalid or missing API key"
            })));
        }
    }
    Ok(())
}

pub async fn health() -> HttpResponse {
    HttpResponse::Ok().json(serde_json::json!({
        "status": "ok",
        "version": env!("CARGO_PKG_VERSION")
    }))
}

pub async fn info(data: web::Data<Arc<StandaloneWappalyzer>>) -> HttpResponse {
    let (technologies, categories) = data.get_stats();
    HttpResponse::Ok().json(serde_json::json!({
        "technologies": technologies,
        "categories": categories
    }))
}

pub async fn analyze(
    req: actix_web::HttpRequest,
    data: web::Data<Arc<StandaloneWappalyzer>>,
    server_insecure: web::Data<bool>,
    vault: web::Data<Arc<Option<vuln::VulnVault>>>,
    poc_vault: web::Data<Arc<Option<poc::PocVault>>>,
    alert_vault: web::Data<Arc<Option<alert::AlertVault>>>,
    rate_limiter: web::Data<crate::middleware::RateLimiter>,
    api_key: web::Data<Option<String>>,
    insecure_instance: web::Data<Arc<Option<StandaloneWappalyzer>>>,
    response_cache: web::Data<ResponseCache>,
    hot_keys: web::Data<super::cache::HotKeys>,
    body: web::Json<AnalyzeRequest>,
) -> HttpResponse {
    use std::collections::{HashMap, HashSet};

    if let Err(resp) = check_auth_and_rate_limit(&req, &rate_limiter, &api_key) {
        return resp;
    }

    let confidence = body.confidence.unwrap_or(50);
    let insecure = body.insecure.unwrap_or(*server_insecure.get_ref());
    let full_scan = body.full_scan.unwrap_or(false);
    let vault_arc = Arc::clone(vault.get_ref());
    let poc_vault_arc = Arc::clone(poc_vault.get_ref());
    let alert_vault_arc = Arc::clone(alert_vault.get_ref());

    // Validate URL — only allow http:// and https:// schemas
    if !body.url.starts_with("http://") && !body.url.starts_with("https://") {
        return HttpResponse::BadRequest().json(serde_json::json!({
            "error": "URL must use http:// or https:// scheme"
        }));
    }

    // SSRF protection
    if let Err(e) = is_safe_url(&body.url).await {
        return HttpResponse::BadRequest().json(serde_json::json!({ "error": e }));
    }

    // Response cache: only for plain (non-insecure, non-full-scan, no auto-escalate) requests.
    let cache_key = format!("{}:{}:{}:{}", body.url, confidence, full_scan, insecure);
    let auto_escalate = body.auto_escalate.unwrap_or(false);
    if !insecure && !auto_escalate {
        if let Some(cached) = response_cache.get(&cache_key) {
            tracing::debug!(url = %body.url, "Cache hit");
            // Refresh last_accessed so the background task keeps this URL warm.
            if let Ok(mut guard) = hot_keys.lock() {
                if let Some(entry) = guard.get_mut(&cache_key) {
                    entry.last_accessed = std::time::Instant::now();
                }
            }
            let result: AnalysisResult = (*cached).clone();
            return HttpResponse::Ok().json(enrich_result(result, vault_arc, poc_vault_arc, alert_vault_arc).await);
        }
    }

    // Insecure-override path: use the pre-built insecure instance.
    if insecure && !*server_insecure.get_ref() {
        match insecure_instance.get_ref().as_ref() {
            Some(w) => {
                tracing::debug!(url = %body.url, "Using pre-built insecure wappalyzer instance");
                let result = w.analyze_url(&body.url, confidence, full_scan).await;
                return HttpResponse::Ok().json(enrich_result(result, vault_arc, poc_vault_arc, alert_vault_arc).await);
            }
            None => {
                return HttpResponse::ServiceUnavailable().json(serde_json::json!({
                    "error": "Insecure mode is not available on this server instance"
                }));
            }
        }
    }

    // Initial scan.
    let mut result = data.analyze_url(&body.url, confidence, full_scan).await;

    // Auto-escalation: when the caller opts in and any detected technology lacks a
    // version, silently re-run with full_scan=true and merge results.
    // Opt-in only (auto_escalate=true) because it doubles the request cost.
    if auto_escalate && !full_scan && result.error.is_none() {
        let has_unversioned = result.technologies.iter().any(|t| t.version.is_none());
        if has_unversioned {
            tracing::debug!(url = %body.url, "Auto-escalating to full_scan for version enrichment");
            let full_result = data.analyze_url(&body.url, confidence, true).await;
            if full_result.error.is_none() {
                // Map tech name → version from the full-scan result.
                let version_map: HashMap<&str, &str> = full_result
                    .technologies
                    .iter()
                    .filter_map(|t| t.version.as_deref().map(|v| (t.name.as_str(), v)))
                    .collect();

                // Patch unversioned techs from the initial scan.
                for tech in &mut result.technologies {
                    if tech.version.is_none() {
                        if let Some(&v) = version_map.get(tech.name.as_str()) {
                            tech.version = Some(v.to_string());
                        }
                    }
                }

                // Append techs discovered only by the full scan.
                let existing: HashSet<String> =
                    result.technologies.iter().map(|t| t.name.clone()).collect();
                for tech in full_result.technologies {
                    if !existing.contains(&tech.name) {
                        result.technologies.push(tech);
                    }
                }
            }
        }
    }

    // Store in cache and mark as hot for background auto-refresh.
    if !insecure && !auto_escalate {
        response_cache.insert(cache_key.clone(), Arc::new(result.clone()));
        if let Ok(mut guard) = hot_keys.lock() {
            guard.insert(cache_key, super::cache::HotEntry {
                url: body.url.clone(),
                confidence,
                full_scan,
                last_accessed: std::time::Instant::now(),
            });
        }
    }

    HttpResponse::Ok().json(enrich_result(result, vault_arc, poc_vault_arc, alert_vault_arc).await)
}

pub async fn wayback_analyze(
    req: actix_web::HttpRequest,
    data: web::Data<Arc<StandaloneWappalyzer>>,
    rate_limiter: web::Data<crate::middleware::RateLimiter>,
    api_key: web::Data<Option<String>>,
    body: web::Json<WaybackRequest>,
) -> HttpResponse {
    if let Err(resp) = check_auth_and_rate_limit(&req, &rate_limiter, &api_key) {
        return resp;
    }

    if !body.url.starts_with("http://") && !body.url.starts_with("https://") {
        return HttpResponse::BadRequest().json(serde_json::json!({
            "error": "URL must use http:// or https:// scheme"
        }));
    }

    // SSRF protection
    if let Err(e) = is_safe_url(&body.url).await {
        return HttpResponse::BadRequest().json(serde_json::json!({ "error": e }));
    }

    let confidence = body.confidence.unwrap_or(50);
    let full_scan = body.full_scan.unwrap_or(true);

    // Find both snapshots concurrently
    let (snap365, snap735) = tokio::join!(
        crate::wayback::find_snapshot(&body.url, 365),
        crate::wayback::find_snapshot(&body.url, 735),
    );

    let snap365 = match snap365 {
        Err(e) => return HttpResponse::InternalServerError().json(serde_json::json!({
            "error": format!("CDX lookup failed (365d): {}", e)
        })),
        Ok(v) => v,
    };
    let snap735 = match snap735 {
        Err(e) => return HttpResponse::InternalServerError().json(serde_json::json!({
            "error": format!("CDX lookup failed (735d): {}", e)
        })),
        Ok(v) => v,
    };

    // Build archive URLs for found snapshots
    let archive_url_365 = snap365.as_ref().map(|(ts, u)| (ts.clone(), u.clone()));
    let archive_url_735 = snap735.as_ref().map(|(ts, u)| (ts.clone(), u.clone()));

    // Analyze current site, then any found snapshots
    let current = data.analyze_url(&body.url, confidence, full_scan).await;

    let snapshot_365 = if let Some((ts, url)) = &archive_url_365 {
        let hist = data.analyze_url(url, confidence, false).await;
        Some(crate::wayback::compare_snapshot(&current, &hist, ts, url))
    } else {
        None
    };

    let snapshot_735 = if let Some((ts, url)) = &archive_url_735 {
        let hist = data.analyze_url(url, confidence, false).await;
        Some(crate::wayback::compare_snapshot(&current, &hist, ts, url))
    } else {
        None
    };

    let comparison = crate::wayback::WaybackComparison {
        url: body.url.clone(),
        current: current.technologies.iter()
            .map(|t| crate::wayback::TechEntry { name: t.name.clone(), version: t.version.clone() })
            .collect(),
        snapshot_365,
        snapshot_735,
    };
    HttpResponse::Ok().json(comparison)
}

pub async fn batch(
    req: actix_web::HttpRequest,
    data: web::Data<Arc<StandaloneWappalyzer>>,
    vault: web::Data<Arc<Option<vuln::VulnVault>>>,
    poc_vault: web::Data<Arc<Option<poc::PocVault>>>,
    alert_vault: web::Data<Arc<Option<alert::AlertVault>>>,
    rate_limiter: web::Data<crate::middleware::RateLimiter>,
    api_key: web::Data<Option<String>>,
    body: web::Json<BatchRequest>,
) -> HttpResponse {
    if let Err(resp) = check_auth_and_rate_limit(&req, &rate_limiter, &api_key) {
        return resp;
    }

    let confidence = body.confidence.unwrap_or(50);
    let concurrency = body.concurrency.unwrap_or(5);
    let full_scan = body.full_scan.unwrap_or(false);
    let vault_arc = Arc::clone(vault.get_ref());
    let poc_vault_arc = Arc::clone(poc_vault.get_ref());
    let alert_vault_arc = Arc::clone(alert_vault.get_ref());

    let max_batch = data.max_batch_size();
    if body.urls.len() > max_batch {
        return HttpResponse::BadRequest().json(serde_json::json!({
            "error": format!("Batch size {} exceeds maximum of {}", body.urls.len(), max_batch)
        }));
    }

    // Validate URL schemes first (cheap, synchronous).
    for url in &body.urls {
        if !url.starts_with("http://") && !url.starts_with("https://") {
            return HttpResponse::BadRequest().json(serde_json::json!({
                "error": format!("URL '{}' must use http:// or https:// scheme", url)
            }));
        }
    }

    // SSRF-check all URLs concurrently (DNS lookups are independent).
    let ssrf_checks: Vec<_> = body.urls.iter().map(|url| {
        let url = url.clone();
        async move { is_safe_url(&url).await.map_err(|e| e) }
    }).collect();
    for result in futures::future::join_all(ssrf_checks).await {
        if let Err(e) = result {
            return HttpResponse::BadRequest().json(serde_json::json!({ "error": e }));
        }
    }

    match data.analyze_urls_batch(body.urls.clone(), concurrency, confidence, full_scan).await {
        Ok(results) => {
            let enriched = join_all(
                results.into_iter().map(|r| enrich_result(r, Arc::clone(&vault_arc), Arc::clone(&poc_vault_arc), Arc::clone(&alert_vault_arc)))
            ).await;
            HttpResponse::Ok().json(enriched)
        }
        Err(e) => HttpResponse::InternalServerError().json(serde_json::json!({
            "error": e.to_string()
        })),
    }
}
