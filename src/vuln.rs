use futures::TryStreamExt;
use mongodb::{
    bson::{doc, Document},
    Client, Collection,
};
use serde::Serialize;
use std::collections::HashSet;

#[derive(Serialize, Clone, Debug)]
pub struct CveEntry {
    pub id: String,
    pub score: f64,
    pub severity: String,
    pub description: String,
    pub published: String,
}

pub struct VulnVault {
    cves: Collection<Document>,
}

impl VulnVault {
    /// Try to connect to VulnVault MongoDB.  Returns `None` on failure or empty collection.
    pub async fn try_connect() -> Option<Self> {
        let uri = match std::env::var("MONGODB_URI") {
            Ok(u) => u,
            Err(_) => {
                tracing::debug!("MONGODB_URI not set; VulnVault CVE enrichment disabled");
                return None;
            }
        };
        let client = match Client::with_uri_str(&uri).await {
            Ok(c) => c,
            Err(e) => {
                tracing::warn!(error = %e, "VulnVault: MongoDB client creation failed");
                return None;
            }
        };
        // Async ping to confirm connectivity.
        client
            .database("admin")
            .run_command(doc! { "ping": 1 })
            .await
            .ok()?;
        let cves: Collection<Document> =
            client.database("nvd").collection("cves");
        let count = cves.estimated_document_count().await.unwrap_or(0);
        if count == 0 {
            tracing::warn!("VulnVault CVE collection is empty — CVE enrichment disabled");
            return None;
        }
        tracing::info!(cve_count = count, "VulnVault connected — CVE enrichment enabled");
        Some(VulnVault { cves })
    }

    /// Inject a detected version string into CPE template at field index 5.
    fn inject_version(template: &str, version: &str) -> String {
        let mut parts: Vec<&str> = template.split(':').collect();
        if parts.len() >= 6 {
            parts[5] = version;
        }
        parts.join(":")
    }

    /// Extract the highest available CVSS score + severity from a CVE document.
    fn extract_cvss(doc: &Document) -> (f64, String) {
        for key in &["metrics_v31", "metrics_v30", "metrics_v40", "metrics_v20"] {
            if let Ok(metrics) = doc.get_document(*key) {
                for (_, entry_bson) in metrics.iter() {
                    if let Some(entry) = entry_bson.as_document() {
                        let score = entry
                            .get_f64("base_score")
                            .or_else(|_| entry.get_f64("baseScore"))
                            .unwrap_or(0.0);
                        if score > 0.0 {
                            let severity = entry
                                .get_str("base_severity")
                                .or_else(|_| entry.get_str("baseSeverity"))
                                .unwrap_or("UNKNOWN")
                                .to_uppercase();
                            return (score, severity);
                        }
                    }
                }
            }
        }
        (0.0, "UNKNOWN".to_string())
    }

    fn doc_to_cve(doc: &Document) -> Option<CveEntry> {
        let id = doc.get_str("_id").ok()?.to_string();
        let description: String =
            doc.get_str("description").unwrap_or("").chars().take(200).collect();
        let published: String =
            doc.get_str("published").unwrap_or("").chars().take(10).collect();
        let (score, severity) = Self::extract_cvss(doc);
        Some(CveEntry { id, score, severity, description, published })
    }

    /// Parse a version string into a comparable `Vec<u64>` for range checks.
    fn parse_ver(v: &str) -> Vec<u64> {
        let clean: String = v.chars().take_while(|c| c.is_ascii_digit() || *c == '.').collect();
        clean.split('.').filter_map(|p| p.parse::<u64>().ok()).collect()
    }

    fn version_in_range(version: &str, cm: &Document) -> bool {
        let v = Self::parse_ver(version);
        if v.is_empty() {
            return false;
        }

        let has_start = cm.get_str("versionStartIncluding").is_ok()
            || cm.get_str("versionStartExcluding").is_ok();
        let has_end = cm.get_str("versionEndIncluding").is_ok()
            || cm.get_str("versionEndExcluding").is_ok();

        if let Ok(s) = cm.get_str("versionStartIncluding") {
            if v < Self::parse_ver(s) { return false; }
        }
        if let Ok(s) = cm.get_str("versionStartExcluding") {
            if v <= Self::parse_ver(s) { return false; }
        }
        if let Ok(e) = cm.get_str("versionEndIncluding") {
            if v > Self::parse_ver(e) { return false; }
        }
        if let Ok(e) = cm.get_str("versionEndExcluding") {
            if v >= Self::parse_ver(e) { return false; }
        }

        // No range fields → exact-version pin embedded in the criteria string.
        // CPE 2.3 format: cpe:2.3:part:vendor:product:VERSION:...
        // Field index 5 holds the pinned version. Wildcards ('*', '-') match any.
        if !has_start && !has_end {
            let criteria = cm.get_str("criteria").unwrap_or("");
            let parts: Vec<&str> = criteria.split(':').collect();
            if parts.len() > 5 {
                let pinned = parts[5];
                if pinned != "*" && pinned != "-" {
                    let pv = Self::parse_ver(pinned);
                    if !pv.is_empty() && v != pv {
                        return false;
                    }
                }
            }
        }

        true
    }

    /// Look up CVEs by CPE prefix alone — used when no version was detected.
    /// Returns all CVEs whose CPE criteria matches the base vendor:product prefix,
    /// sorted by CVSS descending, capped at 10.
    pub async fn lookup_unversioned(&self, cpe_template: &str) -> Vec<CveEntry> {
        let parts: Vec<&str> = cpe_template.split(':').collect();
        if parts.len() < 5 { return vec![]; }
        let base_prefix = format!("{}:", parts[..5].join(":"));
        let escaped = regex::escape(&base_prefix);
        let filter = doc! {
            "configurations.nodes.cpeMatch.criteria": {
                "$regex": escaped,
                "$options": "i"
            }
        };
        let mut results: Vec<CveEntry> = Vec::new();
        let mut seen: HashSet<String> = HashSet::new();
        match self.cves.find(filter).limit(200).await {
            Err(e) => {
                tracing::warn!(error = %e, "VulnVault: unversioned CVE lookup failed");
            }
            Ok(mut cursor) => {
                while let Ok(Some(doc)) = cursor.try_next().await {
                    if let Some(e) = Self::doc_to_cve(&doc) {
                        if seen.insert(e.id.clone()) { results.push(e); }
                    }
                }
            }
        }
        results.sort_by(|a, b| b.score.partial_cmp(&a.score).unwrap_or(std::cmp::Ordering::Equal));
        results.truncate(10);
        results
    }

    /// Look up CVEs for a detected technology version + optional CPE template.
    /// Two strategies: exact injected CPE, then version-range scan.
    pub async fn lookup(&self, version: &str, cpe_template: Option<&str>) -> Vec<CveEntry> {
        let mut results: Vec<CveEntry> = Vec::new();
        let mut seen: HashSet<String> = HashSet::new();

        // ── Strategy 1: exact version injected into CPE ──────────────────────
        if let Some(tmpl) = cpe_template {
            let injected = Self::inject_version(tmpl, version);
            let filter = doc! {
                "configurations.nodes.cpeMatch": {
                    "$elemMatch": { "criteria": &injected, "vulnerable": true }
                }
            };
            match self.cves.find(filter).await {
                Err(e) => {
                    tracing::warn!(error = %e, "VulnVault: exact CVE lookup failed");
                }
                Ok(mut cursor) => {
                    while let Ok(Some(doc)) = cursor.try_next().await {
                        if let Some(e) = Self::doc_to_cve(&doc) {
                            if seen.insert(e.id.clone()) { results.push(e); }
                        }
                    }
                }
            }
        }

        // ── Strategy 2: version-range scan via base CPE prefix ───────────────
        if results.is_empty() {
            if let Some(tmpl) = cpe_template {
                let parts: Vec<&str> = tmpl.split(':').collect();
                if parts.len() >= 5 {
                    let base_prefix = format!("{}:", parts[..5].join(":"));
                    let escaped = regex::escape(&base_prefix);
                    let filter = doc! {
                        "configurations.nodes.cpeMatch.criteria": {
                            "$regex": escaped,
                            "$options": "i"
                        }
                    };
                    match self.cves.find(filter).limit(500).await {
                        Err(e) => {
                            tracing::warn!(error = %e, "VulnVault: version-range CVE lookup failed");
                        }
                        Ok(mut cursor) => {
                            'outer: while let Ok(Some(doc)) = cursor.try_next().await {
                                if let Ok(configs) = doc.get_array("configurations") {
                                    for cfg_bson in configs.iter() {
                                        let Some(cfg) = cfg_bson.as_document() else { continue };
                                        let Ok(nodes) = cfg.get_array("nodes") else { continue };
                                        for node_bson in nodes.iter() {
                                            let Some(node) = node_bson.as_document() else { continue };
                                            let Ok(cpe_matches) = node.get_array("cpeMatch") else { continue };
                                            for cm_bson in cpe_matches.iter() {
                                                let Some(cm) = cm_bson.as_document() else { continue };
                                                if !cm.get_bool("vulnerable").unwrap_or(false) { continue; }
                                                let criteria = cm.get_str("criteria").unwrap_or("");
                                                if !criteria.to_lowercase().starts_with(&base_prefix.to_lowercase()) { continue; }
                                                if Self::version_in_range(version, cm) {
                                                    if let Some(e) = Self::doc_to_cve(&doc) {
                                                        if seen.insert(e.id.clone()) { results.push(e); }
                                                    }
                                                    continue 'outer;
                                                }
                                            }
                                        }
                                    }
                                }
                            }
                        }
                    }
                }
            }
        }

        // Sort by CVSS descending, cap at 20 per technology.
        results.sort_by(|a, b| b.score.partial_cmp(&a.score).unwrap_or(std::cmp::Ordering::Equal));
        results.truncate(20);
        results
    }
}
