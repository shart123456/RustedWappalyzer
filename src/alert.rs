use futures::TryStreamExt;
use mongodb::{
    bson::{doc, Document},
    Client, Collection,
};
use serde::Serialize;

#[derive(Serialize, Clone, Debug)]
pub struct KevEntry {
    pub cve_id: String,
    pub vulnerability_name: String,
    pub date_added: String,
    pub due_date: String,
    pub known_ransomware: bool,
    pub required_action: String,
}

#[derive(Serialize, Clone, Debug)]
pub struct GhsaEntry {
    pub id: String,
    pub cve_id: Option<String>,
    pub summary: String,
    pub severity: f64,
    pub severity_level: String,
    pub ecosystem: String,
    pub package_name: String,
    pub published: String,
}

pub struct AlertVault {
    kev: Collection<Document>,
    ghsa: Collection<Document>,
}

/// Static mapping from Wappalyzer technology name → (ecosystem, package_name).
/// Used to supplement CVE-based GHSA lookups with package-level advisories.
pub fn tech_package_lookup(tech_name: &str) -> Option<(&'static str, &'static str)> {
    // (wappalyzer_tech_name, ecosystem, package_name)
    const TABLE: &[(&str, &str, &str)] = &[
        ("React", "npm", "react"),
        ("Vue.js", "npm", "vue"),
        ("Angular", "npm", "@angular/core"),
        ("Next.js", "npm", "next"),
        ("jQuery", "npm", "jquery"),
        ("Express", "npm", "express"),
        ("Nuxt.js", "npm", "nuxt"),
        ("Gatsby", "npm", "gatsby"),
        ("Svelte", "npm", "svelte"),
        ("Ember.js", "npm", "ember-source"),
        ("Backbone.js", "npm", "backbone"),
        ("Bootstrap", "npm", "bootstrap"),
        ("Lodash", "npm", "lodash"),
        ("Moment.js", "npm", "moment"),
        ("Axios", "npm", "axios"),
        ("Webpack", "npm", "webpack"),
        ("Django", "PyPI", "Django"),
        ("Flask", "PyPI", "Flask"),
        ("FastAPI", "PyPI", "fastapi"),
        ("Pillow", "PyPI", "Pillow"),
        ("Rails", "RubyGems", "rails"),
        ("Devise", "RubyGems", "devise"),
        ("Laravel", "Packagist", "laravel/framework"),
        ("Symfony", "Packagist", "symfony/symfony"),
        ("Drupal", "Packagist", "drupal/core"),
        ("WordPress", "Packagist", "wordpress/wordpress"),
        ("Spring Boot", "Maven", "org.springframework.boot:spring-boot"),
        ("Spring Framework", "Maven", "org.springframework:spring-core"),
        ("Log4j", "Maven", "org.apache.logging.log4j:log4j-core"),
        ("Struts", "Maven", "org.apache.struts:struts2-core"),
    ];
    TABLE.iter()
        .find(|(name, _, _)| name.eq_ignore_ascii_case(tech_name))
        .map(|(_, eco, pkg)| (*eco, *pkg))
}

impl AlertVault {
    /// Try to connect to AlertVault MongoDB.  Returns `None` on failure or empty collections.
    pub async fn try_connect() -> Option<Self> {
        let uri = match std::env::var("MONGODB_URI") {
            Ok(u) => u,
            Err(_) => {
                tracing::debug!("MONGODB_URI not set; AlertVault KEV/GHSA enrichment disabled");
                return None;
            }
        };
        let client = match Client::with_uri_str(&uri).await {
            Ok(c) => c,
            Err(e) => {
                tracing::warn!(error = %e, "AlertVault: MongoDB client creation failed");
                return None;
            }
        };
        if let Err(e) = client.database("admin").run_command(doc! { "ping": 1 }).await {
            tracing::warn!(error = %e, "AlertVault: MongoDB ping failed");
            return None;
        }
        let kev: Collection<Document> = client.database("alerts").collection("kev");
        let ghsa: Collection<Document> = client.database("alerts").collection("ghsa");
        let kev_count = kev.estimated_document_count().await.unwrap_or(0);
        let ghsa_count = ghsa.estimated_document_count().await.unwrap_or(0);
        if kev_count == 0 && ghsa_count == 0 {
            tracing::warn!("AlertVault collections are empty — KEV/GHSA enrichment disabled");
            return None;
        }
        tracing::info!(
            kev_count,
            ghsa_count,
            "AlertVault connected — KEV/GHSA enrichment enabled"
        );
        Some(AlertVault { kev, ghsa })
    }

    fn doc_to_kev(doc: &Document) -> Option<KevEntry> {
        let cve_id = doc.get_str("_id").ok()?.to_string();
        let vulnerability_name = doc.get_str("vulnerability_name").unwrap_or("").to_string();
        let date_added: String = doc.get_str("date_added").unwrap_or("").chars().take(10).collect();
        let due_date: String = doc.get_str("due_date").unwrap_or("").chars().take(10).collect();
        let known_ransomware = doc.get_bool("known_ransomware").unwrap_or(false);
        let required_action = doc.get_str("required_action").unwrap_or("").to_string();
        Some(KevEntry {
            cve_id,
            vulnerability_name,
            date_added,
            due_date,
            known_ransomware,
            required_action,
        })
    }

    fn doc_to_ghsa(doc: &Document) -> Option<GhsaEntry> {
        let id = doc.get_str("_id").ok()?.to_string();
        let cve_id = doc.get_str("cve_id").ok().map(|s| s.to_string());
        let summary: String = doc
            .get_str("summary")
            .unwrap_or("")
            .chars()
            .take(200)
            .collect();
        let severity = doc.get_f64("severity").unwrap_or(0.0);
        let severity_level = doc.get_str("severity_level").unwrap_or("UNKNOWN").to_string();
        let ecosystem = doc.get_str("ecosystem").unwrap_or("").to_string();
        let package_name = doc.get_str("package_name").unwrap_or("").to_string();
        let published: String = doc
            .get_str("published")
            .unwrap_or("")
            .chars()
            .take(10)
            .collect();
        Some(GhsaEntry {
            id,
            cve_id,
            summary,
            severity,
            severity_level,
            ecosystem,
            package_name,
            published,
        })
    }

    /// Returns KEV entries for each CVE ID that is in CISA's catalog.
    pub async fn kev_by_cves(&self, cve_ids: &[&str]) -> Vec<KevEntry> {
        if cve_ids.is_empty() {
            return vec![];
        }
        let ids: Vec<mongodb::bson::Bson> = cve_ids
            .iter()
            .map(|id| mongodb::bson::Bson::String(id.to_string()))
            .collect();
        let filter = doc! { "_id": { "$in": ids } };
        let mut results: Vec<KevEntry> = Vec::new();
        if let Ok(mut cursor) = self.kev.find(filter).await {
            while let Ok(Some(doc)) = cursor.try_next().await {
                if let Some(e) = Self::doc_to_kev(&doc) {
                    results.push(e);
                }
            }
        }
        results
    }

    /// Returns GHSA advisories linked to found CVE IDs.
    pub async fn ghsa_by_cves(&self, cve_ids: &[&str]) -> Vec<GhsaEntry> {
        if cve_ids.is_empty() {
            return vec![];
        }
        let ids: Vec<mongodb::bson::Bson> = cve_ids
            .iter()
            .map(|id| mongodb::bson::Bson::String(id.to_string()))
            .collect();
        let filter = doc! { "cve_id": { "$in": ids } };
        let mut results: Vec<GhsaEntry> = Vec::new();
        if let Ok(mut cursor) = self.ghsa.find(filter).limit(20).await {
            while let Ok(Some(doc)) = cursor.try_next().await {
                if let Some(e) = Self::doc_to_ghsa(&doc) {
                    results.push(e);
                }
            }
        }
        results.sort_by(|a, b| b.severity.partial_cmp(&a.severity).unwrap_or(std::cmp::Ordering::Equal));
        results
    }

    /// Returns GHSA advisories by package name + ecosystem (tech-name→package mapping).
    pub async fn ghsa_by_package(&self, name: &str, ecosystem: &str) -> Vec<GhsaEntry> {
        let filter = doc! {
            "package_name": name,
            "ecosystem": ecosystem,
        };
        let mut results: Vec<GhsaEntry> = Vec::new();
        if let Ok(mut cursor) = self.ghsa.find(filter).limit(10).await {
            while let Ok(Some(doc)) = cursor.try_next().await {
                if let Some(e) = Self::doc_to_ghsa(&doc) {
                    results.push(e);
                }
            }
        }
        results.sort_by(|a, b| b.severity.partial_cmp(&a.severity).unwrap_or(std::cmp::Ordering::Equal));
        results
    }
}
