use futures::TryStreamExt;
use mongodb::{
    bson::{doc, Document},
    Client, Collection,
};
use serde::Serialize;

#[derive(Serialize, Clone, Debug)]
pub struct PocEntry {
    pub cve_id: String,
    pub url: String,
    pub name: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub description: Option<String>,
    pub stars: u32,
    pub pushed_at: String,
    pub verified: bool,
}

pub struct PocVault {
    entries: Collection<Document>,
}

impl PocVault {
    /// Try to connect to PocVault MongoDB.  Returns `None` on failure or empty collection.
    pub async fn try_connect() -> Option<Self> {
        let uri = match std::env::var("MONGODB_URI") {
            Ok(u) => u,
            Err(_) => {
                tracing::debug!("MONGODB_URI not set; PocVault PoC enrichment disabled");
                return None;
            }
        };
        let client = match Client::with_uri_str(&uri).await {
            Ok(c) => c,
            Err(e) => {
                tracing::warn!(error = %e, "PocVault: MongoDB client creation failed");
                return None;
            }
        };
        client
            .database("admin")
            .run_command(doc! { "ping": 1 })
            .await
            .ok()?;
        let entries: Collection<Document> =
            client.database("poc").collection("entries");
        let count = entries.estimated_document_count().await.unwrap_or(0);
        if count == 0 {
            tracing::warn!("PocVault PoC collection is empty — PoC enrichment disabled");
            return None;
        }
        tracing::info!(poc_count = count, "PocVault connected — PoC enrichment enabled");
        Some(PocVault { entries })
    }

    fn doc_to_poc(doc: &Document) -> Option<PocEntry> {
        let cve_id = doc.get_str("cve_id").ok()?.to_string();
        let url = doc.get_str("url").ok()?.to_string();
        let name = doc.get_str("name").ok()?.to_string();
        let description = doc.get_str("description").ok()
            .map(|s| s.chars().take(200).collect());
        let stars = doc.get_i32("stars").unwrap_or(0) as u32;
        let pushed_at: String = doc.get_str("pushed_at").unwrap_or("").chars().take(10).collect();
        let verified = doc.get_bool("verified").unwrap_or(false);
        Some(PocEntry { cve_id, url, name, description, stars, pushed_at, verified })
    }

    /// Look up PoC entries by a list of CVE IDs.
    /// Returns up to 10 entries sorted by stars descending.
    pub async fn lookup_by_cves(&self, cve_ids: &[&str]) -> Vec<PocEntry> {
        if cve_ids.is_empty() {
            return vec![];
        }
        let ids: Vec<mongodb::bson::Bson> = cve_ids.iter()
            .map(|id| mongodb::bson::Bson::String(id.to_string()))
            .collect();
        let filter = doc! { "cve_id": { "$in": ids } };
        let mut results: Vec<PocEntry> = Vec::new();
        match self.entries.find(filter)
            .sort(doc! { "stars": -1 })
            .limit(50)
            .await
        {
            Err(e) => {
                tracing::warn!(error = %e, "PocVault: CVE PoC lookup failed");
            }
            Ok(mut cursor) => {
                while let Ok(Some(doc)) = cursor.try_next().await {
                    if let Some(e) = Self::doc_to_poc(&doc) {
                        results.push(e);
                    }
                }
            }
        }
        results.truncate(10);
        results
    }

    /// Look up PoC entries by CPE prefix (fallback when no CVEs found).
    /// Returns up to 5 entries sorted by stars descending.
    pub async fn lookup_by_cpe(&self, cpe: &str) -> Vec<PocEntry> {
        let parts: Vec<&str> = cpe.split(':').collect();
        if parts.len() < 5 {
            return vec![];
        }
        let prefix = parts[..5].join(":");
        let escaped = regex::escape(&prefix);
        let filter = doc! {
            "cpe_prefix": { "$regex": escaped, "$options": "i" }
        };
        let mut results: Vec<PocEntry> = Vec::new();
        match self.entries.find(filter)
            .sort(doc! { "stars": -1 })
            .limit(100)
            .await
        {
            Err(e) => {
                tracing::warn!(error = %e, "PocVault: CPE PoC lookup failed");
            }
            Ok(mut cursor) => {
                while let Ok(Some(doc)) = cursor.try_next().await {
                    if let Some(e) = Self::doc_to_poc(&doc) {
                        results.push(e);
                    }
                }
            }
        }
        results.truncate(5);
        results
    }
}
