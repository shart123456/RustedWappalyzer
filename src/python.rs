use pyo3::prelude::*;
use pyo3::exceptions::PyRuntimeError;
use crate::{TechnologyAnalyzer, HttpResponse};

#[pyclass(get_all)]
pub struct PyTechnology {
    pub name: String,
    pub confidence: u8,
    pub version: Option<String>,
    pub categories: Vec<String>,
    pub website: Option<String>,
    pub description: Option<String>,
    pub cpe: Option<String>,
}

#[pyclass]
pub struct PyWappalyzer {
    analyzer: std::sync::Arc<TechnologyAnalyzer>,
}

#[pymethods]
impl PyWappalyzer {
    #[new]
    fn new() -> PyResult<Self> {
        let rt = tokio::runtime::Runtime::new()
            .map_err(|e| PyRuntimeError::new_err(e.to_string()))?;
        let analyzer = rt
            .block_on(TechnologyAnalyzer::new())
            .map_err(|e| PyRuntimeError::new_err(e.to_string()))?;
        Ok(Self { analyzer: std::sync::Arc::new(analyzer) })
    }

    /// Analyze a pre-fetched HTTP response without making new HTTP requests.
    /// headers: flat dict of header_name -> value (lowercase keys)
    /// Returns list of PyTechnology objects.
    fn analyze_from_response(
        &self,
        url: &str,
        headers: std::collections::HashMap<String, String>,
        body: &str,
        status_code: u16,
        min_confidence: Option<u8>,
    ) -> Vec<PyTechnology> {
        let response = HttpResponse {
            url: url.to_string(),
            headers,
            body: body.to_string(),
            status_code,
            response_time_ms: 0,
        };
        self.analyzer
            .analyze(&response, min_confidence.unwrap_or(50))
            .into_iter()
            .map(|t| PyTechnology {
                name: t.name,
                confidence: t.confidence,
                version: t.version,
                categories: t.categories,
                website: t.website,
                description: t.description,
                cpe: t.cpe,
            })
            .collect()
    }
}

#[pymodule]
pub fn rusty_wappalyzer(_py: Python<'_>, m: &PyModule) -> PyResult<()> {
    m.add_class::<PyWappalyzer>()?;
    m.add_class::<PyTechnology>()?;
    Ok(())
}
