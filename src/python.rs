// pyo3 0.20's `#[pymethods]` / `#[pyclass]` macros expand into `impl` blocks nested
// inside a generated function body (a `trampoline`), which rustc's `non_local_definitions`
// lint reports. It is an artifact of the pinned macro version, not of anything in this
// file, and there is no way to write the bindings that avoids it short of upgrading pyo3.
// CI builds this feature with `RUSTFLAGS: -D warnings`, so the warning would be a hard
// build failure; allow it here (module-scoped, so it cannot mask the lint elsewhere).
// Remove this once pyo3 is upgraded past the 0.20 pre-Bound macro API.
#![allow(non_local_definitions)]

use pyo3::prelude::*;
use pyo3::exceptions::PyRuntimeError;
use crate::{TechnologyAnalyzer, HttpResponse, Signal};

/// One piece of evidence behind a detection, mirroring [`crate::types::Signal`].
///
/// `Technology.signals` is the only part of a result that explains *why* something was
/// detected, which is exactly what a caller triaging a false positive needs. It is a
/// separate `#[pyclass]` rather than a tuple so the fields stay named on the Python side;
/// `Clone` is required because `get_all` getters hand out a clone of the field.
#[pyclass(get_all)]
#[derive(Clone)]
pub struct PySignal {
    /// "header", "html", "script", "cookie", "dns", "probe", "favicon", "implied", ...
    pub signal_type: String,
    /// The matched pattern or source description (truncated to 100 chars upstream).
    pub value: String,
    /// 0-100 contribution of this signal to the technology's confidence.
    pub weight: u8,
}

/// A detected technology. Field-for-field mirror of [`crate::types::Technology`].
///
/// Keep this in sync with that struct: the Rust side is what the analyzer fills in, and a
/// field that exists there but not here is silently invisible to every Python caller. The
/// bindings previously dropped `icon`, `saas`, `pricing` and `signals` for exactly that
/// reason — nothing forced the two definitions to agree.
#[pyclass(get_all)]
pub struct PyTechnology {
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
    pub signals: Vec<PySignal>,
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
    ///
    /// headers: flat dict of header_name -> value (lowercase keys)
    /// min_confidence: drop technologies scoring below this (default 50)
    /// set_cookie_headers: the response's Set-Cookie values, one string per header line
    ///
    /// `set_cookie_headers` is separate from `headers` because a dict cannot hold the
    /// repeated Set-Cookie headers a real response carries: whatever client produced the
    /// dict had to collapse them into one value, and the cookie layer matches on
    /// per-cookie boundaries (it splits each line on `;` and then on the first `=` to
    /// recover the cookie name). Cookies joined with the conventional ", " therefore
    /// arrive as one bogus cookie name and detections keyed on `connect.sid`,
    /// `csrftoken`, `laravel_session`, `_shopify_s` and friends are lost.
    ///
    /// Omitting it is allowed and degrades gracefully rather than failing: the analyzer
    /// falls back to splitting `headers["set-cookie"]` on newlines, so a caller that
    /// joined the headers with "\n" still gets cookie detection, and one that joined them
    /// any other way loses only the cookie-derived matches. Everything else — headers,
    /// HTML, scripts, meta, DOM — is unaffected. Pass the real list when you have it.
    fn analyze_from_response(
        &self,
        url: &str,
        headers: std::collections::HashMap<String, String>,
        body: &str,
        status_code: u16,
        min_confidence: Option<u8>,
        set_cookie_headers: Option<Vec<String>>,
    ) -> Vec<PyTechnology> {
        let response = HttpResponse {
            url: url.to_string(),
            headers,
            body: body.to_string(),
            status_code,
            response_time_ms: 0,
            // Empty means "caller gave us nothing"; the cookie layer treats an empty vec
            // as absent and falls back to the flat headers map, so this is not a silent
            // loss of the newline-joined case.
            set_cookie_headers: set_cookie_headers.unwrap_or_default(),
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
                icon: t.icon,
                cpe: t.cpe,
                saas: t.saas,
                pricing: t.pricing,
                signals: t
                    .signals
                    .into_iter()
                    .map(|Signal { signal_type, value, weight }| PySignal {
                        signal_type,
                        value,
                        weight,
                    })
                    .collect(),
            })
            .collect()
    }
}

#[pymodule]
pub fn rusty_wappalyzer(_py: Python<'_>, m: &PyModule) -> PyResult<()> {
    m.add_class::<PyWappalyzer>()?;
    m.add_class::<PyTechnology>()?;
    // PySignal is only ever produced by the analyzer, never constructed from Python, but
    // it still has to be registered: an unregistered pyclass returned from a method is an
    // opaque object whose type Python cannot name, repr or isinstance-check.
    m.add_class::<PySignal>()?;
    Ok(())
}
