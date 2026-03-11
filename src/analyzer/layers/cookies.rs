//! Cookie analysis methods for [`TechnologyAnalyzer`].

use crate::analyzer::TechnologyAnalyzer;
use crate::types::*;

use std::collections::HashMap;

impl TechnologyAnalyzer {
    /// Detect framework/platform signatures from Set-Cookie names that the Wappalyzer DB
    /// does not cover (or covers poorly). Called unconditionally from `analyze()`.
    pub(crate) fn scan_cookie_generic(&self, response: &HttpResponse, detected: &mut HashMap<String, TechDetection>) {
        // Use set_cookie_headers vec as authoritative source if available
        let cookie_lines: Vec<String> = if !response.set_cookie_headers.is_empty() {
            response.set_cookie_headers.clone()
        } else {
            match response.headers.get("set-cookie") {
                Some(v) => v.lines().map(|l| l.to_string()).collect(),
                None => return,
            }
        };

        // Collect all cookie names (lowercased)
        let mut names: Vec<String> = Vec::new();
        for line in &cookie_lines {
            if let Some(nv) = line.split(';').next() {
                if let Some(eq) = nv.find('=') {
                    names.push(nv[..eq].trim().to_lowercase());
                }
            }
        }

        let has = |name: &str| -> bool { names.iter().any(|c| c == name) };

        let mut ins = |tech: &str, cookie: &str, conf: u8| {
            if let Some(db_name) = self.find_tech_name(tech) {
                Self::update_detection(detected, db_name, "cookie", cookie, conf, None);
            }
        };

        // Express: signed session cookie from connect/express-session
        if has("connect.sid") {
            ins("express", "connect.sid", 90);
        }

        // Ruby Rack session
        if has("rack.session") || has("_session_id") {
            ins("rack", "rack.session", 85);
        }

        // Django: csrftoken is definitive; sessionid alone is too generic
        if has("csrftoken") {
            ins("django", "csrftoken", 92);
        }
        if has("sessionid") && has("csrftoken") {
            ins("django", "sessionid+csrftoken", 90);
        }

        // Laravel: encrypted session + CSRF
        if has("laravel_session") {
            ins("laravel", "laravel_session", 95);
        }
        if has("xsrf-token") && !has("connect.sid") {
            // XSRF-TOKEN without Express connect.sid → more likely Laravel or Angular
            ins("laravel", "xsrf-token", 65);
        }

        // Shopify storefront cookies
        if has("_shopify_s") || has("_shopify_y") || has("shopify_pay_redirect") {
            ins("shopify", "_shopify_s", 92);
        }

        // WordPress: authenticated user cookie
        if names.iter().any(|c| c.starts_with("wordpress_logged_in") || c.starts_with("wp-settings-")) {
            ins("wordpress", "wordpress_logged_in", 95);
        }

        // Google Analytics tracking cookies
        if has("_ga") || has("_gid") {
            ins("google analytics", "_ga", 88);
        }

        // Facebook Pixel / Conversions API
        if has("_fbp") || has("_fbc") {
            ins("facebook pixel", "_fbp", 85);
        }

        // Hotjar
        if has("_hjid") || has("_hjsessionuser") || has("_hjfirstseen") {
            ins("hotjar", "_hjid", 90);
        }

        // Intercom
        if names.iter().any(|c| c.starts_with("intercom-session") || c.starts_with("intercom-id")) {
            ins("intercom", "intercom-session", 90);
        }

        // HubSpot CRM tracking
        if has("hubspotutk") || has("__hstc") || has("__hssc") || has("__hssrc") {
            ins("hubspot", "hubspotutk", 90);
        }

        // Zendesk
        if has("zdlang") || has("__zlcmid") || has("zd-suid") {
            ins("zendesk", "zdlang", 85);
        }

        // Cloudflare
        if has("__cflb") || has("__cfwaitingroom") || has("cf_clearance") {
            ins("cloudflare", "cf_clearance", 88);
        }

        // Pardot / Salesforce Marketing
        if names.iter().any(|c| c.starts_with("visitor_id") || c == "pardot") {
            ins("pardot", "visitor_id", 82);
        }
    }

    /// Analyze cookies from response headers for technology patterns
    pub(crate) fn analyze_cookies(&self, response: &HttpResponse, detected: &mut HashMap<String, TechDetection>) {
        // Use set_cookie_headers vec as authoritative source if available
        let cookie_lines: Vec<String> = if !response.set_cookie_headers.is_empty() {
            response.set_cookie_headers.clone()
        } else {
            match response.headers.get("set-cookie") {
                Some(v) => v.lines().map(|l| l.to_string()).collect(),
                None => return,
            }
        };

        // Parse cookie name=value pairs (each line is one Set-Cookie header value)
        let mut cookies: HashMap<String, String> = HashMap::new();
        for cookie_line in &cookie_lines {
            if let Some(name_value) = cookie_line.split(';').next() {
                if let Some(eq_pos) = name_value.find('=') {
                    let name = name_value[..eq_pos].trim().to_lowercase();
                    let value = name_value[eq_pos + 1..].trim().to_string();
                    cookies.insert(name, value);
                }
            }
        }

        for (tech_name, cookie_patterns) in &self.cookie_patterns {
            for (cookie_name, patterns) in cookie_patterns {
                if let Some(cookie_value) = cookies.get(cookie_name) {
                    for pattern in patterns {
                        if let Some(captures) = pattern.regex.captures(cookie_value) {
                            let version = Self::extract_version(&pattern.version, &captures);
                            Self::update_detection(detected, tech_name, "cookie", cookie_name, pattern.confidence, version);
                        }
                    }
                }
            }
        }
    }
}
