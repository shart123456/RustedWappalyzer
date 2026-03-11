//! Content-Security-Policy analysis methods for [`TechnologyAnalyzer`].

use crate::analyzer::TechnologyAnalyzer;
use crate::types::*;

use std::collections::HashMap;
use once_cell::sync::Lazy;
use regex::Regex;

impl TechnologyAnalyzer {
    /// Parse the Content-Security-Policy header and detect third-party services
    /// whose domain appears in `connect-src`, `script-src`, `img-src`, or `frame-src`.
    ///
    /// This covers SaaS tools that inject script snippets (analytics, monitoring, support,
    /// payments) and CDNs that are otherwise invisible in the HTML response.
    pub(crate) fn scan_csp_header(&self, headers: &HashMap<String, String>, detected: &mut HashMap<String, TechDetection>) {
        let csp = match headers.get("content-security-policy")
            .or_else(|| headers.get("content-security-policy-report-only"))
        {
            Some(v) => v.clone(),
            None => return,
        };

        // CSP domain-fragment → (tech_name, confidence) table.
        // Fragment is matched as a hostname suffix (e.g. "sentry.io" matches "o123.ingest.sentry.io").
        static CSP_MAP: &[(&str, &str, u8)] = &[
            ("sentry.io",                   "sentry",                 90),
            ("segment.com",                 "segment",                90),
            ("segment.io",                  "segment",                90),
            ("intercom.io",                 "intercom",               90),
            ("intercomcdn.com",             "intercom",               90),
            ("hotjar.com",                  "hotjar",                 90),
            ("fullstory.com",               "fullstory",              90),
            ("mixpanel.com",                "mixpanel",               90),
            ("amplitude.com",               "amplitude",              90),
            ("heap.io",                     "heap",                   90),
            ("rollbar.com",                 "rollbar",                90),
            ("bugsnag.com",                 "bugsnag",                90),
            ("logrocket.com",               "logrocket",              90),
            ("cloudinary.com",              "cloudinary",             90),
            ("algolia.net",                 "algolia",                90),
            ("algolia.io",                  "algolia",                90),
            ("hubspot.com",                 "hubspot",                85),
            ("hubspotusercontent.com",      "hubspot",                85),
            ("hsforms.com",                 "hubspot",                85),
            ("hs-scripts.com",              "hubspot",                85),
            ("salesforce.com",              "salesforce",             85),
            ("force.com",                   "salesforce",             85),
            ("marketo.com",                 "marketo",                90),
            ("mktoresp.com",                "marketo",                90),
            ("mktoweb.com",                 "marketo",                90),
            ("crisp.chat",                  "crisp",                  90),
            ("tawk.to",                     "tawk.to",                90),
            ("zendesk.com",                 "zendesk",                85),
            ("zdassets.com",                "zendesk",                90),
            ("freshdesk.com",               "freshdesk",              85),
            ("freshchat.com",               "freshdesk",              85),
            ("typeform.com",                "typeform",               90),
            ("datadoghq.com",               "datadog",                90),
            ("datadoghq-browser-agent.com", "datadog",                90),
            ("newrelic.com",                "new relic",              90),
            ("nr-data.net",                 "new relic",              90),
            ("stripe.com",                  "stripe",                 90),
            ("stripe.network",              "stripe",                 90),
            ("twilio.com",                  "twilio",                 85),
            ("sendgrid.net",                "sendgrid",               90),
            ("sendgrid.com",                "sendgrid",               90),
            ("mailchimp.com",               "mailchimp",              85),
            ("list-manage.com",             "mailchimp",              85),
            ("klaviyo.com",                 "klaviyo",                90),
            ("onesignal.com",               "onesignal",              90),
            ("pusher.com",                  "pusher",                 90),
            ("pusherapp.com",               "pusher",                 90),
            ("ably.io",                     "ably",                   90),
            ("ably.com",                    "ably",                   90),
            ("cloudflareinsights.com",      "cloudflare",             90),
            ("cloudflare.com",              "cloudflare",             75),
            ("google-analytics.com",        "google analytics",       90),
            ("googletagmanager.com",        "google tag manager",     90),
            ("googletagservices.com",       "google tag manager",     85),
            ("facebook.net",                "facebook pixel",         85),
            ("fbcdn.net",                   "facebook",               70),
            ("fonts.googleapis.com",        "google fonts",           90),
            ("fonts.gstatic.com",           "google fonts",           90),
            ("maps.googleapis.com",         "google maps",            90),
            ("recaptcha.net",               "google recaptcha",       90),
            ("recaptcha.google.com",        "google recaptcha",       90),
            ("doubleclick.net",             "doubleclick",            90),
            ("akamaihd.net",                "akamai",                 85),
            ("akamai.net",                  "akamai",                 85),
            ("fastly.net",                  "fastly",                 80),
            ("amazonaws.com",               "amazon web services",    75),
            ("cloudfront.net",              "amazon cloudfront",      85),
            ("cdn.jsdelivr.net",            "jsdelivr",               85),
            ("cdnjs.cloudflare.com",        "cdnjs",                  85),
            ("unpkg.com",                   "unpkg",                  85),
            ("jsdelivr.net",                "jsdelivr",               85),
            ("braze.com",                   "braze",                  90),
            ("appboy.com",                  "braze",                  90),
            ("driftt.com",                  "drift",                  90),
            ("drift.com",                   "drift",                  90),
            ("churnzero.net",               "churnzero",              90),
            ("gainsight.com",               "gainsight",              90),
            ("pendo.io",                    "pendo",                  90),
            ("appcues.com",                 "appcues",                90),
            ("userguiding.com",             "userguiding",            90),
            ("cookiebot.com",               "cookiebot",              90),
            ("cookiepro.com",               "onetrust",               90),
            ("onetrust.com",                "onetrust",               90),
        ];

        // Extract all hostname tokens from CSP URIs (skip scheme-only like 'https:')
        static CSP_URI_RE: Lazy<Regex> = Lazy::new(|| {
            Regex::new(r"https?://([a-zA-Z0-9][a-zA-Z0-9._-]*)").unwrap()
        });

        let mut seen: std::collections::HashSet<String> = std::collections::HashSet::new();
        for cap in CSP_URI_RE.captures_iter(&csp) {
            let hostname = cap[1].to_lowercase();
            for &(fragment, tech, confidence) in CSP_MAP {
                if seen.contains(tech) { continue; }
                if hostname == fragment || hostname.ends_with(&format!(".{}", fragment)) {
                    if let Some(db_name) = self.find_tech_name(tech) {
                        Self::update_detection(detected, db_name, "header", "content-security-policy", confidence, None);
                        seen.insert(tech.to_string());
                    }
                    break;
                }
            }
        }
    }
}
