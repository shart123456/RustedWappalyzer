use std::collections::HashMap;
use std::net::{IpAddr, SocketAddr};
use std::sync::Arc;
use std::time::Instant;

use reqwest::dns::{Addrs, Name, Resolve, Resolving};

use crate::types::{HttpResponse, WappalyzerConfig, WappalyzerError};

/// Maximum response body size buffered during page analysis (10 MB).
/// Responses larger than this are truncated to avoid OOM on huge pages.
const MAX_BODY_BYTES: usize = 10 * 1024 * 1024;

/// DNS-resolution timeout for pre-flight `is_safe_url()` and the SSRF resolver.
/// Cuts the long-tail of "system getaddrinfo blocks for ~10s on parked / dead
/// domains" so batch scans fail those URLs fast.
const DNS_LOOKUP_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(3);

/// Returns `true` if an IPv4 address (as octets) falls in a range that must
/// never be reachable from a public HTTP scanner. Shared by the IPv4 arm and
/// the IPv4-mapped-IPv6 arm of [`is_private_ip`] so the two can't drift.
///
/// Checked ranges:
/// - `0.0.0.0/8`      "this network" / unspecified — `0.0.0.0` routes to
///                    localhost on Linux, a classic SSRF bypass.
/// - `10.0.0.0/8`, `172.16.0.0/12`, `192.168.0.0/16`  RFC 1918 private
/// - `100.64.0.0/10`  CGNAT (RFC 6598) — reachable inside many cloud networks
/// - `127.0.0.0/8`    loopback
/// - `169.254.0.0/16` link-local, incl. the cloud metadata IP 169.254.169.254
fn is_private_v4(o: [u8; 4]) -> bool {
    // 0.0.0.0/8
    o[0] == 0
    // 10.0.0.0/8
    || o[0] == 10
    // 127.0.0.0/8
    || o[0] == 127
    // 172.16.0.0/12
    || (o[0] == 172 && (o[1] & 0xf0) == 16)
    // 192.168.0.0/16
    || (o[0] == 192 && o[1] == 168)
    // 169.254.0.0/16 (link-local)
    || (o[0] == 169 && o[1] == 254)
    // 100.64.0.0/10 (CGNAT)
    || (o[0] == 100 && (o[1] & 0xc0) == 0x40)
}

/// Returns `true` if the address falls within a private, loopback, link-local,
/// unspecified, or ULA range that should never be reachable from a public HTTP
/// scanner.
///
/// Covers all ranges in [`is_private_v4`] plus, for IPv6:
/// - `::`            unspecified
/// - `::1`           loopback
/// - `fe80::/10`     link-local
/// - `fc00::/7`      unique local (ULA)
/// - `::ffff:x.x.x.x` IPv4-mapped — the embedded IPv4 is checked via [`is_private_v4`]
pub(crate) fn is_private_ip(ip: IpAddr) -> bool {
    match ip {
        IpAddr::V4(v4) => is_private_v4(v4.octets()),
        IpAddr::V6(v6) => {
            let segs = v6.segments();
            // :: unspecified
            v6.is_unspecified()
            // ::1 loopback
            || v6.is_loopback()
            // fe80::/10 link-local
            || (segs[0] & 0xffc0) == 0xfe80
            // fc00::/7 unique local (ULA)
            || (segs[0] & 0xfe00) == 0xfc00
            // ::ffff:0:0/96 — IPv4-mapped; check the embedded IPv4 address
            || (segs[0] == 0 && segs[1] == 0 && segs[2] == 0
                && segs[3] == 0 && segs[4] == 0 && segs[5] == 0xffff
                && is_private_v4([
                    (segs[6] >> 8) as u8,
                    segs[6] as u8,
                    (segs[7] >> 8) as u8,
                    segs[7] as u8,
                ]))
        }
    }
}

/// Custom DNS resolver that validates resolved addresses against the SSRF
/// blocklist **at connection time**.
///
/// This mitigates DNS rebinding attacks: unlike a pre-flight `is_safe_url()`
/// check (which resolves the hostname once before making the request), this
/// resolver runs on every TCP-connect attempt inside reqwest, so the IP that
/// passes validation is the same IP that gets dialled.
#[derive(Debug)]
pub(crate) struct SsrfDnsResolver;

impl Resolve for SsrfDnsResolver {
    fn resolve(&self, name: Name) -> Resolving {
        let host = name.as_str().to_string();
        Box::pin(async move {
            let addrs = match tokio::time::timeout(
                DNS_LOOKUP_TIMEOUT,
                tokio::net::lookup_host(format!("{}:0", host)),
            )
            .await
            {
                Ok(Ok(a)) => a,
                Ok(Err(e)) => {
                    return Err(Box::new(e) as Box<dyn std::error::Error + Send + Sync>);
                }
                Err(_) => {
                    return Err(Box::new(std::io::Error::new(
                        std::io::ErrorKind::TimedOut,
                        format!("DNS lookup for '{}' timed out after {:?}", host, DNS_LOOKUP_TIMEOUT),
                    )) as Box<dyn std::error::Error + Send + Sync>);
                }
            };

            let safe: Vec<SocketAddr> = addrs
                .filter(|addr| !is_private_ip(addr.ip()))
                .collect();

            if safe.is_empty() {
                return Err(Box::new(std::io::Error::new(
                    std::io::ErrorKind::PermissionDenied,
                    format!(
                        "SSRF blocked: '{}' resolves only to private/internal addresses",
                        host
                    ),
                )) as Box<dyn std::error::Error + Send + Sync>);
            }

            Ok(Box::new(safe.into_iter()) as Addrs)
        })
    }
}

/// HTTP client for fetching web pages
pub(crate) struct HttpClient {
    pub(crate) client: reqwest::Client,
}

impl HttpClient {
    /// Build an `HttpClient` using the provided [`WappalyzerConfig`] for timeouts.
    ///
    /// When `config.ssrf_protection` is `true`, a custom [`SsrfDnsResolver`] is
    /// installed so that every TCP connection validates the resolved IP against
    /// the private-address blocklist at dial time (DNS rebinding mitigation).
    pub(crate) fn new_with_config(insecure: bool, config: &WappalyzerConfig) -> Result<Self, WappalyzerError> {
        let mut builder = reqwest::Client::builder()
            .user_agent(config.user_agent.as_str())
            .timeout(std::time::Duration::from_secs(config.http_timeout_secs))
            .connect_timeout(std::time::Duration::from_secs(config.connect_timeout_secs))
            .redirect(reqwest::redirect::Policy::limited(5))
            .danger_accept_invalid_certs(insecure);

        if config.ssrf_protection {
            builder = builder.dns_resolver(Arc::new(SsrfDnsResolver));
        }

        let client = builder.build()?;
        Ok(Self { client })
    }

    pub(crate) async fn fetch_page(&self, url: &str) -> Result<HttpResponse, WappalyzerError> {
        fetch_with_client(&self.client, url).await
    }
}

/// Shared page-fetch logic used by both [`HttpClient::fetch_page`] and the
/// static batch helper.  Extracts headers, handles multi-value `Set-Cookie`,
/// and truncates the body at [`MAX_BODY_BYTES`] to avoid OOM on huge pages.
pub(crate) async fn fetch_with_client(client: &reqwest::Client, url: &str) -> Result<HttpResponse, WappalyzerError> {
    let start = Instant::now();

    let response = client.get(url).send().await?;
    let status_code = response.status().as_u16();

    // Extract headers.  Set-Cookie is special: HTTP allows multiple headers with
    // the same name, and reqwest preserves all of them.  Join multiple Set-Cookie
    // values with newlines so the downstream cookie parser sees each on its own line.
    // All other headers use last-wins semantics (acceptable for detection purposes).
    let mut headers = HashMap::new();
    let set_cookie_headers: Vec<String>;
    {
        let raw = response.headers();
        let set_cookie_vals: Vec<&str> = raw
            .get_all("set-cookie")
            .iter()
            .filter_map(|v| v.to_str().ok())
            .collect();
        set_cookie_headers = raw
            .get_all("set-cookie")
            .iter()
            .filter_map(|v| v.to_str().ok().map(|s| s.to_string()))
            .collect();
        if !set_cookie_vals.is_empty() {
            headers.insert("set-cookie".to_string(), set_cookie_vals.join("\n"));
        }
        for (name, value) in raw.iter() {
            let key = name.as_str().to_lowercase();
            if key == "set-cookie" {
                continue; // already handled above
            }
            if let Ok(value_str) = value.to_str() {
                headers.insert(key, value_str.to_string());
            }
        }
    }

    let bytes = response.bytes().await?;
    let body = if bytes.len() > MAX_BODY_BYTES {
        tracing::warn!(url, bytes = bytes.len(), limit = MAX_BODY_BYTES, "Response body truncated at limit");
        String::from_utf8_lossy(&bytes[..MAX_BODY_BYTES]).into_owned()
    } else {
        String::from_utf8_lossy(&bytes).into_owned()
    };
    let response_time_ms = start.elapsed().as_millis() as u64;

    Ok(HttpResponse {
        url: url.to_string(),
        headers,
        body,
        status_code,
        response_time_ms,
        set_cookie_headers,
    })
}

/// Validate that a URL is safe to fetch (SSRF protection).
///
/// Rejects URLs whose hostname resolves to private / loopback / link-local
/// address ranges so that the server cannot be used as a relay to internal
/// infrastructure.
///
/// Uses async DNS resolution (`tokio::net::lookup_host`) to avoid blocking the
/// Tokio thread pool.
///
/// # Note
/// This is a pre-flight check for user-facing error messages.  In server mode,
/// [`SsrfDnsResolver`] is also installed on the HTTP client, which re-validates
/// the resolved IP at TCP-connect time and fully mitigates DNS rebinding attacks.
pub async fn is_safe_url(url: &str) -> Result<(), String> {
    let parsed = url::Url::parse(url).map_err(|e| format!("Invalid URL: {}", e))?;
    let host = parsed.host_str().ok_or_else(|| "URL has no host".to_string())?;

    // Resolve hostname → IP(s) asynchronously, bounded by DNS_LOOKUP_TIMEOUT so
    // that parked / dead domains don't burn ~10s of system-resolver wall-time
    // before being rejected.
    let addrs = match tokio::time::timeout(
        DNS_LOOKUP_TIMEOUT,
        tokio::net::lookup_host(format!("{}:80", host)),
    )
    .await
    {
        Ok(Ok(a)) => a,
        Ok(Err(e)) => return Err(format!("DNS resolution failed for '{}': {}", host, e)),
        Err(_) => return Err(format!(
            "DNS resolution failed for '{}': lookup timed out after {:?}",
            host, DNS_LOOKUP_TIMEOUT
        )),
    };

    for socket_addr in addrs {
        if is_private_ip(socket_addr.ip()) {
            return Err(format!(
                "URL '{}' resolves to a private/internal IP address and is not allowed",
                url
            ));
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::is_private_ip;
    use std::net::IpAddr;

    fn ip(s: &str) -> IpAddr {
        s.parse().unwrap()
    }

    #[test]
    fn blocks_previously_missed_ranges() {
        // 0.0.0.0/8 — routes to localhost on Linux (the gap this fix closes).
        assert!(is_private_ip(ip("0.0.0.0")));
        assert!(is_private_ip(ip("0.1.2.3")));
        // IPv6 unspecified.
        assert!(is_private_ip(ip("::")));
        // CGNAT 100.64.0.0/10.
        assert!(is_private_ip(ip("100.64.0.1")));
        assert!(is_private_ip(ip("100.127.255.255")));
        // IPv4-mapped forms of the above.
        assert!(is_private_ip(ip("::ffff:0.0.0.0")));
        assert!(is_private_ip(ip("::ffff:100.64.0.1")));
    }

    #[test]
    fn still_blocks_classic_ranges() {
        for s in ["127.0.0.1", "10.0.0.1", "172.16.0.1", "192.168.1.1",
                  "169.254.169.254", "::1", "fe80::1", "fc00::1",
                  "::ffff:127.0.0.1"] {
            assert!(is_private_ip(ip(s)), "{s} should be private");
        }
    }

    #[test]
    fn allows_public_addresses() {
        // 100.0.0.0/8 outside CGNAT, and normal public v4/v6 must pass.
        for s in ["8.8.8.8", "1.1.1.1", "100.63.255.255", "100.128.0.1",
                  "93.184.216.34", "2606:4700:4700::1111"] {
            assert!(!is_private_ip(ip(s)), "{s} should be public");
        }
    }
}
