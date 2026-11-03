//! Tier T2 (web diagnostics, ADR 0001): active but **non-destructive** checks
//! against an authorized URL. This module does the passive response audit -
//! security headers, cookie flags, software disclosure and the transport
//! posture - from one GET. The detection logic (`audit_response`) is pure and
//! unit-tested; `fetch` is the thin HTTPS wrapper (ureq / rustls). Nothing here
//! exploits, extracts data, or bypasses anything - it reports what a single,
//! ordinary response reveals.

use std::time::Duration;

use crate::result::Finding;

/// The scheme of a URL ("http" / "https"), lowercased; empty if none.
pub fn scheme_of(url: &str) -> String {
    match url.find("://") {
        Some(i) => url[..i].to_ascii_lowercase(),
        None => String::new(),
    }
}

/// The host[:port] of a URL (no scheme, userinfo or path).
pub fn host_of(url: &str) -> String {
    let after = match url.find("://") {
        Some(i) => &url[i + 3..],
        None => url,
    };
    let authority = after.split(['/', '?', '#']).next().unwrap_or("");
    // Drop any userinfo (user:pass@host).
    let host = authority.rsplit('@').next().unwrap_or(authority);
    host.to_string()
}

/// A fetched response reduced to what the audit needs.
pub struct Fetched {
    pub status: u16,
    pub headers: Vec<(String, String)>, // (lowercased name, value)
}

fn header<'a>(headers: &'a [(String, String)], name: &str) -> Option<&'a str> {
    headers
        .iter()
        .find(|(k, _)| k == name)
        .map(|(_, v)| v.as_str())
}

/// Audit one HTTP response for common, non-destructive findings. Pure: the
/// caller supplies the URL, status and (lowercased-name) headers.
pub fn audit_response(url: &str, status: u16, headers: &[(String, String)]) -> Vec<Finding> {
    let mut out = Vec::new();
    let https = scheme_of(url) == "https";
    let mk = |sev: &str, title: &str| Finding::new("web", sev, url.to_string(), title.to_string());

    // A summary row so the panel shows what answered.
    let server = header(headers, "server").unwrap_or("");
    out.push(mk("info", "HTTP response").detail(format!(
        "status {status}{}",
        if server.is_empty() {
            String::new()
        } else {
            format!(", server {server}")
        }
    )));

    if !https {
        out.push(
            mk("medium", "Plaintext HTTP")
                .detail("served over http - no transport encryption".to_string()),
        );
    } else if header(headers, "strict-transport-security").is_none() {
        out.push(
            mk("medium", "Missing HSTS").detail("no Strict-Transport-Security header".to_string()),
        );
    }

    if header(headers, "content-security-policy").is_none() {
        out.push(
            mk("low", "Missing Content-Security-Policy")
                .detail("no CSP header; the page has no content-injection baseline".to_string()),
        );
    }
    if header(headers, "x-content-type-options")
        .map(|v| !v.eq_ignore_ascii_case("nosniff"))
        .unwrap_or(true)
    {
        out.push(
            mk("low", "Missing X-Content-Type-Options: nosniff")
                .detail("MIME-sniffing is not disabled".to_string()),
        );
    }
    let csp = header(headers, "content-security-policy").unwrap_or("");
    if header(headers, "x-frame-options").is_none()
        && !csp.to_ascii_lowercase().contains("frame-ancestors")
    {
        out.push(
            mk("low", "Missing clickjacking protection")
                .detail("no X-Frame-Options and no CSP frame-ancestors".to_string()),
        );
    }
    if header(headers, "referrer-policy").is_none() {
        out.push(
            mk("info", "Missing Referrer-Policy").detail("referrer is not constrained".to_string()),
        );
    }

    if !server.is_empty() && server.chars().any(|c| c.is_ascii_digit()) {
        out.push(
            mk("low", "Server banner discloses a version").detail(format!("Server: {server}")),
        );
    }
    if let Some(powered) = header(headers, "x-powered-by") {
        out.push(
            mk("low", "X-Powered-By discloses the stack")
                .detail(format!("X-Powered-By: {powered}")),
        );
    }

    if let Some(cookie) = header(headers, "set-cookie") {
        let low = cookie.to_ascii_lowercase();
        let name = cookie
            .split('=')
            .next()
            .unwrap_or("cookie")
            .trim()
            .to_string();
        if https && !low.contains("secure") {
            out.push(mk("medium", "Cookie without Secure").detail(format!("Set-Cookie {name}")));
        }
        if !low.contains("httponly") {
            out.push(mk("medium", "Cookie without HttpOnly").detail(format!("Set-Cookie {name}")));
        }
        if !low.contains("samesite") {
            out.push(mk("low", "Cookie without SameSite").detail(format!("Set-Cookie {name}")));
        }
    }

    out
}

/// One GET to `url`, following redirects, returning the final response's status
/// and headers. Reads no body. Transport failures are a typed error string.
pub fn fetch(url: &str, timeout: Duration) -> Result<Fetched, String> {
    let agent = ureq::AgentBuilder::new()
        .timeout(timeout)
        .user_agent(concat!("sanctum/", env!("CARGO_PKG_VERSION")))
        .build();
    let resp = match agent.get(url).call() {
        Ok(r) => r,
        // An HTTP error status still carries headers worth auditing.
        Err(ureq::Error::Status(_, r)) => r,
        Err(ureq::Error::Transport(t)) => return Err(t.to_string()),
    };
    let status = resp.status();
    let mut headers = Vec::new();
    for name in resp.headers_names() {
        if let Some(value) = resp.header(&name) {
            headers.push((name.to_ascii_lowercase(), value.to_string()));
        }
    }
    Ok(Fetched { status, headers })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn h(pairs: &[(&str, &str)]) -> Vec<(String, String)> {
        pairs
            .iter()
            .map(|(k, v)| (k.to_ascii_lowercase(), v.to_string()))
            .collect()
    }
    fn titles(fs: &[Finding]) -> Vec<String> {
        fs.iter().map(|f| f.title.clone()).collect()
    }
    fn has(fs: &[Finding], title: &str) -> bool {
        fs.iter().any(|f| f.title == title)
    }

    #[test]
    fn host_and_scheme_parsing() {
        assert_eq!(scheme_of("https://ex.com/a"), "https");
        assert_eq!(host_of("https://user:pw@ex.com:8443/a?b#c"), "ex.com:8443");
        assert_eq!(host_of("ex.com/a"), "ex.com");
    }

    #[test]
    fn flags_a_bare_https_response() {
        // https, no security headers, a versioned server, an insecure cookie.
        let fs = audit_response(
            "https://ex.com/",
            200,
            &h(&[
                ("server", "nginx/1.24.0"),
                ("set-cookie", "sid=abc; Path=/"),
            ]),
        );
        assert!(has(&fs, "Missing HSTS"));
        assert!(has(&fs, "Missing Content-Security-Policy"));
        assert!(has(&fs, "Missing X-Content-Type-Options: nosniff"));
        assert!(has(&fs, "Missing clickjacking protection"));
        assert!(has(&fs, "Server banner discloses a version"));
        assert!(has(&fs, "Cookie without Secure"));
        assert!(has(&fs, "Cookie without HttpOnly"));
        assert!(has(&fs, "Cookie without SameSite"));
    }

    #[test]
    fn plaintext_http_is_flagged_and_hsts_is_not() {
        let fs = audit_response("http://ex.com/", 200, &h(&[]));
        assert!(has(&fs, "Plaintext HTTP"));
        assert!(!has(&fs, "Missing HSTS")); // HSTS only applies to https
    }

    #[test]
    fn a_hardened_response_has_only_the_summary() {
        let fs = audit_response(
            "https://ex.com/",
            200,
            &h(&[
                ("strict-transport-security", "max-age=63072000"),
                (
                    "content-security-policy",
                    "default-src 'self'; frame-ancestors 'none'",
                ),
                ("x-content-type-options", "nosniff"),
                ("referrer-policy", "no-referrer"),
                ("set-cookie", "sid=abc; Secure; HttpOnly; SameSite=Strict"),
            ]),
        );
        assert_eq!(titles(&fs), vec!["HTTP response".to_string()]);
    }
}
