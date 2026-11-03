//! Tier T2 (web diagnostics, ADR 0001): active but **non-destructive** checks
//! against an authorized URL. This module does the passive response audit -
//! security headers, cookie flags, software disclosure and the transport
//! posture - from one GET. The detection logic (`audit_response`) is pure and
//! unit-tested; `fetch` is the thin HTTPS wrapper (ureq / rustls). Nothing here
//! exploits, extracts data, or bypasses anything - it reports what a single,
//! ordinary response reveals.

use std::collections::{HashSet, VecDeque};
use std::io::Read;
use std::time::{Duration, Instant};

use crate::result::Finding;

const BODY_CAP: u64 = 512 * 1024; // bytes of a page body read for link extraction

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
    pub body: String,                   // bounded, UTF-8 lossy (for link extraction)
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
    // A bounded body read, only for link extraction during a crawl.
    let mut buf = Vec::new();
    resp.into_reader().take(BODY_CAP).read_to_end(&mut buf).ok();
    let body = String::from_utf8_lossy(&buf).into_owned();
    Ok(Fetched {
        status,
        headers,
        body,
    })
}

// ---- bounded same-origin crawl (ADR 0001, non-destructive) -----------------

/// Two URLs share an origin when their scheme and host[:port] match.
pub fn same_origin(a: &str, b: &str) -> bool {
    scheme_of(a) == scheme_of(b) && host_of(a) == host_of(b)
}

fn strip_fragment(url: &str) -> String {
    url.split('#').next().unwrap_or("").to_string()
}

/// The directory portion of a URL ("https://h/a/b" -> "https://h/a/").
fn base_dir(base: &str) -> String {
    let prefix = format!("{}://{}", scheme_of(base), host_of(base));
    let rest = base.get(prefix.len()..).unwrap_or("");
    let path = rest.split(['?', '#']).next().unwrap_or("");
    match path.rfind('/') {
        Some(i) => format!("{prefix}{}", &path[..=i]),
        None => format!("{prefix}/"),
    }
}

/// Resolve a link (absolute, scheme-relative, root-relative or relative)
/// against `base` into an absolute http(s) URL; non-navigable schemes and pure
/// fragments yield None.
pub fn resolve_url(base: &str, rel: &str) -> Option<String> {
    let rel = rel.split('#').next().unwrap_or("").trim();
    if rel.is_empty() {
        return None;
    }
    let low = rel.to_ascii_lowercase();
    if low.starts_with("javascript:")
        || low.starts_with("mailto:")
        || low.starts_with("tel:")
        || low.starts_with("data:")
    {
        return None;
    }
    if low.starts_with("http://") || low.starts_with("https://") {
        return Some(rel.to_string());
    }
    let scheme = scheme_of(base);
    if scheme.is_empty() {
        return None;
    }
    if let Some(rest) = rel.strip_prefix("//") {
        return Some(format!("{scheme}://{rest}"));
    }
    let host = host_of(base);
    if rel.starts_with('/') {
        return Some(format!("{scheme}://{host}{rel}"));
    }
    Some(format!("{}{rel}", base_dir(base)))
}

/// Extract candidate link URLs from an HTML body's href / src / action
/// attributes, resolved against `base`.
pub fn extract_links(base: &str, html: &str) -> Vec<String> {
    let lower = html.to_ascii_lowercase();
    let lb = lower.as_bytes();
    let mut out = Vec::new();
    for attr in ["href", "src", "action"] {
        let needle = attr.as_bytes();
        let mut i = 0usize;
        while let Some(rel_p) = lower[i..].find(attr) {
            let p = i + rel_p;
            i = p + needle.len();
            // Word boundary before the attribute name.
            if p > 0 && lb[p - 1].is_ascii_alphanumeric() {
                continue;
            }
            let mut j = p + needle.len();
            while j < lb.len() && lb[j] == b' ' {
                j += 1;
            }
            if j >= lb.len() || lb[j] != b'=' {
                continue;
            }
            j += 1;
            while j < lb.len() && lb[j] == b' ' {
                j += 1;
            }
            if j >= lb.len() {
                break;
            }
            let (val, next) = if lb[j] == b'"' || lb[j] == b'\'' {
                let q = lb[j];
                let start = j + 1;
                let mut e = start;
                while e < lb.len() && lb[e] != q {
                    e += 1;
                }
                (&html[start..e.min(html.len())], e + 1)
            } else {
                let start = j;
                let mut e = start;
                while e < lb.len() && !lb[e].is_ascii_whitespace() && lb[e] != b'>' {
                    e += 1;
                }
                (&html[start..e.min(html.len())], e)
            };
            if let Some(abs) = resolve_url(base, val.trim()) {
                if !out.contains(&abs) {
                    out.push(abs);
                }
            }
            i = next;
        }
    }
    out
}

fn content_is_html(headers: &[(String, String)]) -> bool {
    match header(headers, "content-type") {
        Some(ct) => ct.to_ascii_lowercase().contains("html"),
        None => true, // assume html when unstated
    }
}

/// Collapse identical findings (same severity/title/detail), keeping the first;
/// header weaknesses are usually site-wide, so this avoids one row per page.
fn dedup_findings(fs: Vec<Finding>) -> Vec<Finding> {
    let mut seen = HashSet::new();
    let mut out = Vec::new();
    for f in fs {
        if seen.insert(format!("{}\u{1}{}\u{1}{}", f.severity, f.title, f.detail)) {
            out.push(f);
        }
    }
    out
}

pub struct CrawlResult {
    pub pages: Vec<(String, u16)>, // (url, status) in fetch order
    pub findings: Vec<Finding>,    // deduped audit findings across the pages
}

/// A bounded, same-origin, rate-limited crawl from `seed`. GET only; it reads
/// each page, audits the response, and follows same-origin links up to
/// `max_pages` / `max_depth`, sleeping `delay` between requests. Non-destructive.
pub fn crawl(
    seed: &str,
    timeout: Duration,
    max_pages: usize,
    max_depth: u32,
    delay: Duration,
) -> CrawlResult {
    let mut visited: HashSet<String> = HashSet::new();
    let mut queue: VecDeque<(String, u32)> = VecDeque::new();
    visited.insert(strip_fragment(seed));
    queue.push_back((seed.to_string(), 0));
    let mut pages = Vec::new();
    let mut findings = Vec::new();
    while let Some((url, depth)) = queue.pop_front() {
        if pages.len() >= max_pages {
            break;
        }
        if !pages.is_empty() {
            std::thread::sleep(delay); // rate limit between requests
        }
        let fetched = match fetch(&url, timeout) {
            Ok(f) => f,
            Err(_) => continue,
        };
        pages.push((url.clone(), fetched.status));
        for f in audit_response(&url, fetched.status, &fetched.headers) {
            if f.title != "HTTP response" {
                findings.push(f);
            }
        }
        if depth < max_depth && content_is_html(&fetched.headers) {
            for link in extract_links(&url, &fetched.body) {
                if !same_origin(seed, &link) {
                    continue;
                }
                let key = strip_fragment(&link);
                if !visited.contains(&key) && visited.len() < max_pages.saturating_mul(8) {
                    visited.insert(key);
                    queue.push_back((link, depth + 1));
                }
            }
        }
    }
    CrawlResult {
        pages,
        findings: dedup_findings(findings),
    }
}

// ---- reflected-XSS detection (ADR 0001, non-destructive) --------------------
//
// For each query parameter we send a benign unique marker followed by the
// XSS-significant characters and observe whether they come back **unencoded**.
// The marker is not a working script and nothing is executed - this detects
// that user input is reflected without output encoding, the precondition for
// reflected XSS. GET only, one request per parameter, rate-limited and capped.

#[derive(Debug, PartialEq, Eq)]
pub enum Reflection {
    None,
    Encoded, // the marker came back but the '<' was encoded
    Raw,     // the raw '<' survived next to the marker - injection is possible
}

/// A unique, alphanumeric probe marker for this process/run.
fn marker() -> String {
    let n = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_nanos())
        .unwrap_or(0);
    format!("sanctumxss{:x}", (n as u64) & 0xff_ffff_ffff)
}

/// Percent-encode a query value (everything but RFC 3986 unreserved).
fn pct_encode(s: &str) -> String {
    let mut o = String::new();
    for b in s.bytes() {
        match b {
            b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'-' | b'.' | b'_' | b'~' => {
                o.push(b as char)
            }
            _ => o.push_str(&format!("%{b:02X}")),
        }
    }
    o
}

/// The query parameters of a URL as (name, value) pairs (empty if none).
pub fn query_params(url: &str) -> Vec<(String, String)> {
    let after_q = match url.split_once('?') {
        Some((_, q)) => q,
        None => return Vec::new(),
    };
    let query = after_q.split('#').next().unwrap_or("");
    if query.is_empty() {
        return Vec::new();
    }
    query
        .split('&')
        .filter(|p| !p.is_empty())
        .map(|p| match p.split_once('=') {
            Some((n, v)) => (n.to_string(), v.to_string()),
            None => (p.to_string(), String::new()),
        })
        .collect()
}

/// Rebuild `url` with parameter `index`'s value replaced by `value`
/// (percent-encoded). Returns the original URL if it has no such parameter.
pub fn set_param(url: &str, index: usize, value: &str) -> String {
    let (head, rest) = match url.split_once('?') {
        Some(hr) => hr,
        None => return url.to_string(),
    };
    let (query, frag) = match rest.split_once('#') {
        Some((q, f)) => (q, format!("#{f}")),
        None => (rest, String::new()),
    };
    let mut params: Vec<(String, String)> = query
        .split('&')
        .filter(|p| !p.is_empty())
        .map(|p| match p.split_once('=') {
            Some((n, v)) => (n.to_string(), v.to_string()),
            None => (p.to_string(), String::new()),
        })
        .collect();
    if index >= params.len() {
        return url.to_string();
    }
    params[index].1 = pct_encode(value);
    let rebuilt: Vec<String> = params.iter().map(|(n, v)| format!("{n}={v}")).collect();
    format!("{head}?{}{frag}", rebuilt.join("&"))
}

/// Classify how `marker` (and the '<' sent right after it) came back in `body`.
pub fn detect_reflection(marker: &str, body: &str) -> Reflection {
    if body.contains(&format!("{marker}<")) {
        Reflection::Raw
    } else if body.contains(marker) {
        Reflection::Encoded
    } else {
        Reflection::None
    }
}

/// A finding for a parameter's reflection, if any is worth reporting.
pub fn xss_finding(url: &str, param: &str, refl: Reflection) -> Option<Finding> {
    match refl {
        Reflection::Raw => Some(
            Finding::new("web", "high", url.to_string(), "Reflected XSS candidate").detail(
                format!("parameter `{param}` is reflected unencoded (the injected '<' survived)"),
            ),
        ),
        Reflection::Encoded => Some(
            Finding::new(
                "web",
                "info",
                url.to_string(),
                "Parameter reflected (encoded)",
            )
            .detail(format!("parameter `{param}` is reflected but HTML-encoded")),
        ),
        Reflection::None => None,
    }
}

/// Probe the query parameters of each URL for reflected XSS. One GET per
/// parameter (deduped by path+name across URLs), capped at `max_probes` and
/// rate-limited by `delay`. Non-destructive.
pub fn reflected_xss_scan(
    urls: &[String],
    timeout: Duration,
    delay: Duration,
    max_probes: usize,
) -> Vec<Finding> {
    let mark = marker();
    let probe_value = format!("{mark}<>\"'");
    let mut out = Vec::new();
    let mut seen: HashSet<String> = HashSet::new();
    let mut probes = 0usize;
    for url in urls {
        let params = query_params(url);
        for (i, (name, _)) in params.iter().enumerate() {
            if probes >= max_probes {
                return out;
            }
            let path = url.split('?').next().unwrap_or(url);
            if !seen.insert(format!("{path}\u{1}{name}")) {
                continue; // the same path+param, already probed
            }
            if probes > 0 {
                std::thread::sleep(delay);
            }
            probes += 1;
            let probe_url = set_param(url, i, &probe_value);
            if let Ok(resp) = fetch(&probe_url, timeout) {
                if let Some(f) = xss_finding(url, name, detect_reflection(&mark, &resp.body)) {
                    out.push(f);
                }
            }
        }
    }
    out
}

// ---- SQL-injection detection (ADR 0001, non-destructive, existence only) ----
//
// Error-based: a single quote should break a query and surface a DB error that
// a clean response did not have. Time-based: a bounded sleep payload should
// delay the response only if it is injected into a query; a delay is confirmed
// with a second probe to shed network jitter. Nothing is extracted - this only
// establishes that a parameter reaches a SQL interpreter. GET only, capped,
// rate-limited.

const SQL_SLEEP_SECONDS: u64 = 3;
const SQL_TIME_THRESHOLD_MS: u128 = 2500; // a convincing delay for a 3 s sleep
const SQL_BASE_MAX_MS: u128 = 1200; // only trust timing when the baseline is fast

/// A known database error signature in `body` -> the database name.
pub fn sql_error_signature(body: &str) -> Option<&'static str> {
    let low = body.to_ascii_lowercase();
    const SIGS: &[(&str, &str)] = &[
        ("you have an error in your sql syntax", "MySQL"),
        ("warning: mysqli", "MySQL"),
        ("warning: mysql_", "MySQL"),
        ("mysql_fetch", "MySQL"),
        ("check the manual that corresponds to your", "MySQL"),
        (
            "unclosed quotation mark after the character string",
            "MSSQL",
        ),
        ("microsoft odbc", "MSSQL"),
        ("microsoft ole db provider for sql server", "MSSQL"),
        ("odbc sql server driver", "MSSQL"),
        ("unterminated quoted string at or near", "PostgreSQL"),
        ("syntax error at or near", "PostgreSQL"),
        ("pg_query(", "PostgreSQL"),
        ("ora-00933", "Oracle"),
        ("ora-01756", "Oracle"),
        ("quoted string not properly terminated", "Oracle"),
        ("sqlite3::", "SQLite"),
        ("sqlite error", "SQLite"),
        ("sqlite_error", "SQLite"),
    ];
    SIGS.iter()
        .find(|(n, _)| low.contains(n))
        .map(|(_, db)| *db)
}

/// Percent-decode a query value ('%XX' and '+').
fn pct_decode(s: &str) -> String {
    let b = s.as_bytes();
    let mut out = Vec::with_capacity(b.len());
    let mut i = 0;
    while i < b.len() {
        match b[i] {
            b'%' if i + 2 < b.len() => {
                if let Ok(v) = u8::from_str_radix(&s[i + 1..i + 3], 16) {
                    out.push(v);
                    i += 3;
                } else {
                    out.push(b'%');
                    i += 1;
                }
            }
            b'+' => {
                out.push(b' ');
                i += 1;
            }
            c => {
                out.push(c);
                i += 1;
            }
        }
    }
    String::from_utf8_lossy(&out).into_owned()
}

/// A delay is a time-based SQLi signal when the baseline was fast and both the
/// probe and its confirmation crossed the threshold.
pub fn timing_verdict(base_ms: u128, probe_ms: u128, confirm_ms: u128, threshold: u128) -> bool {
    base_ms < threshold && probe_ms >= threshold && confirm_ms >= threshold
}

/// Probe query parameters for SQL injection (error-based, then bounded
/// time-based). Non-destructive: no data is read; it only establishes that a
/// parameter reaches a SQL interpreter. Deduped by path+name, capped, rate-limited.
pub fn sql_injection_scan(
    urls: &[String],
    timeout: Duration,
    delay: Duration,
    max_probes: usize,
) -> Vec<Finding> {
    let time_payloads = [
        format!("' AND SLEEP({SQL_SLEEP_SECONDS})-- -"),
        format!("';SELECT pg_sleep({SQL_SLEEP_SECONDS})-- -"),
        format!("';WAITFOR DELAY '0:0:{SQL_SLEEP_SECONDS}'-- -"),
        format!(" AND SLEEP({SQL_SLEEP_SECONDS})"),
    ];
    let mut out = Vec::new();
    let mut seen: HashSet<String> = HashSet::new();
    let mut probes = 0usize;
    for url in urls {
        let params = query_params(url);
        if params.is_empty() {
            continue;
        }
        let t0 = Instant::now();
        let baseline = fetch(url, timeout).ok();
        let base_ms = t0.elapsed().as_millis();
        let base_has_err = baseline
            .as_ref()
            .map(|r| sql_error_signature(&r.body).is_some())
            .unwrap_or(false);
        for (i, (name, value)) in params.iter().enumerate() {
            if probes >= max_probes {
                return out;
            }
            let path = url.split('?').next().unwrap_or(url);
            if !seen.insert(format!("{path}\u{1}{name}\u{1}sql")) {
                continue;
            }
            let decoded = pct_decode(value);
            // Error-based: a single quote.
            if probes > 0 {
                std::thread::sleep(delay);
            }
            probes += 1;
            let mut flagged = false;
            let err_url = set_param(url, i, &format!("{decoded}'"));
            if let Ok(r) = fetch(&err_url, timeout) {
                if !base_has_err {
                    if let Some(db) = sql_error_signature(&r.body) {
                        out.push(
                            Finding::new(
                                "web",
                                "high",
                                url.clone(),
                                "SQL injection (error-based) candidate",
                            )
                            .detail(format!(
                                "parameter `{name}` triggers a {db} error on a single quote"
                            )),
                        );
                        flagged = true;
                    }
                }
            }
            if flagged || base_ms >= SQL_BASE_MAX_MS {
                continue; // already found, or baseline too slow to trust timing
            }
            // Time-based: a bounded sleep payload, confirmed once.
            for payload in &time_payloads {
                if probes >= max_probes {
                    return out;
                }
                std::thread::sleep(delay);
                probes += 1;
                let u = set_param(url, i, &format!("{decoded}{payload}"));
                let t = Instant::now();
                let ok1 = fetch(&u, timeout).is_ok();
                let ms1 = t.elapsed().as_millis();
                if !ok1 || ms1 < SQL_TIME_THRESHOLD_MS {
                    continue;
                }
                if probes >= max_probes {
                    return out;
                }
                probes += 1;
                let t2 = Instant::now();
                let ok2 = fetch(&u, timeout).is_ok();
                let ms2 = t2.elapsed().as_millis();
                if ok2 && timing_verdict(base_ms, ms1, ms2, SQL_TIME_THRESHOLD_MS) {
                    out.push(
                        Finding::new("web", "high", url.clone(), "SQL injection (time-based) candidate")
                            .detail(format!(
                                "parameter `{name}` delayed ~{SQL_SLEEP_SECONDS}s on a time-based payload"
                            )),
                    );
                    break;
                }
            }
        }
    }
    out
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
    fn resolves_links_of_each_shape() {
        let b = "https://ex.com/app/page";
        assert_eq!(
            resolve_url(b, "https://other/x").as_deref(),
            Some("https://other/x")
        );
        assert_eq!(
            resolve_url(b, "//cdn.ex.com/j").as_deref(),
            Some("https://cdn.ex.com/j")
        );
        assert_eq!(
            resolve_url(b, "/login").as_deref(),
            Some("https://ex.com/login")
        );
        assert_eq!(
            resolve_url(b, "sub").as_deref(),
            Some("https://ex.com/app/sub")
        );
        assert_eq!(
            resolve_url(b, "x#frag").as_deref(),
            Some("https://ex.com/app/x")
        );
        assert_eq!(resolve_url(b, "#top"), None);
        assert_eq!(resolve_url(b, "javascript:void(0)"), None);
        assert_eq!(resolve_url(b, "mailto:a@ex.com"), None);
    }

    #[test]
    fn extracts_and_resolves_html_links() {
        let html = r#"<a href="/a">A</a><a href='b/c'>B</a>
                      <script src="https://cdn.ex.com/x.js"></script>
                      <form action="/submit"><img src="data:xxx"></form>
                      <a href="mailto:x@ex.com">m</a>"#;
        let links = extract_links("https://ex.com/app/", html);
        assert!(links.contains(&"https://ex.com/a".to_string()));
        assert!(links.contains(&"https://ex.com/app/b/c".to_string()));
        assert!(links.contains(&"https://cdn.ex.com/x.js".to_string()));
        assert!(links.contains(&"https://ex.com/submit".to_string()));
        assert!(!links
            .iter()
            .any(|l| l.starts_with("data:") || l.starts_with("mailto:")));
    }

    #[test]
    fn same_origin_compares_scheme_and_host() {
        assert!(same_origin("https://ex.com/a", "https://ex.com/b"));
        assert!(!same_origin("https://ex.com/a", "http://ex.com/a"));
        assert!(!same_origin("https://ex.com/a", "https://cdn.ex.com/a"));
    }

    #[test]
    fn parses_and_rewrites_query_params() {
        let url = "https://ex.com/s?q=hi&page=2#frag";
        let ps = query_params(url);
        assert_eq!(
            ps,
            vec![("q".into(), "hi".into()), ("page".into(), "2".into())]
        );
        // Replacing q keeps page and the fragment, and percent-encodes specials.
        assert_eq!(
            set_param(url, 0, "a<b>\"'"),
            "https://ex.com/s?q=a%3Cb%3E%22%27&page=2#frag"
        );
        assert_eq!(
            query_params("https://ex.com/s"),
            Vec::<(String, String)>::new()
        );
    }

    #[test]
    fn classifies_reflection() {
        let m = "sanctumxssDEAD";
        assert_eq!(
            detect_reflection(m, &format!("<p>{m}<>\"'</p>")),
            Reflection::Raw
        );
        assert_eq!(
            detect_reflection(m, &format!("<p>{m}&lt;&gt;</p>")),
            Reflection::Encoded
        );
        assert_eq!(
            detect_reflection(m, "<p>nothing here</p>"),
            Reflection::None
        );
    }

    #[test]
    fn xss_finding_severity() {
        assert_eq!(
            xss_finding("https://ex.com/?q=1", "q", Reflection::Raw)
                .unwrap()
                .severity,
            "high"
        );
        assert_eq!(
            xss_finding("https://ex.com/?q=1", "q", Reflection::Encoded)
                .unwrap()
                .severity,
            "info"
        );
        assert!(xss_finding("https://ex.com/?q=1", "q", Reflection::None).is_none());
    }

    #[test]
    fn recognizes_sql_error_signatures() {
        assert_eq!(
            sql_error_signature("You have an error in your SQL syntax; check..."),
            Some("MySQL")
        );
        assert_eq!(
            sql_error_signature("Unclosed quotation mark after the character string ''."),
            Some("MSSQL")
        );
        assert_eq!(
            sql_error_signature("ERROR: unterminated quoted string at or near \"'\""),
            Some("PostgreSQL")
        );
        assert_eq!(
            sql_error_signature("ORA-00933: SQL command not properly ended"),
            Some("Oracle")
        );
        assert_eq!(sql_error_signature("a perfectly normal page"), None);
    }

    #[test]
    fn pct_decode_roundish() {
        assert_eq!(pct_decode("a%3Cb%3E"), "a<b>");
        assert_eq!(pct_decode("x+y"), "x y");
        assert_eq!(pct_decode("plain"), "plain");
        assert_eq!(pct_decode("bad%zz"), "bad%zz");
    }

    #[test]
    fn timing_verdict_needs_fast_baseline_and_two_slow_probes() {
        let t = 2500;
        assert!(timing_verdict(200, 3000, 3100, t)); // fast base, both slow
        assert!(!timing_verdict(200, 3000, 500, t)); // confirmation fast -> jitter
        assert!(!timing_verdict(3000, 3000, 3000, t)); // slow baseline -> untrusted
        assert!(!timing_verdict(200, 1000, 1000, t)); // no delay
    }

    #[test]
    fn dedup_collapses_identical_findings() {
        let fs = vec![
            Finding::new(
                "web",
                "low",
                "https://ex.com/1",
                "Missing Content-Security-Policy",
            )
            .detail("no CSP".to_string()),
            Finding::new(
                "web",
                "low",
                "https://ex.com/2",
                "Missing Content-Security-Policy",
            )
            .detail("no CSP".to_string()),
            Finding::new("web", "medium", "https://ex.com/2", "Missing HSTS")
                .detail("x".to_string()),
        ];
        assert_eq!(dedup_findings(fs).len(), 2);
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
