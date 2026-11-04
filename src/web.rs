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

const USER_AGENT: &str = concat!("sanctum/", env!("CARGO_PKG_VERSION"));

/// Perform one request with the given method and redirect policy, capturing the
/// response's status, headers and a bounded body. `extra` carries any
/// operator-supplied request headers (authenticated scanning, ADR 0002); they
/// flow only into the outgoing request and are never logged or emitted.
fn fetch_with(
    url: &str,
    timeout: Duration,
    redirects: u32,
    method: &str,
    extra: &[(String, String)],
) -> Result<Fetched, String> {
    let agent = ureq::AgentBuilder::new()
        .timeout(timeout)
        .redirects(redirects)
        .user_agent(USER_AGENT)
        .build();
    let mut req = agent.request(method, url);
    for (name, value) in extra {
        req = req.set(name, value);
    }
    let resp = match req.call() {
        Ok(r) => r,
        // An HTTP error status (and, with redirects(0), a 3xx) still carries
        // headers worth auditing.
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
    let mut buf = Vec::new();
    resp.into_reader().take(BODY_CAP).read_to_end(&mut buf).ok();
    let body = String::from_utf8_lossy(&buf).into_owned();
    Ok(Fetched {
        status,
        headers,
        body,
    })
}

/// One GET to `url`, following redirects, returning the final response's status,
/// headers and a bounded body. `extra` carries operator-supplied request headers
/// (empty for an anonymous scan). Transport failures are a typed error string.
pub fn fetch(url: &str, timeout: Duration, extra: &[(String, String)]) -> Result<Fetched, String> {
    fetch_with(url, timeout, 5, "GET", extra)
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

// Link path fragments that suggest following the link could change state. The
// crawl skips a *discovered* link matching any of these so a GET - especially an
// authenticated one (ADR 0002) - never logs the session out or triggers an
// action. The operator-chosen seed is always fetched.
const DESTRUCTIVE_HINTS: &[&str] = &[
    "logout",
    "log-out",
    "signout",
    "sign-out",
    "delete",
    "remove",
    "destroy",
    "deactivate",
    "disable",
    "shutdown",
    "reboot",
    "purge",
    "revoke",
    "unsubscribe",
    "/drop",
    "=delete",
    "action=delete",
];

/// Whether following `url` could plausibly change server state (by path/query).
pub fn is_destructive_link(url: &str) -> bool {
    let low = url.to_ascii_lowercase();
    DESTRUCTIVE_HINTS.iter().any(|h| low.contains(h))
}

pub struct CrawlResult {
    pub pages: Vec<(String, u16)>, // (url, status) in fetch order
    pub findings: Vec<Finding>,    // deduped audit findings across the pages
}

/// A bounded, same-origin, rate-limited crawl from `seed`. GET only; it reads
/// each page, audits the response, and follows same-origin links up to
/// `max_pages` / `max_depth`, sleeping `delay` between requests. Discovered
/// destructive-looking links are skipped. `extra` carries operator-supplied
/// request headers (authenticated scanning). Non-destructive.
pub fn crawl(
    seed: &str,
    timeout: Duration,
    max_pages: usize,
    max_depth: u32,
    delay: Duration,
    extra: &[(String, String)],
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
        let fetched = match fetch(&url, timeout, extra) {
            Ok(f) => f,
            Err(_) => continue,
        };
        pages.push((url.clone(), fetched.status));
        for f in audit_response(&url, fetched.status, &fetched.headers) {
            if f.title != "HTTP response" {
                findings.push(f);
            }
        }
        for f in csrf_findings(&url, &fetched.body) {
            findings.push(f); // passive; deduped site-wide below
        }
        if depth < max_depth && content_is_html(&fetched.headers) {
            for link in extract_links(&url, &fetched.body) {
                if !same_origin(seed, &link) {
                    continue;
                }
                if is_destructive_link(&link) {
                    continue; // never follow a state-changing link (ADR 0002)
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

/// A unique, alphanumeric token for this process/run, with a given prefix.
fn unique_token(prefix: &str) -> String {
    let n = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_nanos())
        .unwrap_or(0);
    format!("{prefix}{:x}", (n as u64) & 0xff_ffff_ffff)
}

/// A unique, alphanumeric probe marker for this process/run.
fn marker() -> String {
    unique_token("sanctumxss")
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
    extra: &[(String, String)],
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
            if let Ok(resp) = fetch(&probe_url, timeout, extra) {
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
    extra: &[(String, String)],
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
        let baseline = fetch(url, timeout, extra).ok();
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
            if let Ok(r) = fetch(&err_url, timeout, extra) {
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
                let ok1 = fetch(&u, timeout, extra).is_ok();
                let ms1 = t.elapsed().as_millis();
                if !ok1 || ms1 < SQL_TIME_THRESHOLD_MS {
                    continue;
                }
                if probes >= max_probes {
                    return out;
                }
                probes += 1;
                let t2 = Instant::now();
                let ok2 = fetch(&u, timeout, extra).is_ok();
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

// ---- open-redirect detection (ADR 0001, non-destructive) --------------------
//
// Set a redirect-looking parameter to an external canary and see whether the
// server issues a 3xx Location to it. We do NOT follow the redirect; the canary
// host is a reserved .example domain that routes nowhere.

const CANARY_HOST: &str = "sanctum-canary.example";
const REDIRECT_PARAMS: &[&str] = &[
    "url",
    "next",
    "redirect",
    "redir",
    "return",
    "returnurl",
    "return_url",
    "dest",
    "destination",
    "continue",
    "goto",
    "to",
    "u",
    "r",
    "callback",
    "out",
    "view",
    "link",
];

/// Whether a parameter is a plausible redirect target (by name or value shape).
pub fn is_redirect_param(name: &str, value: &str) -> bool {
    let n = name.to_ascii_lowercase();
    REDIRECT_PARAMS.contains(&n.as_str())
        || value.starts_with("http://")
        || value.starts_with("https://")
        || value.starts_with("//")
        || value.starts_with('/')
}

/// Whether a Location header points at our external canary host.
pub fn location_targets_canary(location: &str) -> bool {
    location.to_ascii_lowercase().contains(CANARY_HOST)
}

/// Probe redirect-looking parameters for open redirect. GET only, redirects not
/// followed, deduped by path+name, capped and rate-limited.
pub fn open_redirect_scan(
    urls: &[String],
    timeout: Duration,
    delay: Duration,
    max_probes: usize,
    extra: &[(String, String)],
) -> Vec<Finding> {
    let canary = format!("https://{CANARY_HOST}/");
    let mut out = Vec::new();
    let mut seen: HashSet<String> = HashSet::new();
    let mut probes = 0usize;
    for url in urls {
        for (i, (name, value)) in query_params(url).iter().enumerate() {
            if !is_redirect_param(name, value) {
                continue;
            }
            if probes >= max_probes {
                return out;
            }
            let path = url.split('?').next().unwrap_or(url);
            if !seen.insert(format!("{path}\u{1}{name}\u{1}redir")) {
                continue;
            }
            if probes > 0 {
                std::thread::sleep(delay);
            }
            probes += 1;
            let probe = set_param(url, i, &canary);
            if let Ok(resp) = fetch_with(&probe, timeout, 0, "GET", extra) {
                if (300..400).contains(&resp.status) {
                    if let Some(loc) = header(&resp.headers, "location") {
                        if location_targets_canary(loc) {
                            out.push(
                                Finding::new("web", "high", url.clone(), "Open redirect candidate")
                                    .detail(format!(
                                        "parameter `{name}` redirects (Location) to an external host"
                                    )),
                            );
                        }
                    }
                }
            }
        }
    }
    out
}

// ---- directory / method enumeration (ADR 0001, non-destructive) -------------

/// The origin root ("https://host/") of a URL.
pub fn origin_root(url: &str) -> String {
    format!("{}://{}/", scheme_of(url), host_of(url))
}

// Common sensitive paths and the severity if one is reachable.
const SENSITIVE_PATHS: &[(&str, &str)] = &[
    (".git/HEAD", "high"),
    (".env", "high"),
    (".svn/entries", "high"),
    ("wp-config.php.bak", "high"),
    ("backup.zip", "medium"),
    ("backup.sql", "medium"),
    ("server-status", "medium"),
    ("phpinfo.php", "medium"),
    (".htaccess", "medium"),
    ("robots.txt", "info"),
    (".well-known/security.txt", "info"),
    ("admin/", "low"),
];

/// A finding for a probed sensitive path given its response status.
pub fn dir_finding(path: &str, status: u16, sev: &str) -> Option<Finding> {
    match status {
        200 => Some(
            Finding::new("web", sev, path.to_string(), "Exposed path")
                .detail(format!("{path} is reachable (HTTP 200)")),
        ),
        401 | 403 => Some(
            Finding::new(
                "web",
                "info",
                path.to_string(),
                "Path present but protected",
            )
            .detail(format!("{path} returned HTTP {status}")),
        ),
        _ => None,
    }
}

/// Enumerate allowed methods (OPTIONS) and probe a small set of sensitive paths
/// at the origin root. GET/OPTIONS only, rate-limited. Run once per origin.
pub fn enum_scan(
    origin: &str,
    timeout: Duration,
    delay: Duration,
    extra: &[(String, String)],
) -> Vec<Finding> {
    let mut out = Vec::new();
    // Method enumeration via OPTIONS (safe, idempotent).
    if let Ok(resp) = fetch_with(origin, timeout, 0, "OPTIONS", extra) {
        if let Some(allow) = header(&resp.headers, "allow") {
            out.push(
                Finding::new("web", "info", origin.to_string(), "Allowed methods")
                    .detail(format!("Allow: {allow}")),
            );
            if allow.to_ascii_uppercase().contains("TRACE") {
                out.push(
                    Finding::new("web", "medium", origin.to_string(), "HTTP TRACE advertised")
                        .detail(
                            "the Allow header lists TRACE (cross-site tracing risk)".to_string(),
                        ),
                );
            }
        }
    }
    // Directory probes.
    for (path, sev) in SENSITIVE_PATHS {
        std::thread::sleep(delay);
        let url = format!("{origin}{path}");
        if let Ok(resp) = fetch(&url, timeout, extra) {
            if let Some(f) = dir_finding(path, resp.status, sev) {
                out.push(f);
            }
        }
    }
    out
}

// ---- CSRF token presence (ADR 0001, passive) --------------------------------

const CSRF_TOKEN_HINTS: &[&str] = &[
    "csrf",
    "_token",
    "authenticity_token",
    "xsrf",
    "nonce",
    "__requestverificationtoken",
];

fn form_is_post(open_tag_lower: &str) -> bool {
    match open_tag_lower.find("method") {
        Some(p) => open_tag_lower[p..(p + 20).min(open_tag_lower.len())].contains("post"),
        None => false,
    }
}

/// Passive: report POST forms that carry no apparent CSRF token field.
pub fn csrf_findings(url: &str, body: &str) -> Vec<Finding> {
    let low = body.to_ascii_lowercase();
    let mut out = Vec::new();
    let mut idx = 0usize;
    let mut form_no = 0usize;
    while let Some(rel) = low[idx..].find("<form") {
        let start = idx + rel;
        let end = low[start..]
            .find("</form>")
            .map(|e| start + e + "</form>".len())
            .unwrap_or(low.len());
        let form = &low[start..end];
        idx = end;
        let open_tag = &form[..form.find('>').unwrap_or(form.len())];
        if !form_is_post(open_tag) {
            continue;
        }
        form_no += 1;
        if !CSRF_TOKEN_HINTS.iter().any(|h| form.contains(h)) {
            out.push(
                Finding::new(
                    "web",
                    "low",
                    url.to_string(),
                    "POST form without apparent CSRF token",
                )
                .detail(format!(
                    "form #{form_no} has no hidden token field (csrf / token / nonce / ...)"
                )),
            );
        }
    }
    out
}

// ---- OS command injection detection (time-based, existence only; ADR 0002) --
//
// Inject a *benign* delay command (only ever a sleep) into a parameter and
// confirm a measured delay, twice, to shed jitter - the time-based SQLi pattern.
// This establishes that a parameter reaches a shell without running a harmful
// command and without reading any output.

const CMD_SLEEP_SECONDS: u64 = 3;

/// Benign delay payloads (a sleep only) for time-based command-injection
/// existence detection. `sleep` covers POSIX shells; `ping`/`timeout` Windows.
fn cmd_time_payloads() -> Vec<String> {
    let s = CMD_SLEEP_SECONDS;
    vec![
        format!(";sleep {s}"),
        format!("|sleep {s}"),
        format!("`sleep {s}`"),
        format!("$(sleep {s})"),
        format!("& ping -n {} 127.0.0.1", s + 1), // Windows ping delays ~(n-1)s
        format!("& timeout /t {s}"),
    ]
}

/// Probe query parameters for OS command injection (time-based, existence only).
/// GET only, deduped by path+name, capped, rate-limited. Non-destructive: the
/// only command ever injected is a sleep, and no output is read.
pub fn command_injection_scan(
    urls: &[String],
    timeout: Duration,
    delay: Duration,
    max_probes: usize,
    extra: &[(String, String)],
) -> Vec<Finding> {
    let payloads = cmd_time_payloads();
    let mut out = Vec::new();
    let mut seen: HashSet<String> = HashSet::new();
    let mut probes = 0usize;
    for url in urls {
        let params = query_params(url);
        if params.is_empty() {
            continue;
        }
        let t0 = Instant::now();
        let _ = fetch(url, timeout, extra);
        let base_ms = t0.elapsed().as_millis();
        if base_ms >= SQL_BASE_MAX_MS {
            continue; // baseline too slow to trust timing (same bar as SQLi)
        }
        for (i, (name, value)) in params.iter().enumerate() {
            if probes >= max_probes {
                return out;
            }
            let path = url.split('?').next().unwrap_or(url);
            if !seen.insert(format!("{path}\u{1}{name}\u{1}cmd")) {
                continue;
            }
            let decoded = pct_decode(value);
            for payload in &payloads {
                if probes >= max_probes {
                    return out;
                }
                std::thread::sleep(delay);
                probes += 1;
                let u = set_param(url, i, &format!("{decoded}{payload}"));
                let t = Instant::now();
                let ok1 = fetch(&u, timeout, extra).is_ok();
                let ms1 = t.elapsed().as_millis();
                if !ok1 || ms1 < SQL_TIME_THRESHOLD_MS {
                    continue;
                }
                if probes >= max_probes {
                    return out;
                }
                std::thread::sleep(delay);
                probes += 1;
                let t2 = Instant::now();
                let ok2 = fetch(&u, timeout, extra).is_ok();
                let ms2 = t2.elapsed().as_millis();
                if ok2 && timing_verdict(base_ms, ms1, ms2, SQL_TIME_THRESHOLD_MS) {
                    out.push(
                        Finding::new(
                            "web",
                            "high",
                            url.clone(),
                            "OS command injection (time-based) candidate",
                        )
                        .detail(format!(
                            "parameter `{name}` delayed ~{CMD_SLEEP_SECONDS}s on a benign sleep payload"
                        )),
                    );
                    break;
                }
            }
        }
    }
    out
}

// ---- path traversal detection (structural-signature existence; ADR 0002) ----
//
// Send a traversal payload and match only a well-known *structural, non-secret*
// signature to confirm the flaw. The finding reports existence and which
// signature matched - never file contents, and no secret-bearing file is read.

const TRAVERSAL_PAYLOADS: &[&str] = &[
    "../../../../../../etc/passwd",
    "....//....//....//....//....//etc/passwd",
    "/etc/passwd",
    "../../../../../../../../windows/win.ini",
    "..\\..\\..\\..\\..\\..\\windows\\win.ini",
];

/// A well-known structural, non-secret signature in `body` that confirms a
/// traversal read occurred; returns the signature's name, never any contents.
pub fn traversal_signature(body: &str) -> Option<&'static str> {
    // A unix passwd line has 7 colon-separated fields; we match the shape and a
    // conventional account name, not any secret value.
    if body.lines().any(|l| {
        l.matches(':').count() >= 6
            && (l.starts_with("root:") || l.starts_with("daemon:") || l.starts_with("nobody:"))
    }) {
        return Some("unix passwd structure");
    }
    let low = body.to_ascii_lowercase();
    if low.contains("[extensions]") || low.contains("; for 16-bit app support") {
        return Some("windows win.ini structure");
    }
    None
}

/// Probe query parameters for path traversal (structural-signature existence).
/// GET only, deduped, capped, rate-limited; reports existence only.
pub fn path_traversal_scan(
    urls: &[String],
    timeout: Duration,
    delay: Duration,
    max_probes: usize,
    extra: &[(String, String)],
) -> Vec<Finding> {
    let mut out = Vec::new();
    let mut seen: HashSet<String> = HashSet::new();
    let mut probes = 0usize;
    for url in urls {
        let params = query_params(url);
        if params.is_empty() {
            continue;
        }
        // Only trust a signature the clean page did not already show.
        let base_has_sig = fetch(url, timeout, extra)
            .ok()
            .map(|r| traversal_signature(&r.body).is_some())
            .unwrap_or(false);
        if base_has_sig {
            continue;
        }
        for (i, (name, _)) in params.iter().enumerate() {
            if probes >= max_probes {
                return out;
            }
            let path = url.split('?').next().unwrap_or(url);
            if !seen.insert(format!("{path}\u{1}{name}\u{1}trav")) {
                continue;
            }
            for payload in TRAVERSAL_PAYLOADS {
                if probes >= max_probes {
                    return out;
                }
                std::thread::sleep(delay);
                probes += 1;
                let u = set_param(url, i, payload);
                if let Ok(r) = fetch(&u, timeout, extra) {
                    if let Some(sig) = traversal_signature(&r.body) {
                        out.push(
                            Finding::new("web", "high", url.clone(), "Path traversal candidate")
                                .detail(format!(
                                    "parameter `{name}` returned a {sig} (traversal confirmed; \
                                 contents not shown)"
                                )),
                        );
                        break;
                    }
                }
            }
        }
    }
    out
}

// ---- CRLF / HTTP response-header injection (existence; ADR 0002) ------------
//
// Inject a CR LF plus a benign, inert marker header into a parameter and detect
// the marker coming back as a real response header. Nothing is cached or poisoned.

const CRLF_HEADER: &str = "x-sanctum-inject";
const CRLF_VALUE: &str = "1";

/// Whether the inert marker header is present in a response's headers.
pub fn response_has_injected_header(headers: &[(String, String)]) -> bool {
    headers
        .iter()
        .any(|(k, v)| k == CRLF_HEADER && v == CRLF_VALUE)
}

/// Probe query parameters for CRLF / response-header injection. GET only,
/// redirects not followed, deduped, capped, rate-limited. Non-destructive.
pub fn crlf_injection_scan(
    urls: &[String],
    timeout: Duration,
    delay: Duration,
    max_probes: usize,
    extra: &[(String, String)],
) -> Vec<Finding> {
    let tail = format!("\r\n{CRLF_HEADER}: {CRLF_VALUE}");
    let mut out = Vec::new();
    let mut seen: HashSet<String> = HashSet::new();
    let mut probes = 0usize;
    for url in urls {
        for (i, (name, value)) in query_params(url).iter().enumerate() {
            if probes >= max_probes {
                return out;
            }
            let path = url.split('?').next().unwrap_or(url);
            if !seen.insert(format!("{path}\u{1}{name}\u{1}crlf")) {
                continue;
            }
            if probes > 0 {
                std::thread::sleep(delay);
            }
            probes += 1;
            let decoded = pct_decode(value);
            // set_param percent-encodes the CR/LF to %0D%0A on the wire.
            let u = set_param(url, i, &format!("{decoded}{tail}"));
            if let Ok(r) = fetch_with(&u, timeout, 0, "GET", extra) {
                if response_has_injected_header(&r.headers) {
                    out.push(
                        Finding::new(
                            "web",
                            "high",
                            url.clone(),
                            "CRLF / response-header injection candidate",
                        )
                        .detail(format!(
                            "parameter `{name}` injected a response header via CR LF"
                        )),
                    );
                }
            }
        }
    }
    out
}

// ---- non-destructive fuzzing (ADR 0002) -------------------------------------
//
// Bounded input mutation that classifies response *differences* - never a flood
// or a crash attempt. A curated benign payload set per parameter (including a
// template-evaluation marker for SSTI existence), plus hidden-parameter
// discovery. Each is capped by the shared probe budget and rate-limited.

const SSTI_PRODUCT: &str = "1787569"; // 1337 * 1337 - too specific to occur by chance
const SSTI_PAYLOADS: &[&str] = &[
    "{{1337*1337}}",
    "${1337*1337}",
    "#{1337*1337}",
    "<%= 1337*1337 %>",
    "${{1337*1337}}",
];

/// Whether a template expression evaluated (SSTI existence) in `body`.
pub fn detect_ssti(body: &str) -> bool {
    body.contains(SSTI_PRODUCT)
}

/// A response reduced to the shape the fuzzer compares against a baseline.
pub struct RespShape {
    pub status_class: u16, // the status / 100 (2,3,4,5)
    pub len: usize,
    pub sql_error: bool,
}

/// Reduce a response to its shape.
pub fn shape_of(status: u16, body: &str) -> RespShape {
    RespShape {
        status_class: status / 100,
        len: body.len(),
        sql_error: sql_error_signature(body).is_some(),
    }
}

/// Classify how a probe response differs from the baseline; None = no anomaly.
/// Returns (severity, detail).
pub fn classify_anomaly(base: &RespShape, probe: &RespShape) -> Option<(String, String)> {
    if probe.sql_error && !base.sql_error {
        return Some((
            "high".to_string(),
            "input surfaced a database error".to_string(),
        ));
    }
    if probe.status_class == 5 && base.status_class != 5 {
        return Some((
            "medium".to_string(),
            "input changed the status to 5xx (server error)".to_string(),
        ));
    }
    if probe.status_class != base.status_class {
        return Some((
            "info".to_string(),
            format!(
                "input changed the status class {}xx -> {}xx",
                base.status_class, probe.status_class
            ),
        ));
    }
    let diff = base.len.abs_diff(probe.len);
    let bigger = base.len.max(probe.len).max(1);
    if diff > 512 && diff * 100 / bigger >= 30 {
        return Some((
            "info".to_string(),
            format!(
                "input changed the response length markedly ({} -> {} bytes)",
                base.len, probe.len
            ),
        ));
    }
    None
}

/// The curated, benign fuzz payload set (bounded - the long string is one 1 KiB
/// request for length-handling observation, never a flood).
fn fuzz_payloads() -> Vec<String> {
    let mut v: Vec<String> = [
        "'",
        "\"",
        "\\",
        "<x>",
        "../",
        "%00",
        "-1",
        "0",
        "2147483648",
        "1e309",
        "[]",
        "{}",
        "null",
        "true",
    ]
    .iter()
    .map(|s| s.to_string())
    .collect();
    for s in SSTI_PAYLOADS {
        v.push((*s).to_string());
    }
    v.push("A".repeat(1024));
    v
}

/// Fuzz each URL's query parameters with the curated payload set, reporting at
/// most one SSTI candidate and one response anomaly per parameter. GET only,
/// deduped, capped, rate-limited. Non-destructive and bounded (never a flood).
pub fn fuzz_scan(
    urls: &[String],
    timeout: Duration,
    delay: Duration,
    max_probes: usize,
    extra: &[(String, String)],
) -> Vec<Finding> {
    let payloads = fuzz_payloads();
    let mut out = Vec::new();
    let mut seen: HashSet<String> = HashSet::new();
    let mut probes = 0usize;
    for url in urls {
        let params = query_params(url);
        if params.is_empty() {
            continue;
        }
        let base = match fetch(url, timeout, extra) {
            Ok(r) => shape_of(r.status, &r.body),
            Err(_) => continue,
        };
        for (i, (name, value)) in params.iter().enumerate() {
            let path = url.split('?').next().unwrap_or(url);
            if !seen.insert(format!("{path}\u{1}{name}\u{1}fuzz")) {
                continue;
            }
            let decoded = pct_decode(value);
            let mut ssti_reported = false;
            let mut anomaly_reported = false;
            for payload in &payloads {
                if probes >= max_probes {
                    return out;
                }
                std::thread::sleep(delay);
                probes += 1;
                let u = set_param(url, i, &format!("{decoded}{payload}"));
                let r = match fetch(&u, timeout, extra) {
                    Ok(r) => r,
                    Err(_) => continue,
                };
                if !ssti_reported && detect_ssti(&r.body) {
                    out.push(
                        Finding::new(
                            "web",
                            "high",
                            url.clone(),
                            "Template injection (SSTI) candidate",
                        )
                        .detail(format!(
                            "parameter `{name}` evaluated a template expression \
                             (`1337*1337` -> {SSTI_PRODUCT})"
                        )),
                    );
                    ssti_reported = true;
                    continue;
                }
                if !anomaly_reported {
                    if let Some((sev, detail)) =
                        classify_anomaly(&base, &shape_of(r.status, &r.body))
                    {
                        out.push(
                            Finding::new("web", &sev, url.clone(), "Input anomaly (fuzz)")
                                .detail(format!("parameter `{name}`: {detail}")),
                        );
                        anomaly_reported = true;
                    }
                }
                if ssti_reported && anomaly_reported {
                    break;
                }
            }
        }
    }
    out
}

// Common parameter names for hidden-parameter discovery (a small wordlist).
const PARAM_WORDLIST: &[&str] = &[
    "debug", "test", "admin", "id", "page", "q", "search", "file", "path", "url", "redirect",
    "lang", "view", "action", "user", "token", "key", "callback", "format", "mode", "show",
    "preview", "source", "template", "include",
];

/// Append `name=value` (value percent-encoded) to a URL's query.
pub fn add_param(url: &str, name: &str, value: &str) -> String {
    let (base, frag) = match url.split_once('#') {
        Some((b, f)) => (b.to_string(), format!("#{f}")),
        None => (url.to_string(), String::new()),
    };
    let sep = if base.contains('?') { '&' } else { '?' };
    format!("{base}{sep}{name}={}{frag}", pct_encode(value))
}

/// Discover hidden parameters: try a small wordlist with a unique sentinel and
/// report a name that reflects or changes the response against the baseline.
/// One pass per path, capped, rate-limited. Non-destructive.
pub fn hidden_param_scan(
    urls: &[String],
    timeout: Duration,
    delay: Duration,
    max_probes: usize,
    extra: &[(String, String)],
) -> Vec<Finding> {
    let sentinel = unique_token("sanctumhp");
    let mut out = Vec::new();
    let mut seen_path: HashSet<String> = HashSet::new();
    let mut probes = 0usize;
    for url in urls {
        let path = url.split('?').next().unwrap_or(url).to_string();
        if !seen_path.insert(path) {
            continue; // probe each distinct path once
        }
        let base = match fetch(url, timeout, extra) {
            Ok(r) => shape_of(r.status, &r.body),
            Err(_) => continue,
        };
        let existing: HashSet<String> = query_params(url).into_iter().map(|(n, _)| n).collect();
        for cand in PARAM_WORDLIST {
            if probes >= max_probes {
                return out;
            }
            if existing.contains(*cand) {
                continue;
            }
            std::thread::sleep(delay);
            probes += 1;
            let u = add_param(url, cand, &sentinel);
            if let Ok(r) = fetch(&u, timeout, extra) {
                if r.body.contains(&sentinel) {
                    out.push(
                        Finding::new(
                            "web",
                            "info",
                            url.clone(),
                            "Hidden parameter candidate (reflected)",
                        )
                        .detail(format!("parameter `{cand}` is reflected in the response")),
                    );
                } else if shape_of(r.status, &r.body).status_class != base.status_class {
                    out.push(
                        Finding::new(
                            "web",
                            "info",
                            url.clone(),
                            "Hidden parameter candidate (behavioral)",
                        )
                        .detail(format!(
                            "parameter `{cand}` changed the status class vs the baseline"
                        )),
                    );
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
    fn redirect_param_and_canary_detection() {
        assert!(is_redirect_param("next", "x"));
        assert!(is_redirect_param("anything", "https://evil/"));
        assert!(is_redirect_param("q", "/path"));
        assert!(!is_redirect_param("q", "hello"));
        assert!(location_targets_canary("https://sanctum-canary.example/"));
        assert!(location_targets_canary("//sanctum-canary.example/x"));
        assert!(!location_targets_canary("https://ex.com/home"));
    }

    #[test]
    fn dir_finding_by_status() {
        assert_eq!(dir_finding(".env", 200, "high").unwrap().severity, "high");
        assert_eq!(
            dir_finding(".git/HEAD", 403, "high").unwrap().severity,
            "info"
        );
        assert!(dir_finding(".env", 404, "high").is_none());
        assert_eq!(origin_root("https://ex.com/a/b?x=1"), "https://ex.com/");
    }

    #[test]
    fn csrf_flags_post_form_without_token() {
        let body = r#"<form method="POST" action="/pay"><input name="amount"></form>
                      <form method="post"><input type="hidden" name="csrf_token" value="z"></form>
                      <form method="get"><input name="q"></form>"#;
        let fs = csrf_findings("https://ex.com/", body);
        assert_eq!(fs.len(), 1); // only the first POST form lacks a token; GET form ignored
        assert!(fs[0].title.contains("CSRF"));
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

    #[test]
    fn destructive_links_are_recognized() {
        assert!(is_destructive_link("https://ex.com/account/logout"));
        assert!(is_destructive_link(
            "https://ex.com/post?action=delete&id=5"
        ));
        assert!(is_destructive_link("https://ex.com/users/remove/3"));
        assert!(!is_destructive_link("https://ex.com/articles/42"));
        assert!(!is_destructive_link("https://ex.com/search?q=hello"));
    }

    #[test]
    fn command_payloads_only_sleep() {
        // Every command-injection payload must be a delay only - never a
        // destructive command.
        for p in cmd_time_payloads() {
            let low = p.to_ascii_lowercase();
            assert!(
                low.contains("sleep") || low.contains("ping") || low.contains("timeout"),
                "payload must be benign delay only: {p}"
            );
            for bad in [
                "rm ", "del ", "cat ", "curl", "wget", "nc ", "mkfifo", ">", "whoami",
            ] {
                assert!(!low.contains(bad), "payload must not contain `{bad}`: {p}");
            }
        }
    }

    #[test]
    fn traversal_signature_matches_structure_only() {
        assert_eq!(
            traversal_signature("root:x:0:0:root:/root:/bin/bash\ndaemon:x:1:1:"),
            Some("unix passwd structure")
        );
        assert_eq!(
            traversal_signature("; for 16-bit app support\n[extensions]\n"),
            Some("windows win.ini structure")
        );
        // A page that merely talks about files is not a match.
        assert_eq!(
            traversal_signature("Welcome to /etc/passwd documentation"),
            None
        );
        assert_eq!(traversal_signature("nothing structural here"), None);
    }

    #[test]
    fn injected_header_detection() {
        assert!(response_has_injected_header(&h(&[(
            "x-sanctum-inject",
            "1"
        )])));
        assert!(!response_has_injected_header(&h(&[(
            "x-sanctum-inject",
            "2"
        )])));
        assert!(!response_has_injected_header(&h(&[(
            "content-type",
            "text/html"
        )])));
    }

    #[test]
    fn ssti_product_is_specific() {
        assert!(detect_ssti("output is 1787569 here"));
        assert!(!detect_ssti("the answer is 49"));
        assert!(!detect_ssti("{{1337*1337}}")); // unevaluated input is not a hit
    }

    #[test]
    fn anomaly_classification_ranks_by_severity() {
        let base = shape_of(200, "a normal page of some length");
        // A new DB error is the strongest signal.
        assert_eq!(
            classify_anomaly(
                &base,
                &shape_of(200, "You have an error in your SQL syntax")
            )
            .unwrap()
            .0,
            "high"
        );
        // A 500 on input is medium.
        assert_eq!(
            classify_anomaly(&base, &shape_of(500, "err")).unwrap().0,
            "medium"
        );
        // A different status class (not 5xx) is info.
        assert_eq!(
            classify_anomaly(&base, &shape_of(404, "x")).unwrap().0,
            "info"
        );
        // A large length change is info.
        assert_eq!(
            classify_anomaly(&base, &shape_of(200, &"z".repeat(4096)))
                .unwrap()
                .0,
            "info"
        );
        // Same shape -> no anomaly.
        assert!(classify_anomaly(&base, &shape_of(200, "a normal page of some length")).is_none());
    }

    #[test]
    fn add_param_appends_to_query() {
        assert_eq!(
            add_param("https://ex.com/p", "id", "9"),
            "https://ex.com/p?id=9"
        );
        assert_eq!(
            add_param("https://ex.com/p?a=1", "id", "9"),
            "https://ex.com/p?a=1&id=9"
        );
        assert_eq!(
            add_param("https://ex.com/p?a=1#frag", "id", "x y"),
            "https://ex.com/p?a=1&id=x%20y#frag"
        );
    }
}
