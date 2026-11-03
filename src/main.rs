//! sanctum - an authorized-scope reconnaissance companion for Zume Editor.
//!
//! It runs *scoped* reconnaissance (tier T1: TCP connect host discovery and port
//! enumeration) and writes its findings as result format v1 JSON, which Zume
//! Editor (Tools: Run Security Analyzer...) and its MCP server (analyze_run)
//! read. It is a separate, optional tool: nothing here is bundled with the
//! editor.
//!
//! AUTHORIZED USE ONLY. Active probing is refused unless you pass
//! `--i-am-authorized`, confirming you are permitted to test the given scope.
//! Running recon against systems you do not own or have explicit permission to
//! test may be illegal. The operator is responsible for staying in scope.

mod aes;
mod audit;
mod creds;
mod dcerpc;
mod hash;
mod kerberos;
mod ldap;
mod ntlm;
mod pcap;
mod probe;
mod quic;
mod radius;
mod result;
mod scope;
mod smb;
mod snmp;
mod t0;
mod timefmt;
mod tls;
mod util;
mod web;

use std::fs::File;
use std::io::Read;
use std::net::IpAddr;
use std::time::Duration;

use result::{Finding, Report};

const DEFAULT_TIMEOUT_MS: u64 = 800;
const DEFAULT_MAX_HOSTS: usize = 1024;
const DEFAULT_MAX_PORTS: usize = 1024;
const DEFAULT_MAX_PAGES: usize = 20; // T2 crawl page cap
const WEB_CRAWL_DEPTH: u32 = 2;
const WEB_CRAWL_DELAY_MS: u64 = 300; // rate limit between crawl requests
const WEB_MAX_PROBES: usize = 50; // cap on active probe requests (--active)
const PCAP_READ_CAP: u64 = 64 * 1024 * 1024; // bytes of a pcap read for summary
const PCAP_MAX_PACKETS: u64 = 200_000;
const PCAP_MAX_ROWS: usize = 50; // cap host / service findings

struct Args {
    scope: Option<String>,
    file: Option<String>,
    web: Option<String>,
    json_out: Option<String>,
    ports: Option<String>,
    authorized: bool,
    audit: Option<String>,
    timeout_ms: u64,
    max_hosts: usize,
    max_ports: usize,
    banner: bool,
    crawl: bool,
    active: bool,
    max_pages: usize,
    help: bool,
}

impl Default for Args {
    fn default() -> Self {
        Args {
            scope: None,
            file: None,
            web: None,
            json_out: None,
            ports: None,
            authorized: false,
            audit: None,
            timeout_ms: DEFAULT_TIMEOUT_MS,
            max_hosts: DEFAULT_MAX_HOSTS,
            max_ports: DEFAULT_MAX_PORTS,
            banner: true,
            crawl: false,
            active: false,
            max_pages: DEFAULT_MAX_PAGES,
            help: false,
        }
    }
}

fn main() {
    std::process::exit(run());
}

fn run() -> i32 {
    let args = match parse_args() {
        Ok(a) => a,
        Err(e) => {
            eprintln!("sanctum: {e}");
            eprintln!();
            eprint_usage();
            return 2;
        }
    };
    if args.help {
        print_usage();
        return 0;
    }
    let modes = args.scope.is_some() as u8 + args.file.is_some() as u8 + args.web.is_some() as u8;
    if modes > 1 {
        eprintln!(
            "sanctum: choose one of --scope (recon), --file (offline) or --web (web), not several"
        );
        return 2;
    }
    // Tier T0: offline analysis of a local file (no network, no authorization gate).
    if let Some(file) = args.file.clone() {
        return run_file_analysis(&args, &file);
    }
    // Tier T2: active but non-destructive web diagnostics (ADR 0001).
    if let Some(url) = args.web.clone() {
        return run_web(&args, &url);
    }
    let scope_str = match &args.scope {
        Some(s) => s.clone(),
        None => {
            eprintln!("sanctum: --scope (network recon) or --file (offline analysis) is required");
            eprintln!();
            eprint_usage();
            return 2;
        }
    };

    let started = timefmt::iso8601_now();
    let mut report = Report::new(scope_str.clone(), started.clone());
    let audit = audit::audit_path(args.audit.as_deref());

    // Parse the scope (also the blast-radius boundary).
    let parsed = match scope::parse_scope(&scope_str, args.max_hosts) {
        Ok(s) => s,
        Err(e) => {
            report.warnings.push(format!("scope error: {e}"));
            report.finished = timefmt::iso8601_now();
            audit::log(
                &audit,
                &format!(
                    "{started} scope_error scope={} err={}",
                    result::jstr(&scope_str),
                    result::jstr(&e)
                ),
            );
            write_result(&report, &args);
            eprintln!("sanctum: scope error: {e}");
            return 2;
        }
    };

    // Authorization gate: active probing is off unless explicitly confirmed.
    if !args.authorized {
        let w = format!(
            "refused: active probing is off. Re-run with --i-am-authorized to confirm you are \
             authorized to test this scope ({} host(s)). Authorized testing only.",
            parsed.hosts.len()
        );
        report.warnings.push(w);
        report.finished = timefmt::iso8601_now();
        audit::log(
            &audit,
            &format!(
                "{started} refused_unauthorized scope={} hosts={}",
                result::jstr(&scope_str),
                parsed.hosts.len()
            ),
        );
        write_result(&report, &args);
        eprintln!(
            "sanctum: refused - pass --i-am-authorized to run against {} host(s). \
             You must be authorized to test this scope.",
            parsed.hosts.len()
        );
        return 3;
    }

    let ports = match &args.ports {
        Some(spec) => match probe::parse_ports(spec, args.max_ports) {
            Ok(v) => v,
            Err(e) => {
                eprintln!("sanctum: {e}");
                return 2;
            }
        },
        None => probe::default_ports(),
    };

    audit::log(
        &audit,
        &format!(
            "{started} run scope={} hosts={} ports={} timeout_ms={}",
            result::jstr(&scope_str),
            parsed.hosts.len(),
            ports.len(),
            args.timeout_ms
        ),
    );

    let timeout = Duration::from_millis(args.timeout_ms);
    let mut live = 0usize;
    for ip in &parsed.hosts {
        let (up, open) = probe::scan_host(*ip, &ports, timeout);
        if !up {
            continue;
        }
        live += 1;
        report.findings.push(
            Finding::new("host", "info", ip.to_string(), "Host up")
                .detail(format!("{} open port(s)", open.len())),
        );
        for port in open {
            let name = probe::service_name(port);
            let title = if name.is_empty() {
                format!("open {port}/tcp")
            } else {
                format!("open {port}/tcp ({name})")
            };
            let mut finding = Finding::new("service", "low", target_label(ip, port), title);
            // Banner grab (v0.2): record the greeting / Server header the service
            // volunteers, as the finding detail.
            if args.banner {
                if let Some(banner) = probe::grab_banner(*ip, port, timeout) {
                    finding = finding.detail(banner);
                }
            }
            report.findings.push(finding);
        }
    }
    if parsed.hosts.len() > 1 {
        report.warnings.push(format!(
            "scanned {} host(s), {live} responded",
            parsed.hosts.len()
        ));
    }

    report.finished = timefmt::iso8601_now();
    audit::log(
        &audit,
        &format!(
            "{} done scope={} live={live} findings={}",
            report.finished,
            result::jstr(&scope_str),
            report.findings.len()
        ),
    );
    eprintln!(
        "sanctum: {} host(s) scanned, {live} up, {} finding(s).",
        parsed.hosts.len(),
        report.findings.len()
    );
    write_result(&report, &args);
    0
}

/// Read up to `cap` bytes of a file (bounded, for the pcap summary).
fn read_capped(path: &str, cap: u64) -> std::io::Result<Vec<u8>> {
    let f = File::open(path)?;
    let mut buf = Vec::new();
    f.take(cap).read_to_end(&mut buf)?;
    Ok(buf)
}

/// Turn a pcap summary into findings (a note, then top hosts and services).
fn add_pcap_findings(report: &mut Report, sum: &pcap::PcapSummary) {
    report.findings.push(
        Finding::new(
            "note",
            "info",
            "capture",
            format!("capture ({})", pcap::link_type_name(sum.link_type)),
        )
        .detail(format!(
            "{} packets, {} hosts, {} services{}",
            sum.packets,
            sum.hosts.len(),
            sum.services.len(),
            if sum.truncated { " (truncated)" } else { "" }
        )),
    );
    for (ip, n) in sum.hosts.iter().take(PCAP_MAX_ROWS) {
        report.findings.push(
            Finding::new("host", "info", ip.to_string(), "seen in capture")
                .detail(format!("{n} packets")),
        );
    }
    for (proto, port, n) in sum.services.iter().take(PCAP_MAX_ROWS) {
        let name = probe::service_name(*port);
        let title = if name.is_empty() {
            format!("{port}/{proto}")
        } else {
            format!("{name} ({port}/{proto})")
        };
        report.findings.push(
            Finding::new("service", "low", format!("{port}/{proto}"), title)
                .detail(format!("{n} packets")),
        );
    }
    // Plaintext credentials recovered from payloads - high severity.
    for cred in sum.creds.iter().take(PCAP_MAX_ROWS) {
        report.findings.push(
            Finding::new("credential", "high", "capture", "Plaintext credential")
                .detail(cred.clone()),
        );
    }
    // NTLM / Kerberos authentication material - high severity.
    for a in sum.auth.iter().take(PCAP_MAX_ROWS) {
        report.findings.push(
            Finding::new("credential", "high", "capture", "Authentication material")
                .detail(a.clone()),
        );
    }
    // Protocol session facts (SMB dialect / SMB1 / tree connect, LDAP SASL).
    for note in sum.notes.iter().take(PCAP_MAX_ROWS) {
        report
            .findings
            .push(Finding::new("note", "info", "capture", "Session context").detail(note.clone()));
    }
    // TLS server names (SNI) seen in ClientHello messages.
    for host in sum.sni.iter().take(PCAP_MAX_ROWS) {
        report
            .findings
            .push(Finding::new("note", "info", host.clone(), "TLS SNI").detail(host.clone()));
    }
}

/// Tier T0: analyze a local file offline (no network, no authorization gate)
/// and report its type, hashes, entropy and strings as findings.
fn run_file_analysis(args: &Args, path: &str) -> i32 {
    let started = timefmt::iso8601_now();
    let mut report = Report::new(path.to_string(), started.clone());
    let audit = audit::audit_path(args.audit.as_deref());

    let a = match t0::analyze_file(path) {
        Ok(a) => a,
        Err(e) => {
            report.warnings.push(format!("cannot read file: {e}"));
            report.finished = timefmt::iso8601_now();
            audit::log(
                &audit,
                &format!(
                    "{started} file_error file={} err={}",
                    result::jstr(path),
                    result::jstr(&e.to_string())
                ),
            );
            write_result(&report, args);
            eprintln!("sanctum: cannot read {path}: {e}");
            return 2;
        }
    };
    audit::log(
        &audit,
        &format!(
            "{started} analyze file={} size={} sha256={}",
            result::jstr(path),
            a.size,
            a.sha256
        ),
    );

    // Summary artifact finding - its evidence_path opens the file from the panel.
    let mut summary = Finding::new(
        "artifact",
        "info",
        path.to_string(),
        format!("{} ({} bytes)", a.kind, a.size),
    );
    summary.detail = format!("entropy {:.2} bits/byte", a.entropy);
    summary.evidence_path = path.to_string();
    report.findings.push(summary);

    // Hashes - each row copies its line (hash in the detail).
    report
        .findings
        .push(Finding::new("hash", "info", path.to_string(), "CRC32").detail(a.crc32));
    report
        .findings
        .push(Finding::new("hash", "info", path.to_string(), "MD5").detail(a.md5));
    report
        .findings
        .push(Finding::new("hash", "info", path.to_string(), "SHA-1").detail(a.sha1));
    report
        .findings
        .push(Finding::new("hash", "info", path.to_string(), "SHA-256").detail(a.sha256));

    if a.entropy >= 7.5 {
        report.findings.push(
            Finding::new("note", "medium", path.to_string(), "High entropy").detail(format!(
                "{:.2} bits/byte - likely compressed or encrypted",
                a.entropy
            )),
        );
    }

    let title = if a.strings_truncated {
        format!(
            "printable strings: {} (first 4 MiB scanned)",
            a.string_count
        )
    } else {
        format!("printable strings: {}", a.string_count)
    };
    let sample = a
        .sample_strings
        .iter()
        .take(8)
        .cloned()
        .collect::<Vec<_>>()
        .join(" | ");
    let mut strings = Finding::new("artifact", "info", path.to_string(), title);
    if !sample.is_empty() {
        strings = strings.detail(sample);
    }
    report.findings.push(strings);

    // If it is a capture (classic pcap or pcapng), summarize endpoints/services.
    if a.kind == "pcap capture" || a.kind == "pcapng capture" {
        let ng = a.kind == "pcapng capture";
        match read_capped(path, PCAP_READ_CAP) {
            Ok(bytes) => {
                let parsed = if ng {
                    pcap::parse_pcapng(&bytes, PCAP_MAX_PACKETS)
                } else {
                    pcap::parse_pcap(&bytes, PCAP_MAX_PACKETS)
                };
                match parsed {
                    Ok(sum) => add_pcap_findings(&mut report, &sum),
                    Err(e) => report.warnings.push(format!("capture parse: {e}")),
                }
            }
            Err(e) => report.warnings.push(format!("capture read: {e}")),
        }
    }

    report.finished = timefmt::iso8601_now();
    audit::log(
        &audit,
        &format!(
            "{} file_done file={} findings={}",
            report.finished,
            result::jstr(path),
            report.findings.len()
        ),
    );
    eprintln!(
        "sanctum: analyzed {path} ({} bytes), {} finding(s).",
        a.size,
        report.findings.len()
    );
    write_result(&report, args);
    0
}

/// "ip:port", bracketing an IPv6 literal so the target is unambiguous.
fn target_label(ip: &IpAddr, port: u16) -> String {
    match ip {
        IpAddr::V4(v4) => format!("{v4}:{port}"),
        IpAddr::V6(v6) => format!("[{v6}]:{port}"),
    }
}

/// Tier T2 (ADR 0001): active but non-destructive web diagnostics against one
/// authorized URL. Gated by --i-am-authorized, like network recon; it makes one
/// GET and audits the response (headers, cookies, transport). No exploitation.
fn run_web(args: &Args, url: &str) -> i32 {
    let started = timefmt::iso8601_now();
    let mut report = Report::new(url.to_string(), started.clone());
    let audit = audit::audit_path(args.audit.as_deref());

    let scheme = web::scheme_of(url);
    if scheme != "http" && scheme != "https" {
        report.warnings.push(format!(
            "web: unsupported URL scheme (need http/https): {url}"
        ));
        report.finished = timefmt::iso8601_now();
        write_result(&report, args);
        eprintln!("sanctum: --web needs an http:// or https:// URL");
        return 2;
    }

    if !args.authorized {
        let w = format!(
            "refused: web diagnostics are active requests. Re-run with --i-am-authorized to \
             confirm you are authorized to test {}. Authorized testing only.",
            web::host_of(url)
        );
        report.warnings.push(w);
        report.finished = timefmt::iso8601_now();
        audit::log(
            &audit,
            &format!("{started} refused_unauthorized web={}", result::jstr(url)),
        );
        write_result(&report, args);
        eprintln!(
            "sanctum: refused - pass --i-am-authorized to run web diagnostics against {}. \
             You must be authorized to test this target.",
            web::host_of(url)
        );
        return 3;
    }

    audit::log(
        &audit,
        &format!(
            "{started} web_run url={} crawl={}",
            result::jstr(url),
            args.crawl
        ),
    );
    // Web responses need more headroom than a TCP connect; honor an explicit
    // --timeout-ms but floor it so a default 800 ms does not spuriously fail.
    let timeout = Duration::from_millis(args.timeout_ms.max(5000));
    // The URLs an active probe (--active) will target: the crawled pages, else
    // just the given URL.
    let mut candidates: Vec<String> = Vec::new();
    if args.crawl {
        // Bounded, same-origin, rate-limited crawl, auditing every page.
        let res = web::crawl(
            url,
            timeout,
            args.max_pages,
            WEB_CRAWL_DEPTH,
            Duration::from_millis(WEB_CRAWL_DELAY_MS),
        );
        report.findings.push(
            Finding::new("web", "info", url.to_string(), "Crawl summary").detail(format!(
                "{} same-origin page(s) fetched (depth <= {}, cap {})",
                res.pages.len(),
                WEB_CRAWL_DEPTH,
                args.max_pages
            )),
        );
        for (page, status) in res.pages.iter().take(PCAP_MAX_ROWS) {
            report.findings.push(
                Finding::new("web", "info", page.clone(), "Page")
                    .detail(format!("status {status}")),
            );
        }
        candidates = res.pages.into_iter().map(|(u, _)| u).collect();
        for f in res.findings {
            report.findings.push(f);
        }
    } else {
        match web::fetch(url, timeout) {
            Ok(resp) => {
                for f in web::audit_response(url, resp.status, &resp.headers) {
                    report.findings.push(f);
                }
            }
            Err(e) => {
                report.warnings.push(format!("web: request failed: {e}"));
                audit::log(
                    &audit,
                    &format!(
                        "{started} web_error url={} err={}",
                        result::jstr(url),
                        result::jstr(&e)
                    ),
                );
            }
        }
        candidates.push(url.to_string());
    }
    // Active, non-destructive detection (--active): reflected-XSS probing of
    // query parameters (ADR 0001 increment 2).
    if args.active {
        audit::log(
            &audit,
            &format!("{started} web_active url={}", result::jstr(url)),
        );
        let delay = Duration::from_millis(WEB_CRAWL_DELAY_MS);
        for f in web::reflected_xss_scan(&candidates, timeout, delay, WEB_MAX_PROBES) {
            report.findings.push(f);
        }
        for f in web::sql_injection_scan(&candidates, timeout, delay, WEB_MAX_PROBES) {
            report.findings.push(f);
        }
    }
    report.finished = timefmt::iso8601_now();
    audit::log(
        &audit,
        &format!(
            "{started} web_done url={} findings={}",
            result::jstr(url),
            report.findings.len()
        ),
    );
    write_result(&report, args);
    eprintln!(
        "sanctum: web diagnostics of {} - {} finding(s)",
        web::host_of(url),
        report.findings.len()
    );
    0
}

/// Write the result JSON to --json (the editor's {out}), else to stdout.
fn write_result(report: &Report, args: &Args) {
    let json = report.to_json();
    match &args.json_out {
        Some(path) => {
            if let Err(e) = std::fs::write(path, json.as_bytes()) {
                eprintln!("sanctum: cannot write result to {path}: {e}");
            }
        }
        None => println!("{json}"),
    }
}

fn parse_args() -> Result<Args, String> {
    let mut args = Args::default();
    let mut it = std::env::args().skip(1);
    while let Some(arg) = it.next() {
        match arg.as_str() {
            "-h" | "--help" => args.help = true,
            "--i-am-authorized" => args.authorized = true,
            "--scope" => args.scope = Some(need_value(&mut it, "--scope")?),
            "--file" => args.file = Some(need_value(&mut it, "--file")?),
            "--web" => args.web = Some(need_value(&mut it, "--web")?),
            "--json" => args.json_out = Some(need_value(&mut it, "--json")?),
            "--ports" => args.ports = Some(need_value(&mut it, "--ports")?),
            "--audit" => args.audit = Some(need_value(&mut it, "--audit")?),
            "--timeout-ms" => {
                args.timeout_ms = need_value(&mut it, "--timeout-ms")?
                    .parse()
                    .map_err(|_| "invalid --timeout-ms".to_string())?;
            }
            "--max-hosts" => {
                args.max_hosts = need_value(&mut it, "--max-hosts")?
                    .parse()
                    .map_err(|_| "invalid --max-hosts".to_string())?;
            }
            "--max-ports" => {
                args.max_ports = need_value(&mut it, "--max-ports")?
                    .parse()
                    .map_err(|_| "invalid --max-ports".to_string())?;
            }
            "--no-banner" => args.banner = false,
            "--crawl" => args.crawl = true,
            "--active" => args.active = true,
            "--max-pages" => {
                args.max_pages = need_value(&mut it, "--max-pages")?
                    .parse()
                    .map_err(|_| "invalid --max-pages".to_string())?;
            }
            other => return Err(format!("unknown argument: {other}")),
        }
    }
    Ok(args)
}

fn need_value(it: &mut impl Iterator<Item = String>, flag: &str) -> Result<String, String> {
    it.next().ok_or_else(|| format!("{flag} needs a value"))
}

fn print_usage() {
    print!("{USAGE}");
}

fn eprint_usage() {
    eprint!("{USAGE}");
}

const USAGE: &str = "\
sanctum - authorized-scope reconnaissance companion for Zume Editor

USAGE:
    Network recon (tier T1):
      sanctum --scope <SCOPE> --i-am-authorized [--json <PATH>] [--ports <SPEC>]
              [--no-banner] [--audit <PATH>] [--timeout-ms <N>] [--max-hosts <N>]
              [--max-ports <N>]
    Offline file analysis (tier T0, no network):
      sanctum --file <PATH> [--json <PATH>] [--audit <PATH>]
    Web diagnostics (tier T2, non-destructive):
      sanctum --web <URL> --i-am-authorized [--crawl] [--active] [--max-pages <N>]
              [--json <PATH>] [--audit <PATH>] [--timeout-ms <N>]

AUTHORIZED USE ONLY. Active work (--scope, --web) is refused without
--i-am-authorized. Only run it against systems you own or are explicitly
permitted to test. --file is passive: it reads a local file and sends nothing.
--web is non-destructive: it never exploits, extracts data or bypasses anything.

OPTIONS:
    --scope <SCOPE>      An IP, an IPv4 CIDR (a.b.c.d/bits), a hostname, or a URL.
    --file <PATH>        Analyze a local file offline: type, hashes (CRC32 / MD5 /
                         SHA-1 / SHA-256), entropy and printable strings.
    --web <URL>          Audit one http(s) URL non-destructively: security headers,
                         cookie flags, software disclosure and transport posture.
    --crawl              With --web: follow same-origin links and audit each page
                         (bounded, rate-limited; non-destructive).
    --active             With --web: non-destructive active detection - probe
                         query parameters for reflected XSS (benign marker) and
                         SQL injection (error- and bounded time-based; existence
                         only, no data read). Rate-limited and capped.
    --max-pages <N>      Crawl page cap (default 20).
    --i-am-authorized    Confirm you are authorized to test the scope (required).
    --json <PATH>        Write the result JSON here (Zume passes {out}); else stdout.
    --ports <SPEC>       Ports: \"22,80,443,8000-8010\" (default: a common set).
    --audit <PATH>       Audit-log file (default: $SANCTUM_AUDIT or ./sanctum-audit.log).
    --timeout-ms <N>     Per-connection timeout in ms (default: 800).
    --max-hosts <N>      Refuse a scope larger than this many hosts (default: 1024).
    --max-ports <N>      Cap the port list (default: 1024).
    --no-banner          Do not read service banners (just report open ports).
    -h, --help           Show this help.

OUTPUT:
    Result format v1 JSON: { schema, tool, version, started, finished, scope,
    findings[ {kind,severity,target,title,detail,evidence_path,address} ],
    warnings[] }. The {out} file is the source of truth, so a non-zero exit with
    a written result is still read.

EXIT CODES:
    0 ok   2 usage/scope error   3 refused (not authorized)
";

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ipv6_target_is_bracketed() {
        let v6: IpAddr = "2001:db8::1".parse().unwrap();
        assert_eq!(target_label(&v6, 443), "[2001:db8::1]:443");
        let v4: IpAddr = "192.0.2.1".parse().unwrap();
        assert_eq!(target_label(&v4, 22), "192.0.2.1:22");
    }
}
