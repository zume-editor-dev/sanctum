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

mod audit;
mod probe;
mod result;
mod scope;
mod timefmt;

use std::net::IpAddr;
use std::time::Duration;

use result::{Finding, Report};

const DEFAULT_TIMEOUT_MS: u64 = 800;
const DEFAULT_MAX_HOSTS: usize = 1024;
const DEFAULT_MAX_PORTS: usize = 1024;

struct Args {
    scope: Option<String>,
    json_out: Option<String>,
    ports: Option<String>,
    authorized: bool,
    audit: Option<String>,
    timeout_ms: u64,
    max_hosts: usize,
    max_ports: usize,
    help: bool,
}

impl Default for Args {
    fn default() -> Self {
        Args {
            scope: None,
            json_out: None,
            ports: None,
            authorized: false,
            audit: None,
            timeout_ms: DEFAULT_TIMEOUT_MS,
            max_hosts: DEFAULT_MAX_HOSTS,
            max_ports: DEFAULT_MAX_PORTS,
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
    let scope_str = match &args.scope {
        Some(s) => s.clone(),
        None => {
            eprintln!("sanctum: --scope is required");
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
            report
                .findings
                .push(Finding::new("service", "low", target_label(ip, port), title));
        }
    }
    if parsed.hosts.len() > 1 {
        report
            .warnings
            .push(format!("scanned {} host(s), {live} responded", parsed.hosts.len()));
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

/// "ip:port", bracketing an IPv6 literal so the target is unambiguous.
fn target_label(ip: &IpAddr, port: u16) -> String {
    match ip {
        IpAddr::V4(v4) => format!("{v4}:{port}"),
        IpAddr::V6(v6) => format!("[{v6}]:{port}"),
    }
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
    sanctum --scope <SCOPE> --i-am-authorized [--json <PATH>] [--ports <SPEC>]
            [--audit <PATH>] [--timeout-ms <N>] [--max-hosts <N>] [--max-ports <N>]

AUTHORIZED USE ONLY. Active probing is refused without --i-am-authorized. Only
run this against systems you own or are explicitly permitted to test.

OPTIONS:
    --scope <SCOPE>      An IP, an IPv4 CIDR (a.b.c.d/bits), a hostname, or a URL.
    --i-am-authorized    Confirm you are authorized to test the scope (required).
    --json <PATH>        Write the result JSON here (Zume passes {out}); else stdout.
    --ports <SPEC>       Ports: \"22,80,443,8000-8010\" (default: a common set).
    --audit <PATH>       Audit-log file (default: $SANCTUM_AUDIT or ./sanctum-audit.log).
    --timeout-ms <N>     Per-connection timeout in ms (default: 800).
    --max-hosts <N>      Refuse a scope larger than this many hosts (default: 1024).
    --max-ports <N>      Cap the port list (default: 1024).
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
