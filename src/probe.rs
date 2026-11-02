//! Active recon (tier T1): TCP connect probes only. No raw sockets, no SYN
//! scanning, no exploitation. Deliberately conservative - sequential connects
//! with a per-connection timeout - so a run is not an aggressive scan.
//!
//! Optional banner grabbing (v0.2) reads the greeting a service volunteers on
//! connect (SSH / SMTP / FTP / POP3 / IMAP ...), or, for HTTP ports, the Server
//! header from a single HEAD request. It is a light, passive-leaning read of
//! what the service already advertises - still over a TCP connect, so it stays
//! within the authorized scope - and never sends protocol-specific exploits.

use std::io::{Read, Write};
use std::net::{IpAddr, SocketAddr, TcpStream};
use std::time::Duration;

const BANNER_CAP: usize = 200;

/// A small, common default port set (used when --ports is not given).
pub fn default_ports() -> Vec<u16> {
    vec![
        21, 22, 23, 25, 53, 80, 110, 143, 443, 445, 587, 993, 995, 1433, 3306, 3389, 5432, 6379,
        8080, 8443,
    ]
}

/// Parse "22,80,443,8000-8010" into a deduplicated, capped port list.
pub fn parse_ports(spec: &str, max_ports: usize) -> Result<Vec<u16>, String> {
    let mut ports: Vec<u16> = Vec::new();
    let push = |p: u16, ports: &mut Vec<u16>| {
        if !ports.contains(&p) {
            ports.push(p);
        }
    };
    for part in spec.split(',') {
        let part = part.trim();
        if part.is_empty() {
            continue;
        }
        if let Some((a, b)) = part.split_once('-') {
            let a: u16 = a.trim().parse().map_err(|_| format!("invalid port: {a}"))?;
            let b: u16 = b.trim().parse().map_err(|_| format!("invalid port: {b}"))?;
            if a == 0 || b == 0 {
                return Err("port 0 is not allowed".to_string());
            }
            let (lo, hi) = if a <= b { (a, b) } else { (b, a) };
            for p in lo..=hi {
                push(p, &mut ports);
                if ports.len() > max_ports {
                    return Err(format!("too many ports (cap {max_ports})"));
                }
            }
        } else {
            let p: u16 = part.parse().map_err(|_| format!("invalid port: {part}"))?;
            if p == 0 {
                return Err("port 0 is not allowed".to_string());
            }
            push(p, &mut ports);
        }
        if ports.len() > max_ports {
            return Err(format!("too many ports (cap {max_ports})"));
        }
    }
    if ports.is_empty() {
        return Err("no ports to scan".to_string());
    }
    Ok(ports)
}

/// Connect-scan one host: returns (is_up, open_ports). A host is "up" if any
/// probed port accepted a TCP connection.
pub fn scan_host(ip: IpAddr, ports: &[u16], timeout: Duration) -> (bool, Vec<u16>) {
    let mut open = Vec::new();
    for &port in ports {
        let addr = SocketAddr::new(ip, port);
        if TcpStream::connect_timeout(&addr, timeout).is_ok() {
            open.push(port);
        }
    }
    (!open.is_empty(), open)
}

/// A best-effort service name for a well-known port ("" when unknown).
pub fn service_name(port: u16) -> &'static str {
    match port {
        21 => "ftp",
        22 => "ssh",
        23 => "telnet",
        25 => "smtp",
        53 => "dns",
        80 => "http",
        110 => "pop3",
        143 => "imap",
        443 => "https",
        445 => "smb",
        587 => "submission",
        993 => "imaps",
        995 => "pop3s",
        1433 => "mssql",
        3306 => "mysql",
        3389 => "rdp",
        5432 => "postgres",
        6379 => "redis",
        8080 => "http-alt",
        8443 => "https-alt",
        _ => "",
    }
}

/// Ports where a plaintext read is not meaningful (TLS wraps the protocol);
/// v0.2 does not do a TLS handshake, so these are skipped for banner grabbing.
fn is_tls_port(port: u16) -> bool {
    matches!(
        port,
        443 | 465 | 563 | 636 | 853 | 989 | 990 | 993 | 995 | 8443
    )
}

/// Ports spoken to with a minimal HTTP HEAD request to read the Server header.
fn is_http_port(port: u16) -> bool {
    matches!(port, 80 | 591 | 8000 | 8008 | 8080 | 8888)
}

/// The first printable line of a byte buffer, trimmed and capped - a service's
/// greeting, sanitized so no control bytes reach the result JSON.
pub fn banner_line(bytes: &[u8]) -> Option<String> {
    let mut s = String::new();
    for &b in bytes {
        if b == b'\n' || b == b'\r' {
            break;
        }
        if (0x20..0x7f).contains(&b) {
            s.push(b as char);
        }
        if s.len() >= BANNER_CAP {
            break;
        }
    }
    let t = s.trim();
    if t.is_empty() {
        None
    } else {
        Some(t.to_string())
    }
}

/// From an HTTP response, prefer the `Server:` header, else the status line.
pub fn http_banner(bytes: &[u8]) -> Option<String> {
    let text = String::from_utf8_lossy(bytes);
    for line in text.split("\r\n") {
        let l = line.trim();
        if l.len() >= 7 && l[..7].eq_ignore_ascii_case("server:") {
            return banner_line(l.as_bytes());
        }
    }
    banner_line(bytes)
}

/// Read a service's banner over a fresh TCP connect: the greeting it sends on
/// connect, or (for an HTTP port) the Server header from one HEAD request.
/// Returns None for a TLS port, no data, or an unreadable line.
pub fn grab_banner(ip: IpAddr, port: u16, timeout: Duration) -> Option<String> {
    if is_tls_port(port) {
        return None;
    }
    let addr = SocketAddr::new(ip, port);
    let mut stream = TcpStream::connect_timeout(&addr, timeout).ok()?;
    stream.set_read_timeout(Some(timeout)).ok()?;
    stream.set_write_timeout(Some(timeout)).ok()?;
    let http = is_http_port(port);
    if http {
        let req = format!("HEAD / HTTP/1.0\r\nHost: {ip}\r\nUser-Agent: sanctum\r\n\r\n");
        stream.write_all(req.as_bytes()).ok()?;
    }
    let mut buf = [0u8; 1024];
    let n = stream.read(&mut buf).ok()?;
    if n == 0 {
        return None;
    }
    if http {
        http_banner(&buf[..n])
    } else {
        banner_line(&buf[..n])
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_ports_and_ranges() {
        assert_eq!(parse_ports("22, 80,443", 1024).unwrap(), vec![22, 80, 443]);
        assert_eq!(
            parse_ports("8000-8003", 1024).unwrap(),
            vec![8000, 8001, 8002, 8003]
        );
        assert_eq!(parse_ports("443-443", 1024).unwrap(), vec![443]);
        // Reversed ranges are normalized; duplicates are dropped.
        assert_eq!(parse_ports("82-80,80", 1024).unwrap(), vec![80, 81, 82]);
    }

    #[test]
    fn rejects_bad_ports() {
        assert!(parse_ports("0", 1024).is_err());
        assert!(parse_ports("http", 1024).is_err());
        assert!(parse_ports("", 1024).is_err());
        assert!(parse_ports("1-2000", 100).is_err());
    }

    #[test]
    fn names_common_ports() {
        assert_eq!(service_name(22), "ssh");
        assert_eq!(service_name(65000), "");
    }

    #[test]
    fn banner_line_takes_first_printable_line() {
        assert_eq!(
            banner_line(b"220 mail ESMTP Postfix\r\nmore"),
            Some("220 mail ESMTP Postfix".to_string())
        );
        assert_eq!(banner_line(b"\x00\x01\x02"), None);
        assert_eq!(banner_line(b"   \r\n"), None);
        // Control bytes are dropped, the line is capped.
        let long = vec![b'a'; 500];
        assert_eq!(banner_line(&long).unwrap().len(), 200);
    }

    #[test]
    fn http_banner_prefers_server_header() {
        let resp = b"HTTP/1.1 200 OK\r\nDate: x\r\nServer: nginx/1.24.0\r\n\r\n";
        assert_eq!(http_banner(resp), Some("Server: nginx/1.24.0".to_string()));
        let resp2 = b"HTTP/1.0 404 Not Found\r\n\r\n";
        assert_eq!(
            http_banner(resp2),
            Some("HTTP/1.0 404 Not Found".to_string())
        );
    }

    #[test]
    fn grabs_a_greeting_banner_over_loopback() {
        use std::io::Write as _;
        use std::net::TcpListener;
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let port = listener.local_addr().unwrap().port();
        let handle = std::thread::spawn(move || {
            if let Ok((mut s, _)) = listener.accept() {
                let _ = s.write_all(b"SSH-2.0-OpenSSH_9.6\r\ntail");
            }
        });
        let b = grab_banner(
            "127.0.0.1".parse().unwrap(),
            port,
            Duration::from_millis(800),
        );
        let _ = handle.join();
        assert_eq!(b.as_deref(), Some("SSH-2.0-OpenSSH_9.6"));
    }
}
