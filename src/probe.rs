//! Active recon (tier T1): TCP connect probes only. No raw sockets, no SYN
//! scanning, no exploitation. Deliberately conservative - sequential connects
//! with a per-connection timeout - so a run is not an aggressive scan.

use std::net::{IpAddr, SocketAddr, TcpStream};
use std::time::Duration;

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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_ports_and_ranges() {
        assert_eq!(parse_ports("22, 80,443", 1024).unwrap(), vec![22, 80, 443]);
        assert_eq!(parse_ports("8000-8003", 1024).unwrap(), vec![8000, 8001, 8002, 8003]);
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
}
