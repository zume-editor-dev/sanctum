//! Scope parsing. A scope is one of: a single IP, an IPv4 CIDR, a hostname, or a
//! URL (its host is taken). Every active probe target comes from here, so the
//! scope *is* the blast-radius boundary, capped by `max_hosts`.

use std::net::{IpAddr, Ipv4Addr, ToSocketAddrs};

pub struct Scope {
    /// The scope string as the user entered it (echoed into the result).
    pub echo: String,
    /// The resolved target hosts.
    pub hosts: Vec<IpAddr>,
}

/// Parse a scope string into its hosts, refusing a range larger than `max_hosts`.
pub fn parse_scope(input: &str, max_hosts: usize) -> Result<Scope, String> {
    let echo = input.trim().to_string();
    if echo.is_empty() {
        return Err("empty scope".to_string());
    }

    // A URL: take the authority's host.
    if let Some(pos) = echo.find("://") {
        let rest = &echo[pos + 3..];
        let authority = rest.split('/').next().unwrap_or(rest);
        let host = authority.rsplit('@').next().unwrap_or(authority);
        return host_to_scope(strip_port(host), echo);
    }

    // An IPv4 CIDR: a.b.c.d/bits.
    if let Some((base, bits)) = echo.split_once('/') {
        if let Ok(ip) = base.trim().parse::<Ipv4Addr>() {
            let bits: u32 = bits
                .trim()
                .parse()
                .map_err(|_| format!("invalid CIDR prefix length: {bits}"))?;
            if bits > 32 {
                return Err("CIDR prefix length must be 0..=32".to_string());
            }
            let count: u64 = 1u64 << (32 - bits);
            if count as usize > max_hosts {
                return Err(format!(
                    "CIDR /{bits} covers {count} hosts, over the --max-hosts cap of {max_hosts}; narrow the scope"
                ));
            }
            let network = u32::from(ip) & mask(bits);
            let mut hosts = Vec::with_capacity(count as usize);
            for i in 0..count as u32 {
                hosts.push(IpAddr::V4(Ipv4Addr::from(network + i)));
            }
            return Ok(Scope { echo, hosts });
        }
        // Not an IPv4 CIDR: fall through (treated as a host below).
    }

    host_to_scope(strip_port(&echo), echo)
}

fn host_to_scope(host: &str, echo: String) -> Result<Scope, String> {
    if host.is_empty() {
        return Err("no host in scope".to_string());
    }
    if let Ok(ip) = host.parse::<IpAddr>() {
        return Ok(Scope { echo, hosts: vec![ip] });
    }
    // A hostname: resolve it (port 0 is a placeholder for resolution only).
    let iter = (host, 0u16)
        .to_socket_addrs()
        .map_err(|e| format!("cannot resolve '{host}': {e}"))?;
    let mut hosts: Vec<IpAddr> = Vec::new();
    for sa in iter {
        let ip = sa.ip();
        if !hosts.contains(&ip) {
            hosts.push(ip);
        }
    }
    if hosts.is_empty() {
        return Err(format!("no addresses for '{host}'"));
    }
    Ok(Scope { echo, hosts })
}

fn mask(bits: u32) -> u32 {
    if bits == 0 {
        0
    } else {
        u32::MAX << (32 - bits)
    }
}

/// Drop a trailing `:port` from an authority, handling `[ipv6]:port` and leaving
/// a bare IPv6 literal (which has several colons) untouched.
fn strip_port(s: &str) -> &str {
    let s = s.trim();
    if let Some(rest) = s.strip_prefix('[') {
        // [ipv6] or [ipv6]:port
        return rest.split(']').next().unwrap_or(rest);
    }
    if s.matches(':').count() > 1 {
        return s; // a bare IPv6 literal, no port
    }
    if let Some((host, port)) = s.rsplit_once(':') {
        if !host.is_empty() && !port.is_empty() && port.bytes().all(|b| b.is_ascii_digit()) {
            return host;
        }
    }
    s
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn single_ip() {
        let s = parse_scope("192.0.2.5", 1024).unwrap();
        assert_eq!(s.hosts, vec!["192.0.2.5".parse::<IpAddr>().unwrap()]);
    }

    #[test]
    fn ipv4_cidr_expands() {
        let s = parse_scope("192.0.2.0/30", 1024).unwrap();
        assert_eq!(s.hosts.len(), 4);
        assert_eq!(s.hosts[0], "192.0.2.0".parse::<IpAddr>().unwrap());
        assert_eq!(s.hosts[3], "192.0.2.3".parse::<IpAddr>().unwrap());
    }

    #[test]
    fn cidr_over_cap_is_refused() {
        let err = parse_scope("10.0.0.0/8", 1024).unwrap_err();
        assert!(err.contains("over the --max-hosts cap"));
    }

    #[test]
    fn url_host_with_port_and_path() {
        let s = parse_scope("https://192.0.2.9:8443/admin", 1024).unwrap();
        assert_eq!(s.hosts, vec!["192.0.2.9".parse::<IpAddr>().unwrap()]);
    }

    #[test]
    fn ipv4_with_port() {
        let s = parse_scope("192.0.2.9:22", 1024).unwrap();
        assert_eq!(s.hosts, vec!["192.0.2.9".parse::<IpAddr>().unwrap()]);
    }

    #[test]
    fn bare_ipv6_literal() {
        let s = parse_scope("::1", 1024).unwrap();
        assert_eq!(s.hosts, vec!["::1".parse::<IpAddr>().unwrap()]);
    }

    #[test]
    fn bracketed_ipv6_with_port() {
        let s = parse_scope("[2001:db8::1]:443", 1024).unwrap();
        assert_eq!(s.hosts, vec!["2001:db8::1".parse::<IpAddr>().unwrap()]);
    }

    #[test]
    fn empty_is_an_error() {
        assert!(parse_scope("   ", 1024).is_err());
    }
}
