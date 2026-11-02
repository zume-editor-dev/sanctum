//! Tier T0 (offline): a capture reader for classic `.pcap` and `.pcapng`. It
//! summarizes the endpoints and destination services seen - Ethernet (incl.
//! stacked VLAN / QinQ) / MPLS / raw / Linux-SLL link layers, IPv4 / IPv6
//! (extension headers followed), TCP / UDP, and IP-in-IP / GRE tunnels - and
//! recovers plaintext credentials from payloads (see creds.rs). Purely passive:
//! it parses a file you already hold and touches no network.

use std::collections::HashMap;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

pub struct PcapSummary {
    pub link_type: u32,
    pub packets: u64,
    /// (ip, packets it appeared in as source or destination), most-seen first.
    pub hosts: Vec<(IpAddr, u64)>,
    /// (proto, destination port, packet count), most-seen first.
    pub services: Vec<(&'static str, u16, u64)>,
    /// Plaintext credentials recovered from packet payloads (deduplicated).
    pub creds: Vec<String>,
    /// TLS server names (SNI) seen in ClientHello messages (deduplicated).
    pub sni: Vec<String>,
    /// NTLM / Kerberos authentication material seen (deduplicated).
    pub auth: Vec<String>,
    pub truncated: bool,
}

/// Accumulators threaded through packet decoding for payload-derived artifacts.
#[derive(Default)]
struct Extract {
    creds: Vec<String>,
    sni: Vec<String>,
    auth: Vec<String>,
}

fn push_uniq(out: &mut Vec<String>, s: String, cap: usize) {
    if out.len() < cap && !s.is_empty() && !out.contains(&s) {
        out.push(s);
    }
}

fn u16r(b: &[u8], le: bool) -> u16 {
    if le {
        u16::from_le_bytes([b[0], b[1]])
    } else {
        u16::from_be_bytes([b[0], b[1]])
    }
}
fn u32r(b: &[u8], le: bool) -> u32 {
    if le {
        u32::from_le_bytes([b[0], b[1], b[2], b[3]])
    } else {
        u32::from_be_bytes([b[0], b[1], b[2], b[3]])
    }
}

/// Sort the accumulated counters and build the summary.
fn summarize(
    hosts: HashMap<IpAddr, u64>,
    services: HashMap<(&'static str, u16), u64>,
    ex: Extract,
    packets: u64,
    link_type: u32,
    truncated: bool,
) -> PcapSummary {
    let mut host_vec: Vec<(IpAddr, u64)> = hosts.into_iter().collect();
    host_vec.sort_by(|a, b| b.1.cmp(&a.1).then(a.0.cmp(&b.0)));
    let mut svc_vec: Vec<(&'static str, u16, u64)> = services
        .into_iter()
        .map(|((p, port), n)| (p, port, n))
        .collect();
    svc_vec.sort_by(|a, b| b.2.cmp(&a.2).then(a.1.cmp(&b.1)));
    PcapSummary {
        link_type,
        packets,
        hosts: host_vec,
        services: svc_vec,
        creds: ex.creds,
        sni: ex.sni,
        auth: ex.auth,
        truncated,
    }
}

fn be16(b: &[u8]) -> u16 {
    u16::from_be_bytes([b[0], b[1]])
}

/// Peel the link layer (Ethernet incl. stacked VLAN / QinQ, MPLS, raw IP,
/// Linux-SLL) and return the IP packet slice.
fn l2_to_ip(pkt: &[u8], link_type: u32) -> Option<&[u8]> {
    match link_type {
        1 => {
            if pkt.len() < 14 {
                return None;
            }
            let mut off = 14usize;
            let mut ethertype = be16(&pkt[12..14]);
            // Unwrap stacked VLAN tags: 802.1Q (0x8100) and 802.1ad / QinQ (0x88a8).
            let mut guard = 0;
            while (ethertype == 0x8100 || ethertype == 0x88a8) && pkt.len() >= off + 4 && guard < 4
            {
                ethertype = be16(&pkt[off + 2..off + 4]);
                off += 4;
                guard += 1;
            }
            match ethertype {
                0x0800 | 0x86DD => Some(&pkt[off..]),
                0x8847 | 0x8848 => mpls_to_ip(&pkt[off..]), // MPLS unicast / multicast
                _ => None,
            }
        }
        101 => Some(pkt),                             // DLT_RAW
        113 => (pkt.len() >= 16).then(|| &pkt[16..]), // DLT_LINUX_SLL
        _ => None,
    }
}

/// Skip an MPLS label stack to the inner IP packet (bottom-of-stack bit).
fn mpls_to_ip(data: &[u8]) -> Option<&[u8]> {
    let mut off = 0usize;
    let mut guard = 0;
    loop {
        if data.len() < off + 4 || guard > 16 {
            return None;
        }
        let bottom = data[off + 2] & 0x01;
        off += 4;
        guard += 1;
        if bottom == 1 {
            break;
        }
    }
    let rest = data.get(off..)?;
    match rest.first().map(|b| b >> 4) {
        Some(4) | Some(6) => Some(rest),
        _ => None,
    }
}

/// Decode an IP packet (following IPv6 extension headers and IP-in-IP / GRE
/// tunnels up to a small depth), counting hosts and services and scanning L4
/// payloads for plaintext credentials.
fn decode_ip(
    ip: &[u8],
    depth: u32,
    hosts: &mut HashMap<IpAddr, u64>,
    services: &mut HashMap<(&'static str, u16), u64>,
    ex: &mut Extract,
) {
    if depth > 3 || ip.is_empty() {
        return;
    }
    let version = ip[0] >> 4;
    let (src, dst, proto, l4): (IpAddr, IpAddr, u8, &[u8]) = if version == 4 {
        if ip.len() < 20 {
            return;
        }
        let ihl = ((ip[0] & 0x0f) as usize) * 4;
        if ihl < 20 || ip.len() < ihl {
            return;
        }
        (
            IpAddr::V4(Ipv4Addr::new(ip[12], ip[13], ip[14], ip[15])),
            IpAddr::V4(Ipv4Addr::new(ip[16], ip[17], ip[18], ip[19])),
            ip[9],
            &ip[ihl..],
        )
    } else if version == 6 {
        if ip.len() < 40 {
            return;
        }
        let mut s = [0u8; 16];
        let mut d = [0u8; 16];
        s.copy_from_slice(&ip[8..24]);
        d.copy_from_slice(&ip[24..40]);
        // Follow IPv6 extension headers to the real upper-layer protocol.
        let mut nh = ip[6];
        let mut off = 40usize;
        let mut guard = 0;
        loop {
            let ext_len = match nh {
                0 | 43 | 60 => {
                    // Hop-by-Hop, Routing, Destination Options: 8 * (len+1) bytes.
                    if ip.len() < off + 2 {
                        return;
                    }
                    (ip[off + 1] as usize + 1) * 8
                }
                51 => {
                    // Authentication Header: 4 * (len+2) bytes.
                    if ip.len() < off + 2 {
                        return;
                    }
                    (ip[off + 1] as usize + 2) * 4
                }
                44 => {
                    // Fragment header (fixed 8 bytes); only offset 0 has the L4.
                    if ip.len() < off + 8 {
                        return;
                    }
                    if (be16(&ip[off + 2..off + 4]) >> 3) != 0 {
                        return; // a later fragment: no usable L4 here
                    }
                    8
                }
                _ => break,
            };
            nh = ip[off];
            off += ext_len;
            guard += 1;
            if off > ip.len() || guard > 16 {
                return;
            }
        }
        (
            IpAddr::V6(Ipv6Addr::from(s)),
            IpAddr::V6(Ipv6Addr::from(d)),
            nh,
            &ip[off..],
        )
    } else {
        return;
    };

    *hosts.entry(src).or_insert(0) += 1;
    *hosts.entry(dst).or_insert(0) += 1;

    match proto {
        6 => {
            // TCP
            if l4.len() < 20 {
                return;
            }
            let dport = be16(&l4[2..4]);
            *services.entry(("tcp", dport)).or_insert(0) += 1;
            let doff = ((l4[12] >> 4) as usize) * 4;
            if doff >= 20 && l4.len() >= doff {
                let payload = &l4[doff..];
                crate::creds::scan(payload, dport, &mut ex.creds);
                crate::ntlm::scan(payload, &mut ex.auth);
                crate::kerberos::scan(payload, &mut ex.auth);
                if let Some(host) = crate::tls::client_hello_sni(payload) {
                    push_uniq(&mut ex.sni, host, 200);
                }
            }
        }
        17 => {
            // UDP
            if l4.len() < 8 {
                return;
            }
            let dport = be16(&l4[2..4]);
            *services.entry(("udp", dport)).or_insert(0) += 1;
            crate::creds::scan(&l4[8..], dport, &mut ex.creds);
            crate::kerberos::scan(&l4[8..], &mut ex.auth); // Kerberos is often UDP/88
                                                           // QUIC Initial packets (usually UDP/443) carry a cleartext-recoverable SNI.
            if let Some(host) = crate::quic::initial_sni(&l4[8..]) {
                push_uniq(&mut ex.sni, host, 200);
            }
        }
        4 | 41 => decode_ip(l4, depth + 1, hosts, services, ex), // IP-in-IP / 6in4
        47 => {
            // GRE: skip the (variable) header, then the inner IP by protocol.
            if l4.len() < 4 {
                return;
            }
            let flags = l4[0];
            let gre_proto = be16(&l4[2..4]);
            let mut hlen = 4usize;
            if flags & 0x80 != 0 {
                hlen += 4; // checksum present
            }
            if flags & 0x20 != 0 {
                hlen += 4; // key present
            }
            if flags & 0x10 != 0 {
                hlen += 4; // sequence present
            }
            if l4.len() >= hlen && matches!(gre_proto, 0x0800 | 0x86DD) {
                decode_ip(&l4[hlen..], depth + 1, hosts, services, ex);
            }
        }
        _ => {}
    }
}

/// Decode one captured packet from its link layer down.
fn decode_packet(
    pkt: &[u8],
    link_type: u32,
    hosts: &mut HashMap<IpAddr, u64>,
    services: &mut HashMap<(&'static str, u16), u64>,
    ex: &mut Extract,
) {
    if let Some(ip) = l2_to_ip(pkt, link_type) {
        decode_ip(ip, 0, hosts, services, ex);
    }
}

/// Parse a classic pcap, summarizing up to `max_packets` packets.
pub fn parse_pcap(bytes: &[u8], max_packets: u64) -> Result<PcapSummary, String> {
    if bytes.len() < 24 {
        return Err("too small to be a pcap".to_string());
    }
    let le = match bytes[0..4] {
        [0xa1, 0xb2, 0xc3, 0xd4] | [0xa1, 0xb2, 0x3c, 0x4d] => false,
        [0xd4, 0xc3, 0xb2, 0xa1] | [0x4d, 0x3c, 0xb2, 0xa1] => true,
        _ => return Err("not a classic pcap (bad magic; pcapng is not supported yet)".to_string()),
    };
    let link_type = u32r(&bytes[20..24], le);

    let mut hosts: HashMap<IpAddr, u64> = HashMap::new();
    let mut services: HashMap<(&'static str, u16), u64> = HashMap::new();
    let mut ex = Extract::default();
    let mut packets = 0u64;
    let mut truncated = false;

    let mut pos = 24usize;
    while pos + 16 <= bytes.len() {
        let incl_len = u32r(&bytes[pos + 8..pos + 12], le) as usize;
        pos += 16;
        if incl_len == 0 || pos + incl_len > bytes.len() {
            if pos + incl_len > bytes.len() {
                truncated = true; // a record runs past the (capped) buffer
            }
            break;
        }
        decode_packet(
            &bytes[pos..pos + incl_len],
            link_type,
            &mut hosts,
            &mut services,
            &mut ex,
        );
        pos += incl_len;
        packets += 1;
        if packets >= max_packets {
            truncated = true;
            break;
        }
    }

    Ok(summarize(
        hosts, services, ex, packets, link_type, truncated,
    ))
}

/// Parse a pcapng capture (SHB / IDB / EPB / SPB), summarizing up to
/// `max_packets` packets. The byte order is set by each Section Header Block;
/// other block types are skipped.
pub fn parse_pcapng(bytes: &[u8], max_packets: u64) -> Result<PcapSummary, String> {
    if bytes.len() < 12 || bytes[0..4] != [0x0a, 0x0d, 0x0d, 0x0a] {
        return Err("not a pcapng capture (no Section Header Block)".to_string());
    }
    let mut le = match bytes[8..12] {
        [0x1a, 0x2b, 0x3c, 0x4d] => false,
        [0x4d, 0x3c, 0x2b, 0x1a] => true,
        _ => return Err("bad pcapng byte-order magic".to_string()),
    };

    let mut interfaces: Vec<u16> = Vec::new(); // link type per interface index
    let mut hosts: HashMap<IpAddr, u64> = HashMap::new();
    let mut services: HashMap<(&'static str, u16), u64> = HashMap::new();
    let mut ex = Extract::default();
    let mut packets = 0u64;
    let mut truncated = false;

    let mut pos = 0usize;
    while pos + 12 <= bytes.len() {
        let is_shb = bytes[pos..pos + 4] == [0x0a, 0x0d, 0x0d, 0x0a]; // endian-invariant
        if is_shb {
            le = match bytes[pos + 8..pos + 12] {
                [0x1a, 0x2b, 0x3c, 0x4d] => false,
                [0x4d, 0x3c, 0x2b, 0x1a] => true,
                _ => return Err("bad pcapng byte-order magic".to_string()),
            };
        }
        let btype = u32r(&bytes[pos..pos + 4], le);
        let total = u32r(&bytes[pos + 4..pos + 8], le) as usize;
        if total < 12 || pos + total > bytes.len() {
            if pos + total > bytes.len() {
                truncated = true;
            }
            break;
        }
        let body = &bytes[pos + 8..pos + total - 4];
        if !is_shb {
            match btype {
                0x01 => {
                    // Interface Description Block: link type is a u16 at body[0..2].
                    interfaces.push(if body.len() >= 2 { u16r(body, le) } else { 0 });
                }
                // Enhanced Packet Block.
                0x06 if body.len() >= 20 => {
                    let iface = u32r(&body[0..4], le) as usize;
                    let caplen = u32r(&body[12..16], le) as usize;
                    if 20 + caplen <= body.len() {
                        let lt = *interfaces.get(iface).unwrap_or(&0) as u32;
                        decode_packet(
                            &body[20..20 + caplen],
                            lt,
                            &mut hosts,
                            &mut services,
                            &mut ex,
                        );
                        packets += 1;
                    }
                }
                // Simple Packet Block: captured data is body[4..].
                0x03 if body.len() >= 4 => {
                    let lt = *interfaces.first().unwrap_or(&0) as u32;
                    decode_packet(&body[4..], lt, &mut hosts, &mut services, &mut ex);
                    packets += 1;
                }
                _ => {}
            }
        }
        pos += total;
        if packets >= max_packets {
            truncated = true;
            break;
        }
    }

    let link_type = *interfaces.first().unwrap_or(&0) as u32;
    Ok(summarize(
        hosts, services, ex, packets, link_type, truncated,
    ))
}

/// A human-readable name for a link type (pcap "network" field).
pub fn link_type_name(lt: u32) -> &'static str {
    match lt {
        1 => "Ethernet",
        101 => "raw IP",
        113 => "Linux SLL",
        _ => "other",
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // A classic LE pcap: global header + one Ethernet/IPv4/TCP packet
    // (10.0.0.1:12345 -> 10.0.0.2:80).
    fn synthetic_pcap() -> Vec<u8> {
        let mut v = Vec::new();
        v.extend_from_slice(&[0xd4, 0xc3, 0xb2, 0xa1]); // LE magic
        v.extend_from_slice(&2u16.to_le_bytes()); // ver major
        v.extend_from_slice(&4u16.to_le_bytes()); // ver minor
        v.extend_from_slice(&0u32.to_le_bytes()); // thiszone
        v.extend_from_slice(&0u32.to_le_bytes()); // sigfigs
        v.extend_from_slice(&65535u32.to_le_bytes()); // snaplen
        v.extend_from_slice(&1u32.to_le_bytes()); // network = EN10MB

        let mut pkt = Vec::new();
        pkt.extend_from_slice(&[0u8; 6]); // dst mac
        pkt.extend_from_slice(&[0u8; 6]); // src mac
        pkt.extend_from_slice(&[0x08, 0x00]); // ethertype IPv4
                                              // IPv4 header (20 bytes)
        pkt.push(0x45); // version 4, IHL 5
        pkt.push(0x00); // tos
        pkt.extend_from_slice(&40u16.to_be_bytes()); // total length
        pkt.extend_from_slice(&0u16.to_be_bytes()); // id
        pkt.extend_from_slice(&0u16.to_be_bytes()); // flags/frag
        pkt.push(64); // ttl
        pkt.push(6); // proto TCP
        pkt.extend_from_slice(&0u16.to_be_bytes()); // checksum
        pkt.extend_from_slice(&[10, 0, 0, 1]); // src
        pkt.extend_from_slice(&[10, 0, 0, 2]); // dst
                                               // TCP header (first 4 bytes: sport, dport)
        pkt.extend_from_slice(&12345u16.to_be_bytes());
        pkt.extend_from_slice(&80u16.to_be_bytes());
        pkt.extend_from_slice(&[0u8; 16]); // rest of a minimal TCP header

        v.extend_from_slice(&0u32.to_le_bytes()); // ts_sec
        v.extend_from_slice(&0u32.to_le_bytes()); // ts_usec
        v.extend_from_slice(&(pkt.len() as u32).to_le_bytes()); // incl_len
        v.extend_from_slice(&(pkt.len() as u32).to_le_bytes()); // orig_len
        v.extend_from_slice(&pkt);
        v
    }

    #[test]
    fn parses_a_classic_pcap() {
        let s = parse_pcap(&synthetic_pcap(), 1000).unwrap();
        assert_eq!(s.link_type, 1);
        assert_eq!(s.packets, 1);
        assert!(s.hosts.iter().any(|(ip, _)| ip.to_string() == "10.0.0.1"));
        assert!(s.hosts.iter().any(|(ip, _)| ip.to_string() == "10.0.0.2"));
        assert_eq!(s.services, vec![("tcp", 80u16, 1u64)]);
        assert!(!s.truncated);
    }

    #[test]
    fn rejects_non_pcap() {
        assert!(parse_pcap(b"not a pcap file at all!!", 1000).is_err());
        // parse_pcap does not accept pcapng; parse_pcapng does.
        assert!(parse_pcap(&[0x0a, 0x0d, 0x0d, 0x0a, 0, 0, 0, 0], 1000).is_err());
    }

    /// The Ethernet/IPv4/TCP packet used by the pcapng test
    /// (10.0.0.1:12345 -> 10.0.0.2:80), 54 bytes.
    fn eth_ipv4_tcp() -> Vec<u8> {
        let mut pkt = Vec::new();
        pkt.extend_from_slice(&[0u8; 12]); // dst+src mac
        pkt.extend_from_slice(&[0x08, 0x00]); // ethertype IPv4
        pkt.push(0x45);
        pkt.push(0x00);
        pkt.extend_from_slice(&40u16.to_be_bytes());
        pkt.extend_from_slice(&[0u8; 4]); // id, flags/frag
        pkt.push(64);
        pkt.push(6); // TCP
        pkt.extend_from_slice(&0u16.to_be_bytes()); // checksum
        pkt.extend_from_slice(&[10, 0, 0, 1]);
        pkt.extend_from_slice(&[10, 0, 0, 2]);
        pkt.extend_from_slice(&12345u16.to_be_bytes());
        pkt.extend_from_slice(&80u16.to_be_bytes());
        pkt.extend_from_slice(&[0u8; 16]);
        pkt
    }

    fn synthetic_pcapng() -> Vec<u8> {
        let mut v = Vec::new();
        // Section Header Block (little-endian).
        let shb_total = 28u32;
        v.extend_from_slice(&0x0a0d_0d0au32.to_le_bytes());
        v.extend_from_slice(&shb_total.to_le_bytes());
        v.extend_from_slice(&[0x4d, 0x3c, 0x2b, 0x1a]); // byte-order magic (LE)
        v.extend_from_slice(&1u16.to_le_bytes()); // major
        v.extend_from_slice(&0u16.to_le_bytes()); // minor
        v.extend_from_slice(&(-1i64).to_le_bytes()); // section length
        v.extend_from_slice(&shb_total.to_le_bytes());
        // Interface Description Block (link type EN10MB).
        let idb_total = 20u32;
        v.extend_from_slice(&1u32.to_le_bytes());
        v.extend_from_slice(&idb_total.to_le_bytes());
        v.extend_from_slice(&1u16.to_le_bytes()); // linktype
        v.extend_from_slice(&0u16.to_le_bytes()); // reserved
        v.extend_from_slice(&65535u32.to_le_bytes()); // snaplen
        v.extend_from_slice(&idb_total.to_le_bytes());
        // Enhanced Packet Block.
        let pkt = eth_ipv4_tcp();
        let mut data = pkt.clone();
        while data.len() % 4 != 0 {
            data.push(0);
        }
        let epb_total = (8 + 20 + data.len() + 4) as u32;
        v.extend_from_slice(&6u32.to_le_bytes());
        v.extend_from_slice(&epb_total.to_le_bytes());
        v.extend_from_slice(&0u32.to_le_bytes()); // interface id
        v.extend_from_slice(&0u32.to_le_bytes()); // ts high
        v.extend_from_slice(&0u32.to_le_bytes()); // ts low
        v.extend_from_slice(&(pkt.len() as u32).to_le_bytes()); // captured len
        v.extend_from_slice(&(pkt.len() as u32).to_le_bytes()); // original len
        v.extend_from_slice(&data);
        v.extend_from_slice(&epb_total.to_le_bytes());
        v
    }

    #[test]
    fn parses_a_pcapng() {
        let s = parse_pcapng(&synthetic_pcapng(), 1000).unwrap();
        assert_eq!(s.link_type, 1);
        assert_eq!(s.packets, 1);
        assert!(s.hosts.iter().any(|(ip, _)| ip.to_string() == "10.0.0.1"));
        assert!(s.hosts.iter().any(|(ip, _)| ip.to_string() == "10.0.0.2"));
        assert_eq!(s.services, vec![("tcp", 80u16, 1u64)]);
        assert!(!s.truncated);
    }

    #[test]
    fn pcapng_rejects_non_pcapng() {
        assert!(parse_pcapng(b"\xd4\xc3\xb2\xa1 not pcapng", 1000).is_err());
    }

    /// Wrap a single link-layer frame in a one-packet little-endian classic pcap.
    fn classic_pcap(frame: &[u8], link_type: u32) -> Vec<u8> {
        let mut v = Vec::new();
        v.extend_from_slice(&[0xd4, 0xc3, 0xb2, 0xa1]);
        v.extend_from_slice(&2u16.to_le_bytes());
        v.extend_from_slice(&4u16.to_le_bytes());
        v.extend_from_slice(&0u32.to_le_bytes());
        v.extend_from_slice(&0u32.to_le_bytes());
        v.extend_from_slice(&65535u32.to_le_bytes());
        v.extend_from_slice(&link_type.to_le_bytes());
        v.extend_from_slice(&0u32.to_le_bytes());
        v.extend_from_slice(&0u32.to_le_bytes());
        v.extend_from_slice(&(frame.len() as u32).to_le_bytes());
        v.extend_from_slice(&(frame.len() as u32).to_le_bytes());
        v.extend_from_slice(frame);
        v
    }

    fn tcp_header(dport: u16) -> Vec<u8> {
        let mut t = Vec::new();
        t.extend_from_slice(&40000u16.to_be_bytes()); // sport
        t.extend_from_slice(&dport.to_be_bytes());
        t.extend_from_slice(&[0u8; 8]); // seq, ack
        t.push(0x50); // data offset 5
        t.push(0x18); // flags
        t.extend_from_slice(&[0u8; 6]); // window, checksum, urgent
        t
    }

    #[test]
    fn follows_ipv6_extension_headers() {
        // Ethernet + IPv6 (next = Hop-by-Hop) + Hop-by-Hop (next = TCP) + TCP:443.
        let tcp = tcp_header(443);
        let mut frame = vec![0u8; 12];
        frame.extend_from_slice(&[0x86, 0xDD]); // IPv6
        frame.extend_from_slice(&[0x60, 0, 0, 0]); // version/tc/flow
        frame.extend_from_slice(&((8 + tcp.len()) as u16).to_be_bytes()); // payload length
        frame.push(0); // next header = Hop-by-Hop
        frame.push(64); // hop limit
        frame.extend_from_slice(&[1u8; 16]); // src
        frame.extend_from_slice(&[2u8; 16]); // dst
        frame.extend_from_slice(&[6, 0, 0, 0, 0, 0, 0, 0]); // HbH: next = TCP, len 0
        frame.extend_from_slice(&tcp);
        let s = parse_pcap(&classic_pcap(&frame, 1), 100).unwrap();
        assert!(
            s.services.contains(&("tcp", 443, 1)),
            "the IPv6 extension header must be followed to reach TCP/443"
        );
    }

    #[test]
    fn unwraps_qinq_vlan() {
        // Ethernet + 802.1ad (QinQ) + 802.1Q + IPv4 + TCP:80.
        let tcp = tcp_header(80);
        let mut ip = vec![0x45, 0u8];
        ip.extend_from_slice(&((20 + tcp.len()) as u16).to_be_bytes());
        ip.extend_from_slice(&[0, 0, 0, 0, 64, 6, 0, 0]);
        ip.extend_from_slice(&[10, 0, 0, 1, 10, 0, 0, 2]);
        ip.extend_from_slice(&tcp);
        let mut frame = vec![0u8; 12];
        frame.extend_from_slice(&[0x88, 0xa8]); // outer 802.1ad
        frame.extend_from_slice(&[0x00, 0x0a]);
        frame.extend_from_slice(&[0x81, 0x00]); // inner 802.1Q
        frame.extend_from_slice(&[0x00, 0x14]);
        frame.extend_from_slice(&[0x08, 0x00]); // IPv4
        frame.extend_from_slice(&ip);
        let s = parse_pcap(&classic_pcap(&frame, 1), 100).unwrap();
        assert!(
            s.services.contains(&("tcp", 80, 1)),
            "stacked VLAN tags must be unwrapped"
        );
    }
}
