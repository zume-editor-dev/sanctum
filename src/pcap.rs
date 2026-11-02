//! Tier T0 (offline): a minimal classic-pcap reader. Given a `.pcap` capture
//! (not pcapng), it summarizes the endpoints and destination services seen -
//! Ethernet / raw / Linux-SLL link layers, IPv4 / IPv6, TCP / UDP. Purely
//! passive: it parses a file you already hold and touches no network. pcapng is
//! not parsed yet (a later increment).

use std::collections::HashMap;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

pub struct PcapSummary {
    pub link_type: u32,
    pub packets: u64,
    /// (ip, packets it appeared in as source or destination), most-seen first.
    pub hosts: Vec<(IpAddr, u64)>,
    /// (proto, destination port, packet count), most-seen first.
    pub services: Vec<(&'static str, u16, u64)>,
    pub truncated: bool,
}

fn u32r(b: &[u8], le: bool) -> u32 {
    if le {
        u32::from_le_bytes([b[0], b[1], b[2], b[3]])
    } else {
        u32::from_be_bytes([b[0], b[1], b[2], b[3]])
    }
}

/// Decode one packet's L3/L4 and bump the counters. `link_type` is the pcap
/// global header's network field.
fn decode_packet(
    pkt: &[u8],
    link_type: u32,
    hosts: &mut HashMap<IpAddr, u64>,
    services: &mut HashMap<(&'static str, u16), u64>,
) {
    // Advance to the IP header per link layer.
    let ip = match link_type {
        1 => {
            // Ethernet: 14-byte header, optional 802.1Q VLAN tag.
            if pkt.len() < 14 {
                return;
            }
            let mut off = 12;
            let mut ethertype = u16::from_be_bytes([pkt[off], pkt[off + 1]]);
            off = 14;
            if ethertype == 0x8100 && pkt.len() >= 18 {
                ethertype = u16::from_be_bytes([pkt[16], pkt[17]]);
                off = 18;
            }
            match ethertype {
                0x0800 | 0x86DD => &pkt[off..],
                _ => return,
            }
        }
        101 => pkt, // DLT_RAW: IP directly
        113 => {
            // DLT_LINUX_SLL: 16-byte header
            if pkt.len() < 16 {
                return;
            }
            &pkt[16..]
        }
        _ => return,
    };
    if ip.is_empty() {
        return;
    }
    let version = ip[0] >> 4;
    let (src, dst, proto, l4) = if version == 4 {
        if ip.len() < 20 {
            return;
        }
        let ihl = ((ip[0] & 0x0f) as usize) * 4;
        if ihl < 20 || ip.len() < ihl {
            return;
        }
        let src = IpAddr::V4(Ipv4Addr::new(ip[12], ip[13], ip[14], ip[15]));
        let dst = IpAddr::V4(Ipv4Addr::new(ip[16], ip[17], ip[18], ip[19]));
        (src, dst, ip[9], &ip[ihl..])
    } else if version == 6 {
        if ip.len() < 40 {
            return;
        }
        let mut s = [0u8; 16];
        let mut d = [0u8; 16];
        s.copy_from_slice(&ip[8..24]);
        d.copy_from_slice(&ip[24..40]);
        (
            IpAddr::V6(Ipv6Addr::from(s)),
            IpAddr::V6(Ipv6Addr::from(d)),
            ip[6], // next header (extension headers not followed in v0.4)
            &ip[40..],
        )
    } else {
        return;
    };

    *hosts.entry(src).or_insert(0) += 1;
    *hosts.entry(dst).or_insert(0) += 1;

    let proto_name = match proto {
        6 => "tcp",
        17 => "udp",
        _ => return, // only TCP/UDP services are summarized
    };
    if l4.len() >= 4 {
        let dport = u16::from_be_bytes([l4[2], l4[3]]);
        *services.entry((proto_name, dport)).or_insert(0) += 1;
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
        );
        pos += incl_len;
        packets += 1;
        if packets >= max_packets {
            truncated = true;
            break;
        }
    }

    let mut host_vec: Vec<(IpAddr, u64)> = hosts.into_iter().collect();
    host_vec.sort_by(|a, b| b.1.cmp(&a.1).then(a.0.cmp(&b.0)));
    let mut svc_vec: Vec<(&'static str, u16, u64)> = services
        .into_iter()
        .map(|((p, port), n)| (p, port, n))
        .collect();
    svc_vec.sort_by(|a, b| b.2.cmp(&a.2).then(a.1.cmp(&b.1)));

    Ok(PcapSummary {
        link_type,
        packets,
        hosts: host_vec,
        services: svc_vec,
        truncated,
    })
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
        assert!(parse_pcap(&[0x0a, 0x0d, 0x0d, 0x0a, 0, 0, 0, 0], 1000).is_err());
        // pcapng
    }
}
