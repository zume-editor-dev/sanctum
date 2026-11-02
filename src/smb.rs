//! SMB1 / SMB2 session context (tier T0, offline). Flags SMB1 (legacy and
//! insecure), reports the negotiated SMB2 dialect and that a SESSION_SETUP
//! (where NTLM / Kerberos authentication happens - the token itself is
//! recovered by ntlm.rs / kerberos.rs) was seen, and lists TREE_CONNECT share
//! paths. Structure parsing only; nothing is decrypted.

use crate::util::{find, push_uniq};

const CAP: usize = 100;
const SMB2: &[u8] = b"\xFESMB";
const SMB1: &[u8] = b"\xFFSMB";

fn le16(b: &[u8], o: usize) -> Option<u16> {
    Some(u16::from_le_bytes([*b.get(o)?, *b.get(o + 1)?]))
}

fn dialect_name(d: u16) -> Option<&'static str> {
    Some(match d {
        0x0202 => "2.0.2",
        0x0210 => "2.1",
        0x0222 => "2.2.2",
        0x0224 => "2.2.4",
        0x0300 => "3.0",
        0x0302 => "3.0.2",
        0x0311 => "3.1.1",
        _ => return None,
    })
}

/// Scan a TCP payload for SMB1 / SMB2 session facts.
pub fn scan(payload: &[u8], notes: &mut Vec<String>) {
    if find(payload, SMB1).is_some() {
        push_uniq(
            notes,
            "SMB1 (legacy) protocol in use - deprecated and insecure".to_string(),
            CAP,
        );
    }
    // Walk SMB2 messages, following the compound NextCommand chain.
    let mut base = match find(payload, SMB2) {
        Some(i) => i,
        None => return,
    };
    for _ in 0..16 {
        let hdr = match payload.get(base..) {
            Some(h) if h.len() >= 64 => h,
            _ => break,
        };
        let command = match le16(hdr, 12) {
            Some(c) => c,
            None => break,
        };
        let flags = u32::from_le_bytes([hdr[16], hdr[17], hdr[18], hdr[19]]);
        let is_response = flags & 1 != 0;
        let next = u32::from_le_bytes([hdr[20], hdr[21], hdr[22], hdr[23]]) as usize;
        let body = &hdr[64..];
        match command {
            0x0000 if is_response => {
                // NEGOTIATE response: StructureSize(2), SecurityMode(2), DialectRevision(2).
                if let Some(name) = le16(body, 4).and_then(dialect_name) {
                    push_uniq(notes, format!("SMB2 negotiate: dialect {name}"), CAP);
                }
            }
            0x0001 => {
                push_uniq(
                    notes,
                    "SMB2 SESSION_SETUP (NTLM / Kerberos authentication)".to_string(),
                    CAP,
                );
            }
            0x0003 if !is_response => {
                // TREE_CONNECT request: StructureSize(2), Flags(2), PathOffset(2),
                // PathLength(2); PathOffset is from the SMB2 header start.
                if let (Some(poff), Some(plen)) = (le16(body, 4), le16(body, 6)) {
                    let (poff, plen) = (poff as usize, plen as usize);
                    if (2..=1024).contains(&plen) {
                        if let Some(raw) = hdr.get(poff..poff + plen) {
                            let units: Vec<u16> = raw
                                .chunks_exact(2)
                                .map(|c| u16::from_le_bytes([c[0], c[1]]))
                                .collect();
                            let path = String::from_utf16_lossy(&units);
                            push_uniq(notes, format!("SMB2 tree connect: {path}"), CAP);
                        }
                    }
                }
            }
            _ => {}
        }
        match payload.len().checked_sub(base) {
            Some(room) if next != 0 && next < room => base += next,
            _ => break,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // A 64-byte SMB2 header with the given command / flags / next, then a body.
    fn smb2(command: u16, response: bool, next: u32, body: &[u8]) -> Vec<u8> {
        let mut h = vec![0u8; 64];
        h[0..4].copy_from_slice(SMB2);
        h[4..6].copy_from_slice(&64u16.to_le_bytes());
        h[12..14].copy_from_slice(&command.to_le_bytes());
        h[16..20].copy_from_slice(&(if response { 1u32 } else { 0 }).to_le_bytes());
        h[20..24].copy_from_slice(&next.to_le_bytes());
        h.extend_from_slice(body);
        h
    }

    #[test]
    fn reports_session_setup() {
        let mut body = vec![25u8, 0]; // StructureSize
        body.extend_from_slice(&[0u8; 22]);
        let pkt = smb2(0x0001, false, 0, &body);
        let mut notes = Vec::new();
        scan(&pkt, &mut notes);
        assert!(notes.iter().any(|n| n.contains("SESSION_SETUP")));
    }

    #[test]
    fn reports_negotiated_dialect() {
        let mut body = vec![65u8, 0, 0, 0]; // StructureSize, SecurityMode
        body.extend_from_slice(&0x0311u16.to_le_bytes()); // DialectRevision 3.1.1
        body.extend_from_slice(&[0u8; 10]);
        let pkt = smb2(0x0000, true, 0, &body);
        let mut notes = Vec::new();
        scan(&pkt, &mut notes);
        assert!(notes.iter().any(|n| n == "SMB2 negotiate: dialect 3.1.1"));
    }

    #[test]
    fn extracts_tree_connect_path() {
        let unc = "\\\\fileserver\\share";
        let path: Vec<u8> = unc.encode_utf16().flat_map(|u| u.to_le_bytes()).collect();
        // Body: StructureSize(2), Flags(2), PathOffset(2), PathLength(2), then path.
        let path_off = 64 + 8; // header + the 8-byte fixed body
        let mut body = vec![9u8, 0, 0, 0];
        body.extend_from_slice(&(path_off as u16).to_le_bytes());
        body.extend_from_slice(&(path.len() as u16).to_le_bytes());
        body.extend_from_slice(&path);
        let pkt = smb2(0x0003, false, 0, &body);
        let mut notes = Vec::new();
        scan(&pkt, &mut notes);
        assert!(notes
            .iter()
            .any(|n| *n == format!("SMB2 tree connect: {unc}")));
    }

    #[test]
    fn flags_smb1() {
        let mut pkt = vec![0u8; 4];
        pkt[0..4].copy_from_slice(SMB1);
        let mut notes = Vec::new();
        scan(&pkt, &mut notes);
        assert!(notes.iter().any(|n| n.contains("SMB1")));
    }

    #[test]
    fn ignores_non_smb() {
        let mut notes = Vec::new();
        scan(b"GET / HTTP/1.1\r\n\r\n", &mut notes);
        assert!(notes.is_empty());
    }
}
