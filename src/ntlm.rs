//! NTLMSSP (NTLM) message extraction (tier T0, offline). Finds NTLM messages in
//! payloads - raw (e.g. inside SMB) or base64 in HTTP `Authorization` /
//! `WWW-Authenticate` headers (incl. SPNEGO-wrapped) - and reports the domain /
//! user / workstation and the server challenge, surfacing the authentication
//! handshake and the presence of a crackable NetNTLM response. Structure
//! parsing only; nothing is decrypted or cracked.

use crate::util::{b64, find, find_ci, hex, push_uniq, take_token};

const SIG: &[u8] = b"NTLMSSP\x00";
const CAP: usize = 100;

fn le16(b: &[u8], o: usize) -> Option<usize> {
    Some(u16::from_le_bytes([*b.get(o)?, *b.get(o + 1)?]) as usize)
}
fn le32(b: &[u8], o: usize) -> Option<u32> {
    Some(u32::from_le_bytes([
        *b.get(o)?,
        *b.get(o + 1)?,
        *b.get(o + 2)?,
        *b.get(o + 3)?,
    ]))
}

/// The payload bytes of a `len/maxlen/offset` security-buffer field at `pos`.
fn field(msg: &[u8], pos: usize) -> Option<&[u8]> {
    let len = le16(msg, pos)?;
    let off = le32(msg, pos + 4)? as usize;
    if len == 0 {
        return Some(&[]);
    }
    msg.get(off..off + len)
}

fn decode_str(bytes: &[u8], unicode: bool) -> String {
    if unicode {
        let units: Vec<u16> = bytes
            .chunks_exact(2)
            .map(|c| u16::from_le_bytes([c[0], c[1]]))
            .collect();
        String::from_utf16_lossy(&units)
    } else {
        String::from_utf8_lossy(bytes).to_string()
    }
}

fn parse(msg: &[u8], out: &mut Vec<String>) {
    if msg.len() < 12 || &msg[0..8] != SIG {
        return;
    }
    match le32(msg, 8) {
        Some(2) => {
            // CHALLENGE: flags @20, server challenge @24..32, target name field @12.
            let unicode = le32(msg, 20).unwrap_or(0) & 1 != 0;
            let target = field(msg, 12)
                .map(|b| decode_str(b, unicode))
                .unwrap_or_default();
            let challenge = msg.get(24..32).map(hex).unwrap_or_default();
            push_uniq(
                out,
                format!("NTLM challenge: target={target} server-challenge={challenge}"),
                CAP,
            );
        }
        Some(3) => {
            // AUTHENTICATE: flags @60; Domain @28, User @36, Workstation @44;
            // NtChallengeResponse @20 (>24 bytes => NTLMv2, ==24 => NTLMv1).
            let unicode = le32(msg, 60).unwrap_or(0) & 1 != 0;
            let domain = field(msg, 28)
                .map(|b| decode_str(b, unicode))
                .unwrap_or_default();
            let user = field(msg, 36)
                .map(|b| decode_str(b, unicode))
                .unwrap_or_default();
            let host = field(msg, 44)
                .map(|b| decode_str(b, unicode))
                .unwrap_or_default();
            let nt = field(msg, 20).map(|b| b.len()).unwrap_or(0);
            let kind = if nt > 24 {
                "NetNTLMv2"
            } else if nt == 24 {
                "NetNTLMv1"
            } else {
                "no"
            };
            push_uniq(
                out,
                format!(
                    "NTLM authenticate: {domain}\\{user} (host {host}) - {kind} response present"
                ),
                CAP,
            );
        }
        _ => {}
    }
}

/// Scan a payload for an NTLMSSP message (raw or base64 in an HTTP header).
pub fn scan(payload: &[u8], out: &mut Vec<String>) {
    if let Some(i) = find(payload, SIG) {
        parse(&payload[i..], out);
        return;
    }
    for mark in [&b"ntlm "[..], &b"negotiate "[..]] {
        if let Some(i) = find_ci(payload, mark) {
            let tok = take_token(payload, i + mark.len(), b" \r\n,");
            if let Some(dec) = b64(tok) {
                if let Some(j) = find(&dec, SIG) {
                    parse(&dec[j..], out);
                    return;
                }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Build a minimal NTLM AUTHENTICATE (type 3) with UTF-16LE domain/user and
    /// a 32-byte NtChallengeResponse (NTLMv2-sized).
    fn type3() -> Vec<u8> {
        let domain: Vec<u8> = "CORP"
            .encode_utf16()
            .flat_map(|u| u.to_le_bytes())
            .collect();
        let user: Vec<u8> = "alice"
            .encode_utf16()
            .flat_map(|u| u.to_le_bytes())
            .collect();
        let host: Vec<u8> = "PC1".encode_utf16().flat_map(|u| u.to_le_bytes()).collect();
        let nt = vec![0xAAu8; 32];
        // Lay out fixed header (64 bytes) then the payloads.
        let mut m = vec![0u8; 64];
        m[0..8].copy_from_slice(SIG);
        m[8..12].copy_from_slice(&3u32.to_le_bytes());
        let mut off = 64u32;
        let put = |m: &mut Vec<u8>, pos: usize, data: &[u8], off: &mut u32| {
            let len = data.len() as u16;
            m[pos..pos + 2].copy_from_slice(&len.to_le_bytes());
            m[pos + 2..pos + 4].copy_from_slice(&len.to_le_bytes());
            m[pos + 4..pos + 8].copy_from_slice(&off.to_le_bytes());
            m.extend_from_slice(data);
            *off += data.len() as u32;
        };
        put(&mut m, 20, &nt, &mut off); // NtChallengeResponse
        put(&mut m, 28, &domain, &mut off);
        put(&mut m, 36, &user, &mut off);
        put(&mut m, 44, &host, &mut off);
        m[60..64].copy_from_slice(&1u32.to_le_bytes()); // NEGOTIATE_UNICODE
        m
    }

    #[test]
    fn parses_authenticate() {
        let mut out = Vec::new();
        scan(&type3(), &mut out);
        assert_eq!(
            out,
            vec![
                "NTLM authenticate: CORP\\alice (host PC1) - NetNTLMv2 response present"
                    .to_string()
            ]
        );
    }

    #[test]
    fn parses_challenge() {
        let mut m = vec![0u8; 48];
        m[0..8].copy_from_slice(SIG);
        m[8..12].copy_from_slice(&2u32.to_le_bytes());
        m[20..24].copy_from_slice(&1u32.to_le_bytes()); // unicode flag
        m[24..32].copy_from_slice(&[0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88]);
        let mut out = Vec::new();
        scan(&m, &mut out);
        assert!(out
            .iter()
            .any(|s| s.contains("server-challenge=1122334455667788")));
    }

    #[test]
    fn parses_http_base64_ntlm() {
        // "Authorization: NTLM <base64 of a type-3 message>"
        let b = base64_encode(&type3());
        let header = format!("Authorization: NTLM {b}\r\n");
        let mut out = Vec::new();
        scan(header.as_bytes(), &mut out);
        assert!(out.iter().any(|s| s.contains("CORP\\alice")));
    }

    // A tiny base64 encoder for the test (the tool only needs to decode).
    fn base64_encode(data: &[u8]) -> String {
        const T: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
        let mut s = String::new();
        for chunk in data.chunks(3) {
            let b = [
                chunk[0],
                *chunk.get(1).unwrap_or(&0),
                *chunk.get(2).unwrap_or(&0),
            ];
            let n = ((b[0] as u32) << 16) | ((b[1] as u32) << 8) | b[2] as u32;
            s.push(T[(n >> 18 & 63) as usize] as char);
            s.push(T[(n >> 12 & 63) as usize] as char);
            s.push(if chunk.len() > 1 {
                T[(n >> 6 & 63) as usize] as char
            } else {
                '='
            });
            s.push(if chunk.len() > 2 {
                T[(n & 63) as usize] as char
            } else {
                '='
            });
        }
        s
    }
}
