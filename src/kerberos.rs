//! Kerberos message detection (tier T0, offline). Recognizes AS-REQ / AS-REP /
//! TGS-REQ / TGS-REP / AP-REQ / KRB-ERROR by their ASN.1 APPLICATION tag (raw,
//! or behind a TCP 4-byte length prefix) and extracts the GeneralString values
//! (principal name components and realm) with a lightweight DER walk, surfacing
//! who authenticated to which realm. Structure parsing only.

use crate::util::push_uniq;

const CAP: usize = 100;

fn type_name(tag: u8) -> Option<&'static str> {
    match tag {
        0x6a => Some("AS-REQ"),
        0x6b => Some("AS-REP"),
        0x6c => Some("TGS-REQ"),
        0x6d => Some("TGS-REP"),
        0x6e => Some("AP-REQ"),
        0x7e => Some("KRB-ERROR"),
        _ => None,
    }
}

/// DER length at `*pos` (definite form only); advances `*pos` past it.
fn read_len(b: &[u8], pos: &mut usize) -> Option<usize> {
    let first = *b.get(*pos)?;
    *pos += 1;
    if first < 0x80 {
        return Some(first as usize);
    }
    let n = (first & 0x7f) as usize;
    if n == 0 || n > 4 {
        return None;
    }
    let mut len = 0usize;
    for _ in 0..n {
        len = (len << 8) | *b.get(*pos)? as usize;
        *pos += 1;
    }
    Some(len)
}

/// Walk DER TLVs collecting GeneralString (tag 0x1b) values.
fn collect(b: &[u8], start: usize, end: usize, depth: u32, out: &mut Vec<String>) {
    let mut pos = start;
    while pos < end && out.len() < 16 && depth < 32 {
        let tag = b[pos];
        pos += 1;
        let len = match read_len(b, &mut pos) {
            Some(l) => l,
            None => return,
        };
        let cend = (pos + len).min(end);
        if pos > cend {
            return;
        }
        if tag & 0x20 != 0 {
            collect(b, pos, cend, depth + 1, out); // constructed
        } else if tag == 0x1b {
            let v = &b[pos..cend];
            if !v.is_empty() && v.len() <= 256 && v.iter().all(|&c| (0x20..0x7f).contains(&c)) {
                let s = String::from_utf8_lossy(v).to_string();
                if !out.contains(&s) {
                    out.push(s);
                }
            }
        }
        pos = cend;
    }
}

/// Scan a payload for a Kerberos message and report its type and principals.
pub fn scan(payload: &[u8], out: &mut Vec<String>) {
    // Raw (UDP/88), or behind a 4-byte TCP length prefix.
    let (msg, tag) = if !payload.is_empty() && type_name(payload[0]).is_some() {
        (payload, payload[0])
    } else if payload.len() > 4 && type_name(payload[4]).is_some() {
        (&payload[4..], payload[4])
    } else {
        return;
    };
    let name = match type_name(tag) {
        Some(n) => n,
        None => return,
    };
    let mut strings = Vec::new();
    let mut pos = 1usize;
    if read_len(msg, &mut pos).is_some() {
        collect(msg, pos, msg.len(), 0, &mut strings);
    }
    let detail = if strings.is_empty() {
        format!("Kerberos {name}")
    } else {
        format!("Kerberos {name}: {}", strings.join(", "))
    };
    push_uniq(out, detail, CAP);
}

#[cfg(test)]
mod tests {
    use super::*;

    fn gstr(s: &str) -> Vec<u8> {
        let mut v = vec![0x1b, s.len() as u8];
        v.extend_from_slice(s.as_bytes());
        v
    }

    fn as_req() -> Vec<u8> {
        // SEQUENCE { GeneralString "alice", GeneralString "EXAMPLE.COM" }
        let mut seq_body = gstr("alice");
        seq_body.extend_from_slice(&gstr("EXAMPLE.COM"));
        let mut seq = vec![0x30, seq_body.len() as u8];
        seq.extend_from_slice(&seq_body);
        // [APPLICATION 10] AS-REQ
        let mut app = vec![0x6a, seq.len() as u8];
        app.extend_from_slice(&seq);
        app
    }

    #[test]
    fn extracts_as_req_principals() {
        let mut out = Vec::new();
        scan(&as_req(), &mut out);
        assert_eq!(out, vec!["Kerberos AS-REQ: alice, EXAMPLE.COM".to_string()]);
    }

    #[test]
    fn handles_tcp_length_prefix() {
        let msg = as_req();
        let mut framed = (msg.len() as u32).to_be_bytes().to_vec();
        framed.extend_from_slice(&msg);
        let mut out = Vec::new();
        scan(&framed, &mut out);
        assert!(out.iter().any(|s| s.starts_with("Kerberos AS-REQ:")));
    }

    #[test]
    fn ignores_non_kerberos() {
        let mut out = Vec::new();
        scan(b"GET / HTTP/1.1\r\n", &mut out);
        assert!(out.is_empty());
    }
}
