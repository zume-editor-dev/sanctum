//! SNMP community-string extraction (tier T0, offline). SNMP v1 / v2c carry the
//! community string - effectively the device password - in the clear. Parses
//! the BER message { version, community, pdu } and reports the community;
//! SNMPv3 (USM) has no cleartext community and is skipped. Structure only.

use crate::util::push_uniq;

const CAP: usize = 100;

fn tlv(b: &[u8], pos: usize) -> Option<(u8, usize, usize)> {
    let tag = *b.get(pos)?;
    let l0 = *b.get(pos + 1)?;
    if l0 < 0x80 {
        Some((tag, 2, l0 as usize))
    } else {
        let n = (l0 & 0x7f) as usize;
        if n == 0 || n > 4 {
            return None;
        }
        let mut len = 0usize;
        for i in 0..n {
            len = (len << 8) | *b.get(pos + 2 + i)? as usize;
        }
        Some((tag, 2 + n, len))
    }
}

/// Scan a payload for an SNMP v1 / v2c message and report its community string.
pub fn scan(payload: &[u8], creds: &mut Vec<String>) {
    // SEQUENCE { version INTEGER, community OCTET STRING, pdu ... }.
    let (t0, h0, _l0) = match tlv(payload, 0) {
        Some(x) => x,
        None => return,
    };
    if t0 != 0x30 {
        return;
    }
    let mut p = h0;
    let (tv, hv, lv) = match tlv(payload, p) {
        Some(x) => x,
        None => return,
    };
    if tv != 0x02 || lv != 1 {
        return; // version is a one-byte INTEGER
    }
    let ver = payload[p + hv];
    p += hv + lv;
    let vname = match ver {
        0 => "v1",
        1 => "v2c",
        _ => return, // v3 (3) carries no cleartext community
    };
    let (tc, hc, lc) = match tlv(payload, p) {
        Some(x) => x,
        None => return,
    };
    if tc != 0x04 || lc == 0 || lc > 128 {
        return;
    }
    let raw = match payload.get(p + hc..p + hc + lc) {
        Some(r) => r,
        None => return,
    };
    // A community string is printable; reject binary to avoid false positives.
    if !raw.iter().all(|&c| (0x20..0x7f).contains(&c)) {
        return;
    }
    let community = String::from_utf8_lossy(raw);
    push_uniq(creds, format!("SNMP {vname} community: {community}"), CAP);
}

#[cfg(test)]
mod tests {
    use super::*;

    fn snmp(version: u8, community: &[u8]) -> Vec<u8> {
        let mut body = vec![0x02, 0x01, version]; // version INTEGER
        body.push(0x04);
        body.push(community.len() as u8);
        body.extend_from_slice(community);
        body.extend_from_slice(&[0xA0, 0x00]); // empty GetRequest PDU
        let mut msg = vec![0x30, body.len() as u8];
        msg.extend_from_slice(&body);
        msg
    }

    #[test]
    fn recovers_v2c_community() {
        let mut creds = Vec::new();
        scan(&snmp(1, b"public"), &mut creds);
        assert_eq!(creds, vec!["SNMP v2c community: public"]);
    }

    #[test]
    fn recovers_v1_private() {
        let mut creds = Vec::new();
        scan(&snmp(0, b"private"), &mut creds);
        assert_eq!(creds, vec!["SNMP v1 community: private"]);
    }

    #[test]
    fn skips_v3() {
        let mut creds = Vec::new();
        scan(&snmp(3, b"ignored"), &mut creds);
        assert!(creds.is_empty());
    }

    #[test]
    fn ignores_non_snmp() {
        let mut creds = Vec::new();
        scan(b"\x16\x03\x01not asn1", &mut creds);
        assert!(creds.is_empty());
    }
}
