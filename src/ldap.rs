//! LDAP bind credential extraction (tier T0, offline). Parses an LDAP
//! BindRequest and recovers a *simple* bind's DN and cleartext password - LDAP
//! simple bind sends the password in the clear - and notes a SASL bind's
//! mechanism (the NTLM / Kerberos token a SASL bind carries is recovered by
//! ntlm.rs / kerberos.rs). BER structure parsing only; nothing is decrypted.

use crate::util::push_uniq;

const CAP: usize = 100;

/// Minimal BER TLV at `pos`: returns (tag, header_len, content_len).
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

fn octet(b: &[u8], start: usize, len: usize) -> String {
    String::from_utf8_lossy(b.get(start..start + len).unwrap_or(&[])).to_string()
}

/// Scan a TCP payload for an LDAP BindRequest at its start.
pub fn scan(payload: &[u8], creds: &mut Vec<String>, notes: &mut Vec<String>) {
    // LDAPMessage ::= SEQUENCE { messageID INTEGER, protocolOp CHOICE { ... } };
    // BindRequest is [APPLICATION 0] -> tag 0x60.
    let (t0, h0, l0) = match tlv(payload, 0) {
        Some(x) => x,
        None => return,
    };
    if t0 != 0x30 {
        return; // not a SEQUENCE
    }
    let end = (h0 + l0).min(payload.len());
    let mut p = h0;
    let (tid, hid, lid) = match tlv(payload, p) {
        Some(x) => x,
        None => return,
    };
    if tid != 0x02 {
        return; // messageID must be INTEGER
    }
    p += hid + lid;
    let (top, hop, lop) = match tlv(payload, p) {
        Some(x) => x,
        None => return,
    };
    if top != 0x60 {
        return; // protocolOp is not a BindRequest
    }
    let body_start = p + hop;
    let body_end = (body_start + lop).min(end).min(payload.len());
    if let Some(body) = payload.get(body_start..body_end) {
        parse_bind(body, creds, notes);
    }
}

fn parse_bind(b: &[u8], creds: &mut Vec<String>, notes: &mut Vec<String>) {
    let mut p = 0usize;
    let (tv, hv, lv) = match tlv(b, p) {
        Some(x) => x,
        None => return,
    };
    if tv != 0x02 {
        return; // version INTEGER
    }
    p += hv + lv;
    let (tn, hn, ln) = match tlv(b, p) {
        Some(x) => x,
        None => return,
    };
    if tn != 0x04 {
        return; // name LDAPDN (OCTET STRING)
    }
    let dn = octet(b, p + hn, ln);
    p += hn + ln;
    let (ta, ha, la) = match tlv(b, p) {
        Some(x) => x,
        None => return,
    };
    match ta {
        // simple [0] OCTET STRING (context, primitive): the cleartext password.
        0x80 => {
            let pw = octet(b, p + ha, la);
            if pw.is_empty() {
                push_uniq(
                    notes,
                    format!("LDAP anonymous / unauthenticated bind (dn=\"{dn}\")"),
                    CAP,
                );
            } else {
                let who = if dn.is_empty() {
                    "(empty DN)".to_string()
                } else {
                    dn
                };
                push_uniq(creds, format!("LDAP simple bind: {who} : {pw}"), CAP);
            }
        }
        // sasl [3] SEQUENCE { mechanism OCTET STRING, credentials OPTIONAL }.
        0xA3 => {
            let sasl = b.get(p + ha..p + ha + la).unwrap_or(&[]);
            if let Some((tm, hm, lm)) = tlv(sasl, 0) {
                if tm == 0x04 {
                    let mech = octet(sasl, hm, lm);
                    push_uniq(notes, format!("LDAP SASL bind: mechanism={mech}"), CAP);
                }
            }
        }
        _ => {}
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // Build a TLV with a short-form length (test payloads are small).
    fn tlv_b(tag: u8, content: &[u8]) -> Vec<u8> {
        let mut v = vec![tag, content.len() as u8];
        v.extend_from_slice(content);
        v
    }

    fn bind_message(version: u8, dn: &[u8], auth: &[u8]) -> Vec<u8> {
        let mut body = tlv_b(0x02, &[version]);
        body.extend(tlv_b(0x04, dn));
        body.extend_from_slice(auth);
        let bindreq = tlv_b(0x60, &body);
        let mut msg_body = tlv_b(0x02, &[0x01]); // messageID = 1
        msg_body.extend(bindreq);
        tlv_b(0x30, &msg_body)
    }

    #[test]
    fn recovers_simple_bind_password() {
        let msg = bind_message(3, b"cn=admin,dc=corp", &tlv_b(0x80, b"S3cret!"));
        let (mut creds, mut notes) = (Vec::new(), Vec::new());
        scan(&msg, &mut creds, &mut notes);
        assert_eq!(creds, vec!["LDAP simple bind: cn=admin,dc=corp : S3cret!"]);
        assert!(notes.is_empty());
    }

    #[test]
    fn flags_anonymous_bind() {
        let msg = bind_message(3, b"", &tlv_b(0x80, b""));
        let (mut creds, mut notes) = (Vec::new(), Vec::new());
        scan(&msg, &mut creds, &mut notes);
        assert!(creds.is_empty());
        assert!(notes.iter().any(|n| n.contains("anonymous")));
    }

    #[test]
    fn notes_sasl_mechanism() {
        let sasl = tlv_b(0xA3, &tlv_b(0x04, b"GSS-SPNEGO"));
        let msg = bind_message(3, b"", &sasl);
        let (mut creds, mut notes) = (Vec::new(), Vec::new());
        scan(&msg, &mut creds, &mut notes);
        assert!(creds.is_empty());
        assert!(notes
            .iter()
            .any(|n| n == "LDAP SASL bind: mechanism=GSS-SPNEGO"));
    }

    #[test]
    fn ignores_non_bind() {
        // A SearchRequest ([APPLICATION 3] = 0x63) must not be read as a bind.
        let mut msg_body = tlv_b(0x02, &[0x02]);
        msg_body.extend(tlv_b(0x63, b"whatever"));
        let msg = tlv_b(0x30, &msg_body);
        let (mut creds, mut notes) = (Vec::new(), Vec::new());
        scan(&msg, &mut creds, &mut notes);
        assert!(creds.is_empty() && notes.is_empty());
    }
}
