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
    let body_start = p + hop;
    let body_end = (body_start + lop).min(end).min(payload.len());
    let body = match payload.get(body_start..body_end) {
        Some(b) => b,
        None => return,
    };
    match top {
        0x60 => parse_bind(body, creds, notes), // BindRequest
        0x63 => parse_search(body, notes),      // SearchRequest
        0x77 => parse_extended(body, notes),    // ExtendedRequest
        _ => {}
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

/// ExtendedRequest: requestName [0] LDAPOID (context primitive, 0x80). The
/// StartTLS OID is 1.3.6.1.4.1.1466.20037.
fn parse_extended(b: &[u8], notes: &mut Vec<String>) {
    if let Some((0x80, h, l)) = tlv(b, 0) {
        let oid = octet(b, h, l);
        if oid == "1.3.6.1.4.1.1466.20037" {
            push_uniq(notes, "LDAP StartTLS requested".to_string(), CAP);
        } else {
            push_uniq(notes, format!("LDAP extended request: {oid}"), CAP);
        }
    }
}

/// SearchRequest ::= SEQUENCE { baseObject LDAPDN, scope, derefAliases,
/// sizeLimit, timeLimit, typesOnly, filter Filter, attributes }. Report the
/// base DN, a rendered filter and the requested attributes.
fn parse_search(b: &[u8], notes: &mut Vec<String>) {
    let (tb, hb, lb) = match tlv(b, 0) {
        Some(x) => x,
        None => return,
    };
    if tb != 0x04 {
        return; // baseObject LDAPDN
    }
    let base = octet(b, hb, lb);
    // Skip scope, derefAliases, sizeLimit, timeLimit, typesOnly (5 TLVs).
    let mut p = hb + lb;
    for _ in 0..5 {
        let (_, h, l) = match tlv(b, p) {
            Some(x) => x,
            None => return,
        };
        p += h + l;
    }
    // filter
    let (_, fh, fl) = match tlv(b, p) {
        Some(x) => x,
        None => return,
    };
    let filter = render_filter(b.get(p..p + fh + fl).unwrap_or(&[]), 0);
    p += fh + fl;
    // attributes: SEQUENCE OF OCTET STRING (optional).
    let attrs = tlv(b, p)
        .filter(|&(t, _, _)| t == 0x30)
        .and_then(|(_, ah, al)| b.get(p + ah..p + ah + al))
        .map(attr_list)
        .unwrap_or_default();
    let base_s = if base.is_empty() {
        "(root DSE)".to_string()
    } else {
        base
    };
    let mut note = format!("LDAP search: base=\"{base_s}\" filter={filter}");
    if !attrs.is_empty() {
        note.push_str(&format!(" attrs={attrs}"));
    }
    push_uniq(notes, note, CAP);
}

fn attr_list(b: &[u8]) -> String {
    let mut p = 0usize;
    let mut names: Vec<String> = Vec::new();
    while p < b.len() && names.len() < 12 {
        let (t, h, l) = match tlv(b, p) {
            Some(x) => x,
            None => break,
        };
        if t == 0x04 {
            names.push(octet(b, p + h, l));
        }
        p += h + l;
    }
    names.join(",")
}

/// Render an LDAP Filter as its string form, e.g. (&(objectClass=*)(cn=bob)).
fn render_filter(b: &[u8], depth: u32) -> String {
    if depth > 12 {
        return "(...)".to_string();
    }
    let (tag, h, l) = match tlv(b, 0) {
        Some(x) => x,
        None => return "(?)".to_string(),
    };
    let c = b.get(h..h + l).unwrap_or(&[]);
    match tag {
        0xA0 => format!("(&{})", render_set(c, depth)),
        0xA1 => format!("(|{})", render_set(c, depth)),
        0xA2 => format!("(!{})", render_filter(c, depth + 1)),
        0xA3 => render_ava(c, "="),
        0xA5 => render_ava(c, ">="),
        0xA6 => render_ava(c, "<="),
        0xA8 => render_ava(c, "~="),
        0xA4 => render_substrings(c),
        0x87 => format!("({}=*)", String::from_utf8_lossy(c)), // present (primitive)
        _ => "(?)".to_string(),
    }
}

fn render_set(b: &[u8], depth: u32) -> String {
    let mut p = 0usize;
    let mut s = String::new();
    while p < b.len() {
        let (_, h, l) = match tlv(b, p) {
            Some(x) => x,
            None => break,
        };
        let end = (p + h + l).min(b.len());
        s.push_str(&render_filter(&b[p..end], depth + 1));
        p = end;
    }
    s
}

fn render_ava(c: &[u8], op: &str) -> String {
    let (_, h1, l1) = match tlv(c, 0) {
        Some(x) => x,
        None => return "(?)".to_string(),
    };
    let desc = octet(c, h1, l1);
    let (_, h2, l2) = match tlv(c, h1 + l1) {
        Some(x) => x,
        None => return format!("({desc}{op}?)"),
    };
    let val = octet(c, h1 + l1 + h2, l2);
    format!("({desc}{op}{val})")
}

fn render_substrings(c: &[u8]) -> String {
    // SubstringFilter ::= SEQUENCE { type OCTET STRING, substrings SEQUENCE OF
    // CHOICE { initial [0], any [1], final [2] } }.
    let (_, h, l) = match tlv(c, 0) {
        Some(x) => x,
        None => return "(?)".to_string(),
    };
    let ty = octet(c, h, l);
    let mut out = String::new();
    let mut leading_star = true;
    if let Some((0x30, sh, sl)) = tlv(c, h + l) {
        let seq = c.get(h + l + sh..h + l + sh + sl).unwrap_or(&[]);
        let mut p = 0usize;
        while p < seq.len() {
            let (t, ih, il) = match tlv(seq, p) {
                Some(x) => x,
                None => break,
            };
            let piece = octet(seq, p + ih, il);
            match t {
                0x80 => {
                    out.push_str(&piece);
                    leading_star = true;
                }
                0x81 => {
                    out.push('*');
                    out.push_str(&piece);
                }
                0x82 => {
                    out.push('*');
                    out.push_str(&piece);
                    leading_star = false;
                }
                _ => {}
            }
            p += ih + il;
        }
    }
    if leading_star {
        out.push('*');
    }
    format!("({ty}={out})")
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

    fn msg_with(op: u8, body: &[u8]) -> Vec<u8> {
        let mut mb = tlv_b(0x02, &[0x02]); // messageID = 2
        mb.extend(tlv_b(op, body));
        tlv_b(0x30, &mb)
    }

    #[test]
    fn detects_starttls() {
        let ext = tlv_b(0x80, b"1.3.6.1.4.1.1466.20037");
        let msg = msg_with(0x77, &ext);
        let (mut creds, mut notes) = (Vec::new(), Vec::new());
        scan(&msg, &mut creds, &mut notes);
        assert!(notes.iter().any(|n| n == "LDAP StartTLS requested"));
    }

    #[test]
    fn renders_search_filter_and_attrs() {
        let ava = {
            let mut a = tlv_b(0x04, b"servicePrincipalName");
            a.extend(tlv_b(0x04, b"*"));
            a
        };
        let mut body = tlv_b(0x04, b"dc=corp,dc=local");
        body.extend(tlv_b(0x0A, &[2])); // scope
        body.extend(tlv_b(0x0A, &[0])); // derefAliases
        body.extend(tlv_b(0x02, &[0])); // sizeLimit
        body.extend(tlv_b(0x02, &[0])); // timeLimit
        body.extend(tlv_b(0x01, &[0])); // typesOnly
        body.extend(tlv_b(0xA3, &ava)); // filter (servicePrincipalName=*)
        let attrs = {
            let mut a = tlv_b(0x04, b"cn");
            a.extend(tlv_b(0x04, b"servicePrincipalName"));
            a
        };
        body.extend(tlv_b(0x30, &attrs));
        let msg = msg_with(0x63, &body);
        let (mut creds, mut notes) = (Vec::new(), Vec::new());
        scan(&msg, &mut creds, &mut notes);
        assert!(creds.is_empty());
        assert!(notes.iter().any(|n| n.contains("base=\"dc=corp,dc=local\"")
            && n.contains("filter=(servicePrincipalName=*)")
            && n.contains("attrs=cn,servicePrincipalName")));
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
