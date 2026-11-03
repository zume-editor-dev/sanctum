//! RADIUS authentication extraction (tier T0, offline). Reads a RADIUS packet
//! (Code / Identifier / Length / Authenticator + attribute TLVs) and reports
//! the cleartext **User-Name**, the calling station, and whether a (secret-
//! encrypted) User-Password or a Microsoft VSA (MS-CHAP - crackable offline) is
//! present. Structure parsing only; no secret is known so nothing is decrypted.

use crate::util::push_uniq;

const CAP: usize = 100;

fn code_name(c: u8) -> Option<&'static str> {
    Some(match c {
        1 => "Access-Request",
        2 => "Access-Accept",
        3 => "Access-Reject",
        4 => "Accounting-Request",
        5 => "Accounting-Response",
        11 => "Access-Challenge",
        _ => return None,
    })
}

fn text(v: &[u8]) -> String {
    String::from_utf8_lossy(v).to_string()
}

/// Scan a UDP payload for a RADIUS packet.
pub fn scan(payload: &[u8], notes: &mut Vec<String>, auth: &mut Vec<String>) {
    if payload.len() < 20 {
        return;
    }
    let name = match code_name(payload[0]) {
        Some(n) => n,
        None => return,
    };
    // The Length field must describe a packet that fits the payload - a strong
    // gate that keeps non-RADIUS UDP out.
    let len = u16::from_be_bytes([payload[2], payload[3]]) as usize;
    if !(20..=payload.len()).contains(&len) {
        return;
    }

    let mut user: Option<String> = None;
    let mut calling: Option<String> = None;
    let mut has_password = false;
    let mut mschap = false;
    let mut p = 20usize;
    while p + 2 <= len {
        let t = payload[p];
        let l = payload[p + 1] as usize;
        if l < 2 || p + l > len {
            break;
        }
        let val = &payload[p + 2..p + l];
        match t {
            1 => user = Some(text(val)),     // User-Name (cleartext)
            2 => has_password = true,        // User-Password (secret-encrypted)
            31 => calling = Some(text(val)), // Calling-Station-Id
            // Vendor-Specific; Microsoft (vendor 311) means MS-CHAP.
            26 if val.len() >= 4 && u32::from_be_bytes([val[0], val[1], val[2], val[3]]) == 311 => {
                mschap = true;
            }
            _ => {}
        }
        p += l;
    }

    let mut parts = vec![format!("RADIUS {name}")];
    if let Some(u) = &user {
        parts.push(format!("user={u}"));
    }
    if let Some(c) = &calling {
        parts.push(format!("calling-station={c}"));
    }
    if has_password {
        parts.push("User-Password present (secret-encrypted)".to_string());
    }
    push_uniq(notes, parts.join(" "), CAP);

    if mschap {
        let who = user.unwrap_or_default();
        push_uniq(
            auth,
            format!("RADIUS MS-CHAP response (user {who}) - crackable offline"),
            CAP,
        );
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn attr(t: u8, v: &[u8]) -> Vec<u8> {
        let mut a = vec![t, (v.len() + 2) as u8];
        a.extend_from_slice(v);
        a
    }

    fn packet(code: u8, attrs: &[u8]) -> Vec<u8> {
        let mut p = vec![code, 0x2a]; // code, identifier
        let total = 20 + attrs.len();
        p.extend_from_slice(&(total as u16).to_be_bytes());
        p.extend_from_slice(&[0u8; 16]); // authenticator
        p.extend_from_slice(attrs);
        p
    }

    #[test]
    fn extracts_user_name_and_password_flag() {
        let mut attrs = attr(1, b"alice"); // User-Name
        attrs.extend(attr(2, &[0u8; 16])); // User-Password
        let (mut notes, mut auth) = (Vec::new(), Vec::new());
        scan(&packet(1, &attrs), &mut notes, &mut auth);
        assert!(notes.iter().any(|n| n.contains("Access-Request")
            && n.contains("user=alice")
            && n.contains("User-Password present")));
        assert!(auth.is_empty());
    }

    #[test]
    fn flags_mschap_vsa() {
        let mut attrs = attr(1, b"bob");
        // Vendor-Specific: vendor 311 (Microsoft) + some VSA body.
        let mut vsa = 311u32.to_be_bytes().to_vec();
        vsa.extend_from_slice(&[25, 6, 0, 0, 0, 0]);
        attrs.extend(attr(26, &vsa));
        let (mut notes, mut auth) = (Vec::new(), Vec::new());
        scan(&packet(1, &attrs), &mut notes, &mut auth);
        assert!(auth
            .iter()
            .any(|a| a.contains("MS-CHAP") && a.contains("bob")));
    }

    #[test]
    fn ignores_non_radius() {
        let (mut notes, mut auth) = (Vec::new(), Vec::new());
        scan(b"\x30\x82not radius at all......", &mut notes, &mut auth);
        assert!(notes.is_empty() && auth.is_empty());
    }
}
