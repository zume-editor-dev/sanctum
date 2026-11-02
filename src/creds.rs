//! Plaintext-credential detection in captured packet payloads (tier T0, offline).
//! It surfaces credentials that cross the wire in the clear - HTTP Basic auth,
//! FTP / POP3 USER/PASS, web form password fields, SMTP AUTH PLAIN - which is a
//! classic argument for not using plaintext protocols. It reads a capture you
//! already hold; it sends nothing. For authorized analysis only.

const CRED_CAP: usize = 50;
const MAX_PAYLOAD: usize = 64 * 1024;

/// Scan one L4 payload for plaintext credentials, appending deduplicated,
/// human-readable findings to `out` (bounded).
pub fn scan(payload: &[u8], _dport: u16, out: &mut Vec<String>) {
    if payload.is_empty() || payload.len() > MAX_PAYLOAD || out.len() >= CRED_CAP {
        return;
    }
    http_basic(payload, out);
    smtp_auth_plain(payload, out);
    user_pass_lines(payload, out);
    form_fields(payload, out);
}

fn push(out: &mut Vec<String>, s: String) {
    let s = s.trim().to_string();
    if !s.is_empty() && out.len() < CRED_CAP && !out.contains(&s) {
        out.push(s);
    }
}

fn find_ci(hay: &[u8], needle: &[u8]) -> Option<usize> {
    if needle.is_empty() || hay.len() < needle.len() {
        return None;
    }
    (0..=hay.len() - needle.len()).find(|&i| {
        hay[i..i + needle.len()]
            .iter()
            .zip(needle)
            .all(|(a, b)| a.eq_ignore_ascii_case(b))
    })
}

fn starts_with_ci(hay: &[u8], needle: &[u8]) -> bool {
    hay.len() >= needle.len()
        && hay[..needle.len()]
            .iter()
            .zip(needle)
            .all(|(a, b)| a.eq_ignore_ascii_case(b))
}

/// Printable token from `start` up to any byte in `stop` (or a control byte).
fn take_until<'a>(hay: &'a [u8], start: usize, stop: &[u8]) -> &'a [u8] {
    let mut end = start;
    while end < hay.len() && !stop.contains(&hay[end]) && (0x20..0x7f).contains(&hay[end]) {
        end += 1;
    }
    &hay[start..end]
}

/// Base64 decode, tolerant of '=' padding and embedded whitespace.
fn b64(input: &[u8]) -> Option<Vec<u8>> {
    fn val(c: u8) -> Option<u8> {
        match c {
            b'A'..=b'Z' => Some(c - b'A'),
            b'a'..=b'z' => Some(c - b'a' + 26),
            b'0'..=b'9' => Some(c - b'0' + 52),
            b'+' => Some(62),
            b'/' => Some(63),
            _ => None,
        }
    }
    let mut bytes = Vec::new();
    let mut buf = 0u32;
    let mut bits = 0u32;
    for &c in input {
        if c == b'=' || c == b'\r' || c == b'\n' || c == b' ' || c == b'\t' {
            continue;
        }
        let v = val(c)?;
        buf = (buf << 6) | v as u32;
        bits += 6;
        if bits >= 8 {
            bits -= 8;
            bytes.push((buf >> bits) as u8);
        }
    }
    Some(bytes)
}

fn http_basic(payload: &[u8], out: &mut Vec<String>) {
    const MARK: &[u8] = b"authorization: basic ";
    if let Some(i) = find_ci(payload, MARK) {
        let tok = take_until(payload, i + MARK.len(), b" \r\n");
        if let Some(dec) = b64(tok) {
            let s = String::from_utf8_lossy(&dec);
            push(out, format!("HTTP Basic auth: {}", s.trim()));
        }
    }
}

fn smtp_auth_plain(payload: &[u8], out: &mut Vec<String>) {
    const MARK: &[u8] = b"auth plain ";
    if let Some(i) = find_ci(payload, MARK) {
        let tok = take_until(payload, i + MARK.len(), b" \r\n");
        if let Some(dec) = b64(tok) {
            // PLAIN = authzid \0 authcid \0 passwd
            let parts: Vec<&[u8]> = dec.split(|&b| b == 0).collect();
            if parts.len() >= 3 {
                push(
                    out,
                    format!(
                        "SMTP AUTH PLAIN: {} / {}",
                        String::from_utf8_lossy(parts[1]),
                        String::from_utf8_lossy(parts[2])
                    ),
                );
            }
        }
    }
}

fn user_pass_lines(payload: &[u8], out: &mut Vec<String>) {
    for raw in payload.split(|&b| b == b'\n') {
        let mut line = raw;
        while line.last() == Some(&b'\r') || line.last() == Some(&b' ') {
            line = &line[..line.len() - 1];
        }
        if starts_with_ci(line, b"USER ") {
            push(
                out,
                format!("USER command: {}", String::from_utf8_lossy(&line[5..])),
            );
        } else if starts_with_ci(line, b"PASS ") {
            push(
                out,
                format!("PASS command: {}", String::from_utf8_lossy(&line[5..])),
            );
        }
    }
}

fn form_fields(payload: &[u8], out: &mut Vec<String>) {
    const STOP: &[u8] = b"& \r\n;\"'";
    for mark in [
        &b"password="[..],
        &b"passwd="[..],
        &b"pwd="[..],
        &b"username="[..],
        &b"user="[..],
    ] {
        if let Some(i) = find_ci(payload, mark) {
            let val = take_until(payload, i + mark.len(), STOP);
            if !val.is_empty() {
                let field = String::from_utf8_lossy(&mark[..mark.len() - 1]);
                push(
                    out,
                    format!("web form {}={}", field, String::from_utf8_lossy(val)),
                );
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn base64_decodes() {
        assert_eq!(b64(b"dXNlcjpwYXNz").unwrap(), b"user:pass");
        assert_eq!(b64(b"AHVzZXIAcGFzcw==").unwrap(), b"\x00user\x00pass");
    }

    #[test]
    fn http_basic_auth() {
        let mut out = Vec::new();
        scan(
            b"GET / HTTP/1.1\r\nHost: x\r\nAuthorization: Basic dXNlcjpwYXNz\r\n\r\n",
            80,
            &mut out,
        );
        assert!(out.iter().any(|s| s == "HTTP Basic auth: user:pass"));
    }

    #[test]
    fn ftp_user_pass() {
        let mut out = Vec::new();
        scan(b"USER bob\r\n", 21, &mut out);
        scan(b"PASS hunter2\r\n", 21, &mut out);
        assert!(out.iter().any(|s| s == "USER command: bob"));
        assert!(out.iter().any(|s| s == "PASS command: hunter2"));
    }

    #[test]
    fn web_form_password() {
        let mut out = Vec::new();
        scan(
            b"POST /login\r\n\r\nusername=alice&password=s3cr3t&submit=1",
            80,
            &mut out,
        );
        assert!(out.iter().any(|s| s == "web form password=s3cr3t"));
        assert!(out.iter().any(|s| s == "web form username=alice"));
    }

    #[test]
    fn smtp_auth_plain_creds() {
        let mut out = Vec::new();
        scan(b"AUTH PLAIN AHVzZXIAcGFzcw==\r\n", 25, &mut out);
        assert!(out.iter().any(|s| s == "SMTP AUTH PLAIN: user / pass"));
    }

    #[test]
    fn nothing_in_plain_traffic() {
        let mut out = Vec::new();
        scan(
            b"GET /index.html HTTP/1.1\r\nHost: example\r\n\r\n",
            80,
            &mut out,
        );
        assert!(out.is_empty());
    }
}
