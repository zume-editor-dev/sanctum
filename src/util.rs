//! Small byte-slice helpers shared by the protocol extractors.

/// Case-sensitive substring search.
pub fn find(hay: &[u8], needle: &[u8]) -> Option<usize> {
    if needle.is_empty() || hay.len() < needle.len() {
        return None;
    }
    (0..=hay.len() - needle.len()).find(|&i| &hay[i..i + needle.len()] == needle)
}

/// Case-insensitive (ASCII) substring search.
pub fn find_ci(hay: &[u8], needle: &[u8]) -> Option<usize> {
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

/// Printable token from `start` up to any byte in `stop` (or a control byte).
pub fn take_token<'a>(hay: &'a [u8], start: usize, stop: &[u8]) -> &'a [u8] {
    let mut end = start;
    while end < hay.len() && !stop.contains(&hay[end]) && (0x20..0x7f).contains(&hay[end]) {
        end += 1;
    }
    &hay[start..end]
}

/// Base64 decode, tolerant of '=' padding and embedded whitespace.
pub fn b64(input: &[u8]) -> Option<Vec<u8>> {
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
        if matches!(c, b'=' | b'\r' | b'\n' | b' ' | b'\t') {
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

/// Lowercase hex of a byte slice.
pub fn hex(b: &[u8]) -> String {
    let mut s = String::with_capacity(b.len() * 2);
    for x in b {
        s.push_str(&format!("{x:02x}"));
    }
    s
}

/// Append `s` to `out` if non-empty, not a duplicate, and under `cap`.
pub fn push_uniq(out: &mut Vec<String>, s: String, cap: usize) {
    let s = s.trim().to_string();
    if !s.is_empty() && out.len() < cap && !out.contains(&s) {
        out.push(s);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn helpers() {
        assert_eq!(find(b"abcdef", b"cd"), Some(2));
        assert_eq!(find_ci(b"ABCdef", b"cde"), Some(2));
        assert_eq!(b64(b"dXNlcg==").unwrap(), b"user");
        assert_eq!(hex(&[0x0a, 0xff]), "0aff");
        assert_eq!(take_token(b"host:80 x", 0, b": "), b"host");
    }
}
