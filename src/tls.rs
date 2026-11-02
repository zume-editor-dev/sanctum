//! Minimal TLS ClientHello SNI extraction (tier T0, offline). Reads the
//! server_name (SNI) from a ClientHello that fits in the supplied TCP payload.
//! It parses structure only and decrypts nothing; a ClientHello split across
//! segments (rare for the first packet) is simply not recognized.

fn be16(b: &[u8]) -> usize {
    ((b[0] as usize) << 8) | b[1] as usize
}

/// The SNI host name from a TLS ClientHello in `payload`, if present.
pub fn client_hello_sni(payload: &[u8]) -> Option<String> {
    // TLS record: content type 22 (handshake), version (2), length (2).
    if payload.len() < 5 || payload[0] != 22 {
        return None;
    }
    // Handshake: type 1 (ClientHello) + 3-byte length, then the body.
    let hs = payload.get(5..)?;
    if hs.len() < 4 || hs[0] != 1 {
        return None;
    }
    let b = hs.get(4..)?;
    let mut p = 2 + 32; // client_version (2) + random (32)
    let sid_len = *b.get(p)? as usize;
    p += 1 + sid_len;
    if b.len() < p + 2 {
        return None;
    }
    let cs_len = be16(&b[p..p + 2]);
    p += 2 + cs_len;
    let cm_len = *b.get(p)? as usize;
    p += 1 + cm_len;
    if b.len() < p + 2 {
        return None;
    }
    let ext_total = be16(&b[p..p + 2]);
    p += 2;
    let ext_end = (p + ext_total).min(b.len());
    while p + 4 <= ext_end {
        let etype = be16(&b[p..p + 2]);
        let elen = be16(&b[p + 2..p + 4]);
        p += 4;
        if p + elen > b.len() {
            break;
        }
        if etype == 0 {
            // server_name: list_len(2), name_type(1, 0=host_name), name_len(2), name.
            let e = &b[p..p + elen];
            if e.len() >= 5 && e[2] == 0 {
                let nlen = be16(&e[3..5]);
                if e.len() >= 5 + nlen && nlen > 0 {
                    let name = &e[5..5 + nlen];
                    if name.iter().all(|&c| (0x20..0x7f).contains(&c)) {
                        return Some(String::from_utf8_lossy(name).to_string());
                    }
                }
            }
            return None;
        }
        p += elen;
    }
    None
}

#[cfg(test)]
mod tests {
    use super::*;

    fn client_hello(sni: &[u8]) -> Vec<u8> {
        // server_name extension data.
        let mut ext = Vec::new();
        let entry_len = 1 + 2 + sni.len(); // type + length + name
        ext.extend_from_slice(&(entry_len as u16).to_be_bytes()); // server_name_list length
        ext.push(0); // name type = host_name
        ext.extend_from_slice(&(sni.len() as u16).to_be_bytes());
        ext.extend_from_slice(sni);
        let mut extension = Vec::new();
        extension.extend_from_slice(&0u16.to_be_bytes()); // extension type 0
        extension.extend_from_slice(&(ext.len() as u16).to_be_bytes());
        extension.extend_from_slice(&ext);

        let mut body = Vec::new();
        body.extend_from_slice(&[0x03, 0x03]); // client version
        body.extend_from_slice(&[0u8; 32]); // random
        body.push(0); // session id length
        body.extend_from_slice(&2u16.to_be_bytes()); // cipher suites length
        body.extend_from_slice(&[0x00, 0x2f]); // one cipher suite
        body.push(1); // compression methods length
        body.push(0); // null compression
        body.extend_from_slice(&(extension.len() as u16).to_be_bytes());
        body.extend_from_slice(&extension);

        let mut hs = Vec::new();
        hs.push(1); // ClientHello
        let bl = body.len();
        hs.extend_from_slice(&[(bl >> 16) as u8, (bl >> 8) as u8, bl as u8]);
        hs.extend_from_slice(&body);

        let mut rec = Vec::new();
        rec.push(22); // handshake
        rec.extend_from_slice(&[0x03, 0x01]); // record version
        rec.extend_from_slice(&(hs.len() as u16).to_be_bytes());
        rec.extend_from_slice(&hs);
        rec
    }

    #[test]
    fn extracts_sni() {
        let ch = client_hello(b"example.com");
        assert_eq!(client_hello_sni(&ch).as_deref(), Some("example.com"));
    }

    #[test]
    fn ignores_non_clienthello() {
        assert_eq!(client_hello_sni(b"GET / HTTP/1.1\r\n"), None);
        assert_eq!(client_hello_sni(&[22, 3, 1, 0, 0]), None);
    }
}
