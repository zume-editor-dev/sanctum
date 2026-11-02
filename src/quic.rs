//! QUIC v1 Initial-packet SNI extraction (tier T0, offline). QUIC Initial
//! packets are "encrypted" with keys derived from the (visible) Destination
//! Connection ID via a fixed salt (RFC 9001 section 5.2), so a passive observer
//! can decrypt them and read the TLS ClientHello - and its SNI - inside. This
//! removes QUIC's Initial protection to recover the SNI only. Nothing with a
//! secret key is touched.

use crate::aes::{aes128_gcm_open, Aes128};
use crate::hash::{hkdf_expand_label, hkdf_extract};
use crate::tls::sni_from_handshake;

// RFC 9001 section 5.2: the QUIC v1 Initial salt.
const INITIAL_SALT: [u8; 20] = [
    0x38, 0x76, 0x2c, 0xf7, 0xf5, 0x59, 0x34, 0xb3, 0x4d, 0x17, 0x9a, 0xe6, 0xa4, 0xc8, 0x0c, 0xad,
    0xcc, 0xbb, 0x7f, 0x0a,
];

struct Keys {
    key: [u8; 16],
    iv: [u8; 12],
    hp: [u8; 16],
}

fn derive_initial(dcid: &[u8]) -> Keys {
    let initial_secret = hkdf_extract(&INITIAL_SALT, dcid);
    let client = hkdf_expand_label(&initial_secret, "client in", &[], 32);
    let key = hkdf_expand_label(&client, "quic key", &[], 16);
    let iv = hkdf_expand_label(&client, "quic iv", &[], 12);
    let hp = hkdf_expand_label(&client, "quic hp", &[], 16);
    let mut k = Keys {
        key: [0; 16],
        iv: [0; 12],
        hp: [0; 16],
    };
    k.key.copy_from_slice(&key);
    k.iv.copy_from_slice(&iv);
    k.hp.copy_from_slice(&hp);
    k
}

/// Read a QUIC variable-length integer at `*pos`, advancing it.
fn varint(b: &[u8], pos: &mut usize) -> Option<u64> {
    let first = *b.get(*pos)?;
    let len = 1usize << (first >> 6);
    let mut v = (first & 0x3f) as u64;
    for i in 1..len {
        v = (v << 8) | *b.get(*pos + i)? as u64;
    }
    *pos += len;
    Some(v)
}

/// Decrypt a client QUIC v1 Initial packet, returning the plaintext frames.
fn decrypt_initial(pkt: &[u8]) -> Option<Vec<u8>> {
    if pkt.len() < 7 {
        return None;
    }
    let first = pkt[0];
    if first & 0xc0 != 0xc0 || (first >> 4) & 0x03 != 0 {
        return None; // not a long-header Initial packet
    }
    if u32::from_be_bytes([pkt[1], pkt[2], pkt[3], pkt[4]]) != 1 {
        return None; // only QUIC v1
    }
    let mut p = 5usize;
    let dcid_len = *pkt.get(p)? as usize;
    p += 1;
    let dcid = pkt.get(p..p + dcid_len)?.to_vec();
    p += dcid_len;
    let scid_len = *pkt.get(p)? as usize;
    p += 1 + scid_len;
    let token_len = varint(pkt, &mut p)? as usize;
    p += token_len;
    let length = varint(pkt, &mut p)? as usize;
    let pn_offset = p;
    let end = pn_offset.checked_add(length)?;
    if end > pkt.len() || length < 20 {
        return None;
    }

    let keys = derive_initial(&dcid);
    // Header protection: sample 16 bytes starting 4 bytes into the PN field.
    let sample: [u8; 16] = pkt.get(pn_offset + 4..pn_offset + 20)?.try_into().ok()?;
    let mask = Aes128::new(&keys.hp).encrypt_block(&sample);
    let first_unmasked = first ^ (mask[0] & 0x0f);
    let pn_len = ((first_unmasked & 0x03) + 1) as usize;

    // Build the AAD: the header with the first byte and PN unmasked.
    let mut hdr = pkt[..pn_offset + pn_len].to_vec();
    hdr[0] = first_unmasked;
    let mut pn_be = [0u8; 8];
    for i in 0..pn_len {
        hdr[pn_offset + i] ^= mask[1 + i];
        pn_be[8 - pn_len + i] = hdr[pn_offset + i];
    }
    let pn = u64::from_be_bytes(pn_be);

    // Nonce = iv XOR left-padded packet number.
    let mut nonce = keys.iv;
    for i in 0..8 {
        nonce[4 + i] ^= pn_be[i];
    }
    let _ = pn;

    let ciphertext = pkt.get(pn_offset + pn_len..end)?;
    aes128_gcm_open(&keys.key, &nonce, &hdr, ciphertext)
}

/// Reassemble CRYPTO frames from decrypted QUIC frames and read the SNI from
/// the TLS ClientHello they carry.
fn crypto_sni(frames: &[u8]) -> Option<String> {
    let mut crypto: Vec<u8> = Vec::new();
    let mut p = 0usize;
    while p < frames.len() {
        let t = frames[p];
        p += 1;
        match t {
            0x00 | 0x01 => {} // PADDING / PING
            0x06 => {
                let off = varint(frames, &mut p)? as usize;
                let len = varint(frames, &mut p)? as usize;
                let data = frames.get(p..p + len)?;
                if off + len > 1 << 20 {
                    return None; // bound reassembly to 1 MiB
                }
                if crypto.len() < off + len {
                    crypto.resize(off + len, 0);
                }
                crypto[off..off + len].copy_from_slice(data);
                p += len;
            }
            _ => break, // other frame types: stop (ClientHello is at the start)
        }
    }
    sni_from_handshake(&crypto)
}

/// The SNI from a QUIC v1 Initial packet, if one is present and recoverable.
pub fn initial_sni(payload: &[u8]) -> Option<String> {
    let frames = decrypt_initial(payload)?;
    crypto_sni(&frames)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn hx(b: &[u8]) -> String {
        b.iter().map(|x| format!("{x:02x}")).collect()
    }

    #[test]
    fn derive_matches_rfc9001_a1() {
        // RFC 9001 Appendix A.1, DCID 0x8394c8f03e515708.
        let dcid = [0x83, 0x94, 0xc8, 0xf0, 0x3e, 0x51, 0x57, 0x08];
        let k = derive_initial(&dcid);
        assert_eq!(hx(&k.key), "1f369613dd76d5467730efcbe3b1a22d");
        assert_eq!(hx(&k.iv), "fa044b2f42a3fd3b46fb255c");
        assert_eq!(hx(&k.hp), "9f50449e04a0e810283a1e9933adedd2");
    }

    #[test]
    fn header_protection_mask_rfc9001_a2() {
        // hp from A.1, sample from A.2 -> mask begins 437b9aec36.
        let hp = [
            0x9f, 0x50, 0x44, 0x9e, 0x04, 0xa0, 0xe8, 0x10, 0x28, 0x3a, 0x1e, 0x99, 0x33, 0xad,
            0xed, 0xd2,
        ];
        let sample = [
            0xd1, 0xb1, 0xc9, 0x8d, 0xd7, 0x68, 0x9f, 0xb8, 0xec, 0x11, 0xd2, 0x42, 0xb1, 0x23,
            0xdc, 0x9b,
        ];
        let mask = Aes128::new(&hp).encrypt_block(&sample);
        assert_eq!(hx(&mask[..5]), "437b9aec36");
    }

    // A minimal ClientHello handshake (no record layer) advertising `sni`.
    fn client_hello(sni: &[u8]) -> Vec<u8> {
        let mut ext = Vec::new();
        ext.extend_from_slice(&((1 + 2 + sni.len()) as u16).to_be_bytes());
        ext.push(0);
        ext.extend_from_slice(&(sni.len() as u16).to_be_bytes());
        ext.extend_from_slice(sni);
        let mut extension = vec![0u8, 0];
        extension.extend_from_slice(&(ext.len() as u16).to_be_bytes());
        extension.extend_from_slice(&ext);
        let mut body = vec![0x03, 0x03];
        body.extend_from_slice(&[0u8; 32]);
        body.push(0);
        body.extend_from_slice(&2u16.to_be_bytes());
        body.extend_from_slice(&[0x13, 0x01]);
        body.push(1);
        body.push(0);
        body.extend_from_slice(&(extension.len() as u16).to_be_bytes());
        body.extend_from_slice(&extension);
        let mut hs = vec![1u8];
        let bl = body.len();
        hs.extend_from_slice(&[(bl >> 16) as u8, (bl >> 8) as u8, bl as u8]);
        hs.extend_from_slice(&body);
        hs
    }

    fn crypto_frame(hs: &[u8]) -> Vec<u8> {
        let mut f = vec![0x06, 0x00]; // CRYPTO, offset 0
                                      // length as a 2-byte varint
        f.extend_from_slice(&((0x4000 | hs.len()) as u16).to_be_bytes());
        f.extend_from_slice(hs);
        f
    }

    #[test]
    fn reassembles_crypto_and_reads_sni() {
        let frames = crypto_frame(&client_hello(b"example.com"));
        assert_eq!(crypto_sni(&frames).as_deref(), Some("example.com"));
    }

    #[test]
    fn round_trip_initial_packet() {
        use crate::aes::aes128_gcm_seal;
        let dcid = [0x83, 0x94, 0xc8, 0xf0, 0x3e, 0x51, 0x57, 0x08];
        let keys = derive_initial(&dcid);
        let frames = crypto_frame(&client_hello(b"quic.example"));

        // Header: long + fixed + Initial + pn_len 1 (0xC0), v1, dcid, scid 0,
        // token 0, length varint, pn 0.
        let pn_len = 1usize;
        let length = pn_len + frames.len() + 16;
        let mut hdr = vec![0xC0u8];
        hdr.extend_from_slice(&1u32.to_be_bytes());
        hdr.push(dcid.len() as u8);
        hdr.extend_from_slice(&dcid);
        hdr.push(0); // scid len
        hdr.push(0); // token length varint
        hdr.extend_from_slice(&((0x4000 | length) as u16).to_be_bytes());
        let pn_offset = hdr.len();
        hdr.push(0); // packet number = 0

        let nonce = keys.iv; // pn = 0
        let ct = aes128_gcm_seal(&keys.key, &nonce, &hdr, &frames);

        // Apply header protection using the same sample position.
        let mut pkt = hdr.clone();
        pkt.extend_from_slice(&ct);
        let sample: [u8; 16] = pkt[pn_offset + 4..pn_offset + 20].try_into().unwrap();
        let mask = Aes128::new(&keys.hp).encrypt_block(&sample);
        pkt[0] ^= mask[0] & 0x0f;
        pkt[pn_offset] ^= mask[1];

        assert_eq!(initial_sni(&pkt).as_deref(), Some("quic.example"));
    }
}
