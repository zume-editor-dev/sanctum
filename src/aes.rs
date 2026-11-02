//! AES-128 (block cipher) and AES-128-GCM, enough to decrypt QUIC Initial
//! packets (whose keys are derived from a visible connection ID) and read the
//! TLS ClientHello / SNI inside. Not constant-time and not for securing data -
//! it only opens packets whose keys are public by construction.

#[rustfmt::skip]
const SBOX: [u8; 256] = [
    0x63,0x7c,0x77,0x7b,0xf2,0x6b,0x6f,0xc5,0x30,0x01,0x67,0x2b,0xfe,0xd7,0xab,0x76,
    0xca,0x82,0xc9,0x7d,0xfa,0x59,0x47,0xf0,0xad,0xd4,0xa2,0xaf,0x9c,0xa4,0x72,0xc0,
    0xb7,0xfd,0x93,0x26,0x36,0x3f,0xf7,0xcc,0x34,0xa5,0xe5,0xf1,0x71,0xd8,0x31,0x15,
    0x04,0xc7,0x23,0xc3,0x18,0x96,0x05,0x9a,0x07,0x12,0x80,0xe2,0xeb,0x27,0xb2,0x75,
    0x09,0x83,0x2c,0x1a,0x1b,0x6e,0x5a,0xa0,0x52,0x3b,0xd6,0xb3,0x29,0xe3,0x2f,0x84,
    0x53,0xd1,0x00,0xed,0x20,0xfc,0xb1,0x5b,0x6a,0xcb,0xbe,0x39,0x4a,0x4c,0x58,0xcf,
    0xd0,0xef,0xaa,0xfb,0x43,0x4d,0x33,0x85,0x45,0xf9,0x02,0x7f,0x50,0x3c,0x9f,0xa8,
    0x51,0xa3,0x40,0x8f,0x92,0x9d,0x38,0xf5,0xbc,0xb6,0xda,0x21,0x10,0xff,0xf3,0xd2,
    0xcd,0x0c,0x13,0xec,0x5f,0x97,0x44,0x17,0xc4,0xa7,0x7e,0x3d,0x64,0x5d,0x19,0x73,
    0x60,0x81,0x4f,0xdc,0x22,0x2a,0x90,0x88,0x46,0xee,0xb8,0x14,0xde,0x5e,0x0b,0xdb,
    0xe0,0x32,0x3a,0x0a,0x49,0x06,0x24,0x5c,0xc2,0xd3,0xac,0x62,0x91,0x95,0xe4,0x79,
    0xe7,0xc8,0x37,0x6d,0x8d,0xd5,0x4e,0xa9,0x6c,0x56,0xf4,0xea,0x65,0x7a,0xae,0x08,
    0xba,0x78,0x25,0x2e,0x1c,0xa6,0xb4,0xc6,0xe8,0xdd,0x74,0x1f,0x4b,0xbd,0x8b,0x8a,
    0x70,0x3e,0xb5,0x66,0x48,0x03,0xf6,0x0e,0x61,0x35,0x57,0xb9,0x86,0xc1,0x1d,0x9e,
    0xe1,0xf8,0x98,0x11,0x69,0xd9,0x8e,0x94,0x9b,0x1e,0x87,0xe9,0xce,0x55,0x28,0xdf,
    0x8c,0xa1,0x89,0x0d,0xbf,0xe6,0x42,0x68,0x41,0x99,0x2d,0x0f,0xb0,0x54,0xbb,0x16,
];
const RCON: [u8; 10] = [0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40, 0x80, 0x1b, 0x36];

pub struct Aes128 {
    rk: [u8; 176], // 11 round keys x 16 bytes
}

fn xtime(x: u8) -> u8 {
    let h = x & 0x80;
    let s = x << 1;
    if h != 0 {
        s ^ 0x1b
    } else {
        s
    }
}
fn mul(a: u8, b: u8) -> u8 {
    let mut a = a;
    let mut b = b;
    let mut p = 0u8;
    for _ in 0..8 {
        if b & 1 != 0 {
            p ^= a;
        }
        a = xtime(a);
        b >>= 1;
    }
    p
}

impl Aes128 {
    pub fn new(key: &[u8; 16]) -> Self {
        let mut rk = [0u8; 176];
        rk[..16].copy_from_slice(key);
        let mut i = 16;
        let mut rcon_i = 0;
        while i < 176 {
            let mut t = [rk[i - 4], rk[i - 3], rk[i - 2], rk[i - 1]];
            if i % 16 == 0 {
                t = [
                    SBOX[t[1] as usize] ^ RCON[rcon_i],
                    SBOX[t[2] as usize],
                    SBOX[t[3] as usize],
                    SBOX[t[0] as usize],
                ];
                rcon_i += 1;
            }
            for j in 0..4 {
                rk[i + j] = rk[i - 16 + j] ^ t[j];
            }
            i += 4;
        }
        Aes128 { rk }
    }

    pub fn encrypt_block(&self, input: &[u8; 16]) -> [u8; 16] {
        let mut s = *input;
        self.add_round_key(&mut s, 0);
        for round in 1..10 {
            sub_bytes(&mut s);
            shift_rows(&mut s);
            mix_columns(&mut s);
            self.add_round_key(&mut s, round);
        }
        sub_bytes(&mut s);
        shift_rows(&mut s);
        self.add_round_key(&mut s, 10);
        s
    }

    fn add_round_key(&self, s: &mut [u8; 16], round: usize) {
        for (i, b) in s.iter_mut().enumerate() {
            *b ^= self.rk[round * 16 + i];
        }
    }
}

fn sub_bytes(s: &mut [u8; 16]) {
    for b in s.iter_mut() {
        *b = SBOX[*b as usize];
    }
}
fn shift_rows(s: &mut [u8; 16]) {
    let o = *s;
    // column-major state: byte index = col*4 + row.
    for r in 1..4 {
        for c in 0..4 {
            s[c * 4 + r] = o[((c + r) % 4) * 4 + r];
        }
    }
}
fn mix_columns(s: &mut [u8; 16]) {
    for c in 0..4 {
        let col = [s[c * 4], s[c * 4 + 1], s[c * 4 + 2], s[c * 4 + 3]];
        s[c * 4] = mul(col[0], 2) ^ mul(col[1], 3) ^ col[2] ^ col[3];
        s[c * 4 + 1] = col[0] ^ mul(col[1], 2) ^ mul(col[2], 3) ^ col[3];
        s[c * 4 + 2] = col[0] ^ col[1] ^ mul(col[2], 2) ^ mul(col[3], 3);
        s[c * 4 + 3] = mul(col[0], 3) ^ col[1] ^ col[2] ^ mul(col[3], 2);
    }
}

// ---- GCM --------------------------------------------------------------------
// Multiplication in GF(2^128) with GCM's bit-reflected representation
// (reduction polynomial R = 0xe1 in the high byte).
fn gf_mult(x: &[u8; 16], y: &[u8; 16]) -> [u8; 16] {
    let xx = u128::from_be_bytes(*x);
    let mut v = u128::from_be_bytes(*y);
    let mut z = 0u128;
    for i in 0..128 {
        if (xx >> (127 - i)) & 1 == 1 {
            z ^= v;
        }
        let lsb = v & 1;
        v >>= 1;
        if lsb == 1 {
            v ^= 0xe1u128 << 120;
        }
    }
    z.to_be_bytes()
}

fn ghash(h: &[u8; 16], aad: &[u8], ct: &[u8]) -> [u8; 16] {
    let mut y = [0u8; 16];
    for part in [aad, ct] {
        for chunk in part.chunks(16) {
            for (yi, &c) in y.iter_mut().zip(chunk) {
                *yi ^= c;
            }
            y = gf_mult(&y, h);
        }
    }
    let mut lb = [0u8; 16];
    lb[0..8].copy_from_slice(&((aad.len() as u64) * 8).to_be_bytes());
    lb[8..16].copy_from_slice(&((ct.len() as u64) * 8).to_be_bytes());
    for (yi, &l) in y.iter_mut().zip(lb.iter()) {
        *yi ^= l;
    }
    gf_mult(&y, h)
}

fn gctr(aes: &Aes128, icb: &[u8; 16], data: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(data.len());
    let mut ctr = *icb;
    for chunk in data.chunks(16) {
        let ks = aes.encrypt_block(&ctr);
        for (i, &b) in chunk.iter().enumerate() {
            out.push(b ^ ks[i]);
        }
        // increment the low 32 bits of the counter block
        let n = u32::from_be_bytes([ctr[12], ctr[13], ctr[14], ctr[15]]).wrapping_add(1);
        ctr[12..16].copy_from_slice(&n.to_be_bytes());
    }
    out
}

fn j0(iv: &[u8]) -> [u8; 16] {
    // QUIC/TLS always use a 96-bit IV: J0 = IV || 0x00000001.
    let mut b = [0u8; 16];
    b[..12].copy_from_slice(&iv[..12]);
    b[15] = 1;
    b
}

/// AES-128-GCM authenticated decryption (96-bit IV). `input` is ciphertext||tag.
/// Returns the plaintext only if the tag verifies.
pub fn aes128_gcm_open(key: &[u8; 16], iv: &[u8], aad: &[u8], input: &[u8]) -> Option<Vec<u8>> {
    if input.len() < 16 {
        return None;
    }
    let (ct, tag) = input.split_at(input.len() - 16);
    let aes = Aes128::new(key);
    let h = aes.encrypt_block(&[0u8; 16]);
    let s = ghash(&h, aad, ct);
    let ej0 = aes.encrypt_block(&j0(iv));
    let mut expected = [0u8; 16];
    for i in 0..16 {
        expected[i] = s[i] ^ ej0[i];
    }
    if expected != tag {
        return None;
    }
    let mut ctr = j0(iv);
    let n = u32::from_be_bytes([ctr[12], ctr[13], ctr[14], ctr[15]]).wrapping_add(1);
    ctr[12..16].copy_from_slice(&n.to_be_bytes());
    Some(gctr(&aes, &ctr, ct))
}

/// AES-128-GCM authenticated encryption (96-bit IV). Returns ciphertext||tag.
/// Only used by tests (the tool decrypts).
#[cfg(test)]
pub fn aes128_gcm_seal(key: &[u8; 16], iv: &[u8], aad: &[u8], plaintext: &[u8]) -> Vec<u8> {
    let aes = Aes128::new(key);
    let h = aes.encrypt_block(&[0u8; 16]);
    let mut ctr = j0(iv);
    let n = u32::from_be_bytes([ctr[12], ctr[13], ctr[14], ctr[15]]).wrapping_add(1);
    ctr[12..16].copy_from_slice(&n.to_be_bytes());
    let ct = gctr(&aes, &ctr, plaintext);
    let s = ghash(&h, aad, &ct);
    let ej0 = aes.encrypt_block(&j0(iv));
    let mut out = ct;
    for i in 0..16 {
        out.push(s[i] ^ ej0[i]);
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    fn hx(b: &[u8]) -> String {
        b.iter().map(|x| format!("{x:02x}")).collect()
    }

    #[test]
    fn aes128_block_fips197() {
        let key: [u8; 16] = [
            0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d,
            0x0e, 0x0f,
        ];
        let pt: [u8; 16] = [
            0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0xaa, 0xbb, 0xcc, 0xdd,
            0xee, 0xff,
        ];
        assert_eq!(
            hx(&Aes128::new(&key).encrypt_block(&pt)),
            "69c4e0d86a7b0430d8cdb78070b4c55a"
        );
    }

    #[test]
    fn gcm_nist_case2() {
        // NIST GCM test case 2: K=0, IV=0, P=0^128.
        let key = [0u8; 16];
        let iv = [0u8; 12];
        let ct = aes128_gcm_seal(&key, &iv, &[], &[0u8; 16]);
        // C = E_K(Y1); tag = GHASH(H,[],C) XOR E_K(Y0). Both operands match the
        // NIST GCM spec Test Case 2 (H=66e9..2e, GHASH=f38c..f885, E(Y0)=58e2..455a).
        assert_eq!(hx(&ct[..16]), "0388dace60b6a392f328c2b971b2fe78");
        assert_eq!(hx(&ct[16..]), "ab6e47d42cec13bdf53a67b21257bddf");
        // And open reverses it.
        assert_eq!(aes128_gcm_open(&key, &iv, &[], &ct).unwrap(), vec![0u8; 16]);
    }

    #[test]
    fn gcm_rejects_bad_tag() {
        let key = [0u8; 16];
        let iv = [0u8; 12];
        let mut ct = aes128_gcm_seal(&key, &iv, &[], &[0u8; 16]);
        let last = ct.len() - 1;
        ct[last] ^= 1;
        assert!(aes128_gcm_open(&key, &iv, &[], &ct).is_none());
    }
}
