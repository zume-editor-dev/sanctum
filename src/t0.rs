//! Tier T0: offline, no-network analysis of a local file (an artifact you
//! already hold) - type identification, hashes, entropy and printable strings -
//! in a single streaming pass so a large file is never loaded whole. Purely
//! passive: it reads a file you point it at and sends nothing anywhere.

use std::fs::File;
use std::io::Read;

use crate::hash::{Crc32, Md5, Sha1, Sha256};

const STRINGS_SCAN_CAP: u64 = 4 * 1024 * 1024; // scan the first 4 MiB for strings
const MIN_STR: usize = 4;
const MAX_SAMPLES: usize = 20;
const MAX_RUN: usize = 400;

pub struct FileAnalysis {
    pub size: u64,
    pub kind: String,
    pub entropy: f64,
    pub crc32: String,
    pub md5: String,
    pub sha1: String,
    pub sha256: String,
    pub string_count: usize,
    pub sample_strings: Vec<String>,
    pub strings_truncated: bool,
}

/// Identify a file from its leading bytes (magic), else text vs binary.
pub fn identify(prefix: &[u8]) -> &'static str {
    let p = prefix;
    let starts = |sig: &[u8]| p.len() >= sig.len() && &p[..sig.len()] == sig;
    if starts(b"MZ") {
        "PE/DOS executable (MZ)"
    } else if starts(b"\x7fELF") {
        "ELF executable"
    } else if starts(b"\xfe\xed\xfa\xce")
        || starts(b"\xfe\xed\xfa\xcf")
        || starts(b"\xce\xfa\xed\xfe")
        || starts(b"\xcf\xfa\xed\xfe")
    {
        "Mach-O executable"
    } else if starts(b"\xca\xfe\xba\xbe") {
        "Mach-O universal or Java class"
    } else if starts(b"%PDF") {
        "PDF document"
    } else if starts(b"PK\x03\x04") {
        "ZIP archive (or JAR/OOXML)"
    } else if starts(b"\x1f\x8b") {
        "gzip data"
    } else if starts(b"\x89PNG") {
        "PNG image"
    } else if starts(b"\xff\xd8\xff") {
        "JPEG image"
    } else if starts(b"GIF8") {
        "GIF image"
    } else if starts(b"%!PS") {
        "PostScript"
    } else if p.is_empty() {
        "empty"
    } else if p
        .iter()
        .all(|&b| b == b'\t' || b == b'\n' || b == b'\r' || (0x20..0x7f).contains(&b))
    {
        "text"
    } else {
        "binary data"
    }
}

fn entropy(hist: &[u64; 256], total: u64) -> f64 {
    if total == 0 {
        return 0.0;
    }
    let mut e = 0.0f64;
    for &c in hist.iter() {
        if c > 0 {
            let p = c as f64 / total as f64;
            e -= p * p.log2();
        }
    }
    e
}

struct StringScanner {
    cur: Vec<u8>,
    count: usize,
    samples: Vec<String>,
    scanned: u64,
    truncated: bool,
}

impl StringScanner {
    fn new() -> Self {
        StringScanner {
            cur: Vec::new(),
            count: 0,
            samples: Vec::new(),
            scanned: 0,
            truncated: false,
        }
    }
    fn feed(&mut self, chunk: &[u8]) {
        for &b in chunk {
            if self.scanned >= STRINGS_SCAN_CAP {
                self.truncated = true;
                self.flush();
                return;
            }
            self.scanned += 1;
            if (0x20..0x7f).contains(&b) {
                if self.cur.len() < MAX_RUN {
                    self.cur.push(b);
                }
            } else {
                self.flush();
            }
        }
    }
    fn flush(&mut self) {
        if self.cur.len() >= MIN_STR {
            self.count += 1;
            if self.samples.len() < MAX_SAMPLES {
                self.samples
                    .push(String::from_utf8_lossy(&self.cur).to_string());
            }
        }
        self.cur.clear();
    }
}

/// Analyze a file offline in one streaming pass.
pub fn analyze_file(path: &str) -> std::io::Result<FileAnalysis> {
    let mut f = File::open(path)?;
    let mut crc = Crc32::new();
    let mut md5 = Md5::new();
    let mut sha1 = Sha1::new();
    let mut sha256 = Sha256::new();
    let mut hist = [0u64; 256];
    let mut size = 0u64;
    let mut first: Vec<u8> = Vec::with_capacity(64);
    let mut scanner = StringScanner::new();
    let mut buf = [0u8; 65536];
    loop {
        let n = f.read(&mut buf)?;
        if n == 0 {
            break;
        }
        let chunk = &buf[..n];
        crc.update(chunk);
        md5.update(chunk);
        sha1.update(chunk);
        sha256.update(chunk);
        for &b in chunk {
            hist[b as usize] += 1;
        }
        if first.len() < 64 {
            let need = 64 - first.len();
            first.extend_from_slice(&chunk[..need.min(chunk.len())]);
        }
        scanner.feed(chunk);
        size += n as u64;
    }
    scanner.flush();
    Ok(FileAnalysis {
        size,
        kind: identify(&first).to_string(),
        entropy: entropy(&hist, size),
        crc32: crc.finalize(),
        md5: md5.finalize(),
        sha1: sha1.finalize(),
        sha256: sha256.finalize(),
        string_count: scanner.count,
        sample_strings: scanner.samples,
        strings_truncated: scanner.truncated,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn identifies_magic_and_text() {
        assert_eq!(identify(b"MZ\x90\x00"), "PE/DOS executable (MZ)");
        assert_eq!(identify(b"\x7fELF\x02"), "ELF executable");
        assert_eq!(identify(b"%PDF-1.7"), "PDF document");
        assert_eq!(identify(b"hello world\n"), "text");
        assert_eq!(identify(b"\x00\x01\x02\xff"), "binary data");
        assert_eq!(identify(b""), "empty");
    }

    #[test]
    fn entropy_bounds() {
        let mut uniform = [0u64; 256];
        for c in uniform.iter_mut() {
            *c = 1;
        }
        assert!((entropy(&uniform, 256) - 8.0).abs() < 1e-9);
        let mut constant = [0u64; 256];
        constant[b'A' as usize] = 1000;
        assert!(entropy(&constant, 1000).abs() < 1e-9);
    }

    #[test]
    fn analyze_a_temp_file() {
        let dir = std::env::temp_dir();
        let path = dir.join(format!("sanctum-t0-{}.bin", std::process::id()));
        let p = path.to_str().unwrap();
        std::fs::write(p, b"abc hello sanctum\x00\x01needle_string_here").unwrap();
        let a = analyze_file(p).unwrap();
        let _ = std::fs::remove_file(p);
        assert_eq!(a.size, 37);
        assert_eq!(a.kind, "binary data"); // the NUL makes it binary
                                           // "abc hello sanctum" (17) and "needle_string_here" (18) are runs >= 4.
        assert_eq!(a.string_count, 2);
        assert!(a
            .sample_strings
            .iter()
            .any(|s| s.contains("needle_string_here")));
        assert!(!a.strings_truncated);
        assert_eq!(a.sha256.len(), 64);
        assert_eq!(a.md5.len(), 32);
    }
}
