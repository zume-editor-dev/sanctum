//! Append-only audit log. Every run - and every refusal - is recorded, so there
//! is a local trail of what was probed, when, and against which scope.

use std::fs::OpenOptions;
use std::io::Write;
use std::path::{Path, PathBuf};

/// The audit log path: --audit, else $SANCTUM_AUDIT, else ./sanctum-audit.log.
pub fn audit_path(explicit: Option<&str>) -> PathBuf {
    if let Some(p) = explicit {
        if !p.is_empty() {
            return PathBuf::from(p);
        }
    }
    if let Ok(p) = std::env::var("SANCTUM_AUDIT") {
        if !p.is_empty() {
            return PathBuf::from(p);
        }
    }
    PathBuf::from("sanctum-audit.log")
}

/// Append one line (best-effort: a logging failure never blocks a run).
pub fn log(path: &Path, line: &str) {
    if let Ok(mut f) = OpenOptions::new().create(true).append(true).open(path) {
        let _ = writeln!(f, "{line}");
    }
}
