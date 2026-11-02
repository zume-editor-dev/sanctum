//! Result format v1 — the JSON contract Zume Editor and its MCP server parse
//! (ADR 0048 / docs/PENTEST_COMPANION_DESIGN.md section 4 in the editor repo).
//! Hand-emitted, no serde, so the tool keeps zero third-party dependencies.

/// One finding. `kind` and `severity` are free text; the editor groups by them.
pub struct Finding {
    pub kind: String,
    pub severity: String,
    pub target: String,
    pub title: String,
    pub detail: String,
    pub evidence_path: String,
    pub address: String,
}

impl Finding {
    pub fn new(
        kind: &str,
        severity: &str,
        target: impl Into<String>,
        title: impl Into<String>,
    ) -> Self {
        Finding {
            kind: kind.to_string(),
            severity: severity.to_string(),
            target: target.into(),
            title: title.into(),
            detail: String::new(),
            evidence_path: String::new(),
            address: String::new(),
        }
    }

    pub fn detail(mut self, detail: impl Into<String>) -> Self {
        self.detail = detail.into();
        self
    }
}

/// A whole run's result (result format v1).
pub struct Report {
    pub tool: String,
    pub version: String,
    pub started: String,
    pub finished: String,
    pub scope: String,
    pub findings: Vec<Finding>,
    pub warnings: Vec<String>,
}

impl Report {
    pub fn new(scope: String, started: String) -> Self {
        Report {
            tool: "sanctum".to_string(),
            version: env!("CARGO_PKG_VERSION").to_string(),
            started,
            finished: String::new(),
            scope,
            findings: Vec::new(),
            warnings: Vec::new(),
        }
    }

    /// Serialize as the compact single JSON object the editor reads.
    pub fn to_json(&self) -> String {
        let mut s = String::new();
        s.push('{');
        s.push_str("\"schema\":1,");
        push_field(&mut s, "tool", &self.tool);
        s.push(',');
        push_field(&mut s, "version", &self.version);
        s.push(',');
        push_field(&mut s, "started", &self.started);
        s.push(',');
        push_field(&mut s, "finished", &self.finished);
        s.push(',');
        push_field(&mut s, "scope", &self.scope);
        s.push(',');
        s.push_str("\"findings\":[");
        for (i, f) in self.findings.iter().enumerate() {
            if i > 0 {
                s.push(',');
            }
            s.push('{');
            push_field(&mut s, "kind", &f.kind);
            s.push(',');
            push_field(&mut s, "severity", &f.severity);
            s.push(',');
            push_field(&mut s, "target", &f.target);
            s.push(',');
            push_field(&mut s, "title", &f.title);
            s.push(',');
            push_field(&mut s, "detail", &f.detail);
            s.push(',');
            push_field(&mut s, "evidence_path", &f.evidence_path);
            s.push(',');
            push_field(&mut s, "address", &f.address);
            s.push('}');
        }
        s.push_str("],\"warnings\":[");
        for (i, w) in self.warnings.iter().enumerate() {
            if i > 0 {
                s.push(',');
            }
            s.push_str(&jstr(w));
        }
        s.push_str("]}");
        s
    }
}

fn push_field(out: &mut String, key: &str, value: &str) {
    out.push('"');
    out.push_str(key);
    out.push_str("\":");
    out.push_str(&jstr(value));
}

/// A JSON string literal with the mandatory escapes.
pub fn jstr(s: &str) -> String {
    let mut out = String::with_capacity(s.len() + 2);
    out.push('"');
    for c in s.chars() {
        match c {
            '"' => out.push_str("\\\""),
            '\\' => out.push_str("\\\\"),
            '\n' => out.push_str("\\n"),
            '\r' => out.push_str("\\r"),
            '\t' => out.push_str("\\t"),
            c if (c as u32) < 0x20 => out.push_str(&format!("\\u{:04x}", c as u32)),
            c => out.push(c),
        }
    }
    out.push('"');
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn escapes_json_strings() {
        assert_eq!(jstr("a\"b\\c"), "\"a\\\"b\\\\c\"");
        assert_eq!(jstr("x\ny\tz"), "\"x\\ny\\tz\"");
        assert_eq!(jstr("\u{1}"), "\"\\u0001\"");
        assert_eq!(jstr("ok"), "\"ok\"");
    }

    #[test]
    fn serializes_a_report() {
        let mut r = Report::new(
            "192.0.2.0/30".to_string(),
            "2026-11-03T00:00:00Z".to_string(),
        );
        r.finished = "2026-11-03T00:00:01Z".to_string();
        r.findings
            .push(Finding::new("host", "info", "192.0.2.1", "Host up").detail("1 open port(s)"));
        r.findings.push(Finding::new(
            "service",
            "low",
            "192.0.2.1:22",
            "open 22/tcp (ssh)",
        ));
        r.warnings.push("4 host(s), 1 responded".to_string());
        let json = r.to_json();
        assert!(json.starts_with("{\"schema\":1,\"tool\":\"sanctum\","));
        assert!(json.contains("\"scope\":\"192.0.2.0/30\""));
        assert!(json.contains("\"kind\":\"host\""));
        assert!(json.contains("\"target\":\"192.0.2.1:22\""));
        assert!(json.contains("\"warnings\":[\"4 host(s), 1 responded\"]}"));
    }
}
