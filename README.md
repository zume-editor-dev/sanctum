# sanctum

**Authorized-scope reconnaissance companion for [Zume Editor](https://smolt-stage.com/home/en/zume-editor.html).**

`sanctum` runs *scoped* reconnaissance and writes its findings as a small JSON
document that Zume Editor reads — in the editor via **Tools → Run Security
Analyzer…**, or from an AI agent via the MCP `analyze_run` tool. It is a
separate, optional tool: **nothing here ships with the editor**, and the editor
contains no attack code. See the editor's design note `PENTEST_COMPANION_DESIGN.md`
(ADR 0048) for the integration contract.

> ⚠️ **Authorized use only.** Run `sanctum` only against systems you **own** or
> are **explicitly authorized** to test (your own hosts, a client engagement with
> written permission, or a lab / CTF). Active probing is **refused** unless you
> pass `--i-am-authorized`. Reconnaissance against systems without permission may
> be illegal. You are responsible for staying in scope.

## What it does (v0.1)

- **Tier T1 — active recon** (opt-in, scope-limited): TCP **connect** host
  discovery and port enumeration. Connect scans only — no raw sockets, no SYN
  scanning, no exploitation, no credential attacks.
- Emits **result format v1** JSON: a host that responds and each open port
  become findings the editor lists and can act on.

Heavier capability (authenticated checks, templated probes) is out of scope for
v0.1, and exploitation / payload generation / C2 are **not** goals of this tool.

## Install

```sh
cargo build --release
# binary at target/release/sanctum
```

Zero third-party dependencies — a std-only Rust build, so it builds offline.

## Usage

```sh
sanctum --scope <SCOPE> --i-am-authorized [--json <PATH>] [--ports <SPEC>]
```

- `--scope` — an IP, an IPv4 CIDR (`a.b.c.d/bits`), a hostname, or a URL.
- `--i-am-authorized` — required; confirms you may test the scope.
- `--json <PATH>` — write the result JSON there (Zume passes `{out}`); otherwise
  it goes to stdout.
- `--ports "22,80,443,8000-8010"` — defaults to a small common set.
- `--timeout-ms` (default 800), `--max-hosts` (default 1024), `--max-ports`
  (default 1024), `--audit <PATH>` (default `$SANCTUM_AUDIT` or `./sanctum-audit.log`).

Examples:

```sh
# A single host, common ports, result to stdout:
sanctum --scope 192.0.2.10 --i-am-authorized

# A /28 with chosen ports, result to a file (as Zume invokes it):
sanctum --scope 192.0.2.0/28 --ports 22,80,443 --json out.json --i-am-authorized
```

## Use it from Zume Editor

Point the editor at the binary in `settings.json`:

```json
{
  "analyzer_tools": "recon = sanctum --scope \"{target}\" --json \"{out}\" --i-am-authorized"
}
```

Then **Tools → Run Security Analyzer…**, pick `recon`, and enter the authorized
scope. For the MCP server, set the same `name = command` line in the
`ZUME_ANALYZER_TOOLS` environment variable.

## Result format (v1)

A single JSON object written to `--json` (`{out}`):

```json
{
  "schema": 1,
  "tool": "sanctum", "version": "0.1.0",
  "started": "2026-11-03T09:00:00Z", "finished": "2026-11-03T09:00:12Z",
  "scope": "192.0.2.0/28",
  "findings": [
    { "kind": "host", "severity": "info", "target": "192.0.2.10",
      "title": "Host up", "detail": "2 open port(s)", "evidence_path": "", "address": "" },
    { "kind": "service", "severity": "low", "target": "192.0.2.10:22",
      "title": "open 22/tcp (ssh)", "detail": "", "evidence_path": "", "address": "" }
  ],
  "warnings": []
}
```

The `{out}` file is the source of truth: a run that exits non-zero but still
wrote a result is read normally. Any analyzer that emits this format works with
Zume — `sanctum` is one reference implementation.

## Safety design

- **Authorization gate** — active probing is off until `--i-am-authorized`.
- **Scope is the boundary** — only hosts inside the parsed scope are probed, and
  a scope larger than `--max-hosts` is refused.
- **Conservative** — sequential connects with a short timeout; not an aggressive
  scan, no mass targeting.
- **Audit log** — every run and every refusal is appended to the audit file.

## License

Apache-2.0. Copyright 2026 SMOLT STAGE, K.K. Part of the Zume Editor ecosystem,
developed and released independently of the editor.
