# sanctum

[![CI](https://github.com/zume-editor-dev/sanctum/actions/workflows/ci.yml/badge.svg)](https://github.com/zume-editor-dev/sanctum/actions/workflows/ci.yml)
[![License: Apache-2.0](https://img.shields.io/badge/License-Apache--2.0-blue.svg)](LICENSE)

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

## What it does (v0.13)

- **Tier T1 — active recon** (`--scope`, opt-in, scope-limited): TCP **connect**
  host discovery and port enumeration. Connect scans only — no raw sockets, no
  SYN scanning, no exploitation, no credential attacks.
- **Banner grab / passive fingerprint** (on by default; `--no-banner` to skip):
  reads the greeting a service volunteers on connect (SSH, SMTP, FTP, POP3,
  IMAP, …) or, for an HTTP port, the `Server:` header from one HEAD request, and
  records it as the finding's `detail`. TLS ports are skipped. No
  protocol-specific exploit is ever sent.
- **Tier T0 — offline file analysis** (`--file`, no network): identify the file
  type (magic), compute **CRC32 / MD5 / SHA-1 / SHA-256**, Shannon **entropy**,
  and extract **printable strings** — in one streaming pass. Purely passive: it
  reads a file you point it at and sends nothing anywhere, so it needs no
  `--i-am-authorized`.
- **Tier T0 — capture summary** (`.pcap` and `.pcapng`): when `--file` is a
  capture, it also summarizes the **endpoints and destination services** seen —
  Ethernet (incl. stacked **VLAN / QinQ**) / **MPLS** / raw / Linux-SLL, IPv4 /
  IPv6 (**extension headers followed**), TCP / UDP, and **IP-in-IP / GRE**
  tunnels — as host and service findings alongside the file's hashes.
- **Tier T0 — plaintext credentials**: recovers credentials that cross a capture
  in the clear — **HTTP Basic** and **Digest** auth, **FTP / POP3** `USER` /
  `PASS`, **IMAP** `LOGIN`, web form password fields, **SMTP AUTH PLAIN**, and
  **Telnet** plaintext sessions — as high-severity findings. A reminder of why
  plaintext protocols are a problem; for authorized analysis of a capture you
  hold.
- **Tier T0 — TLS / QUIC SNI**: extracts the server names (**SNI**) from TLS
  ClientHello messages (TLS 1.2 and 1.3 — the SNI is cleartext in both) and from
  **QUIC v1 Initial** packets (v0.9), whose Initial protection is removed with
  keys derived from the visible connection ID (RFC 9001; AES-128-GCM / HKDF-SHA256
  implemented from scratch and checked against the RFC 9001 and NIST test
  vectors), so you can see which hosts a capture reached even over QUIC / HTTP3.
- **Tier T0 — NTLM / Kerberos** (v0.8): surfaces Windows authentication
  handshakes — **NTLMSSP** challenge/authenticate (domain \\ user, workstation,
  server challenge, NetNTLMv1/v2 presence; raw or base64 in HTTP) and
  **Kerberos** AS-REQ / AS-REP / TGS messages (principal and realm) — as
  high-severity findings. For Kerberos it also reports the **encryption type** of
  any EncryptedData and flags a weak one (RC4-HMAC / DES) as a **Kerberoast /
  AS-REP-roast** candidate (v0.11).
- **Tier T0 — SMB2 / LDAP** (v0.10): reads the **LDAP** BindRequest — a *simple*
  bind's DN and **cleartext password** (a high-severity credential), a SASL
  bind's mechanism, a **StartTLS** request, and a **SearchRequest**'s base DN,
  rendered filter (e.g. `(servicePrincipalName=*)`) and requested attributes
  (v0.11) — and summarizes **SMB1/SMB2** session context: SMB1 (legacy, insecure)
  in use, the negotiated SMB2 dialect, the server's **signing** policy (required
  / enabled / off, v0.11), that a SESSION_SETUP (where NTLM / Kerberos
  authentication happens — the token is recovered above) was seen, and the
  **TREE_CONNECT** share paths and **CREATE** file paths (v0.11) accessed.
- **Tier T0 — DCE/RPC** (v0.12): locates an MSRPC Bind PDU — over TCP or inside
  an SMB named pipe — and names the bound interface, flagging the ones that
  matter for lateral movement: **DRSUAPI** (DCSync), **SVCCTL** / task scheduler
  (remote exec), **SPOOLSS** / **EFSRPC** (coercion), **NETLOGON**, **SAMR** /
  **LSARPC** (enumeration).
- **Tier T0 — SNMP / RADIUS** (v0.13): recovers an **SNMP** v1 / v2c **community
  string** (the device password, in the clear) as a high-severity credential,
  and reads a **RADIUS** packet — the cleartext **User-Name** and calling
  station, whether a secret-encrypted User-Password is present, and a Microsoft
  **MS-CHAP** VSA (crackable offline) — as session context and auth material.
- Emits **result format v1** JSON that the editor lists and can act on.

Heavier network capability (authenticated checks, templated probes) is out of
scope for now, and exploitation / payload generation / C2 are **not** goals.

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
- `--no-banner` — skip banner grabbing (report open ports only).
- `--timeout-ms` (default 800), `--max-hosts` (default 1024), `--max-ports`
  (default 1024), `--audit <PATH>` (default `$SANCTUM_AUDIT` or `./sanctum-audit.log`).

Examples:

```sh
# A single host, common ports, result to stdout:
sanctum --scope 192.0.2.10 --i-am-authorized

# A /28 with chosen ports, result to a file (as Zume invokes it):
sanctum --scope 192.0.2.0/28 --ports 22,80,443 --json out.json --i-am-authorized

# Offline analysis of a local file (no network, no authorization needed):
sanctum --file ./suspect.bin --json out.json
```

In Zume, configure a second analyzer for files (its `{target}` is a path):

```json
{ "analyzer_tools": "recon = sanctum --scope \"{target}\" --json \"{out}\" --i-am-authorized\nfile = sanctum --file \"{target}\" --json \"{out}\"" }
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
  "tool": "sanctum", "version": "0.2.0",
  "started": "2026-11-03T09:00:00Z", "finished": "2026-11-03T09:00:12Z",
  "scope": "192.0.2.0/28",
  "findings": [
    { "kind": "host", "severity": "info", "target": "192.0.2.10",
      "title": "Host up", "detail": "2 open port(s)", "evidence_path": "", "address": "" },
    { "kind": "service", "severity": "low", "target": "192.0.2.10:22",
      "title": "open 22/tcp (ssh)", "detail": "SSH-2.0-OpenSSH_9.6p1", "evidence_path": "", "address": "" }
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
  scan, no mass targeting. Banner grabbing is one extra short read per open port
  (a single HEAD request for HTTP), and sends no protocol-specific exploit.
- **Audit log** — every run and every refusal is appended to the audit file.

## License

Apache-2.0. Copyright 2026 SMOLT STAGE, K.K. Part of the Zume Editor ecosystem,
developed and released independently of the editor.
