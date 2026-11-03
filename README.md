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

## What it does (v0.18)

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
- **Tier T2 — web diagnostics** (`--web <URL>`, opt-in, **non-destructive**;
  v0.14, ADR 0001): makes one HTTP(S) request to an authorized URL and audits
  the response — missing / weak **security headers** (HSTS, CSP,
  X-Content-Type-Options, X-Frame-Options, Referrer-Policy), **cookie flags**
  (Secure / HttpOnly / SameSite), **software / version disclosure** (`Server`,
  `X-Powered-By`) and the **transport posture** (plaintext HTTP). With
  **`--crawl`** (v0.15) it follows **same-origin** links (bounded by
  `--max-pages`, depth-limited and rate-limited) and audits every page, with the
  site-wide findings collapsed. With **`--active`** (v0.16) it probes query
  parameters for **reflected XSS**: it sends a benign unique marker (no script
  executes) and reports a parameter whose injected `<` comes back **unencoded**
  as a high-severity candidate, or an encoded reflection as info. It also probes
  for **SQL injection** (v0.17) — **error-based** (a single quote surfaces a DB
  error a clean response lacked) and **time-based** (a bounded `SLEEP`/`pg_sleep`/
  `WAITFOR` payload delays the response, confirmed with a second probe to shed
  jitter) — reporting the parameter as a high-severity candidate. **Existence
  only: no data is ever read.** It also checks **open redirect** (a
  redirect-looking parameter that sends a 3xx `Location` to an external canary),
  enumerates **allowed methods** (OPTIONS `Allow`, flagging TRACE) and probes a
  small set of **sensitive paths** (`.git/HEAD`, `.env`, backups, `server-status`,
  …) at the origin root (v0.18). Separately, **CSRF-token presence** is checked
  **passively** (always): a POST form with no apparent hidden token field is
  flagged.
- Emits **result format v1** JSON that the editor lists and can act on.

Exploitation, payload / shellcode generation, C2, data extraction (e.g. sqlmap
`--dump`), authentication-bypass execution, WAF evasion, brute-force and DoS are
**not** goals and are out of scope (ADR 0001).

## Detection matrix

What a capture (`--file capture.pcap[ng]`) is scanned for. All of it is offline
and passive — structure parsing only; nothing is decrypted that needs a secret
key, and nothing is cracked. The finding `kind` / `severity` is what appears in
the result JSON (`credential` / `auth` → `high`, `note` → `info`).

| Source | What sanctum recovers | kind | severity |
|---|---|---|---|
| Any file | type (magic), CRC32 / MD5 / SHA-1 / SHA-256, entropy, strings | `note` | info |
| Link / IP / transport | endpoints and destination services; Ethernet · VLAN / QinQ · MPLS · raw · Linux-SLL, IPv4 / IPv6 (+ ext-headers), TCP / UDP, IP-in-IP / GRE | `host` / `service` | info / low |
| HTTP Basic / Digest | user : password (Basic), realm / nonce (Digest) | `credential` | high |
| FTP / POP3 | `USER` / `PASS` | `credential` | high |
| IMAP | `LOGIN` user / password | `credential` | high |
| SMTP | AUTH PLAIN / LOGIN credentials | `credential` | high |
| Web form | submitted password fields | `credential` | high |
| Telnet | plaintext login / password | `credential` | high |
| LDAP simple bind | bind DN + **cleartext password** | `credential` | high |
| SNMP v1 / v2c | **community string** (device password) | `credential` | high |
| TLS 1.2 / 1.3 | server name (SNI) | `note` | info |
| QUIC v1 Initial | server name (SNI), after removing Initial protection (RFC 9001) | `note` | info |
| NTLMSSP | domain \ user, workstation, server challenge, NetNTLMv1 / v2 presence | `auth` | high |
| Kerberos | AS-REQ / AS-REP / TGS principal + realm; weak etype → Kerberoast / AS-REP-roast | `auth` | high |
| RADIUS | cleartext User-Name, calling station, User-Password present; MS-CHAP (crackable) | `note` + `auth` | info / high |
| SMB1 / SMB2 | SMB1 legacy, dialect, signing policy, SESSION_SETUP, TREE_CONNECT, CREATE paths | `note` | info |
| LDAP (other) | SASL mechanism, StartTLS, SearchRequest base / filter / attributes | `note` | info |
| DCE/RPC | bound interface UUID → service (DRSUAPI / DCSync, SVCCTL / task-sched exec, SPOOLSS / EFSRPC coercion, NETLOGON, SAMR / LSARPC) | `note` | info |

Active scanning (`--scope`, opt-in) adds `host` / `service` findings from TCP
connect host discovery, port enumeration and banner grabbing. Web diagnostics
(`--web <URL>`, opt-in, non-destructive) add `web` findings:

| Check | What it flags | severity |
|---|---|---|
| Transport | plaintext HTTP (no TLS) | medium |
| HSTS | missing Strict-Transport-Security on https | medium |
| Security headers | missing CSP / X-Content-Type-Options / X-Frame-Options / Referrer-Policy | low / info |
| Cookie flags | Set-Cookie without Secure / HttpOnly / SameSite | medium / low |
| Disclosure | `Server` version, `X-Powered-By` | low |
| Reflected XSS (`--active`) | a query parameter reflected unencoded (injected `<` survives) | high |
| Reflected input (`--active`) | a query parameter reflected but HTML-encoded | info |
| SQLi error-based (`--active`) | a single quote surfaces a DB error (MySQL / MSSQL / PostgreSQL / Oracle / SQLite) | high |
| SQLi time-based (`--active`) | a bounded sleep payload delays the response (confirmed twice) | high |
| Open redirect (`--active`) | a redirect parameter sends a 3xx Location to an external canary | high |
| Method enumeration (`--active`) | OPTIONS `Allow` methods; TRACE advertised | info / medium |
| Sensitive paths (`--active`) | `.git/HEAD`, `.env`, backups, `server-status`, … reachable at the root | high / medium / info |
| CSRF (passive) | a POST form with no apparent hidden token field | low |

## Install

```sh
cargo build --release
# binary at target/release/sanctum
```

Tiers T0 / T1 are std-only. The T2 web tier (ADR 0001) adds a small, pinned
dependency set — `ureq` over `rustls` (no OpenSSL, no async runtime) — so the
build fetches those crates; everything else stays dependency-free.

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

# Non-destructive web diagnostics of one authorized URL:
sanctum --web https://app.example.com/ --json out.json --i-am-authorized
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
