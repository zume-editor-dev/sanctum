# ADR 0001 - Active, non-destructive web-diagnostic tier (T2)

Status: accepted (2026-11-03)

## Context

sanctum has so far been a passive capture analyser plus a light TCP-connect
recon tool (tiers T0 / T1), with a deliberate **zero-third-party-dependency**
build. The operator asked for web-application diagnostics in the spirit of Burp
Suite / OWASP ZAP / sqlmap - but **detection only**, not exploitation.

Two decisions follow from that request:

1. A new tier that makes *active* HTTP(S) requests to an authorized target and
   reports weaknesses it can observe or safely detect.
2. A relaxation of the zero-dependency rule: a correct, safe HTTPS client (TLS,
   redirects, timeouts) is not something to re-implement by hand.

## Decision

Add tier **T2 (web diagnostics)**, reached with `--web <URL>`, gated exactly
like T1: it refuses to run without `--i-am-authorized`, treats the target URL's
host as the scope, and appends every run to the audit log. It is
**non-destructive**: it never tries to gain code execution, extract data, bypass
authentication, evade a WAF, brute-force credentials, or cause denial of
service.

Allow a small, curated set of dependencies for this tier. The HTTP client is
**`ureq`** (synchronous, built on **rustls** - no OpenSSL, no async runtime),
which matches sanctum's blocking, single-threaded design. The zero-dependency
property is therefore dropped; the new goal is a *small, audited* dependency set
(rustls / ureq and their transitive crates), pinned in `Cargo.lock`.

### In scope (non-destructive detection)

- Passive response audit: missing / weak security headers (HSTS, CSP,
  X-Content-Type-Options, X-Frame-Options, Referrer-Policy, Permissions-Policy),
  cookie flags (Secure / HttpOnly / SameSite), software/version disclosure
  (`Server`, `X-Powered-By`), and the TLS/plaintext posture of the URL.
- Later increments (still non-destructive): a bounded same-origin crawl,
  reflected-XSS probing, error/boolean/time-based SQL-injection **detection**,
  open-redirect detection, directory / method enumeration, CSRF-token presence.
  Each is rate-limited, scope-bound and audited.

### Explicitly out of scope (unchanged from the charter)

- No exploitation, payload / shellcode generation, or C2 (Metasploit-style).
- No data extraction (sqlmap `--dump`), OS command / file access, or auth
  bypass *execution*.
- No WAF evasion, no brute-force, no DoS / fuzzing-for-crash.

Detection that confirms a vulnerability does so with a **non-weaponised** probe
(e.g. a time-based SQLi check establishes *existence* via a measured delay; it
never reads data).

## Consequences

- sanctum now performs active requests against a target in T2; the
  authorization gate, scope boundary, rate limiting and audit log are the
  controls, and they must stay strict.
- The build is no longer dependency-free / offline; CI fetches crates. The
  README's "zero third-party dependencies" claim is updated accordingly.
- result format v1 is unchanged: T2 emits the same `kind` / `severity` findings
  (a `web` kind), so Zume Editor's analyzer panel shows them with no change.
