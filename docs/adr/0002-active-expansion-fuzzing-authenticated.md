# ADR 0002 - Active web-check expansion, non-destructive fuzzing, authenticated scanning

Status: accepted (2026-11-04)

## Context

ADR 0001 established tier T2 (web diagnostics): active but **non-destructive**
HTTP(S) checks against an authorized URL, gated by `--i-am-authorized`,
scope-bound, rate-limited and audited. Increments 1-4 delivered the passive
response audit, a bounded same-origin crawl, reflected-XSS / SQL-injection
*existence* detection, open-redirect, directory / method enumeration and CSRF
presence.

The operator asked to go further in three directions, each of which needs its
boundary fixed *before* code so the non-destructive guarantee is not eroded by
accident:

1. **More active web checks** - the behaviour-based injection classes that
   naturally follow SQLi/XSS.
2. **Non-destructive fuzzing** - input mutation that surfaces anomalies.
3. **Authenticated / session-aware scanning** - running the checks as a
   logged-in user.

ADR 0001's out-of-scope list is unchanged and still binds: no exploitation,
payload/shellcode/C2, data extraction (sqlmap `--dump`), auth-bypass execution,
WAF evasion, brute-force, or **DoS / fuzzing-for-crash**. This ADR says exactly
how each new capability stays inside that line.

## Decision

### 1. Active web-check expansion (`--active`, increment 5)

Add three behaviour-based **existence** checks, each GET-only, capped by the
shared probe budget, rate-limited, and - where it relies on timing - confirmed
with a second probe to shed jitter (the SQLi time-based pattern):

- **OS command injection (time-based)**. Inject a *benign* delay command
  (`sleep`/`ping`/`timeout`) into a parameter and confirm a measured delay. This
  mirrors time-based SQLi exactly: it establishes that a parameter reaches a
  shell **without running a harmful command and without reading any output**.
  The only command ever sent is a sleep.
- **Path traversal (structural-signature existence)**. Send a traversal payload
  and match only a **well-known structural, non-secret signature** - the shape
  of a `root:x:0:0:` line, or a `[extensions]`/`[fonts]` INI marker - to confirm
  the flaw, suppressed against a baseline that already shows it. The finding
  reports *existence and which signature matched*; it **never includes file
  contents**, never requests a secret-bearing file, and never pages through the
  filesystem. This is the one check that touches "file access"; it is bounded to
  a single existence confirmation and is a deliberate, narrow relaxation of ADR
  0001's "no file access", not data extraction.
- **CRLF / HTTP response-header injection**. Inject a `CR LF` plus a benign
  marker header into a parameter and detect the marker **coming back as a real
  response header**. The marker header is inert (`X-Sanctum-Inject: 1`); nothing
  is cached, poisoned or persisted.

### 2. Non-destructive fuzzing (`--fuzz`, increment 6)

Fuzzing here means **bounded input mutation that classifies response
differences**, not high-volume crash fuzzing. It is explicitly *not* ADR 0001's
forbidden "fuzzing-for-crash / DoS":

- A small, curated, benign payload set (quotes, template markers, boundary
  numbers, a `../`, and one **bounded** 1 KiB string for length-handling
  observation - a single request, never a flood) is sent one payload at a time
  per parameter, rate-limited, under the shared probe cap.
- Each response is compared to a baseline and an **anomaly** is reported when the
  status class changes (e.g. a `500` on input), a known DB error signature
  appears, a **template expression evaluates** (SSTI existence: `1337*1337` ->
  `1787569`, a product too specific to occur by chance), or the body length
  changes markedly.
- **Hidden-parameter discovery**: a small wordlist of common parameter names is
  tried with a unique sentinel; a name is reported when the sentinel reflects or
  the response changes against the no-parameter baseline.

Hard limits make it incapable of acting as a flood: no concurrency, a small
payload/word set, the per-run probe budget, the inter-request delay, and bounded
payload sizes. The goal is never to crash the target; an input that happened to
crash it would be reported, not repeated.

### 3. Authenticated / session-aware scanning (`--auth-cookie`, `--auth-header`)

The operator supplies **their own** session material; sanctum attaches it to
every T2 request so the checks run inside an authenticated session. The
boundary:

- sanctum **never logs in, never brute-forces, never handles or derives
  credentials**. It forwards exactly the `Cookie` value and extra headers the
  operator passed (e.g. a bearer token). Obtaining that session is the operator's
  responsibility, in scope.
- The session material is a **secret**: it is **never** written to the audit log,
  the result JSON, or stderr. Only the *fact* that auth was supplied (and how
  many headers) is audited. This mirrors sanctum's standing rule that credentials
  are never stored or emitted.
- Authenticated scanning stays **GET/OPTIONS-only and non-destructive**. To keep
  an authenticated session from logging itself out or tripping a state change
  through a GET, the crawl now **skips destructive-looking links**
  (logout/delete/remove/reset/...). This guard is unconditional - it hardens the
  non-destructive guarantee for anonymous crawls too.

## Consequences

- The T2 surface grows but stays within ADR 0001: every new check is
  existence-only or difference-only, GET/OPTIONS, capped, rate-limited and
  audited, and the forbidden list is untouched.
- Path traversal is the single deliberate relaxation ("no file access" ->
  "confirm the flaw via a non-secret structural signature, contents never
  emitted"); it is recorded here so the relaxation is explicit and reviewable.
- `fetch` carries operator-supplied headers now; the session secret flows only
  into the outgoing request, never into any sink.
- result format v1 is unchanged: all new findings are the `web` kind with the
  existing severities, so the editor's analyzer panel shows them unchanged.
