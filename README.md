# wp2shell_scanner

[![smoke](https://github.com/zi3lak/wp2shell_scanner/actions/workflows/smoke.yml/badge.svg)](https://github.com/zi3lak/wp2shell_scanner/actions/workflows/smoke.yml)
[![License: MIT](https://img.shields.io/badge/License-MIT-informational.svg)](LICENSE)
[![Python 3.7+](https://img.shields.io/badge/python-3.7%2B-blue.svg)](https://www.python.org/)
[![Mode: detection-only](https://img.shields.io/badge/mode-detection--only-brightgreen.svg)](#what-it-explicitly-does-not-do)
[![CVE-2026-63030 · CVE-2026-60137](https://img.shields.io/badge/CVE-2026--63030%20%C2%B7%202026--60137-C81E3A.svg)](https://github.com/advisories/GHSA-ff9f-jf42-662q)

**Non-intrusive detection scanner for recent WordPress *core* vulnerabilities — including the `wp2shell` pre-authentication RCE chain.**

`wp2shell_scanner.py` fingerprints a WordPress site's core version and reads its
publicly advertised REST API surface, then classifies **each tracked core CVE
independently** against the detected version. Verdicts are **branch-aware** — e.g. a
`6.8.x` site is correctly reported as exposed to the SQL-injection CVE but *not* to the
full RCE chain. It **detects only**: no exploit payload is ever sent. Single file, one
dependency (`requests`), CI-friendly exit codes, and client-ready HTML / JSON / e-mail
reports.

> ⚠️ **Authorised use only.** Scan systems you own or are explicitly authorised (in
> writing) to test. The scanner sends an identifying `User-Agent` so blue teams can
> attribute the traffic — it does not hide.

---

## Tracked vulnerabilities (WordPress core)

| CVE | Weakness | Access | Affected core | Fixed in |
|-----|----------|--------|---------------|----------|
| **CVE-2026-63030** — wp2shell | CWE-436 — REST batch route confusion → **RCE** (Critical, `GHSA-ff9f-jf42-662q`) | Unauthenticated | `6.9.0`–`6.9.4`, `7.0.0`–`7.0.1` | `6.9.5`, `7.0.2` |
| **CVE-2026-60137** | CWE-89 — SQL injection in `WP_Query` `author__not_in` (High) | Unauthenticated | `6.8.0`–`6.8.5`, `6.9.0`–`6.9.4`, `7.0.0`–`7.0.1` | `6.8.6`, `6.9.5`, `7.0.2` |
| **CVE-2026-3906** | CWE-862 — Notes REST API missing authorization (Moderate, CVSS 4.3, `GHSA-6x83-fcf5-r65g`) | Subscriber+ | `6.9.0`–`6.9.3` | `6.9.4` |

**The `wp2shell` RCE chain** = CVE-2026-63030 **+** CVE-2026-60137 together → **pre-auth
remote code execution** on a default install. The scanner reports the chain as *exposed*
only when **both** CVEs classify as vulnerable for the detected version.

**Branch nuances the scanner gets right:**
- `6.8.x` carries the SQL injection (CVE-2026-60137) **only** — not the RCE chain.
- CVE-2026-3906 was only *partially* fixed in `6.9.2`/`6.9.3` and **fully** fixed in
  `6.9.4`, while the wp2shell chain isn't closed until `6.9.5`. So a `6.9.4` site reads
  *patched* for the Notes bug but still *vulnerable* to the RCE chain.

**Operationally important:** technical write-ups and a working PoC for wp2shell are
already public. Version detection is now the *absolute minimum* — the priority is
**patching**. Updating closes the vulnerable path but **does not remove a backdoor
planted before the patch** — hence the compromise-assessment step in the report.

### Scope

This is a **core-version** scanner. Plugin and theme CVEs — the large majority of the
WPScan / Patchstack catalogue — require a live, curated feed and per-plugin version
enumeration, and are intentionally **out of scope** here. Within its lane (recent
WordPress core CVEs), it aims to be precise and branch-accurate rather than to
duplicate a commercial vulnerability database.

---

## What the scanner does

- **Passive version fingerprint** via several independent vectors:
  - `<meta name="generator">` on the homepage
  - `/readme.html`
  - RSS / Atom feed `<generator>` tag
  - `/wp-links-opml.php` (OPML)
  - REST root `/wp-json/`
- **Passive REST-surface read** of `/wp-json/` to check whether the `batch/v1`
  namespace is registered (i.e. the vulnerable endpoint is reachable). **No batch
  request and no payload are sent** — it only reads the advertised route list.
- **Verdict mapping** — the detected version is compared against the affected/fixed
  ranges to produce a per-CVE verdict, plus:
  - a **client-ready HTML report** (print → PDF),
  - a **JSON record** (pipeline/EAV-friendly),
  - a **draft notification e-mail**.

### What it explicitly does **not** do

It does **not** exploit anything. No SQL-injection payload, no batch-route-confusion
request, no attempt to execute code or read data. Detection is version-based plus a
passive read of the publicly advertised API surface.

---

## Install

```bash
pip install requests
```

## Usage

```bash
# single target
python3 wp2shell_scanner.py -t https://site.example --authorized

# list of targets (one per line, # comments allowed)
python3 wp2shell_scanner.py -T scope.txt --authorized -o ./reports

# preview the output formats with synthetic data — no network, no auth needed
python3 wp2shell_scanner.py --demo -o ./reports
```

### Flags

| Flag | Meaning |
|------|---------|
| `-t, --target` | Single target URL or host |
| `-T, --targets-file` | File with one target per line |
| `--demo` | Generate a **SAMPLE** report/e-mail from synthetic data (no network) |
| `-o, --output-dir` | Output directory (default `./wp2shell_reports`) |
| `--formats` | Comma list: `json,html,email` (default: all) |
| `--authorized` | **Authorisation gate** — required for live scans |
| `--timeout` | HTTP timeout in seconds (default 12) |
| `--delay` | Seconds between targets (be polite; default 1.0) |
| `--insecure` | Do not verify TLS certificates |
| `--quiet` | Suppress the console summary |

The `--authorized` flag is an explicit authorisation gate — live scans refuse to run
without it.

### Exit codes (CI-friendly)

| Code | Meaning |
|------|---------|
| `2` | At least one target **vulnerable** |
| `1` | At least one target **inconclusive** / error |
| `0` | Clean (patched / not affected / not WordPress) |

### Configuration

The notification e-mail recipient is the `CSSLTD_CONTACT` constant near the top of the
script (default `ops@cyberssl.co.uk`). Edit it to your own intake address.

---

## Verdicts

| Verdict | Meaning |
|---------|---------|
| `VULNERABLE` | Detected version falls inside an affected range — patch immediately |
| `PATCHED` | On a fixed release; not exposed to this chain |
| `NOT_AFFECTED` | Version predates the flaw (< 6.9.0) |
| `UNKNOWN` | Version could not be confirmed — verify manually |
| `NOT_WORDPRESS` | No WordPress fingerprint found |

---

## Example output

The [`examples/`](examples/) directory contains **synthetic** (`--demo`) output for a
fictional vulnerable host (`example.com`, WordPress 6.9.1 — exposed to all three tracked CVEs):

- [`wp2shell_report_example.com.html`](examples/) — the client-ready HTML report
- [`wp2shell_example.com.json`](examples/) — the JSON record
- [`wp2shell_email_example.com.txt`](examples/) — the draft notification e-mail

> These are generated from fabricated data to illustrate the report format. They are
> **not** the result of scanning any real site.

---

## Remediation (as emitted in the report)

1. Take a verified backup (DB + full file tree) first.
2. Update WordPress core to the fixed release for your branch — **6.8.6 / 6.9.4 / 6.9.5 / 7.0.2** — or later.
3. Confirm the site and admin still work.
4. **Assume compromise** if the host was exposed while vulnerable — run a compromise
   assessment across themes, plugins, `uploads/`, `wp-config.php`, wp-cron, and admin
   accounts; run file-integrity checks against known-good core.
5. Add defence-in-depth at the edge (WAF rules, restrict `/wp-json/batch/v1`).
6. Rotate secrets (auth salts, admin/DB passwords, API keys) if compromise is suspected.
7. Re-scan to confirm the verdict now reads **Patched**.

---

## References

- [WordPress GitHub Security Advisory — wp2shell (GHSA-ff9f-jf42-662q)](https://github.com/advisories/GHSA-ff9f-jf42-662q)
- [WordPress GitHub Security Advisory — Notes REST API (GHSA-6x83-fcf5-r65g)](https://github.com/advisories/GHSA-6x83-fcf5-r65g)
- [NVD — CVE-2026-3906](https://nvd.nist.gov/vuln/detail/CVE-2026-3906)
- [Rapid7 — ETR: CVE-2026-63030 wp2shell](https://www.rapid7.com/blog/post/etr-cve-2026-63030-wp2shell-a-critical-remote-code-execution-vulnerability-in-wordpress-core/)
- [VulnCheck — WP2Shell (CVE-2026-63030 & CVE-2026-60137)](https://www.vulncheck.com/blog/wp2shell)
- [WordPress releases (6.8.6 / 6.9.4 / 6.9.5 / 7.0.2)](https://wordpress.org/download/releases/)

---

## Disclaimer

This tool is for **authorised security testing** only. You are responsible for
ensuring you have permission to scan any target. Unauthorised scanning may be unlawful.
The authors accept no liability for misuse.
