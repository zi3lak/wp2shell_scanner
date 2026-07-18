# wp2shell_scanner

**Non-intrusive detection scanner for the WordPress `wp2shell` pre-authentication RCE chain.**

`wp2shell_scanner.py` fingerprints a WordPress site's core version and reads its
publicly advertised REST API surface to decide whether the host is exposed to the
**wp2shell** chain — **CVE-2026-63030 + CVE-2026-60137**. It **detects only**: no
exploit payload is ever sent. Single file, one dependency (`requests`), CI-friendly
exit codes, and client-ready HTML / JSON / e-mail reports.

> ⚠️ **Authorised use only.** Scan systems you own or are explicitly authorised (in
> writing) to test. The scanner sends an identifying `User-Agent` so blue teams can
> attribute the traffic — it does not hide.

---

## The vulnerability

`wp2shell` is a chain of two WordPress **core** flaws that together yield
**unauthenticated remote code execution**:

| CVE | Weakness | Component | Role in the chain |
|-----|----------|-----------|-------------------|
| **CVE-2026-63030** | CWE-436 — REST batch route confusion (Critical, CVSS 7.5, `GHSA-ff9f-jf42-662q`) | `WP_REST_Server::serve_batch_request_v1()` · `/wp-json/batch/v1` | **Entry point.** A route-confusion flaw lets an unauthenticated request reach an internal query path. |
| **CVE-2026-60137** | CWE-89 — SQL injection | `WP_Query` — `author__not_in` parameter | **Second link.** Unsanitised input reaches the database query; chained with the above → unauth RCE. |

| | |
|---|---|
| **Affected** | WordPress `6.9.0`–`6.9.4` and `7.0.0`–`7.0.1` |
| **Fixed in** | WordPress `6.9.5` and `7.0.2` |
| **First affected** | `6.9.0` (the batch-route weakness was introduced in 6.9) |

**Operationally important:** technical write-ups and a working PoC are already public.
Version detection is now the *absolute minimum* — the priority is **patching**. And
note that updating closes the vulnerable path but **does not remove a backdoor planted
before the patch** — hence the compromise-assessment step in the report.

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
script (default `soc@cyberssl.co.uk`). Edit it to your own intake address.

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
fictional vulnerable host (`example.com`, WordPress 7.0.1):

- [`wp2shell_report_example.com.html`](examples/) — the client-ready HTML report
- [`wp2shell_example.com.json`](examples/) — the JSON record
- [`wp2shell_email_example.com.txt`](examples/) — the draft notification e-mail

> These are generated from fabricated data to illustrate the report format. They are
> **not** the result of scanning any real site.

---

## Remediation (as emitted in the report)

1. Take a verified backup (DB + full file tree) first.
2. Update WordPress core to **6.9.5 / 7.0.2** or later on the matching branch.
3. Confirm the site and admin still work.
4. **Assume compromise** if the host was exposed while vulnerable — run a compromise
   assessment across themes, plugins, `uploads/`, `wp-config.php`, wp-cron, and admin
   accounts; run file-integrity checks against known-good core.
5. Add defence-in-depth at the edge (WAF rules, restrict `/wp-json/batch/v1`).
6. Rotate secrets (auth salts, admin/DB passwords, API keys) if compromise is suspected.
7. Re-scan to confirm the verdict now reads **Patched**.

---

## References

- [WordPress GitHub Security Advisory — GHSA-ff9f-jf42-662q](https://github.com/advisories/GHSA-ff9f-jf42-662q)
- [WordPress releases (6.9.5 / 7.0.2)](https://wordpress.org/download/releases/)

---

## Disclaimer

This tool is for **authorised security testing** only. You are responsible for
ensuring you have permission to scan any target. Unauthorised scanning may be unlawful.
The authors accept no liability for misuse.
