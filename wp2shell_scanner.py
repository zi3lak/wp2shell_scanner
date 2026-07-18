#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
wp2shell_scanner.py  —  CyberSentinel Solutions Ltd (CSSLTD)

Non-intrusive detection scanner for the WordPress "wp2shell" pre-auth RCE chain:

    CVE-2026-63030  REST API batch-route confusion in
                    WP_REST_Server::serve_batch_request_v1()  (entry point)
    CVE-2026-60137  SQL injection in the author__not_in parameter of WP_Query
                    (second link; the chain yields unauthenticated RCE)

Affected:  WordPress 6.9.0-6.9.4 and 7.0.0-7.0.1
Fixed in:  WordPress 6.9.5 and 7.0.2

WHAT THIS TOOL DOES
    * Fingerprints the WordPress core version through several passive vectors
      (generator meta tag, readme.html, RSS/Atom feed, OPML, REST root).
    * Reads the site's advertised REST API surface (/wp-json/) to see whether
      the batch endpoint namespace (batch/v1) is registered.
    * Maps the detected version to the affected/fixed ranges and produces a
      verdict, a client-ready HTML remediation report, a JSON record, and a
      draft notification e-mail to CSSLTD.

WHAT THIS TOOL DOES NOT DO
    * It does NOT exploit anything. It sends no SQL-injection payload, no
      batch-route-confusion request, and makes no attempt to execute code or
      access data. Detection is version-based plus a passive read of the
      publicly advertised API surface.

AUTHORISED USE ONLY
    Run this only against systems you own or are explicitly authorised (in
    writing) to test. Unauthorised scanning may be unlawful. The scanner sends
    an identifying User-Agent so blue teams can attribute the traffic.

Author : CSSLTD Offensive Security
License: Internal / client-engagement use.
"""

from __future__ import annotations

import argparse
import json
import re
import sys
import time
from dataclasses import dataclass, field, asdict
from datetime import datetime, timezone
from html import escape
from pathlib import Path
from urllib.parse import urljoin, urlparse

try:
    import requests
    from requests.adapters import HTTPAdapter
    from urllib3.util.retry import Retry
    import urllib3
except ImportError:  # pragma: no cover
    sys.stderr.write(
        "[!] Missing dependency 'requests'.  Install with:\n"
        "        pip install requests\n"
    )
    sys.exit(1)


# --------------------------------------------------------------------------- #
#  Configuration                                                              #
# --------------------------------------------------------------------------- #

TOOL_NAME = "CSSLTD wp2shell-scanner"
TOOL_VERSION = "1.0"
CSSLTD_CONTACT = "soc@cyberssl.co.uk"          # <-- edit to your intake address
CSSLTD_SITE = "https://cyberssl.co.uk"
USER_AGENT = f"CSSLTD-wp2shell-scanner/{TOOL_VERSION} (+{CSSLTD_SITE})"

# Vulnerable ranges (inclusive) and the fixed releases per branch.
VULN_RANGES = [((6, 9, 0), (6, 9, 4)), ((7, 0, 0), (7, 0, 1))]
FIXED_RELEASES = ["6.9.5", "7.0.2"]
FIRST_AFFECTED = (6, 9, 0)   # the batch-route weakness was introduced in 6.9

# Static knowledge base for the two CVEs (facts, not exploitation detail).
CVE_DB = {
    "CVE-2026-63030": {
        "title": "wp2shell — REST API batch-route confusion",
        "cwe": "CWE-436 (Interpretation Conflict)",
        "component": "WP_REST_Server::serve_batch_request_v1()  ·  /wp-json/batch/v1",
        "cvss": "7.5",
        "severity": "Critical",
        "advisory": "GHSA-ff9f-jf42-662q",
        "role": ("Entry point of the chain. A route-confusion flaw in the REST "
                 "batch endpoint lets an unauthenticated request reach an "
                 "internal query path."),
    },
    "CVE-2026-60137": {
        "title": "author__not_in WP_Query SQL injection",
        "cwe": "CWE-89 (SQL Injection)",
        "component": "WP_Query — author__not_in parameter",
        "cvss": "chained (no standalone score published)",
        "severity": "Critical (as part of the chain)",
        "advisory": "—",
        "role": ("Second link. Unsanitised input in author__not_in reaches the "
                 "database query; combined with CVE-2026-63030 this produces "
                 "unauthenticated remote code execution."),
    },
}

REFERENCES = [
    ("WordPress GitHub Security Advisory (GHSA-ff9f-jf42-662q)",
     "https://github.com/advisories/GHSA-ff9f-jf42-662q"),
    ("Rapid7 — ETR: CVE-2026-63030 wp2shell",
     "https://www.rapid7.com/blog/post/etr-cve-2026-63030-wp2shell-a-critical-remote-code-execution-vulnerability-in-wordpress-core/"),
    ("SOCRadar — wp2shell WordPress RCE",
     "https://socradar.io/blog/wp2shell-wordpress-rce-cve-2026-63030/"),
    ("Official checker (Assetnote / Searchlight Cyber)",
     "https://wp2shell.com/"),
    ("WordPress releases 6.9.5 / 7.0.2",
     "https://wordpress.org/download/releases/"),
]

# Verdict codes.
V_VULN = "VULNERABLE"
V_PATCHED = "PATCHED"
V_NOT_AFFECTED = "NOT_AFFECTED"
V_UNKNOWN = "UNKNOWN"
V_NOT_WP = "NOT_WORDPRESS"

VERDICT_COLOR = {
    V_VULN: "#C81E3A",
    V_PATCHED: "#1B7F4B",
    V_NOT_AFFECTED: "#4A5568",
    V_UNKNOWN: "#B7791F",
    V_NOT_WP: "#4A5568",
}

VERDICT_LABEL = {
    V_VULN: "Vulnerable — patch immediately",
    V_PATCHED: "Patched — not exposed to this chain",
    V_NOT_AFFECTED: "Not affected (version predates the flaw)",
    V_UNKNOWN: "Inconclusive — manual verification required",
    V_NOT_WP: "WordPress not detected",
}


# --------------------------------------------------------------------------- #
#  Version handling                                                           #
# --------------------------------------------------------------------------- #

_VER_RE = re.compile(r"(\d+)\.(\d+)(?:\.(\d+))?")


def parse_version(text: str):
    """Return (major, minor, patch) tuple from a version-like string, or None."""
    if not text:
        return None
    m = _VER_RE.search(text)
    if not m:
        return None
    major, minor, patch = m.group(1), m.group(2), m.group(3)
    return (int(major), int(minor), int(patch) if patch is not None else 0)


def version_str(v) -> str:
    return ".".join(str(p) for p in v) if v else "unknown"


def classify_version(v) -> str:
    """Map a WordPress version tuple to a verdict code."""
    if v is None:
        return V_UNKNOWN
    for low, high in VULN_RANGES:
        if low <= v <= high:
            return V_VULN
    if v < FIRST_AFFECTED:
        return V_NOT_AFFECTED
    return V_PATCHED  # anything not in a vulnerable range and >= 6.9.5 / 7.0.2


# --------------------------------------------------------------------------- #
#  HTTP session                                                               #
# --------------------------------------------------------------------------- #

def build_session(timeout: int, verify_tls: bool) -> requests.Session:
    s = requests.Session()
    s.headers.update({"User-Agent": USER_AGENT, "Accept": "*/*"})
    retry = Retry(total=2, backoff_factor=0.4,
                  status_forcelist=(500, 502, 503, 504),
                  allowed_methods=("GET", "HEAD"))
    adapter = HTTPAdapter(max_retries=retry)
    s.mount("http://", adapter)
    s.mount("https://", adapter)
    s.verify = verify_tls
    s.request_timeout = timeout  # stored for convenience
    if not verify_tls:
        urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
    return s


def _get(session, url, timeout, **kw):
    try:
        return session.get(url, timeout=timeout, allow_redirects=True, **kw)
    except requests.RequestException as exc:
        return exc


# --------------------------------------------------------------------------- #
#  Detection vectors  (all passive)                                           #
# --------------------------------------------------------------------------- #

@dataclass
class Evidence:
    source: str
    detail: str
    version: str | None = None


def detect_from_html(session, base, timeout, evidence):
    r = _get(session, base, timeout)
    if isinstance(r, Exception) or not getattr(r, "ok", False):
        return None
    body = r.text or ""
    # <meta name="generator" content="WordPress 6.9.4" />
    m = re.search(r'name=["\']generator["\']\s+content=["\']WordPress\s*([\d.]+)',
                  body, re.IGNORECASE)
    if not m:
        m = re.search(r'content=["\']WordPress\s*([\d.]+)["\']\s+name=["\']generator',
                      body, re.IGNORECASE)
    is_wp = ("wp-content" in body) or ("wp-includes" in body) or ("/wp-json" in body)
    if m:
        ver = m.group(1)
        evidence.append(Evidence("generator meta tag (homepage)",
                                  f'meta generator = "WordPress {ver}"', ver))
        return parse_version(ver)
    if is_wp:
        evidence.append(Evidence("homepage markup",
                                 "wp-content / wp-includes references present "
                                 "(WordPress confirmed, version hidden)"))
    return None


def detect_from_readme(session, base, timeout, evidence):
    url = urljoin(base, "readme.html")
    r = _get(session, url, timeout)
    if isinstance(r, Exception) or not getattr(r, "ok", False):
        return None
    m = re.search(r"Version\s*([\d.]+)", r.text or "", re.IGNORECASE)
    if m:
        ver = m.group(1)
        evidence.append(Evidence("/readme.html", f"Version {ver}", ver))
        return parse_version(ver)
    return None


def detect_from_feed(session, base, timeout, evidence):
    for path in ("feed/", "?feed=rss2", "comments/feed/"):
        url = urljoin(base, path)
        r = _get(session, url, timeout)
        if isinstance(r, Exception) or not getattr(r, "ok", False):
            continue
        m = re.search(r"<generator>\s*https?://wordpress\.org/\?v=([\d.]+)",
                      r.text or "", re.IGNORECASE)
        if m:
            ver = m.group(1)
            evidence.append(Evidence(f"/{path} generator", f"?v={ver}", ver))
            return parse_version(ver)
    return None


def detect_from_opml(session, base, timeout, evidence):
    url = urljoin(base, "wp-links-opml.php")
    r = _get(session, url, timeout)
    if isinstance(r, Exception) or not getattr(r, "ok", False):
        return None
    m = re.search(r"generator=\"WordPress/([\d.]+)\"", r.text or "", re.IGNORECASE)
    if m:
        ver = m.group(1)
        evidence.append(Evidence("/wp-links-opml.php", f"WordPress/{ver}", ver))
        return parse_version(ver)
    return None


def probe_rest_surface(session, base, timeout, evidence):
    """
    Passive read of /wp-json/. Returns dict:
        { 'is_wp': bool, 'version': tuple|None, 'batch_endpoint': bool }
    Only reads the advertised route/namespace list; sends no batch request.
    """
    result = {"is_wp": False, "version": None, "batch_endpoint": False}
    url = urljoin(base, "wp-json/")
    r = _get(session, url, timeout)
    if isinstance(r, Exception) or r is None:
        return result
    if getattr(r, "status_code", None) in (200, 401, 403):
        result["is_wp"] = True
    try:
        data = r.json()
    except Exception:
        return result
    if isinstance(data, dict):
        result["is_wp"] = True
        namespaces = data.get("namespaces") or []
        routes = data.get("routes") or {}
        if "batch/v1" in namespaces or "/batch/v1" in routes:
            result["batch_endpoint"] = True
            evidence.append(Evidence("/wp-json/ (REST root)",
                                     "batch/v1 namespace is registered "
                                     "(REST batch endpoint reachable)"))
        # Some installs leak version in the description/home fields; check gently.
        for key in ("description", "gmt_offset"):
            _ = data.get(key)
    return result


# --------------------------------------------------------------------------- #
#  Result model                                                               #
# --------------------------------------------------------------------------- #

@dataclass
class ScanResult:
    target: str
    scanned_at: str
    tool: str = f"{TOOL_NAME} v{TOOL_VERSION}"
    is_wordpress: bool = False
    detected_version: str | None = None
    verdict: str = V_UNKNOWN
    batch_endpoint_exposed: bool = False
    per_cve: dict = field(default_factory=dict)
    evidence: list = field(default_factory=list)
    notes: list = field(default_factory=list)
    error: str | None = None

    def to_dict(self):
        d = asdict(self)
        return d


# --------------------------------------------------------------------------- #
#  Scan orchestration                                                         #
# --------------------------------------------------------------------------- #

def normalise_target(raw: str) -> str:
    if not raw.startswith(("http://", "https://")):
        raw = "https://" + raw
    if not raw.endswith("/"):
        raw += "/"
    return raw


def scan_target(raw_target: str, timeout: int, verify_tls: bool) -> ScanResult:
    base = normalise_target(raw_target)
    host = urlparse(base).netloc
    session = build_session(timeout, verify_tls)
    evidence: list[Evidence] = []

    res = ScanResult(target=base, scanned_at=datetime.now(timezone.utc).isoformat())

    # Reachability check.
    root = _get(session, base, timeout)
    if isinstance(root, Exception):
        res.error = f"target unreachable: {root.__class__.__name__}: {root}"
        res.verdict = V_UNKNOWN
        res.evidence = [asdict(e) for e in evidence]
        return res

    # Run detection vectors in order of reliability; keep the most specific hit.
    detected = None
    for fn in (detect_from_html, detect_from_readme,
               detect_from_feed, detect_from_opml):
        v = fn(session, base, timeout, evidence)
        if v and (detected is None):
            detected = v

    surface = probe_rest_surface(session, base, timeout, evidence)

    res.is_wordpress = bool(detected) or surface["is_wp"] or any(
        "WordPress" in e.detail or "wp-content" in e.detail for e in evidence
    )
    res.batch_endpoint_exposed = surface["batch_endpoint"]
    res.detected_version = version_str(detected) if detected else None
    res.evidence = [asdict(e) for e in evidence]

    if not res.is_wordpress:
        res.verdict = V_NOT_WP
        res.notes.append("No WordPress fingerprint found on this host.")
        return res

    verdict = classify_version(detected)
    res.verdict = verdict

    # Build the per-CVE breakdown.
    for cve, meta in CVE_DB.items():
        status = verdict
        res.per_cve[cve] = {
            "title": meta["title"],
            "cwe": meta["cwe"],
            "component": meta["component"],
            "cvss": meta["cvss"],
            "severity": meta["severity"],
            "advisory": meta["advisory"],
            "role": meta["role"],
            "status": status,
        }

    # Notes / caveats.
    if verdict == V_UNKNOWN:
        if res.batch_endpoint_exposed:
            res.notes.append(
                "Core version is hidden but the REST batch endpoint is exposed. "
                "Confirm the exact WordPress version manually (wp-admin > Updates, "
                "or `wp core version`) and compare against 6.9.5 / 7.0.2.")
        else:
            res.notes.append(
                "Could not determine the WordPress version from public vectors. "
                "Verify manually and compare against the fixed releases.")
    elif verdict == V_VULN:
        res.notes.append(
            "Detected version falls inside a vulnerable range. Treat any "
            "internet-facing instance that ran this version as potentially "
            "compromised — patching closes the route but does not remove a "
            "backdoor planted beforehand.")
    elif verdict == V_NOT_AFFECTED:
        res.notes.append(
            "Version predates the batch-route weakness (introduced in 6.9), so "
            "this specific chain does not apply. The install is still outdated; "
            "update to a current supported release.")

    return res


# --------------------------------------------------------------------------- #
#  Reporting — HTML                                                           #
# --------------------------------------------------------------------------- #

REPORT_CSS = """
:root{
  --ink:#0E1116; --ink-2:#3A424E; --muted:#6B7480; --line:#E2E6EB;
  --bg:#FFFFFF; --panel:#F6F8FA; --crit:#C81E3A; --ok:#1B7F4B;
  --warn:#B7791F; --slate:#4A5568; --brand:#12203A;
  --mono:ui-monospace,"SF Mono",SFMono-Regular,Menlo,Consolas,"Liberation Mono",monospace;
  --sans:-apple-system,BlinkMacSystemFont,"Segoe UI",Roboto,Helvetica,Arial,sans-serif;
}
*{box-sizing:border-box}
body{margin:0;background:var(--panel);color:var(--ink);font-family:var(--sans);
  line-height:1.55;-webkit-font-smoothing:antialiased;}
.wrap{max-width:900px;margin:0 auto;padding:32px 20px 64px;}
.sheet{background:var(--bg);border:1px solid var(--line);border-radius:4px;overflow:hidden;}
header.masthead{display:flex;justify-content:space-between;align-items:flex-start;
  gap:24px;padding:24px 32px;border-bottom:2px solid var(--brand);}
.brand{font-family:var(--mono);font-weight:700;letter-spacing:.14em;
  font-size:13px;color:var(--brand);text-transform:uppercase;}
.brand small{display:block;letter-spacing:.05em;color:var(--muted);font-weight:400;
  text-transform:none;margin-top:4px;font-size:11px;}
.doc-meta{font-family:var(--mono);font-size:11px;color:var(--muted);text-align:right;}
.doc-meta b{color:var(--ink-2);}
h1.title{font-size:22px;margin:28px 32px 4px;letter-spacing:-.01em;}
.subtitle{margin:0 32px 24px;color:var(--muted);font-size:14px;}
.verdict{margin:0 32px 8px;border-left:5px solid var(--slate);
  background:var(--panel);padding:18px 20px;border-radius:0 4px 4px 0;}
.verdict .flag{font-family:var(--mono);font-weight:700;font-size:15px;letter-spacing:.04em;}
.verdict .row{display:flex;flex-wrap:wrap;gap:22px;margin-top:10px;font-size:13px;}
.verdict .row div span{display:block;color:var(--muted);font-size:11px;
  text-transform:uppercase;letter-spacing:.06em;margin-bottom:2px;}
.verdict .row div b{font-family:var(--mono);font-size:14px;}
section{margin:28px 32px;}
h2{font-size:13px;text-transform:uppercase;letter-spacing:.1em;color:var(--ink-2);
  border-bottom:1px solid var(--line);padding-bottom:6px;margin:0 0 14px;}
.finding{border:1px solid var(--line);border-radius:4px;margin-bottom:14px;}
.finding .head{display:flex;justify-content:space-between;align-items:center;
  gap:12px;padding:12px 16px;border-bottom:1px solid var(--line);background:var(--panel);}
.finding .cve{font-family:var(--mono);font-weight:700;font-size:14px;}
.finding .cve small{display:block;font-weight:400;color:var(--muted);
  font-size:12px;margin-top:2px;}
.badge{font-family:var(--mono);font-size:11px;font-weight:700;padding:3px 9px;
  border-radius:99px;color:#fff;white-space:nowrap;letter-spacing:.03em;}
.finding table{width:100%;border-collapse:collapse;font-size:13px;}
.finding td{padding:8px 16px;vertical-align:top;border-top:1px solid var(--line);}
.finding td.k{width:150px;color:var(--muted);text-transform:uppercase;
  font-size:11px;letter-spacing:.05em;padding-top:10px;}
.finding td.v{font-family:var(--mono);font-size:12.5px;color:var(--ink);}
.evidence{width:100%;border-collapse:collapse;font-size:13px;}
.evidence th,.evidence td{text-align:left;padding:8px 12px;border-bottom:1px solid var(--line);}
.evidence th{font-size:11px;text-transform:uppercase;letter-spacing:.06em;color:var(--muted);}
.evidence td.mono{font-family:var(--mono);font-size:12px;}
ol.steps{margin:0;padding:0;counter-reset:step;list-style:none;}
ol.steps li{position:relative;padding:0 0 16px 44px;margin:0;}
ol.steps li:before{counter-increment:step;content:counter(step,decimal-leading-zero);
  position:absolute;left:0;top:-2px;font-family:var(--mono);font-weight:700;
  font-size:13px;color:var(--crit);border:1px solid var(--line);border-radius:4px;
  width:30px;height:30px;display:flex;align-items:center;justify-content:center;background:var(--panel);}
ol.steps li b{display:block;margin-bottom:2px;}
ol.steps li p{margin:0;color:var(--ink-2);font-size:13.5px;}
code{font-family:var(--mono);background:var(--panel);border:1px solid var(--line);
  border-radius:3px;padding:1px 5px;font-size:12px;}
.notes{background:var(--panel);border:1px solid var(--line);border-radius:4px;
  padding:14px 16px;font-size:13.5px;color:var(--ink-2);}
.refs{font-size:13px;}
.refs a{color:var(--brand);text-decoration:none;border-bottom:1px solid var(--line);}
.refs li{margin-bottom:6px;}
footer.foot{border-top:1px solid var(--line);padding:16px 32px;font-size:11px;
  color:var(--muted);display:flex;justify-content:space-between;gap:16px;flex-wrap:wrap;}
.confidential{font-family:var(--mono);letter-spacing:.08em;text-transform:uppercase;}
@media (max-width:640px){
  header.masthead{flex-direction:column;gap:10px;}
  .doc-meta{text-align:left;} h1.title,.subtitle,.verdict,section,footer.foot{margin-left:18px;margin-right:18px;}
}
@media print{
  body{background:#fff;} .wrap{padding:0;} .sheet{border:none;border-radius:0;}
  .finding,.notes,.evidence,ol.steps li:before{break-inside:avoid;}
}
"""


def _fixed_list_html():
    return " · ".join(f"<code>{escape(v)}</code>" for v in FIXED_RELEASES)


def render_html_report(res: ScanResult, sample: bool = False) -> str:
    color = VERDICT_COLOR.get(res.verdict, "#4A5568")
    flag = VERDICT_LABEL.get(res.verdict, res.verdict)
    scanned = res.scanned_at.replace("T", " ").split(".")[0] + " UTC"
    host = urlparse(res.target).netloc or res.target
    sample_tag = ('<div style="background:#FEF3C7;border:1px solid #F59E0B;color:#92400E;'
                  'font-family:var(--mono);font-size:11px;padding:6px 12px;text-align:center;'
                  'letter-spacing:.06em;">SAMPLE OUTPUT — SYNTHETIC DATA, NOT A REAL SCAN</div>'
                  if sample else "")

    # Verdict quick-facts row.
    dv = escape(res.detected_version or "not disclosed")
    batch = "yes" if res.batch_endpoint_exposed else "not observed"
    quick = f"""
      <div class="row">
        <div><span>Detected core</span><b>WordPress {dv}</b></div>
        <div><span>Affected range</span><b>6.9.0–6.9.4 · 7.0.0–7.0.1</b></div>
        <div><span>Fixed in</span><b>6.9.5 · 7.0.2</b></div>
        <div><span>REST batch endpoint</span><b>{batch}</b></div>
      </div>"""

    # Findings.
    findings = []
    for cve, info in res.per_cve.items():
        st = info["status"]
        badge_color = VERDICT_COLOR.get(st, "#4A5568")
        badge_txt = {V_VULN: "VULNERABLE", V_PATCHED: "PATCHED",
                     V_NOT_AFFECTED: "N/A", V_UNKNOWN: "VERIFY"}.get(st, st)
        findings.append(f"""
        <div class="finding">
          <div class="head">
            <div class="cve">{escape(cve)}<small>{escape(info['title'])}</small></div>
            <div class="badge" style="background:{badge_color}">{badge_txt}</div>
          </div>
          <table>
            <tr><td class="k">Role in chain</td><td class="v" style="white-space:normal">{escape(info['role'])}</td></tr>
            <tr><td class="k">Component</td><td class="v">{escape(info['component'])}</td></tr>
            <tr><td class="k">Weakness</td><td class="v">{escape(info['cwe'])}</td></tr>
            <tr><td class="k">CVSS</td><td class="v">{escape(str(info['cvss']))}</td></tr>
            <tr><td class="k">Severity</td><td class="v">{escape(info['severity'])}</td></tr>
            <tr><td class="k">Advisory</td><td class="v">{escape(info['advisory'])}</td></tr>
          </table>
        </div>""")
    if not findings:
        findings.append('<div class="notes">No WordPress detected — the wp2shell '
                        'chain does not apply to this host.</div>')

    # Evidence table.
    ev_rows = "".join(
        f"<tr><td>{escape(e['source'])}</td><td class='mono'>{escape(e['detail'])}</td>"
        f"<td class='mono'>{escape(e['version'] or '—')}</td></tr>"
        for e in res.evidence
    ) or "<tr><td colspan='3' style='color:#6B7480'>No public version indicators returned.</td></tr>"

    # Notes.
    notes_html = ""
    if res.notes or res.error:
        items = "".join(f"<p style='margin:0 0 8px'>• {escape(n)}</p>" for n in res.notes)
        if res.error:
            items += f"<p style='margin:0;color:#C81E3A'>• Scan error: {escape(res.error)}</p>"
        notes_html = f'<section><h2>Analyst notes</h2><div class="notes">{items}</div></section>'

    # Remediation (only meaningful when WP present).
    remediation = f"""
      <ol class="steps">
        <li><b>Take a verified backup first.</b>
            <p>Back up the database and the full file tree before making changes, so you can restore and later forensically compare.</p></li>
        <li><b>Update WordPress Core.</b>
            <p>Move to a fixed release — {_fixed_list_html()} or later on the matching branch. Then confirm with <code>wp core version</code> or <b>Dashboard → Updates</b>.</p></li>
        <li><b>Confirm the site still works.</b>
            <p>Verify the public site and admin load correctly after the update; check for plugin/theme conflicts.</p></li>
        <li><b>Assume compromise if it was exposed while vulnerable.</b>
            <p>The patch closes the route but does not remove a backdoor planted beforehand. Inspect themes, plugins, <code>uploads/</code>, <code>wp-config.php</code>, scheduled tasks (wp-cron), and the admin user list for persistence, and run file-integrity checks against known-good core.</p></li>
        <li><b>Add defence-in-depth at the edge.</b>
            <p>Where immediate patching isn't possible, deploy WAF rules to block malicious REST batch requests and SQL-injection patterns, restrict access to <code>/wp-json/batch/v1</code>, and monitor REST API logs. Managed WAFs shipped rules for this chain on 17 Jul 2026.</p></li>
        <li><b>Rotate secrets if compromise is suspected.</b>
            <p>Regenerate the <code>wp-config.php</code> auth salts, reset admin and database passwords, and rotate any API keys stored on the host.</p></li>
        <li><b>Re-scan to confirm.</b>
            <p>Run this scanner again; the verdict should read <b>Patched</b> and the version should sit at or above the fixed release.</p></li>
      </ol>"""

    refs_html = "".join(
        f'<li><a href="{escape(u)}">{escape(t)}</a></li>' for t, u in REFERENCES
    )

    return f"""<!DOCTYPE html>
<html lang="en"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>wp2shell exposure — {escape(host)}</title>
<style>{REPORT_CSS}</style></head>
<body><div class="wrap"><div class="sheet">
{sample_tag}
<header class="masthead">
  <div class="brand">CyberSentinel Solutions Ltd<small>Offensive Security · Vulnerability Assessment</small></div>
  <div class="doc-meta">
    Report: <b>wp2shell exposure</b><br>
    Target: <b>{escape(host)}</b><br>
    Scanned: <b>{escape(scanned)}</b><br>
    Tool: <b>{escape(res.tool)}</b>
  </div>
</header>

<h1 class="title">WordPress wp2shell exposure assessment</h1>
<p class="subtitle">Pre-authentication RCE chain — CVE-2026-63030 + CVE-2026-60137</p>

<div class="verdict" style="border-left-color:{color}">
  <div class="flag" style="color:{color}">{escape(flag)}</div>
  {quick}
</div>

<section>
  <h2>Findings</h2>
  {''.join(findings)}
</section>

<section>
  <h2>Detection evidence</h2>
  <table class="evidence">
    <tr><th>Source</th><th>Observation</th><th>Version</th></tr>
    {ev_rows}
  </table>
</section>

{notes_html}

<section>
  <h2>Remediation</h2>
  {remediation}
</section>

<section class="refs">
  <h2>References</h2>
  <ul>{refs_html}</ul>
</section>

<footer class="foot">
  <span class="confidential">Confidential — client engagement</span>
  <span>Generated by {escape(res.tool)} · Detection-only, non-intrusive</span>
</footer>
</div></div></body></html>"""


# --------------------------------------------------------------------------- #
#  Reporting — e-mail                                                         #
# --------------------------------------------------------------------------- #

def render_email(res: ScanResult, report_filename: str | None = None) -> str:
    host = urlparse(res.target).netloc or res.target
    sev_word = {
        V_VULN: "ACTION REQUIRED", V_UNKNOWN: "REVIEW",
        V_PATCHED: "INFO", V_NOT_AFFECTED: "INFO", V_NOT_WP: "INFO",
    }.get(res.verdict, "REVIEW")

    subject = f"[{sev_word}] wp2shell scan — {host} — {res.verdict}"

    if res.verdict == V_VULN:
        lead = (f"The scan flagged {host} as VULNERABLE to the wp2shell pre-auth "
                f"RCE chain (CVE-2026-63030 + CVE-2026-60137).")
        action = ("Recommend immediate patching to WordPress "
                  + " / ".join(FIXED_RELEASES) +
                  " and a compromise assessment, since this instance was exposed "
                  "while running a vulnerable version.")
    elif res.verdict == V_UNKNOWN:
        lead = (f"The scan of {host} was inconclusive — the WordPress core version "
                f"could not be confirmed from public vectors.")
        action = ("Recommend manual version verification against the fixed releases "
                  + " / ".join(FIXED_RELEASES) + ".")
    elif res.verdict == V_PATCHED:
        lead = (f"{host} is running a patched WordPress release and is not exposed "
                f"to the wp2shell chain.")
        action = "No action required for this CVE chain; keep auto-updates enabled."
    elif res.verdict == V_NOT_AFFECTED:
        lead = (f"{host} runs a WordPress version that predates the flaw; the "
                f"wp2shell chain does not apply.")
        action = "Recommend updating to a current supported release regardless."
    else:
        lead = f"No WordPress fingerprint was found on {host}."
        action = "No wp2shell exposure; no action required."

    ev_lines = "\n".join(
        f"    - {e['source']}: {e['detail']}"
        + (f"  (v{e['version']})" if e.get("version") else "")
        for e in res.evidence
    ) or "    - none returned"

    attach = f"\nAttached: {report_filename}" if report_filename else ""

    body = f"""To: {CSSLTD_CONTACT}
Subject: {subject}

Team,

{lead}

  Target ............ {res.target}
  WordPress version . {res.detected_version or 'not disclosed'}
  Verdict ........... {res.verdict} — {VERDICT_LABEL.get(res.verdict, '')}
  REST batch route .. {'exposed' if res.batch_endpoint_exposed else 'not observed'}
  Scanned (UTC) ..... {res.scanned_at}

Chain:
  CVE-2026-63030 — REST API batch-route confusion (entry point, CVSS 7.5, Critical)
  CVE-2026-60137 — author__not_in WP_Query SQL injection (second link)
  Affected: 6.9.0-6.9.4 / 7.0.0-7.0.1   Fixed: 6.9.5 / 7.0.2

Recommendation:
  {action}

Detection evidence:
{ev_lines}
{attach}

This scan was detection-only (version fingerprint + passive REST-surface read);
no exploitation was attempted.

— {TOOL_NAME} v{TOOL_VERSION}
   {CSSLTD_SITE}
"""
    return body


# --------------------------------------------------------------------------- #
#  Output writing                                                             #
# --------------------------------------------------------------------------- #

def safe_host_slug(target: str) -> str:
    host = urlparse(target).netloc or target
    return re.sub(r"[^A-Za-z0-9._-]", "_", host) or "target"


def write_outputs(res: ScanResult, out_dir: Path, want, sample=False):
    out_dir.mkdir(parents=True, exist_ok=True)
    stamp = datetime.now().strftime("%Y%m%d-%H%M%S")
    slug = safe_host_slug(res.target)
    written = {}

    if "json" in want:
        p = out_dir / f"wp2shell_{slug}_{stamp}.json"
        p.write_text(json.dumps(res.to_dict(), indent=2), encoding="utf-8")
        written["json"] = p

    report_name = None
    if "html" in want:
        p = out_dir / f"wp2shell_report_{slug}_{stamp}.html"
        p.write_text(render_html_report(res, sample=sample), encoding="utf-8")
        written["html"] = p
        report_name = p.name

    if "email" in want:
        p = out_dir / f"wp2shell_email_{slug}_{stamp}.txt"
        p.write_text(render_email(res, report_name), encoding="utf-8")
        written["email"] = p

    return written


# --------------------------------------------------------------------------- #
#  Console summary                                                            #
# --------------------------------------------------------------------------- #

def print_summary(res: ScanResult):
    bar = "-" * 68
    print(bar)
    print(f"  Target   : {res.target}")
    print(f"  WordPress: {res.detected_version or 'not disclosed'}"
          f"   (WP detected: {res.is_wordpress})")
    print(f"  Verdict  : {res.verdict}  —  {VERDICT_LABEL.get(res.verdict,'')}")
    print(f"  Batch EP : {'exposed' if res.batch_endpoint_exposed else 'not observed'}")
    if res.error:
        print(f"  Error    : {res.error}")
    if res.evidence:
        print("  Evidence :")
        for e in res.evidence:
            v = f" (v{e['version']})" if e.get("version") else ""
            print(f"     - {e['source']}: {e['detail']}{v}")
    print(bar)


# --------------------------------------------------------------------------- #
#  Demo data (no network)                                                     #
# --------------------------------------------------------------------------- #

def build_demo_result() -> ScanResult:
    res = ScanResult(target="https://example.com/",
                     scanned_at=datetime.now(timezone.utc).isoformat())
    res.is_wordpress = True
    res.detected_version = "7.0.1"
    res.verdict = V_VULN
    res.batch_endpoint_exposed = True
    res.evidence = [
        {"source": "generator meta tag (homepage)",
         "detail": 'meta generator = "WordPress 7.0.1"', "version": "7.0.1"},
        {"source": "/readme.html", "detail": "Version 7.0.1", "version": "7.0.1"},
        {"source": "/wp-json/ (REST root)",
         "detail": "batch/v1 namespace is registered (REST batch endpoint reachable)",
         "version": None},
    ]
    for cve, meta in CVE_DB.items():
        res.per_cve[cve] = {
            "title": meta["title"], "cwe": meta["cwe"],
            "component": meta["component"], "cvss": meta["cvss"],
            "severity": meta["severity"], "advisory": meta["advisory"],
            "role": meta["role"], "status": V_VULN,
        }
    res.notes = [
        "Detected version falls inside a vulnerable range. Treat any "
        "internet-facing instance that ran this version as potentially "
        "compromised — patching closes the route but does not remove a "
        "backdoor planted beforehand.",
    ]
    return res


# --------------------------------------------------------------------------- #
#  CLI                                                                         #
# --------------------------------------------------------------------------- #

def build_arg_parser():
    p = argparse.ArgumentParser(
        prog="wp2shell_scanner.py",
        description="CSSLTD detection scanner for WordPress wp2shell "
                    "(CVE-2026-63030 / CVE-2026-60137). Detection-only.",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="Examples:\n"
               "  wp2shell_scanner.py -t https://site.example --authorized\n"
               "  wp2shell_scanner.py -T scope.txt --authorized -o ./reports\n"
               "  wp2shell_scanner.py --demo -o ./reports\n")
    g = p.add_mutually_exclusive_group(required=True)
    g.add_argument("-t", "--target", help="single target URL or host")
    g.add_argument("-T", "--targets-file",
                   help="file with one target per line (# comments allowed)")
    g.add_argument("--demo", action="store_true",
                   help="generate a SAMPLE report/email from synthetic data (no network)")
    p.add_argument("-o", "--output-dir", default="./wp2shell_reports",
                   help="directory for reports (default: ./wp2shell_reports)")
    p.add_argument("--formats", default="json,html,email",
                   help="comma list of outputs: json,html,email (default: all)")
    p.add_argument("--authorized", action="store_true",
                   help="confirm you are authorised to scan the target(s)")
    p.add_argument("--timeout", type=int, default=12, help="HTTP timeout seconds")
    p.add_argument("--delay", type=float, default=1.0,
                   help="seconds between targets (be polite)")
    p.add_argument("--insecure", action="store_true",
                   help="do not verify TLS certificates")
    p.add_argument("--quiet", action="store_true", help="suppress console summary")
    return p


def load_targets(path: str):
    out = []
    for line in Path(path).read_text(encoding="utf-8").splitlines():
        line = line.strip()
        if line and not line.startswith("#"):
            out.append(line)
    return out


def main(argv=None):
    args = build_arg_parser().parse_args(argv)
    want = {w.strip() for w in args.formats.split(",") if w.strip()}
    out_dir = Path(args.output_dir)

    # --- Demo path (no authorisation, no network) ---
    if args.demo:
        res = build_demo_result()
        written = write_outputs(res, out_dir, want, sample=True)
        if not args.quiet:
            print("\n[demo] Generated SAMPLE outputs (synthetic data):")
            print_summary(res)
        for kind, path in written.items():
            print(f"  [{kind}] {path}")
        return 0

    # --- Authorisation gate ---
    if not args.authorized:
        sys.stderr.write(
            "\n[!] Authorisation required.\n"
            "    Scan only systems you own or are explicitly authorised to test.\n"
            "    Re-run with --authorized to confirm.\n\n")
        return 1

    targets = ([args.target] if args.target
               else load_targets(args.targets_file))
    if not targets:
        sys.stderr.write("[!] No targets to scan.\n")
        return 1

    print(f"\n{TOOL_NAME} v{TOOL_VERSION} — detection-only")
    print(f"Scope: {len(targets)} target(s). Reports -> {out_dir}\n")

    worst = V_NOT_WP
    order = [V_NOT_WP, V_NOT_AFFECTED, V_PATCHED, V_UNKNOWN, V_VULN]

    for i, tgt in enumerate(targets):
        res = scan_target(tgt, timeout=args.timeout,
                          verify_tls=not args.insecure)
        if not args.quiet:
            print_summary(res)
        written = write_outputs(res, out_dir, want)
        for kind, path in written.items():
            print(f"  [{kind}] {path}")
        if order.index(res.verdict) > order.index(worst):
            worst = res.verdict
        if i < len(targets) - 1 and args.delay > 0:
            time.sleep(args.delay)

    # Exit code: 2 if any vulnerable, 1 if any unknown/error, else 0 (CI-friendly).
    if worst == V_VULN:
        return 2
    if worst == V_UNKNOWN:
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
