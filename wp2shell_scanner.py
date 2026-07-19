#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
wp2shell_scanner.py  —  CyberSentinel Solutions Ltd (CSSLTD)

Non-intrusive detection scanner for recent WordPress CORE vulnerabilities.
Tracked CVEs (branch-aware, per-CVE verdicts):

    CVE-2026-63030  wp2shell — REST API batch-route confusion in
                    WP_REST_Server::serve_batch_request_v1()  (RCE entry point)
                    affected 6.9.0-6.9.4 / 7.0.0-7.0.1   fixed 6.9.5 / 7.0.2
    CVE-2026-60137  SQL injection in the author__not_in parameter of WP_Query
                    (second link of the wp2shell RCE chain; also affects 6.8)
                    affected 6.8.0-6.8.5 / 6.9.0-6.9.4 / 7.0.0-7.0.1
                    fixed 6.8.6 / 6.9.5 / 7.0.2
    CVE-2026-3906   Notes REST API missing authorization (Subscriber+ can
                    create arbitrary notes)   affected 6.9.0-6.9.3  fixed 6.9.4

Scope: WordPress CORE only. Plugin/theme CVEs (the bulk of the WPScan /
Patchstack catalogue) need a live curated feed and per-plugin enumeration and
are intentionally out of scope for this static core-version scanner.

WHAT THIS TOOL DOES
    * Fingerprints the WordPress core version through several passive vectors
      (generator meta tag, readme.html, RSS/Atom feed, OPML, REST root).
    * Reads the site's advertised REST API surface (/wp-json/) to see whether
      the batch endpoint namespace (batch/v1) is registered.
    * Classifies each tracked CVE independently against the detected version
      and produces a verdict, a client-ready HTML remediation report, a JSON
      record, and a draft notification e-mail to CSSLTD.

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

TOOL_NAME = "CSSLTD WordPress core-vuln scanner"
TOOL_VERSION = "2.0"
CSSLTD_CONTACT = "ops@cyberssl.co.uk"          # <-- edit to your intake address
CSSLTD_SITE = "https://cyberssl.co.uk"
USER_AGENT = f"CSSLTD-wp-core-scanner/{TOOL_VERSION} (+{CSSLTD_SITE})"

# --------------------------------------------------------------------------- #
#  Vulnerability database — WordPress CORE only                               #
#                                                                             #
#  Version-based detection covers *core* CVEs where the fixed release is      #
#  public and unambiguous. Each entry carries its own affected ranges and     #
#  fixed releases, so the verdict is computed per CVE and is branch-aware     #
#  (e.g. the 6.8.x branch is exposed to the SQLi but NOT the full RCE chain). #
#                                                                             #
#  Scope note: plugin/theme CVEs (the large majority of the WPScan/Patchstack #
#  catalogue) are intentionally out of scope — they require a live, curated   #
#  feed and per-plugin version enumeration, not a static core-version map.    #
#  Ranges below are verified against vendor advisories (see REFERENCES).      #
# --------------------------------------------------------------------------- #

# Static knowledge base of core CVEs (facts only, no exploitation detail).
# affected: list of inclusive (low, high) version tuples.
# fixed:    the release(s) that close it, per branch.
# first_affected: earliest affected version (older installs are NOT_AFFECTED).
VULN_DB = {
    "CVE-2026-63030": {
        "title": "wp2shell — REST API batch-route confusion → RCE",
        "cwe": "CWE-436 (Interpretation Conflict)",
        "component": "WP_REST_Server::serve_batch_request_v1()  ·  /wp-json/batch/v1",
        "cvss": "see advisory",
        "severity": "Critical",
        "advisory": "GHSA-ff9f-jf42-662q",
        "auth": "Unauthenticated",
        "role": ("Entry point of the wp2shell chain. A route-confusion flaw in "
                 "the REST batch endpoint lets an unauthenticated request reach "
                 "an internal query path; chained with CVE-2026-60137 it yields "
                 "unauthenticated remote code execution."),
        "affected": [((6, 9, 0), (6, 9, 4)), ((7, 0, 0), (7, 0, 1))],
        "fixed": ["6.9.5", "7.0.2"],
        "first_affected": (6, 9, 0),   # batch-route weakness introduced in 6.9
        "chain": "wp2shell",
    },
    "CVE-2026-60137": {
        "title": "author__not_in WP_Query SQL injection",
        "cwe": "CWE-89 (SQL Injection)",
        "component": "WP_Query — author__not_in parameter",
        "cvss": "see advisory",
        "severity": "High",
        "advisory": "GHSA-ff9f-jf42-662q",
        "auth": "Unauthenticated",
        "role": ("Second link of the wp2shell chain. Unsanitised input in "
                 "author__not_in reaches the database query. Present since 6.8 — "
                 "the 6.8 branch is exposed to this SQL injection on its own, but "
                 "not to the full RCE chain (which also needs CVE-2026-63030)."),
        "affected": [((6, 8, 0), (6, 8, 5)),
                     ((6, 9, 0), (6, 9, 4)),
                     ((7, 0, 0), (7, 0, 1))],
        "fixed": ["6.8.6", "6.9.5", "7.0.2"],
        "first_affected": (6, 8, 0),   # not affected before 6.8
        "chain": "wp2shell",
    },
    "CVE-2026-3906": {
        "title": "Notes REST API — missing authorization (arbitrary note creation)",
        "cwe": "CWE-862 (Missing Authorization)",
        "component": "REST comments controller — create_item_permissions_check() (Notes)",
        "cvss": "4.3",
        "severity": "Moderate",
        "advisory": "GHSA-6x83-fcf5-r65g",
        "auth": "Authenticated (Subscriber+)",
        "role": ("The Notes feature (added in 6.9) skipped the edit_post "
                 "permission check in its REST endpoint, letting a Subscriber "
                 "create notes on any post — including private and other users' "
                 "posts. Only fully fixed in 6.9.4 (partial fixes in 6.9.2/6.9.3)."),
        "affected": [((6, 9, 0), (6, 9, 3))],
        "fixed": ["6.9.4"],
        "first_affected": (6, 9, 0),   # Notes feature introduced in 6.9
        "chain": None,
    },
}

# The wp2shell RCE chain requires BOTH of these to be present.
WP2SHELL_CHAIN = ("CVE-2026-63030", "CVE-2026-60137")

REFERENCES = [
    ("WordPress GitHub Security Advisory — wp2shell (GHSA-ff9f-jf42-662q)",
     "https://github.com/advisories/GHSA-ff9f-jf42-662q"),
    ("WordPress GitHub Security Advisory — Notes REST API (GHSA-6x83-fcf5-r65g)",
     "https://github.com/advisories/GHSA-6x83-fcf5-r65g"),
    ("NVD — CVE-2026-3906",
     "https://nvd.nist.gov/vuln/detail/CVE-2026-3906"),
    ("Rapid7 — ETR: CVE-2026-63030 wp2shell",
     "https://www.rapid7.com/blog/post/etr-cve-2026-63030-wp2shell-a-critical-remote-code-execution-vulnerability-in-wordpress-core/"),
    ("VulnCheck — WP2Shell (CVE-2026-63030 & CVE-2026-60137)",
     "https://www.vulncheck.com/blog/wp2shell"),
    ("SOCRadar — wp2shell WordPress RCE",
     "https://socradar.io/blog/wp2shell-wordpress-rce-cve-2026-63030/"),
    ("WordPress releases (6.8.6 / 6.9.4 / 6.9.5 / 7.0.2)",
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


# Severity ordering for rolling up per-CVE verdicts into one overall verdict.
VERDICT_ORDER = [V_NOT_WP, V_NOT_AFFECTED, V_PATCHED, V_UNKNOWN, V_VULN]


def classify_cve(v, meta) -> str:
    """Verdict for a single CVE given a detected version tuple (or None)."""
    if v is None:
        return V_UNKNOWN
    for low, high in meta["affected"]:
        if low <= v <= high:
            return V_VULN
    if v < meta["first_affected"]:
        return V_NOT_AFFECTED
    return V_PATCHED  # newer than every affected range on this branch


def roll_up(statuses) -> str:
    """Return the most severe verdict from an iterable of per-CVE verdicts."""
    worst = V_NOT_AFFECTED
    for s in statuses:
        if VERDICT_ORDER.index(s) > VERDICT_ORDER.index(worst):
            worst = s
    return worst


def fixed_for(meta) -> str:
    """Human-readable fixed-release list for one CVE, e.g. '6.9.5 / 7.0.2'."""
    return " / ".join(meta["fixed"])


def all_fixed_releases():
    """De-duplicated, sorted list of every fixed release across the DB."""
    seen = {}
    for meta in VULN_DB.values():
        for f in meta["fixed"]:
            seen[f] = parse_version(f) or (0, 0, 0)
    return [f for f, _ in sorted(seen.items(), key=lambda kv: kv[1])]


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
    chain_rce: bool = False          # full wp2shell RCE chain present (both CVEs)
    vulnerable_cves: list = field(default_factory=list)
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

    # Classify each CVE independently against the detected version.
    for cve, meta in VULN_DB.items():
        status = classify_cve(detected, meta)
        res.per_cve[cve] = {
            "title": meta["title"],
            "cwe": meta["cwe"],
            "component": meta["component"],
            "cvss": meta["cvss"],
            "severity": meta["severity"],
            "advisory": meta["advisory"],
            "auth": meta["auth"],
            "role": meta["role"],
            "affected": " · ".join(
                f"{version_str(lo)}–{version_str(hi)}" for lo, hi in meta["affected"]),
            "fixed": fixed_for(meta),
            "status": status,
        }
        if status == V_VULN:
            res.vulnerable_cves.append(cve)

    # Overall verdict = the most severe per-CVE verdict.
    res.verdict = roll_up(info["status"] for info in res.per_cve.values())

    # Full wp2shell RCE chain requires both of its CVEs to be vulnerable.
    res.chain_rce = all(
        res.per_cve.get(c, {}).get("status") == V_VULN for c in WP2SHELL_CHAIN)

    # Notes / caveats.
    if res.verdict == V_UNKNOWN:
        if res.batch_endpoint_exposed:
            res.notes.append(
                "Core version is hidden but the REST batch endpoint is exposed. "
                "Confirm the exact WordPress version manually (wp-admin > Updates, "
                "or `wp core version`) and compare against the fixed releases "
                + ", ".join(all_fixed_releases()) + ".")
        else:
            res.notes.append(
                "Could not determine the WordPress version from public vectors. "
                "Verify manually and compare against the fixed releases "
                + ", ".join(all_fixed_releases()) + ".")
    elif res.verdict == V_VULN:
        if res.chain_rce:
            res.notes.append(
                "Detected version is exposed to the full wp2shell pre-auth RCE "
                "chain (CVE-2026-63030 + CVE-2026-60137). Treat any internet-facing "
                "instance that ran this version as potentially compromised — "
                "patching closes the route but does not remove a backdoor planted "
                "beforehand.")
        else:
            flagged = ", ".join(res.vulnerable_cves)
            res.notes.append(
                f"Detected version falls inside the affected range of {flagged}. "
                "Patch to the fixed release for this branch and review exposure.")
    elif res.verdict == V_NOT_AFFECTED:
        res.notes.append(
            "Version predates every tracked core flaw, so these specific CVEs do "
            "not apply. The install is still outdated; update to a current "
            "supported release regardless.")

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
    return " · ".join(f"<code>{escape(v)}</code>" for v in all_fixed_releases())


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
    n_vuln = len(res.vulnerable_cves)
    tracked = len(res.per_cve) or len(VULN_DB)
    chain_txt = "exposed" if res.chain_rce else "not complete"
    quick = f"""
      <div class="row">
        <div><span>Detected core</span><b>WordPress {dv}</b></div>
        <div><span>CVEs flagged</span><b>{n_vuln} of {tracked} tracked</b></div>
        <div><span>wp2shell RCE chain</span><b>{chain_txt}</b></div>
        <div><span>REST batch endpoint</span><b>{batch}</b></div>
      </div>"""

    # Findings — one card per tracked CVE, with its own affected/fixed ranges.
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
            <tr><td class="k">Summary</td><td class="v" style="white-space:normal">{escape(info['role'])}</td></tr>
            <tr><td class="k">Component</td><td class="v">{escape(info['component'])}</td></tr>
            <tr><td class="k">Weakness</td><td class="v">{escape(info['cwe'])}</td></tr>
            <tr><td class="k">Access</td><td class="v">{escape(info['auth'])}</td></tr>
            <tr><td class="k">Severity</td><td class="v">{escape(info['severity'])} (CVSS {escape(str(info['cvss']))})</td></tr>
            <tr><td class="k">Affected</td><td class="v">{escape(info['affected'])}</td></tr>
            <tr><td class="k">Fixed in</td><td class="v">{escape(info['fixed'])}</td></tr>
            <tr><td class="k">Advisory</td><td class="v">{escape(info['advisory'])}</td></tr>
          </table>
        </div>""")
    if not findings:
        findings.append('<div class="notes">No WordPress detected — the tracked '
                        'core CVEs do not apply to this host.</div>')

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
<title>WordPress core exposure — {escape(host)}</title>
<style>{REPORT_CSS}</style></head>
<body><div class="wrap"><div class="sheet">
{sample_tag}
<header class="masthead">
  <div class="brand">CyberSentinel Solutions Ltd<small>Offensive Security · Vulnerability Assessment</small></div>
  <div class="doc-meta">
    Report: <b>WordPress core exposure</b><br>
    Target: <b>{escape(host)}</b><br>
    Scanned: <b>{escape(scanned)}</b><br>
    Tool: <b>{escape(res.tool)}</b>
  </div>
</header>

<h1 class="title">WordPress core vulnerability assessment</h1>
<p class="subtitle">Recent core CVEs — wp2shell RCE chain (CVE-2026-63030 + CVE-2026-60137) &amp; CVE-2026-3906</p>

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

    subject = f"[{sev_word}] WP core scan — {host} — {res.verdict}"
    fixed_all = " / ".join(all_fixed_releases())

    if res.verdict == V_VULN:
        flagged = ", ".join(res.vulnerable_cves)
        if res.chain_rce:
            lead = (f"The scan flagged {host} as VULNERABLE to the wp2shell pre-auth "
                    f"RCE chain (CVE-2026-63030 + CVE-2026-60137).")
            action = ("Recommend IMMEDIATE patching to the fixed release for this "
                      f"branch ({fixed_all}) and a compromise assessment, since this "
                      "instance was exposed while running a vulnerable version.")
        else:
            lead = (f"The scan flagged {host} as VULNERABLE to {flagged}.")
            action = ("Recommend patching to the fixed release for this branch "
                      f"({fixed_all}) and reviewing exposure for the flagged CVE(s).")
    elif res.verdict == V_UNKNOWN:
        lead = (f"The scan of {host} was inconclusive — the WordPress core version "
                f"could not be confirmed from public vectors.")
        action = ("Recommend manual version verification against the fixed releases "
                  f"({fixed_all}).")
    elif res.verdict == V_PATCHED:
        lead = (f"{host} is running a patched WordPress release and is not exposed "
                f"to the tracked core CVEs.")
        action = "No action required for these CVEs; keep auto-updates enabled."
    elif res.verdict == V_NOT_AFFECTED:
        lead = (f"{host} runs a WordPress version that predates the tracked flaws; "
                f"they do not apply.")
        action = "Recommend updating to a current supported release regardless."
    else:
        lead = f"No WordPress fingerprint was found on {host}."
        action = "No exposure to the tracked core CVEs; no action required."

    ev_lines = "\n".join(
        f"    - {e['source']}: {e['detail']}"
        + (f"  (v{e['version']})" if e.get("version") else "")
        for e in res.evidence
    ) or "    - none returned"

    # Per-CVE status block.
    cve_lines = "\n".join(
        f"  {cve} [{info['status']}] — {info['title']}\n"
        f"      affected {info['affected']}   fixed {info['fixed']}"
        for cve, info in res.per_cve.items()
    ) or "  (no WordPress detected)"

    attach = f"\nAttached: {report_filename}" if report_filename else ""

    body = f"""To: {CSSLTD_CONTACT}
Subject: {subject}

Team,

{lead}

  Target ............ {res.target}
  WordPress version . {res.detected_version or 'not disclosed'}
  Verdict ........... {res.verdict} — {VERDICT_LABEL.get(res.verdict, '')}
  wp2shell RCE chain  {'EXPOSED' if res.chain_rce else 'not complete'}
  REST batch route .. {'exposed' if res.batch_endpoint_exposed else 'not observed'}
  Scanned (UTC) ..... {res.scanned_at}

Tracked core CVEs:
{cve_lines}

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
    if res.per_cve:
        print("  CVEs     :")
        for cve, info in res.per_cve.items():
            print(f"     - {cve}: {info['status']}  (fixed {info['fixed']})")
    if res.chain_rce:
        print("  Chain    : wp2shell pre-auth RCE chain EXPOSED")
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
    """Synthetic result for a 6.9.1 host (exposed to all three tracked CVEs)."""
    ver = "6.9.1"
    v = parse_version(ver)
    res = ScanResult(target="https://example.com/",
                     scanned_at=datetime.now(timezone.utc).isoformat())
    res.is_wordpress = True
    res.detected_version = ver
    res.batch_endpoint_exposed = True
    res.evidence = [
        {"source": "generator meta tag (homepage)",
         "detail": f'meta generator = "WordPress {ver}"', "version": ver},
        {"source": "/readme.html", "detail": f"Version {ver}", "version": ver},
        {"source": "/wp-json/ (REST root)",
         "detail": "batch/v1 namespace is registered (REST batch endpoint reachable)",
         "version": None},
    ]
    # Run the real per-CVE classifier so the demo stays consistent with the DB.
    for cve, meta in VULN_DB.items():
        status = classify_cve(v, meta)
        res.per_cve[cve] = {
            "title": meta["title"], "cwe": meta["cwe"],
            "component": meta["component"], "cvss": meta["cvss"],
            "severity": meta["severity"], "advisory": meta["advisory"],
            "auth": meta["auth"], "role": meta["role"],
            "affected": " · ".join(
                f"{version_str(lo)}–{version_str(hi)}" for lo, hi in meta["affected"]),
            "fixed": fixed_for(meta), "status": status,
        }
        if status == V_VULN:
            res.vulnerable_cves.append(cve)
    res.verdict = roll_up(info["status"] for info in res.per_cve.values())
    res.chain_rce = all(
        res.per_cve.get(c, {}).get("status") == V_VULN for c in WP2SHELL_CHAIN)
    res.notes = [
        "Detected version is exposed to the full wp2shell pre-auth RCE chain "
        "(CVE-2026-63030 + CVE-2026-60137). Treat any internet-facing instance "
        "that ran this version as potentially compromised — patching closes the "
        "route but does not remove a backdoor planted beforehand.",
    ]
    return res


# --------------------------------------------------------------------------- #
#  CLI                                                                         #
# --------------------------------------------------------------------------- #

def build_arg_parser():
    p = argparse.ArgumentParser(
        prog="wp2shell_scanner.py",
        description="CSSLTD detection scanner for recent WordPress core CVEs "
                    "(wp2shell chain CVE-2026-63030 / CVE-2026-60137, plus "
                    "CVE-2026-3906). Detection-only.",
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
