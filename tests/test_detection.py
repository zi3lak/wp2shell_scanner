#!/usr/bin/env python3
"""
Offline detection-logic tests for wp2shell_scanner.

No network: a FakeSession returns canned HTTP responses per URL so the real
scan_target() pipeline (version aggregation, conflict/pre-release handling,
per-CVE classification, WordPress detection) is exercised end to end.

Run:  python tests/test_detection.py     (exit 0 = all pass)
"""
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
import wp2shell_scanner as w  # noqa: E402


class FakeResp:
    def __init__(self, url, status=200, text="", data=None, headers=None):
        self.url = url
        self.status_code = status
        self.ok = 200 <= status < 400
        self.text = text
        self._data = data
        self.headers = headers or {}

    def json(self):
        if self._data is None:
            raise ValueError("no json")
        return self._data


class FakeSession:
    """Routes GETs to a scenario dict keyed by URL path suffix."""
    def __init__(self, routes):
        self.routes = routes
        self.headers = {}
        self.verify = True

    def mount(self, *_):  # build_session compatibility (unused here)
        pass

    def get(self, url, timeout=None, allow_redirects=True, **kw):
        for suffix, resp in self.routes.items():
            if url.rstrip("/").endswith(suffix.rstrip("/")) or \
               (suffix == "/" and url.count("/") <= 3):
                r = FakeResp(url, **resp)
                return r
        # Homepage (base URL) fallback.
        return FakeResp(url, **self.routes.get("HOME", {"status": 404}))


WP_REST = {"namespaces": ["oembed/1.0", "wp/v2"], "routes": {"/wp/v2": {}}}
WP_REST_BATCH = {"namespaces": ["oembed/1.0", "wp/v2", "batch/v1"],
                 "routes": {"/wp/v2": {}, "/batch/v1": {}}}


def meta_html(ver):
    return (f'<html><head><meta name="generator" '
            f'content="WordPress {ver}" /></head><body>wp-content</body></html>')


def scenario(routes):
    """Patch build_session to return a FakeSession for one scan."""
    w.build_session = lambda timeout, verify_tls: FakeSession(routes)
    return w.scan_target("https://site.example", timeout=5, verify_tls=True)


FAILS = []


def check(name, cond):
    print(f"  [{'PASS' if cond else 'FAIL'}] {name}")
    if not cond:
        FAILS.append(name)


def main():
    # 1) Vulnerable 7.0.1 — full RCE chain, batch advertised.
    r = scenario({
        "HOME": {"text": meta_html("7.0.1")},
        "readme.html": {"text": "<h1>Version 7.0.1</h1>"},
        "wp-json": {"data": WP_REST_BATCH},
    })
    check("7.0.1 verdict VULNERABLE", r.verdict == w.V_VULN)
    check("7.0.1 chain_rce True", r.chain_rce is True)
    check("7.0.1 63030 VULN", r.per_cve["CVE-2026-63030"]["status"] == w.V_VULN)
    check("7.0.1 3906 not vulnerable", r.per_cve["CVE-2026-3906"]["status"] != w.V_VULN)
    check("7.0.1 batch advertised", r.batch_namespace_advertised is True)

    # 2) Patched 7.0.2.
    r = scenario({
        "HOME": {"text": meta_html("7.0.2")},
        "readme.html": {"text": "Version 7.0.2"},
        "wp-json": {"data": WP_REST},
    })
    check("7.0.2 verdict PATCHED", r.verdict == w.V_PATCHED)
    check("7.0.2 chain_rce False", r.chain_rce is False)

    # 3) 6.8.5 — SQLi only, no RCE chain.
    r = scenario({
        "HOME": {"text": meta_html("6.8.5")},
        "wp-json": {"data": WP_REST},
    })
    check("6.8.5 verdict VULNERABLE", r.verdict == w.V_VULN)
    check("6.8.5 chain_rce False", r.chain_rce is False)
    check("6.8.5 60137 VULN", r.per_cve["CVE-2026-60137"]["status"] == w.V_VULN)
    check("6.8.5 63030 NOT_AFFECTED",
          r.per_cve["CVE-2026-63030"]["status"] == w.V_NOT_AFFECTED)

    # 4) Hidden version — WP confirmed via markup, no version → UNKNOWN.
    r = scenario({
        "HOME": {"text": "<html><body>wp-content wp-includes</body></html>"},
        "wp-json": {"data": WP_REST},
    })
    check("hidden-version is_wordpress", r.is_wordpress is True)
    check("hidden-version verdict UNKNOWN", r.verdict == w.V_UNKNOWN)

    # 5) Not WordPress — plain 200 site, /wp-json is not a WP index.
    r = scenario({
        "HOME": {"text": "<html><body>Just a website</body></html>"},
        "wp-json": {"status": 200, "text": "not json"},
    })
    check("non-wp is_wordpress False", r.is_wordpress is False)
    check("non-wp verdict NOT_WORDPRESS", r.verdict == w.V_NOT_WP)

    # 6) Conflicting versions — homepage 7.0.2 vs readme 6.9.4 → UNKNOWN.
    r = scenario({
        "HOME": {"text": meta_html("7.0.2")},
        "readme.html": {"text": "<h1>WordPress</h1><br /> Version 6.9.4"},
        "wp-json": {"data": WP_REST},
    })
    check("conflict flagged", r.version_conflict is True)
    check("conflict verdict UNKNOWN", r.verdict == w.V_UNKNOWN)

    # 7) Pre-release build — 7.1-beta1 must NOT read as patched.
    r = scenario({
        "HOME": {"text": meta_html("7.1-beta1")},
        "wp-json": {"data": WP_REST},
    })
    check("prerelease flagged", r.prerelease is True)
    check("prerelease verdict UNKNOWN", r.verdict == w.V_UNKNOWN)

    # 8) Cross-host redirect is BLOCKED — verdict UNKNOWN, target not scanned.
    w.build_session = lambda timeout, verify_tls: FakeSession({
        "HOME": {"status": 302,
                 "headers": {"location": "https://evil.other/"}},
    })
    r = w.scan_target("https://site.example", timeout=5, verify_tls=True)
    check("cross-host redirect -> UNKNOWN", r.verdict == w.V_UNKNOWN)
    check("cross-host redirect blocked (error set)",
          bool(r.error) and "redirect blocked" in r.error)
    check("cross-host redirect not flagged WordPress", r.is_wordpress is False)

    # 9) CVE-2026-3906 range: vulnerable at 6.9.1, patched at 6.9.2.
    r = scenario({"HOME": {"text": meta_html("6.9.1")}, "wp-json": {"data": WP_REST}})
    check("6.9.1 3906 VULNERABLE",
          r.per_cve["CVE-2026-3906"]["status"] == w.V_VULN)
    r = scenario({"HOME": {"text": meta_html("6.9.2")}, "wp-json": {"data": WP_REST}})
    check("6.9.2 3906 not vulnerable",
          r.per_cve["CVE-2026-3906"]["status"] != w.V_VULN)

    # 10) readme.html false positive — "API Version 6.9.4" with no WordPress marker.
    r = scenario({
        "HOME": {"text": "<html><body>plain site</body></html>"},
        "readme.html": {"text": "<h1>My API</h1> API Version 6.9.4"},
        "wp-json": {"status": 404, "text": "nope"},
    })
    check("readme without WordPress marker -> NOT_WORDPRESS",
          r.verdict == w.V_NOT_WP)

    # 11) REST false positive — a non-WordPress JSON API.
    r = scenario({
        "HOME": {"text": "<html><body>plain site</body></html>"},
        "wp-json": {"data": {"namespaces": ["api/v1"], "routes": {"/api/v1": {}}}},
    })
    check("non-WP REST API -> NOT_WORDPRESS", r.verdict == w.V_NOT_WP)

    # 12) Scope helper: same registrable domain must NOT mean same scope.
    check("same_scope client vs evil (co.uk) is False",
          w.same_scope("client.co.uk", "evil.co.uk") is False)
    check("same_scope www-tolerant is True",
          w.same_scope("example.com", "www.example.com") is True)

    # 13) recommended_releases never includes the unsafe 6.9.4 / 6.9.2.
    check("recommended releases are the safe set",
          w.recommended_releases() == ["6.8.6", "6.9.5", "7.0.2"])

    print()
    if FAILS:
        print(f"{len(FAILS)} FAILED: {', '.join(FAILS)}")
        return 1
    print("all detection-logic tests passed")
    return 0


if __name__ == "__main__":
    sys.exit(main())
