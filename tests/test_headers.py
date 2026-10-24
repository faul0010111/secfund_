import json
import unittest
from pathlib import Path

from netfixtures import http_server

from secfund import headers

ROOT = Path(__file__).resolve().parent.parent

HARDENED = {
    "Strict-Transport-Security": "max-age=31536000; includeSubDomains",
    "Content-Security-Policy": "default-src 'self'; frame-ancestors 'none'",
    "X-Content-Type-Options": "nosniff",
    "Referrer-Policy": "strict-origin-when-cross-origin",
    "Permissions-Policy": "geolocation=()",
}


class TestHeaders(unittest.TestCase):
    def test_weak_site_fails(self):
        hdrs = json.loads((ROOT / "samples" / "headers_weak.json").read_text())
        _res, pct, letter = headers.analyze_headers(hdrs)
        self.assertEqual(letter, "F")
        self.assertLess(pct, 20)

    def test_hardened_site_passes(self):
        _res, pct, letter = headers.analyze_headers(HARDENED)
        self.assertEqual(letter, "A")
        self.assertGreaterEqual(pct, 90)

    def test_grade_is_monotonic(self):
        # Corrigir um problema nunca pode piorar a nota (bug antigo: pesos mudavam com o status).
        weak = dict(HARDENED, **{"Strict-Transport-Security": "max-age=100"})
        missing = {k: v for k, v in HARDENED.items() if k != "Strict-Transport-Security"}
        p_ok = headers.analyze_headers(HARDENED)[1]
        p_weak = headers.analyze_headers(weak)[1]
        p_missing = headers.analyze_headers(missing)[1]
        self.assertGreater(p_ok, p_weak)
        self.assertGreater(p_weak, p_missing)

    def test_header_names_are_case_insensitive(self):
        upper = {k.upper(): v for k, v in HARDENED.items()}
        self.assertEqual(headers.analyze_headers(upper)[2], "A")

    def test_weak_csp_variants(self):
        for csp in ("default-src * ", "script-src 'unsafe-inline'", "script-src 'unsafe-eval' 'self'"):
            res = {r.header: r for r in headers.analyze_headers({"Content-Security-Policy": csp})[0]}
            self.assertEqual(res["Content-Security-Policy"].status, "FRACO", csp)

    def test_cookie_flags(self):
        hdrs = json.loads((ROOT / "samples" / "headers_cookies.json").read_text())
        res = {r.header: r for r in headers.analyze_headers(hdrs)[0]}
        self.assertEqual(res["Set-Cookie"].status, "FRACO")
        self.assertIn("sid: sem Secure, SameSite", res["Set-Cookie"].detail)
        self.assertIn("theme: sem Secure, HttpOnly, SameSite", res["Set-Cookie"].detail)

    def test_secure_cookie_ok(self):
        hdrs = dict(HARDENED, **{"Set-Cookie": "sid=1; Secure; HttpOnly; SameSite=Strict"})
        res = {r.header: r for r in headers.analyze_headers(hdrs)[0]}
        self.assertEqual(res["Set-Cookie"].status, "OK")

    def test_hsts_malformed_max_age(self):
        res = {r.header: r for r in headers.analyze_headers({"Strict-Transport-Security": "max-age=abc"})[0]}
        self.assertEqual(res["Strict-Transport-Security"].status, "FRACO")

    def test_to_issues_maps_rules_and_skips_ok(self):
        hdrs = json.loads((ROOT / "samples" / "headers_weak.json").read_text())
        results, _, _ = headers.analyze_headers(hdrs)
        issues = headers.to_issues(results, "samples/headers_weak.json")
        self.assertTrue(all(i.title.split(":")[1].strip() != "ok" for i in issues))
        self.assertEqual({i.rule_id for i in issues}, {"SF-HDR-001", "SF-HDR-002", "SF-HDR-004"})
        self.assertTrue(all(i.remediation for i in issues))

    def test_rejects_non_http_scheme(self):
        for url in ("file:///etc/passwd", "ftp://x", "gopher://x", "javascript:alert(1)"):
            with self.assertRaises(ValueError):
                headers.fetch_headers(url)


class TestFetchHeaders(unittest.TestCase):
    def test_fetch_collects_duplicate_set_cookie_headers(self):
        sent = [
            ("Server", "nginx/1.25.3"),
            ("Strict-Transport-Security", "max-age=31536000"),
            ("Set-Cookie", "sid=1; Secure; HttpOnly; SameSite=Lax"),
            ("Set-Cookie", "theme=dark"),
        ]
        with http_server(sent) as (base, _seen):
            hdrs = headers.fetch_headers(base)
        self.assertEqual(hdrs["Server"], "nginx/1.25.3")
        self.assertEqual(len(hdrs["Set-Cookie"]), 2)  # antes do ajuste, o segundo cookie sobrescrevia o primeiro
        res = {r.header: r for r in headers.analyze_headers(hdrs)[0]}
        self.assertEqual(res["Set-Cookie"].status, "FRACO")
        self.assertIn("theme", res["Set-Cookie"].detail)
        self.assertNotIn("sid:", res["Set-Cookie"].detail)

    def test_unreachable_host_raises_oserror(self):
        with self.assertRaises(OSError):
            headers.fetch_headers("http://127.0.0.1:1", timeout=1)


if __name__ == "__main__":
    unittest.main()
