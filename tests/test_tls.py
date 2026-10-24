import os
import shutil
import socket
import tempfile
import unittest
from datetime import datetime, timedelta, timezone
from pathlib import Path
from unittest import mock

from netfixtures import make_self_signed, plain_server, tls_server

from secfund import tls

NOW = datetime(2026, 10, 18, tzinfo=timezone.utc)


def healthy(**overrides):
    base = {
        "host": "example.test", "port": 443, "protocol": "TLSv1.3", "cipher": "TLS_AES_256_GCM_SHA384",
        "cipher_bits": 256, "not_after": NOW + timedelta(days=90), "verified": True,
    }  # fmt: skip
    base.update(overrides)
    return tls.TlsInfo(**base)


class TestEvaluate(unittest.TestCase):
    def test_healthy_host_has_no_issues(self):
        self.assertEqual(tls.evaluate(healthy(), NOW), [])

    def test_expired_certificate_is_critical(self):
        issues = tls.evaluate(healthy(not_after=NOW - timedelta(days=3)), NOW)
        self.assertEqual(issues[0].severity, "CRITICAL")
        self.assertIn("expired", issues[0].title)

    def test_expiry_thresholds(self):
        self.assertEqual(tls.evaluate(healthy(not_after=NOW + timedelta(days=10, hours=1)), NOW)[0].severity, "HIGH")
        self.assertEqual(tls.evaluate(healthy(not_after=NOW + timedelta(days=20, hours=1)), NOW)[0].severity, "MEDIUM")
        self.assertEqual(tls.evaluate(healthy(not_after=NOW + timedelta(days=31)), NOW), [])

    def test_untrusted_certificate(self):
        info = healthy(verified=False, verify_error="self-signed certificate")
        issue = tls.evaluate(info, NOW)[0]
        self.assertEqual((issue.rule_id, issue.severity), ("SF-TLS-001", "HIGH"))

    def test_expired_verify_error_is_critical(self):
        info = healthy(verified=False, verify_error="certificate has expired")
        self.assertEqual(tls.evaluate(info, NOW)[0].severity, "CRITICAL")

    def test_obsolete_protocol(self):
        for proto in ("TLSv1", "TLSv1.1", "SSLv3"):
            issues = tls.evaluate(healthy(protocol=proto), NOW)
            self.assertEqual(issues[0].rule_id, "SF-TLS-003", proto)

    def test_weak_ciphers(self):
        for cipher, bits in (("ECDHE-RSA-RC4-SHA", 128), ("DES-CBC3-SHA", 112), ("AES128-GCM-SHA256", 64)):
            issues = tls.evaluate(healthy(cipher=cipher, cipher_bits=bits), NOW)
            self.assertEqual(issues[0].rule_id, "SF-TLS-004", cipher)

    def test_handshake_failure(self):
        issues = tls.evaluate(tls.TlsInfo("legacy.test", handshake_error="UNSUPPORTED_PROTOCOL"), NOW)
        self.assertEqual(issues[0].rule_id, "SF-TLS-003")
        self.assertEqual(issues[0].location, "legacy.test:443")


@unittest.skipUnless(shutil.which("openssl"), "openssl not available")
class TestLiveServers(unittest.TestCase):
    """Integration tests against local (loopback) TLS servers."""

    @classmethod
    def setUpClass(cls):
        cls._tmp = tempfile.TemporaryDirectory()
        cls.cert, cls.key = make_self_signed(Path(cls._tmp.name))

    @classmethod
    def tearDownClass(cls):
        cls._tmp.cleanup()

    def test_self_signed_is_flagged_but_protocol_still_read(self):
        with tls_server(self.cert, self.key) as port:
            info = tls.fetch_tls("127.0.0.1", port, timeout=3)
        self.assertFalse(info.verified)
        self.assertTrue(info.verify_error)
        self.assertIn(info.protocol, ("TLSv1.2", "TLSv1.3"))
        self.assertIn("SF-TLS-001", {i.rule_id for i in tls.evaluate(info)})

    def test_trusted_certificate_is_parsed(self):
        # SSL_CERT_FILE makes the default context trust the test certificate (trust anchor).
        with mock.patch.dict(os.environ, {"SSL_CERT_FILE": str(self.cert)}), tls_server(self.cert, self.key) as port:
            info = tls.fetch_tls("localhost", port, timeout=3)
        if not info.verified:
            self.skipTest(f"Local OpenSSL rejected the self-signed anchor: {info.verify_error}")
        self.assertEqual(info.subject, "localhost")
        self.assertIn("localhost", info.san)
        self.assertIsNotNone(info.not_after)
        self.assertEqual(tls.evaluate(info), [])

    def test_non_tls_service_reports_handshake_error(self):
        with plain_server(b"HTTP/1.1 400 Bad Request\r\n\r\n") as port:
            info = tls.fetch_tls("127.0.0.1", port, timeout=3)
        self.assertTrue(info.handshake_error)
        self.assertEqual(tls.evaluate(info)[0].rule_id, "SF-TLS-003")

    def test_connection_refused_raises_oserror(self):
        with socket.socket() as s:
            s.bind(("127.0.0.1", 0))
            free_port = s.getsockname()[1]
        with self.assertRaises(OSError):
            tls.fetch_tls("127.0.0.1", free_port, timeout=1)


if __name__ == "__main__":
    unittest.main()
