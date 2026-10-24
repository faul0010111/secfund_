import hashlib
import tempfile
import unittest
from pathlib import Path
from unittest import mock

from netfixtures import http_server

from secfund import passwords

FAST_SCRYPT = {"n": 2**10, "r": 8, "p": 1}


class TestAudit(unittest.TestCase):
    def test_common_is_weak(self):
        self.assertEqual(passwords.audit_password("qwerty123").verdict, "WEAK")

    def test_long_random_is_strong(self):
        self.assertEqual(passwords.audit_password("vK9#tQ2$mZx7!Lp4wR8@").verdict, "STRONG")

    def test_leetspeak_variant_of_common_password_is_caught(self):
        audit = passwords.audit_password("P@ssw0rd2026!")
        self.assertTrue(any("Trivial variation" in i for i in audit.issues))
        self.assertLessEqual(audit.score, 20)

    def test_keyboard_walk_and_repeats(self):
        issues = passwords.audit_password("qwerty-aaa-zzz").issues
        self.assertTrue(any("keyboard" in i for i in issues))
        self.assertTrue(any("Repeated" in i for i in issues))

    def test_pwned_count_forces_weak(self):
        audit = passwords.audit_password("vK9#tQ2$mZx7!Lp4wR8@", pwned_count=12345)
        self.assertEqual(audit.verdict, "WEAK")
        self.assertTrue(any("12,345" in i for i in audit.issues))

    def test_empty_password(self):
        self.assertEqual(passwords.audit_password("").verdict, "WEAK")


class TestGenerate(unittest.TestCase):
    def test_generated_password_is_strong_and_has_all_classes(self):
        for _ in range(20):
            pw = passwords.generate_password(20)
            self.assertEqual(len(pw), 20)
            self.assertTrue(any(c.islower() for c in pw) and any(c.isupper() for c in pw))
            self.assertTrue(any(c.isdigit() for c in pw) and any(not c.isalnum() for c in pw))
            self.assertEqual(passwords.audit_password(pw).verdict, "STRONG")

    def test_values_are_different(self):
        self.assertNotEqual(passwords.generate_password(), passwords.generate_password())

    def test_short_length_rejected(self):
        with self.assertRaises(ValueError):
            passwords.generate_password(8)


class TestHashing(unittest.TestCase):
    def test_scrypt_roundtrip_and_unique_salt(self):
        a = passwords.hash_password("correct horse", **FAST_SCRYPT)
        b = passwords.hash_password("correct horse", **FAST_SCRYPT)
        self.assertTrue(a.startswith("scrypt$1024$8$1$"))
        self.assertNotEqual(a, b)
        self.assertTrue(passwords.verify_password("correct horse", a))
        self.assertFalse(passwords.verify_password("wrong", a))

    def test_pbkdf2_roundtrip(self):
        stored = passwords.hash_password("correct horse", "pbkdf2", iterations=1000)
        self.assertTrue(stored.startswith("pbkdf2_sha256$1000$"))
        self.assertTrue(passwords.verify_password("correct horse", stored))
        self.assertFalse(passwords.verify_password("wrong", stored))

    def test_default_scrypt_parameters_follow_owasp(self):
        stored = passwords.hash_password("x")
        self.assertTrue(stored.startswith("scrypt$131072$8$1$"))
        self.assertTrue(passwords.verify_password("x", stored))

    def test_unicode_normalization(self):
        composed, decomposed = "café", "café"
        stored = passwords.hash_password(composed, **FAST_SCRYPT)
        self.assertTrue(passwords.verify_password(decomposed, stored))

    def test_malformed_hashes_rejected(self):
        for bad in ("", "lixo", "scrypt$1$2", "pbkdf2_sha256$x$y$z", "md5$1$2$3", "scrypt$1024$8$1$!!$!!"):
            self.assertFalse(passwords.verify_password("x", bad), bad)

    def test_hostile_parameters_rejected_without_doing_the_work(self):
        # A forged hash with an absurd cost must not become a DoS.
        self.assertFalse(
            passwords.verify_password(
                "x", "scrypt$1073741824$8$1$AAAAAAAAAAAAAAAAAAAAAA==$AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA="
            )
        )
        self.assertFalse(
            passwords.verify_password(
                "x", "pbkdf2_sha256$999999999999$AAAAAAAAAAAAAAAAAAAAAA==$AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA="
            )
        )
        self.assertFalse(
            passwords.verify_password(
                "x", "scrypt$1000$8$1$AAAAAAAAAAAAAAAAAAAAAA==$AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA="
            )
        )  # n is not a power of 2

    def test_invalid_hash_parameters_rejected_on_creation(self):
        with self.assertRaises(ValueError):
            passwords.hash_password("x", n=3)
        with self.assertRaises(ValueError):
            passwords.hash_password("x", "pbkdf2", iterations=0)
        with self.assertRaises(ValueError):
            passwords.hash_password("x", "md5")

    def test_needs_rehash(self):
        weak_scrypt = passwords.hash_password("x", **FAST_SCRYPT)
        weak_pbkdf2 = passwords.hash_password("x", "pbkdf2", iterations=1000)
        self.assertTrue(passwords.needs_rehash(weak_scrypt))
        self.assertTrue(passwords.needs_rehash(weak_pbkdf2))
        self.assertTrue(passwords.needs_rehash(weak_pbkdf2, "pbkdf2"))
        self.assertTrue(passwords.needs_rehash("lixo"))
        self.assertFalse(passwords.needs_rehash(f"pbkdf2_sha256${passwords.PBKDF2_ITERATIONS}$a$b", "pbkdf2"))
        self.assertFalse(passwords.needs_rehash(f"scrypt${passwords.SCRYPT_N}$8$1$a$b"))


class TestPwned(unittest.TestCase):
    PASSWORD = "P@ssw0rd"

    def _sha1(self):
        return hashlib.sha1(self.PASSWORD.encode(), usedforsecurity=False).hexdigest().upper()

    def test_k_anonymity_only_sends_five_chars(self):
        digest = self._sha1()
        sent: list[str] = []

        def fake_fetch(prefix: str) -> str:
            sent.append(prefix)
            return f"0018A45C4D1DEF81644B54AB7F969B88D65:3\r\n{digest[5:]}:9545824\r\nFFFFF{'0' * 30}:0\r\n"

        self.assertEqual(passwords.pwned_count_range(self.PASSWORD, fake_fetch), 9545824)
        self.assertEqual(sent, [digest[:5]])
        self.assertEqual(len(sent[0]), 5)

    def test_not_found_returns_zero(self):
        self.assertEqual(passwords.pwned_count_range("vK9#tQ2$mZx7!Lp4wR8@", lambda p: "ABCDEF:1\n"), 0)

    def test_offline_file(self):
        with tempfile.TemporaryDirectory() as d:
            f = Path(d) / "hashes.txt"
            f.write_text(f"{'A' * 40}:1\n{self._sha1().lower()}:42\n")
            self.assertEqual(passwords.pwned_count_file(self.PASSWORD, f), 42)
            self.assertEqual(passwords.pwned_count_file("some-other-password", f), 0)

    def test_online_fetch_rejects_bad_prefix(self):
        for bad in ("", "abc", "ZZZZZ", "../etc/passwd", "ABCDEF"):
            with self.assertRaises(ValueError):
                passwords.fetch_range_online(bad)


class TestPwnedOnline(unittest.TestCase):
    def test_online_range_roundtrip_with_local_server(self):
        digest = hashlib.sha1(b"hunter2", usedforsecurity=False).hexdigest().upper()
        body = f"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA:1\r\n{digest[5:]}:17043\r\n"
        with (
            http_server([], range_body=body) as (base, seen),
            mock.patch.object(passwords, "PWNED_API", base + "/range/"),
        ):
            count = passwords.pwned_count_range("hunter2", passwords.fetch_range_online)
        self.assertEqual(count, 17043)
        self.assertEqual(seen["path"], f"/range/{digest[:5]}")  # only the prefix traveled over the wire
        self.assertNotIn(digest[5:], seen["path"])
        self.assertEqual(seen["padding"], "true")


if __name__ == "__main__":
    unittest.main()
