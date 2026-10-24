import json
import os
import stat
import tempfile
import unittest
from pathlib import Path
from unittest import mock

from secfund import fim

KEY = bytes.fromhex("aa" * 32)
OTHER_KEY = bytes.fromhex("bb" * 32)


class FimCase(unittest.TestCase):
    def setUp(self):
        self._tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self._tmp.cleanup)
        self.base_dir = Path(self._tmp.name)
        self.root = self.base_dir / "site"
        self.root.mkdir()
        (self.root / "a.txt").write_text("a")
        (self.root / "b.txt").write_text("b")
        self.baseline = self.base_dir / "base.json"


class TestDetection(FimCase):
    def test_detects_changes(self):
        self.assertEqual(fim.save_baseline(self.root, self.baseline), 2)
        self.assertEqual(sum(map(len, fim.verify(self.root, self.baseline).values())), 0)

        (self.root / "a.txt").write_text("HACKED")
        (self.root / "b.txt").unlink()
        (self.root / "backdoor.php").write_text("x")
        diff = fim.verify(self.root, self.baseline)
        self.assertEqual(diff["modified"], ["a.txt"])
        self.assertEqual(diff["removed"], ["b.txt"])
        self.assertEqual(diff["added"], ["backdoor.php"])

    @unittest.skipIf(os.name != "posix", "POSIX permissions")
    def test_detects_permission_change(self):
        fim.save_baseline(self.root, self.baseline)
        (self.root / "a.txt").chmod(0o777)
        self.assertEqual(fim.verify(self.root, self.baseline)["permissions"], ["a.txt"])

    def test_nested_dirs_and_exclude(self):
        (self.root / "sub").mkdir()
        (self.root / "sub" / "deep.txt").write_text("d")
        (self.root / "cache.tmp").write_text("t")
        n = fim.save_baseline(self.root, self.baseline, exclude=["*.tmp"])
        self.assertEqual(n, 3)
        (self.root / "cache.tmp").write_text("changed")  # excluded: must not alert
        self.assertEqual(sum(map(len, fim.verify(self.root, self.baseline, exclude=["*.tmp"]).values())), 0)

    def test_symlinks_are_not_followed(self):
        outside = self.base_dir / "secret.txt"
        outside.write_text("segredo")
        try:
            (self.root / "link.txt").symlink_to(outside)
        except OSError:
            self.skipTest("symlinks not supported")
        self.assertEqual(fim.save_baseline(self.root, self.baseline), 2)

    def test_baseline_inside_root_is_ignored(self):
        inside = self.root / "baseline.json"
        self.assertEqual(fim.save_baseline(self.root, inside), 2)
        self.assertEqual(sum(map(len, fim.verify(self.root, inside).values())), 0)

    @unittest.skipIf(os.name != "posix" or os.geteuid() == 0, "requires a non-root POSIX user")
    def test_unreadable_file_is_reported_not_fatal(self):
        locked = self.root / "locked.txt"
        locked.write_text("x")
        locked.chmod(0)
        skipped: list[str] = []
        snap = fim.snapshot(self.root, skipped=skipped)
        self.assertEqual(skipped, ["locked.txt"])
        self.assertNotIn("locked.txt", snap)

    def test_to_issues(self):
        diff = {"added": ["x.php"], "removed": ["b"], "modified": ["a"], "permissions": ["c"]}
        issues = fim.to_issues(diff, "site")
        self.assertEqual({i.rule_id for i in issues}, {"SF-FIM-001", "SF-FIM-002", "SF-FIM-003", "SF-FIM-004"})
        self.assertEqual(next(i for i in issues if i.rule_id == "SF-FIM-002").technique, "T1505.003")


class TestSignedBaseline(FimCase):
    def test_signed_roundtrip(self):
        fim.save_baseline(self.root, self.baseline, KEY)
        self.assertEqual(sum(map(len, fim.verify(self.root, self.baseline, KEY).values())), 0)

    def test_tampered_baseline_detected(self):
        fim.save_baseline(self.root, self.baseline, KEY)
        doc = json.loads(self.baseline.read_text())
        doc["files"]["a.txt"]["sha256"] = "0" * 64  # attacker "hides" the change
        self.baseline.write_text(json.dumps(doc))
        with self.assertRaisesRegex(fim.BaselineError, "tampered"):
            fim.verify(self.root, self.baseline, KEY)

    def test_wrong_key_rejected(self):
        fim.save_baseline(self.root, self.baseline, KEY)
        with self.assertRaises(fim.BaselineError):
            fim.verify(self.root, self.baseline, OTHER_KEY)

    def test_missing_key_for_signed_baseline(self):
        fim.save_baseline(self.root, self.baseline, KEY)
        with self.assertRaisesRegex(fim.BaselineError, "signed baseline"):
            fim.verify(self.root, self.baseline)

    def test_signature_stripping_downgrade_rejected(self):
        fim.save_baseline(self.root, self.baseline, KEY)
        doc = json.loads(self.baseline.read_text())
        doc["signature"] = None
        self.baseline.write_text(json.dumps(doc))
        with self.assertRaisesRegex(fim.BaselineError, "NO signature"):
            fim.verify(self.root, self.baseline, KEY)

    def test_corrupt_and_old_format_rejected(self):
        self.baseline.write_text("{not json")
        with self.assertRaises(fim.BaselineError):
            fim.load_baseline(self.baseline)
        self.baseline.write_text(json.dumps({"a.txt": {"sha256": "x"}}))
        with self.assertRaises(fim.BaselineError):
            fim.load_baseline(self.baseline)


class TestKeys(FimCase):
    def test_keygen_creates_private_key_and_never_overwrites(self):
        path = self.base_dir / "fim.key"
        fim.generate_key_file(path)
        self.assertEqual(len(fim.load_key_file(path)), 32)
        if os.name == "posix":
            self.assertEqual(stat.S_IMODE(path.stat().st_mode), 0o600)
        with self.assertRaises(FileExistsError):
            fim.generate_key_file(path)

    def test_parse_key_validation(self):
        with self.assertRaises(ValueError):
            fim.parse_key("zzzz")
        with self.assertRaises(ValueError):
            fim.parse_key("aabb")  # too short


class TestUnreadable(FimCase):
    def test_oserror_during_hash_is_skipped_not_fatal(self):
        skipped: list[str] = []
        real = fim.sha256_file

        def flaky(path, *a, **k):
            if path.name == "b.txt":
                raise PermissionError("negado")
            return real(path, *a, **k)

        with mock.patch.object(fim, "sha256_file", flaky):
            snap = fim.snapshot(self.root, skipped=skipped)
        self.assertEqual(skipped, ["b.txt"])
        self.assertEqual(list(snap), ["a.txt"])


if __name__ == "__main__":
    unittest.main()
