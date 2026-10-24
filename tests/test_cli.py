import contextlib
import io
import json
import os
import shutil
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path
from unittest import mock

from netfixtures import make_self_signed, tls_server

from secfund.cli import main

ROOT = Path(__file__).resolve().parent.parent
LOG = str(ROOT / "samples" / "auth.log")
WEAK = str(ROOT / "samples" / "headers_weak.json")


def run(*argv, env=None):
    out, err = io.StringIO(), io.StringIO()
    old = {k: os.environ.get(k) for k in (env or {})}
    os.environ.update(env or {})
    try:
        with contextlib.redirect_stdout(out), contextlib.redirect_stderr(err):
            code = main(list(argv))
    finally:
        for k, v in old.items():
            if v is None:
                os.environ.pop(k, None)
            else:
                os.environ[k] = v
    return code, out.getvalue(), err.getvalue()


class TestLogsCommand(unittest.TestCase):
    def test_text_report_and_exit_code(self):
        code, out, _ = run("logs", LOG, "--year", "2026")
        self.assertEqual(code, 2)
        self.assertIn("28 events analyzed", out)
        self.assertIn("POSSIBLE COMPROMISE", out)
        self.assertIn("Distributed attack", out)

    def test_json_output_is_pure_json(self):
        code, out, _ = run("logs", LOG, "--year", "2026", "--format", "json")
        doc = json.loads(out)
        self.assertEqual(code, 2)
        self.assertEqual(doc["summary"]["CRITICAL"], 1)

    def test_sarif_to_file(self):
        with tempfile.TemporaryDirectory() as d:
            target = Path(d) / "out.sarif"
            code, out, err = run("logs", LOG, "--year", "2026", "--format", "sarif", "-o", str(target))
            self.assertEqual(code, 2)
            self.assertEqual(out, "")
            self.assertIn("Report saved", err)
            self.assertEqual(json.loads(target.read_text())["version"], "2.1.0")

    def test_allowlist_and_fail_on(self):
        _, out, _ = run("logs", LOG, "--year", "2026", "--allow-ip", "10.0.0.0/8", "--format", "json")
        self.assertNotIn("10.0.0.5", out)
        code, _, _ = run("logs", LOG, "--year", "2026", "--fail-on", "never")
        self.assertEqual(code, 0)

    def test_clean_log_exits_zero(self):
        with tempfile.TemporaryDirectory() as d:
            clean = Path(d) / "ok.log"
            clean.write_text("Oct 17 09:02:20 srv sshd[1]: Accepted publickey for alice from 192.0.2.10 port 3 ssh2\n")
            code, out, _ = run("logs", str(clean), "--year", "2026")
            self.assertEqual(code, 0)
            self.assertIn("No suspicious activity", out)

    def test_missing_file_is_exit_3(self):
        code, _, err = run("logs", "/does/not/exist.log")
        self.assertEqual(code, 3)
        self.assertIn("Error:", err)

    def test_invalid_allowlist_is_exit_3(self):
        self.assertEqual(run("logs", LOG, "--allow-ip", "xyz")[0], 3)


class TestFimCommand(unittest.TestCase):
    def test_full_signed_workflow(self):
        with tempfile.TemporaryDirectory() as d:
            base = Path(d)
            site = base / "site"
            site.mkdir()
            (site / "index.html").write_text("ok")
            key, baseline = str(base / "k"), str(base / "b.json")

            self.assertEqual(run("fim", "keygen", "--key-file", key)[0], 0)
            code, out, _ = run("fim", "init", str(site), "--baseline", baseline, "--key-file", key)
            self.assertEqual(code, 0)
            self.assertIn("signed with HMAC", out)

            code, out, _ = run("fim", "check", str(site), "--baseline", baseline, "--key-file", key)
            self.assertEqual((code, "Integrity OK." in out), (0, True))

            (site / "index.html").write_text("DEFACED")
            code, out, _ = run("fim", "check", str(site), "--baseline", baseline, "--key-file", key)
            self.assertEqual(code, 1)
            self.assertIn("MODIFIED", out)

            doc = json.loads(Path(baseline).read_text())
            doc["files"]["index.html"]["sha256"] = "0" * 64
            Path(baseline).write_text(json.dumps(doc))
            code, _, err = run("fim", "check", str(site), "--baseline", baseline, "--key-file", key)
            self.assertEqual(code, 4)
            self.assertIn("INTEGRITY ALERT", err)

    def test_key_from_environment_and_unsigned_warning(self):
        with tempfile.TemporaryDirectory() as d:
            site = Path(d) / "site"
            site.mkdir()
            (site / "a").write_text("a")
            baseline = str(Path(d) / "b.json")
            _, out, _ = run("fim", "init", str(site), "--baseline", baseline)
            self.assertIn("UNSIGNED", out)
            code, _, err = run("fim", "check", str(site), "--baseline", baseline, env={"SECFUND_KEY": "cc" * 32})
            self.assertEqual(code, 4)  # key provided + unsigned baseline = downgrade attempt
            self.assertIn("NO signature", err)

    def test_usage_errors(self):
        self.assertEqual(run("fim", "keygen")[0], 3)
        self.assertEqual(run("fim", "init")[0], 3)


class TestPasswordCommand(unittest.TestCase):
    def test_weak_password_exit_1(self):
        code, out, _ = run("password", "--password", "qwerty123")
        self.assertEqual(code, 1)
        self.assertIn("WEAK", out)

    def test_generate_hash_verify_cycle(self):
        code, out, _ = run("password", "--generate", "--length", "24", "--hash", "--algo", "pbkdf2")
        self.assertEqual(code, 0)
        pw = out.split("Generated password: ")[1].splitlines()[0]
        stored = out.strip().splitlines()[-1]
        self.assertTrue(stored.startswith("pbkdf2_sha256$"))
        self.assertEqual(run("password", "--password", pw, "--verify", stored)[0], 0)
        self.assertEqual(run("password", "--password", "errada", "--verify", stored)[0], 1)

    def test_verify_warns_about_old_parameters(self):
        from secfund import passwords

        stored = passwords.hash_password("abc", "pbkdf2", iterations=1000)
        code, out, _ = run("password", "--password", "abc", "--verify", stored, "--algo", "pbkdf2")
        self.assertEqual(code, 0)
        self.assertIn("outdated", out)

    def test_offline_pwned_file(self):
        import hashlib

        with tempfile.TemporaryDirectory() as d:
            f = Path(d) / "h.txt"
            digest = hashlib.sha1(b"vK9#tQ2$mZx7!Lp4wR8@", usedforsecurity=False).hexdigest().upper()
            f.write_text(f"{digest}:77\n")
            code, out, _ = run("password", "--password", "vK9#tQ2$mZx7!Lp4wR8@", "--pwned-file", str(f))
            self.assertEqual(code, 1)
            self.assertIn("77 known data breach", out)


class TestHeadersCommand(unittest.TestCase):
    def test_weak_site(self):
        code, out, _ = run("headers", "--json-file", WEAK)
        self.assertEqual(code, 1)
        self.assertIn("Grade: F", out)

    def test_fail_on_critical_ignores_medium_findings(self):
        self.assertEqual(run("headers", "--json-file", WEAK, "--fail-on", "critical")[0], 0)

    def test_sarif(self):
        _, out, _ = run("headers", "--json-file", WEAK, "--format", "sarif")
        self.assertEqual(json.loads(out)["version"], "2.1.0")

    def test_rejects_file_scheme(self):
        self.assertEqual(run("headers", "--url", "file:///etc/passwd")[0], 3)

    def test_url_or_file_required(self):
        with self.assertRaises(SystemExit):
            run("headers")


class TestTlsCommand(unittest.TestCase):
    def test_bad_target_is_exit_3(self):
        self.assertEqual(run("tls", "")[0], 3)

    def test_unreachable_host_is_exit_3(self):
        code, _, err = run("tls", "127.0.0.1:1", "--timeout", "1")
        self.assertEqual(code, 3)
        self.assertIn("Error:", err)


class TestMisc(unittest.TestCase):
    def test_version(self):
        with self.assertRaises(SystemExit) as ctx, contextlib.redirect_stdout(io.StringIO()):
            main(["--version"])
        self.assertEqual(ctx.exception.code, 0)

    def test_command_required(self):
        with self.assertRaises(SystemExit), contextlib.redirect_stderr(io.StringIO()):
            main([])


@unittest.skipUnless(shutil.which("openssl"), "openssl not available")
class TestTlsAgainstLocalServer(unittest.TestCase):
    def test_self_signed_server_report(self):
        with tempfile.TemporaryDirectory() as d:
            cert, key = make_self_signed(Path(d))
            with tls_server(cert, key) as port:
                code, out, _ = run("tls", f"127.0.0.1:{port}", "--timeout", "3")
                self.assertEqual(code, 1)
                self.assertIn("INVALID", out)
                self.assertIn("Certificate not trusted", out)
                code, out, _ = run("tls", f"https://127.0.0.1:{port}/", "--format", "json", "--timeout", "3")
                self.assertEqual(json.loads(out)["issues"][0]["rule_id"], "SF-TLS-001")


class TestEntryPoints(unittest.TestCase):
    def test_python_dash_m(self):
        proc = subprocess.run(  # noqa: S603
            [sys.executable, "-m", "secfund", "--version"], cwd=ROOT, capture_output=True, text=True, check=False
        )
        self.assertEqual(proc.returncode, 0)
        self.assertIn("secfund", proc.stdout)


class TestPwnedOnlineCli(unittest.TestCase):
    def test_pwned_flag_uses_k_anonymity_fetcher(self):
        import hashlib

        from secfund import passwords

        digest = hashlib.sha1(b"hunter2", usedforsecurity=False).hexdigest().upper()
        with mock.patch.object(passwords, "fetch_range_online", lambda prefix: f"{digest[5:]}:5\n") as _:
            code, out, _ = run("password", "--password", "hunter2", "--pwned")
        self.assertEqual(code, 1)
        self.assertIn("5 known data breach", out)
        self.assertIn("k-anonymity", out)


@unittest.skipIf(os.name != "posix", "POSIX permissions")
class TestKeyPermissionWarning(unittest.TestCase):
    def test_world_readable_key_warns(self):
        with tempfile.TemporaryDirectory() as d:
            key = Path(d) / "k"
            key.write_text("ab" * 32)
            key.chmod(0o644)
            site = Path(d) / "site"
            site.mkdir()
            (site / "a").write_text("a")
            _, _, err = run("fim", "init", str(site), "--baseline", str(Path(d) / "b.json"), "--key-file", str(key))
            self.assertIn("chmod 600", err)


if __name__ == "__main__":
    unittest.main()
