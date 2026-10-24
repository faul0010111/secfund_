import unittest
from datetime import datetime, timedelta
from pathlib import Path

from secfund import logs

ROOT = Path(__file__).resolve().parent.parent


def fail_line(minute: int, second: int, user: str, ip: str, port: int = 22) -> str:
    return f"Oct 17 10:{minute:02d}:{second:02d} srv sshd[1]: Failed password for {user} from {ip} port {port} ssh2"


class TestSampleLog(unittest.TestCase):
    def setUp(self):
        lines = (ROOT / "samples" / "auth.log").read_text().splitlines()
        self.events = logs.parse_log(lines, year=2026)

    def test_parses_all_events(self):
        self.assertEqual(len(self.events), 28)

    def test_detects_compromise(self):
        top = logs.analyze(self.events)[0]
        self.assertEqual(top.ip, "203.0.113.45")
        self.assertTrue(top.compromised)
        self.assertEqual(top.severity, "CRITICAL")
        self.assertEqual(top.rule_id, "SF-LOGS-001")

    def test_detects_spraying(self):
        findings = {f.ip: f for f in logs.analyze(self.events)}
        self.assertEqual(findings["198.51.100.7"].kind, logs.KIND_SPRAY)
        self.assertEqual(findings["198.51.100.7"].technique, "T1110.003")

    def test_detects_distributed_attack(self):
        dist = [f for f in logs.analyze(self.events) if f.kind == logs.KIND_DISTRIBUTED]
        self.assertEqual(len(dist), 1)
        self.assertEqual(dist[0].users, ["deploy"])
        self.assertEqual(len(dist[0].sources), 6)
        self.assertEqual(dist[0].rule_id, "SF-LOGS-003")

    def test_legit_user_not_flagged(self):
        flagged = {ip for f in logs.analyze(self.events) for ip in f.sources}
        self.assertNotIn("192.0.2.10", flagged)

    def test_allowlist_cidr_suppresses_scanner(self):
        self.assertIn("10.0.0.5", {f.ip for f in logs.analyze(self.events)})
        self.assertNotIn("10.0.0.5", {f.ip for f in logs.analyze(self.events, allowlist=["10.0.0.0/8"])})

    def test_invalid_allowlist_raises(self):
        with self.assertRaises(ValueError):
            logs.analyze(self.events, allowlist=["not-an-ip"])

    def test_to_issues(self):
        issues = logs.to_issues(logs.analyze(self.events), "samples/auth.log")
        self.assertEqual(issues[0].severity, "CRITICAL")
        self.assertEqual(issues[0].location, "samples/auth.log")
        self.assertGreater(issues[0].line, 0)
        self.assertIn("incident", issues[0].remediation)


class TestWindow(unittest.TestCase):
    def test_slow_attack_outside_window_not_flagged(self):
        # 6 failures spaced 2 minutes apart: at most 3 fall inside any 5-minute window.
        lines = [fail_line(m, 0, "root", "198.18.0.1") for m in range(0, 12, 2)]
        self.assertEqual(logs.analyze(logs.parse_log(lines, 2026)), [])

    def test_wider_window_catches_it(self):
        lines = [fail_line(m, 0, "root", "198.18.0.1") for m in range(0, 12, 2)]
        found = logs.analyze(logs.parse_log(lines, 2026), window=timedelta(minutes=15))
        self.assertEqual(len(found), 1)

    def test_accepted_before_failures_is_not_compromise(self):
        lines = ["Oct 17 09:59:00 srv sshd[1]: Accepted publickey for root from 198.18.0.1 port 5 ssh2: RSA SHA256:x"]
        lines += [fail_line(0, s, "root", "198.18.0.1") for s in range(0, 30, 5)]
        finding = logs.analyze(logs.parse_log(lines, 2026))[0]
        self.assertFalse(finding.compromised)


class TestParserHardening(unittest.TestCase):
    def test_username_cannot_forge_source_ip(self):
        line = (
            "Oct 17 07:00:01 srv01 sshd[4600]: Failed password for invalid user x from 192.0.2.77 port 1 ssh2 "
            "from 203.0.113.99 port 4000 ssh2"
        )
        ev = logs.parse_line(line, 2026)
        self.assertIsNotNone(ev)
        self.assertEqual(ev.ip, "203.0.113.99")  # the real IP, not the one forged inside the username

    def test_control_characters_are_sanitized(self):
        line = (
            "Oct 17 07:00:01 srv01 sshd[1]: Failed password for invalid user \x1b[31mred from 203.0.113.9 port 22 ssh2"
        )
        ev = logs.parse_line(line, 2026)
        self.assertNotIn("\x1b", ev.user)

    def test_long_username_truncated(self):
        line = (
            f"Oct 17 07:00:01 srv01 sshd[1]: Failed password for invalid user {'a' * 500} from 203.0.113.9 port 22 ssh2"
        )
        self.assertLessEqual(len(logs.parse_line(line, 2026).user), logs.MAX_USER_LEN + 3)

    def test_invalid_ip_discarded(self):
        self.assertIsNone(logs.parse_line(fail_line(0, 0, "root", "999.1.1.1"), 2026))

    def test_overlong_line_discarded(self):
        self.assertIsNone(logs.parse_line(fail_line(0, 0, "a" * 5000, "198.18.0.1"), 2026))

    def test_garbage_and_non_ssh_lines_ignored(self):
        for line in ("", "lixo qualquer", "Oct 17 10:00:00 srv cron[1]: job done"):
            self.assertIsNone(logs.parse_line(line, 2026))

    def test_impossible_date_ignored(self):
        self.assertIsNone(
            logs.parse_line("Feb 30 10:00:00 srv sshd[1]: Failed password for a from 1.2.3.4 port 1 ssh2", 2026)
        )

    def test_ipv6_supported(self):
        ev = logs.parse_line(fail_line(0, 0, "root", "2001:db8::1"), 2026)
        self.assertEqual(ev.ip, "2001:db8::1")

    def test_iso_timestamp_and_sshd_session(self):
        line = "2026-10-17T02:11:01.123456-03:00 srv sshd-session[99]: Failed password for root from 198.18.0.9 port 22 ssh2"
        ev = logs.parse_line(line, 2026)
        self.assertEqual(ev.ts, datetime(2026, 10, 17, 2, 11, 1, 123456))

    def test_iso_zulu_timestamp(self):
        line = "2026-10-17T02:11:01Z srv sshd[1]: Failed password for root from 198.18.0.9 port 22 ssh2"
        self.assertEqual(logs.parse_line(line, 2026).ts.hour, 2)

    def test_single_digit_day(self):
        line = "Oct  7 02:11:01 srv sshd[1]: Failed password for root from 198.18.0.9 port 22 ssh2"
        self.assertEqual(logs.parse_line(line, 2026).ts.day, 7)


class TestMoreParsing(unittest.TestCase):
    def test_impossible_iso_date_ignored(self):
        line = "2026-13-45T25:61:61 srv sshd[1]: Failed password for root from 198.18.0.9 port 22 ssh2"
        self.assertIsNone(logs.parse_line(line, 2026))

    def test_unknown_auth_methods_ignored(self):
        self.assertIsNone(logs.parse_line("Oct 17 10:00:00 srv sshd[1]: Connection closed by 1.2.3.4 port 22", 2026))

    def test_log_file_is_streamed_not_loaded(self):
        # parse_log accepts any iterable (open file, generator) without materializing the lines.
        gen = (fail_line(0, s, "root", "198.18.0.1") for s in range(0, 40, 4))
        self.assertEqual(len(logs.parse_log(gen, 2026)), 10)


if __name__ == "__main__":
    unittest.main()
