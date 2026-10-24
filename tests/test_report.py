import json
import unittest

from secfund import report
from secfund.report import Issue


def sample_issues():
    return [
        Issue(
            "SF-LOGS-001",
            "logs",
            "CRITICO",
            "Brute force de 1.2.3.4",
            "7 falhas",
            "auth.log",
            12,
            "T1110.001",
            "bloqueie",
        ),
        Issue("SF-HDR-001", "headers", "BAIXO", "CSP: ausente", "sem CSP", "https://x.test"),
        Issue("SF-LOGS-001", "logs", "MEDIO", "Brute force de 5.6.7.8", "", "auth.log", 0),
    ]


class TestIssue(unittest.TestCase):
    def test_invalid_severity_rejected(self):
        with self.assertRaises(ValueError):
            Issue("X", "m", "SUPER", "t")

    def test_summary_counts_all_levels(self):
        summary = report.summarize(sample_issues())
        self.assertEqual(summary, {"CRITICO": 1, "ALTO": 0, "MEDIO": 1, "BAIXO": 1, "INFO": 0})


class TestExitCode(unittest.TestCase):
    def test_no_issues(self):
        self.assertEqual(report.exit_code([]), 0)

    def test_critical_returns_two(self):
        self.assertEqual(report.exit_code(sample_issues()), 2)

    def test_fail_on_threshold(self):
        low_only = [Issue("SF-HDR-001", "headers", "BAIXO", "t")]
        self.assertEqual(report.exit_code(low_only, "low"), 1)
        self.assertEqual(report.exit_code(low_only, "medium"), 0)
        self.assertEqual(report.exit_code(low_only, "never"), 0)
        self.assertEqual(report.exit_code(sample_issues(), "critical"), 2)

    def test_info_never_fails(self):
        self.assertEqual(report.exit_code([Issue("SF-HDR-001", "headers", "INFO", "t")]), 0)


class TestExporters(unittest.TestCase):
    def test_json_structure(self):
        doc = json.loads(report.to_json(sample_issues()))
        self.assertEqual(doc["tool"]["name"], "secfund")
        self.assertEqual(doc["summary"]["CRITICO"], 1)
        self.assertEqual(len(doc["issues"]), 3)
        self.assertEqual(doc["issues"][0]["technique"], "T1110.001")

    def test_sarif_is_valid_2_1_0_shape(self):
        doc = json.loads(report.to_sarif(sample_issues()))
        self.assertEqual(doc["version"], "2.1.0")
        run = doc["runs"][0]
        self.assertEqual(run["tool"]["driver"]["name"], "SecFund")
        rule_ids = [r["id"] for r in run["tool"]["driver"]["rules"]]
        self.assertEqual(sorted(rule_ids), ["SF-HDR-001", "SF-LOGS-001"])  # regras deduplicadas
        self.assertEqual(len(run["results"]), 3)
        for result in run["results"]:
            self.assertIn(result["ruleId"], rule_ids)
            loc = result["locations"][0]["physicalLocation"]
            self.assertGreaterEqual(loc["region"]["startLine"], 1)  # exigido pelo GitHub
            self.assertTrue(loc["artifactLocation"]["uri"])

    def test_sarif_levels_and_security_severity(self):
        run = json.loads(report.to_sarif(sample_issues()))["runs"][0]
        self.assertEqual([r["level"] for r in run["results"]], ["error", "note", "warning"])
        rule = next(r for r in run["tool"]["driver"]["rules"] if r["id"] == "SF-LOGS-001")
        self.assertEqual(rule["properties"]["security-severity"], "9.5")

    def test_sarif_backslashes_normalized(self):
        issue = Issue("SF-FIM-001", "fim", "ALTO", "t", location="site\\a.txt")
        uri = json.loads(report.to_sarif([issue]))["runs"][0]["results"][0]["locations"][0]["physicalLocation"][
            "artifactLocation"
        ]["uri"]
        self.assertEqual(uri, "site/a.txt")

    def test_empty_report(self):
        self.assertEqual(json.loads(report.to_sarif([]))["runs"][0]["results"], [])
        self.assertEqual(json.loads(report.to_json([]))["issues"], [])

    def test_all_rules_have_descriptions(self):
        for rule_id, text in report.RULES.items():
            self.assertTrue(rule_id.startswith("SF-") and text)


if __name__ == "__main__":
    unittest.main()
