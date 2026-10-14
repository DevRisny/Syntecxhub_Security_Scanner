import json
import unittest

from syntecxhub_scanner import report
from syntecxhub_scanner.findings import Finding, ScanResult, Severity


def sample_result():
    result = ScanResult(target="https://example.test/", pages_scanned=3)
    result.add(Finding("HDR-001", "Missing header", Severity.LOW, "https://example.test/", "e", "fix"))
    result.add(Finding("INFO-002", "Stack trace", Severity.HIGH, "https://example.test/err", "e2", "fix2"))
    return result


class ReportTests(unittest.TestCase):
    def test_json_round_trips(self):
        data = json.loads(report.to_json(sample_result()))
        self.assertEqual(data["target"], "https://example.test/")
        self.assertEqual(data["pages_scanned"], 3)
        self.assertEqual(len(data["findings"]), 2)
        self.assertEqual(data["findings"][0]["severity"], "HIGH")  # sorted, highest first

    def test_csv_has_a_row_per_finding(self):
        text = report.to_csv(sample_result())
        self.assertEqual(text.strip().count("\n") + 1, 3)  # header + 2 rows

    def test_html_contains_findings_and_is_escaped(self):
        result = sample_result()
        result.add(Finding("X-1", "<script>alert(1)</script>", Severity.LOW, "u", "e", "r"))
        html = report.to_html(result)
        self.assertIn("Stack trace", html)
        self.assertNotIn("<script>alert(1)</script>", html)
        self.assertIn("&lt;script&gt;", html)

    def test_empty_result_still_renders(self):
        empty = ScanResult(target="https://clean.test/", pages_scanned=1)
        self.assertIn("No findings", report.to_html(empty))
        self.assertEqual(json.loads(report.to_json(empty))["findings"], [])

    def test_print_summary_does_not_raise(self):
        report.print_summary(sample_result())  # just needs to not throw


if __name__ == "__main__":
    unittest.main()
