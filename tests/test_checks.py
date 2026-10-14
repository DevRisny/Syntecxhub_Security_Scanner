import unittest

from syntecxhub_scanner.checks import (
    PageResult,
    check_cookies,
    check_information_disclosure,
    check_mixed_content,
    check_security_headers,
    run_page_checks,
)
from syntecxhub_scanner.findings import Severity


def page(url="https://example.test/", headers=None, text="<html></html>", https=True, cookies=None):
    return PageResult(
        url=url,
        status_code=200,
        headers=headers or {},
        text=text,
        is_https=https,
        set_cookie_headers=cookies or [],
    )


class SecurityHeaderTests(unittest.TestCase):
    def test_flags_every_missing_header(self):
        findings = check_security_headers(page(headers={}))
        ids = {f.check_id for f in findings}
        self.assertIn("CSP-001", ids)
        self.assertIn("HDR-001", ids)
        self.assertIn("HDR-002", ids)
        self.assertIn("HDR-005", ids)  # HSTS, because is_https=True

    def test_no_hsts_finding_on_plain_http(self):
        findings = check_security_headers(page(headers={}, https=False))
        self.assertNotIn("HDR-005", {f.check_id for f in findings})

    def test_fully_configured_site_has_no_header_findings(self):
        good_headers = {
            "Content-Security-Policy": "default-src 'self'",
            "X-Content-Type-Options": "nosniff",
            "X-Frame-Options": "DENY",
            "Referrer-Policy": "strict-origin-when-cross-origin",
            "Permissions-Policy": "geolocation=()",
            "Strict-Transport-Security": "max-age=31536000",
        }
        self.assertEqual(check_security_headers(page(headers=good_headers)), [])

    def test_weak_csp_flagged(self):
        headers = {"Content-Security-Policy": "default-src 'self' 'unsafe-inline'"}
        findings = check_security_headers(page(headers=headers))
        self.assertIn("CSP-002", {f.check_id for f in findings})


class CookieTests(unittest.TestCase):
    def test_missing_flags_detected(self):
        findings = check_cookies(page(cookies=["session=abc123; Path=/"]))
        self.assertEqual(len(findings), 1)
        self.assertIn("HttpOnly", findings[0].title)

    def test_secure_cookie_passes(self):
        cookie = "session=abc123; Secure; HttpOnly; SameSite=Lax"
        self.assertEqual(check_cookies(page(cookies=[cookie])), [])

    def test_http_page_does_not_require_secure_flag(self):
        findings = check_cookies(page(cookies=["session=abc; HttpOnly; SameSite=Lax"], https=False))
        self.assertEqual(findings, [])


class InformationDisclosureTests(unittest.TestCase):
    def test_server_banner_with_version_flagged(self):
        findings = check_information_disclosure(page(headers={"Server": "Apache/2.4.41 (Ubuntu)"}))
        self.assertTrue(any(f.check_id == "INFO-001" for f in findings))

    def test_generic_server_banner_not_flagged(self):
        findings = check_information_disclosure(page(headers={"Server": "webserver"}))
        self.assertFalse(any(f.check_id == "INFO-001" for f in findings))

    def test_stack_trace_detected(self):
        body = "Traceback (most recent call last):\n  File x\nZeroDivisionError: division by zero"
        findings = check_information_disclosure(page(text=body))
        self.assertTrue(any(f.check_id == "INFO-002" for f in findings))
        self.assertEqual(findings[0].severity, Severity.HIGH)

    def test_sql_error_message_detected(self):
        body = "Warning: You have an error in your SQL syntax; check the manual"
        findings = check_information_disclosure(page(text=body))
        self.assertTrue(any(f.check_id == "INFO-002" for f in findings))

    def test_directory_listing_detected(self):
        body = "<html><head><title>Index of /uploads</title></head><body>Index of /uploads</body></html>"
        findings = check_information_disclosure(page(text=body))
        self.assertTrue(any("directory listing" in f.title.lower() for f in findings))

    def test_clean_page_has_no_findings(self):
        findings = check_information_disclosure(page(text="<html><body>Welcome</body></html>"))
        self.assertEqual(findings, [])


class MixedContentTests(unittest.TestCase):
    def test_http_resource_on_https_page_flagged(self):
        body = '<html><body><img src="http://cdn.example.com/x.png"></body></html>'
        findings = check_mixed_content(page(text=body, https=True))
        self.assertEqual(len(findings), 1)

    def test_not_checked_on_plain_http_page(self):
        body = '<html><body><img src="http://cdn.example.com/x.png"></body></html>'
        self.assertEqual(check_mixed_content(page(text=body, https=False)), [])

    def test_all_https_resources_clean(self):
        body = '<html><body><img src="https://cdn.example.com/x.png"></body></html>'
        self.assertEqual(check_mixed_content(page(text=body, https=True)), [])


class RunAllChecksTests(unittest.TestCase):
    def test_combines_every_check(self):
        findings = run_page_checks(
            page(headers={"Server": "nginx/1.18.0"}, cookies=["a=b"], text="plain page")
        )
        ids = {f.check_id for f in findings}
        self.assertIn("INFO-001", ids)
        self.assertIn("COOKIE-001", ids)
        self.assertIn("CSP-001", ids)


if __name__ == "__main__":
    unittest.main()
