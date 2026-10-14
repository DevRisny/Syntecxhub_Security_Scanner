"""End-to-end test: a real local HTTP server plays a deliberately misconfigured site, and the
real scanner (permission gate + crawler + checks + report) is pointed at it over 127.0.0.1."""

import threading
import unittest
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

from syntecxhub_scanner import report
from syntecxhub_scanner.permission import PermissionDenied
from syntecxhub_scanner.scanner import scan

PAGES = {
    "/": (
        200,
        {"Server": "Werkzeug/3.0.1 Python/3.11.4", "Set-Cookie": "session=abc123; Path=/"},
        b"<html><body><h1>Home</h1><a href='/about'>About</a> <a href='/broken'>Broken</a>"
        b"<a href='/secret/'>no-follow</a></body></html>",
    ),
    "/about": (
        200,
        {
            "Content-Security-Policy": "default-src 'self'",
            "X-Content-Type-Options": "nosniff",
            "X-Frame-Options": "DENY",
            "Referrer-Policy": "no-referrer",
            "Permissions-Policy": "geolocation=()",
        },
        b"<html><body>About us. Well configured page.</body></html>",
    ),
    "/broken": (
        500,
        {},
        b'Traceback (most recent call last):\n  File "app.py", line 1\nZeroDivisionError: boom',
    ),
    "/robots.txt": (200, {}, b"User-agent: *\nDisallow: /secret/\n"),
    "/secret/": (200, {}, b"<html><body>should not be crawled</body></html>"),
}


class DemoHandler(BaseHTTPRequestHandler):
    def do_GET(self):  # noqa: N802 (stdlib method name)
        status, headers, body = PAGES.get(self.path, (404, {}, b"not found"))
        # send_response_only (not send_response) so the test server doesn't add its own
        # Server/Date headers on top of the ones each test page wants to control.
        self.send_response_only(status)
        self.send_header("Date", self.date_time_string())
        self.send_header("Content-Type", "text/html; charset=utf-8")
        for key, value in headers.items():
            self.send_header(key, value)
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, fmt, *args):  # silence test output
        pass


class ScanAgainstLocalSiteTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.server = ThreadingHTTPServer(("127.0.0.1", 0), DemoHandler)
        cls.port = cls.server.server_address[1]
        cls.thread = threading.Thread(target=cls.server.serve_forever, daemon=True)
        cls.thread.start()

    @classmethod
    def tearDownClass(cls):
        cls.server.shutdown()
        cls.thread.join(timeout=2)

    def test_full_scan_finds_the_planted_issues(self):
        result = scan(
            f"http://127.0.0.1:{self.port}/",
            max_pages=10,
            requests_per_second=50,
            check_tls_cert=False,  # plain HTTP test server
        )
        self.assertGreaterEqual(result.pages_scanned, 3)  # /, /about, /broken (robots excludes /secret/)

        ids = {f.check_id for f in result.findings}
        self.assertIn("INFO-001", ids)  # Server banner with version, on /
        self.assertIn("COOKIE-001", ids)  # cookie missing HttpOnly/SameSite, on /
        self.assertIn("CSP-001", ids)  # missing CSP, on /
        self.assertIn("INFO-002", ids)  # stack trace on /broken

        about_findings = [f for f in result.findings if f.url.endswith("/about")]
        self.assertEqual(about_findings, [])  # the well-configured page should be clean

    def test_robots_txt_is_respected(self):
        result = scan(
            f"http://127.0.0.1:{self.port}/", max_pages=10, requests_per_second=50, check_tls_cert=False
        )
        self.assertFalse(any("/secret/" in f.url for f in result.findings))

    def test_reports_render_from_a_real_scan(self):
        result = scan(
            f"http://127.0.0.1:{self.port}/", max_pages=10, requests_per_second=50, check_tls_cert=False
        )
        self.assertIn("http", report.to_json(result))
        self.assertIn("severity", report.to_csv(result))
        self.assertIn("<html", report.to_html(result))

    def test_public_looking_host_refused_without_permission(self):
        with self.assertRaises(PermissionDenied):
            scan("http://example.com/", allow_public=False)

    def test_no_attack_payloads_are_ever_sent(self):
        """The crawler only ever issues plain GET requests; it never submits input."""
        import inspect

        from syntecxhub_scanner import crawler as crawler_module

        source = inspect.getsource(crawler_module)
        for banned in ("' OR ", "UNION SELECT", "<script>alert", "DROP TABLE"):
            self.assertNotIn(banned, source)


if __name__ == "__main__":
    unittest.main()
