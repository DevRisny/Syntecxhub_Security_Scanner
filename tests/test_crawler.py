import time
import unittest

from syntecxhub_scanner.crawler import RateLimiter, extract_links


class ExtractLinksTests(unittest.TestCase):
    def test_extracts_anchors_and_resources(self):
        html = """
        <html><body>
          <a href="/about">About</a>
          <a href="https://example.test/contact">Contact</a>
          <img src="/logo.png">
          <script src="/app.js"></script>
        </body></html>
        """
        links = extract_links("https://example.test/", html)
        self.assertIn("https://example.test/about", links)
        self.assertIn("https://example.test/contact", links)
        self.assertIn("https://example.test/logo.png", links)
        self.assertIn("https://example.test/app.js", links)

    def test_skips_non_http_schemes(self):
        html = '<a href="mailto:a@b.com">mail</a><a href="javascript:void(0)">js</a>'
        self.assertEqual(extract_links("https://example.test/", html), [])

    def test_strips_fragment(self):
        html = '<a href="/page#section2">link</a>'
        self.assertEqual(extract_links("https://example.test/", html), ["https://example.test/page"])

    def test_malformed_html_does_not_crash(self):
        self.assertEqual(extract_links("https://example.test/", "<html <<< not valid"), [])


class RateLimiterTests(unittest.TestCase):
    def test_zero_rate_does_not_block(self):
        limiter = RateLimiter(0)
        start = time.monotonic()
        for _ in range(5):
            limiter.wait()
        self.assertLess(time.monotonic() - start, 0.1)

    def test_limits_throughput(self):
        limiter = RateLimiter(per_second=10)  # 100ms apart
        start = time.monotonic()
        for _ in range(4):
            limiter.wait()
        elapsed = time.monotonic() - start
        self.assertGreaterEqual(elapsed, 0.3)  # 3 intervals of ~0.1s


if __name__ == "__main__":
    unittest.main()
