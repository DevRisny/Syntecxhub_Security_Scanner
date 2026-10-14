"""Syntecxhub Security Scanner: a passive web security posture and misconfiguration scanner.

This tool never sends attack payloads (no SQL injection strings, no script tags). It crawls
a site and checks the *responses themselves* for well-known, real vulnerability indicators:
missing security headers, insecure cookie flags, information disclosure, weak TLS, and more.
"""

__version__ = "1.0.0"
