"""Passive checks: every function reads a response that already happened (headers, body,
cookies, certificate) and looks for known weaknesses. None of them send attack payloads —
there is no SQL injection string and no injected script anywhere in this module.
"""

from __future__ import annotations

import datetime
import re
import socket
import ssl
from dataclasses import dataclass, field
from http.cookies import SimpleCookie
from typing import List

from .findings import Finding, Severity

STACK_TRACE_PATTERNS = [
    (re.compile(r"Traceback \(most recent call last\)", re.I), "Python traceback"),
    (re.compile(r"Warning:.*on line \d+.*\.php", re.I), "PHP warning with file path"),
    (re.compile(r"Fatal error:.*in .*\.php on line \d+", re.I), "PHP fatal error with file path"),
    (re.compile(r"Microsoft OLE DB Provider for (ODBC|SQL Server)", re.I), "MS SQL error message"),
    (re.compile(r"You have an error in your SQL syntax", re.I), "MySQL syntax error message"),
    (re.compile(r"ORA-\d{5}", re.I), "Oracle database error code"),
    (re.compile(r"org\.apache\.catalina|java\.lang\.\w+Exception", re.I), "Java stack trace"),
    (re.compile(r"Whitelabel Error Page", re.I), "Spring Boot default error page"),
    (re.compile(r"System\.NullReferenceException|at System\.\w+", re.I), ".NET stack trace"),
    (re.compile(r"Index of /\S*\s*</title>|Index of /[\s<]", re.I), "directory listing enabled"),
]

VERSIONED_SERVER_BANNER = re.compile(r"^[A-Za-z][\w.\-]*/\d[\w.\-]*")


@dataclass
class PageResult:
    """The minimal shape a check needs; keeps checks independent of the HTTP library used."""

    url: str
    status_code: int
    headers: dict  # case-insensitive mapping (e.g. requests.structures.CaseInsensitiveDict)
    text: str
    is_https: bool
    set_cookie_headers: List[str] = field(default_factory=list)


def check_security_headers(page: PageResult) -> List[Finding]:
    findings: List[Finding] = []
    headers = {k.lower(): v for k, v in page.headers.items()}

    required = [
        (
            "content-security-policy",
            "CSP-001",
            "Missing Content-Security-Policy header",
            Severity.MEDIUM,
            "Add a Content-Security-Policy header to reduce the impact of any script injection "
            "(e.g. `default-src 'self'`).",
        ),
        (
            "x-content-type-options",
            "HDR-001",
            "Missing X-Content-Type-Options header",
            Severity.LOW,
            "Add `X-Content-Type-Options: nosniff` to stop browsers from MIME-sniffing responses.",
        ),
        (
            "x-frame-options",
            "HDR-002",
            "Missing X-Frame-Options header (clickjacking)",
            Severity.MEDIUM,
            "Add `X-Frame-Options: DENY` or a CSP `frame-ancestors` directive.",
        ),
        (
            "referrer-policy",
            "HDR-003",
            "Missing Referrer-Policy header",
            Severity.LOW,
            "Add `Referrer-Policy: strict-origin-when-cross-origin` (or stricter).",
        ),
        (
            "permissions-policy",
            "HDR-004",
            "Missing Permissions-Policy header",
            Severity.INFO,
            "Add a Permissions-Policy header to restrict powerful browser features.",
        ),
    ]
    for header_name, check_id, title, severity, remediation in required:
        if header_name not in headers:
            findings.append(
                Finding(
                    check_id,
                    title,
                    severity,
                    page.url,
                    "header not present in the response",
                    remediation,
                    "OWASP A05:2021 - Security Misconfiguration",
                )
            )

    if page.is_https and "strict-transport-security" not in headers:
        findings.append(
            Finding(
                "HDR-005",
                "Missing Strict-Transport-Security (HSTS) header",
                Severity.HIGH,
                page.url,
                "HTTPS page served without an HSTS header",
                "Add `Strict-Transport-Security: max-age=31536000; includeSubDomains`.",
                "OWASP A05:2021 - Security Misconfiguration",
            )
        )

    csp = headers.get("content-security-policy", "")
    if csp and ("unsafe-inline" in csp or "unsafe-eval" in csp):
        findings.append(
            Finding(
                "CSP-002",
                "Weak Content-Security-Policy ('unsafe-inline'/'unsafe-eval')",
                Severity.MEDIUM,
                page.url,
                f"CSP: {csp[:200]}",
                "Remove 'unsafe-inline' / 'unsafe-eval'; use nonces or hashes for needed inline scripts.",
                "OWASP A05:2021 - Security Misconfiguration",
            )
        )
    return findings


def check_cookies(page: PageResult) -> List[Finding]:
    findings: List[Finding] = []
    for raw in page.set_cookie_headers:
        jar = SimpleCookie()
        try:
            jar.load(raw)
        except Exception:
            continue
        for name, morsel in jar.items():
            lowered = raw.lower()
            missing = []
            if not morsel["secure"] and page.is_https:
                missing.append("Secure")
            if not morsel["httponly"]:
                missing.append("HttpOnly")
            if "samesite" not in lowered:
                missing.append("SameSite")
            if missing:
                findings.append(
                    Finding(
                        "COOKIE-001",
                        f"Cookie '{name}' missing {', '.join(missing)} flag(s)",
                        Severity.MEDIUM if "HttpOnly" in missing else Severity.LOW,
                        page.url,
                        f"Set-Cookie: {raw[:200]}",
                        "Set Secure, HttpOnly and SameSite=Lax (or Strict) on session/auth cookies.",
                        "OWASP A05:2021 - Security Misconfiguration",
                    )
                )
    return findings


def check_information_disclosure(page: PageResult) -> List[Finding]:
    findings: List[Finding] = []
    headers = {k.lower(): v for k, v in page.headers.items()}

    for header_name in ("server", "x-powered-by"):
        value = headers.get(header_name, "")
        if value and VERSIONED_SERVER_BANNER.match(value.strip()):
            findings.append(
                Finding(
                    "INFO-001",
                    f"'{header_name}' header reveals a software version",
                    Severity.LOW,
                    page.url,
                    f"{header_name}: {value}",
                    "Remove or generalize the header (e.g. `ServerTokens Prod` on Apache, "
                    "`expose_php = Off` in PHP, hide the ASP.NET version banner).",
                    "OWASP A05:2021 - Security Misconfiguration",
                )
            )

    snippet = page.text[:20000]  # error pages are usually near the top; cap the work per page
    for pattern, label in STACK_TRACE_PATTERNS:
        match = pattern.search(snippet)
        if match:
            findings.append(
                Finding(
                    "INFO-002",
                    f"Verbose error output / information disclosure ({label})",
                    Severity.HIGH,
                    page.url,
                    match.group(0)[:200],
                    "Disable debug mode and verbose error pages in production; show a generic "
                    "error page and log details server-side only.",
                    "OWASP A05:2021 / CWE-209: Information Exposure Through an Error Message",
                )
            )
    return findings


def check_mixed_content(page: PageResult) -> List[Finding]:
    if not page.is_https:
        return []
    matches = re.findall(r'(?:src|href)=["\']http://[^"\']+["\']', page.text[:50000], re.I)
    if not matches:
        return []
    return [
        Finding(
            "MIXED-001",
            "Mixed content: HTTPS page loads resources over plain HTTP",
            Severity.MEDIUM,
            page.url,
            matches[0][:200],
            "Serve all page resources (scripts, styles, images) over HTTPS.",
            "OWASP A05:2021 - Security Misconfiguration",
        )
    ]


def check_tls(host: str, port: int = 443, timeout: float = 5.0) -> List[Finding]:
    """Certificate expiry and protocol version, checked once per host (not once per page)."""
    findings: List[Finding] = []
    try:
        ctx = ssl.create_default_context()
        with socket.create_connection((host, port), timeout=timeout) as sock:
            with ctx.wrap_socket(sock, server_hostname=host) as tls:
                cert = tls.getpeercert()
                protocol = tls.version()
    except Exception as exc:
        return [
            Finding(
                "TLS-000",
                "Could not establish a TLS connection to verify certificate/protocol",
                Severity.INFO,
                f"https://{host}:{port}",
                str(exc)[:200],
                "Re-run once the HTTPS endpoint is reachable, or check firewall/DNS settings.",
                "",
            )
        ]

    if protocol in ("TLSv1", "TLSv1.1", "SSLv3", "SSLv2"):
        findings.append(
            Finding(
                "TLS-001",
                f"Outdated TLS protocol negotiated ({protocol})",
                Severity.HIGH,
                f"https://{host}:{port}",
                f"negotiated protocol: {protocol}",
                "Disable TLS 1.0/1.1 and SSLv3 on the server; require TLS 1.2 or newer.",
                "",
            )
        )

    not_after = cert.get("notAfter") if cert else None
    if not_after:
        try:
            expires = datetime.datetime.strptime(not_after, "%b %d %H:%M:%S %Y %Z")
            days_left = (expires - datetime.datetime.utcnow()).days
            if days_left < 0:
                findings.append(
                    Finding(
                        "TLS-002",
                        "TLS certificate has expired",
                        Severity.CRITICAL,
                        f"https://{host}:{port}",
                        f"expired on {not_after}",
                        "Renew the TLS certificate immediately.",
                        "",
                    )
                )
            elif days_left < 14:
                findings.append(
                    Finding(
                        "TLS-003",
                        f"TLS certificate expires soon ({days_left} days)",
                        Severity.MEDIUM,
                        f"https://{host}:{port}",
                        f"expires {not_after}",
                        "Renew the TLS certificate before it expires.",
                        "",
                    )
                )
        except ValueError:
            pass
    return findings


ALL_PAGE_CHECKS = [check_security_headers, check_cookies, check_information_disclosure, check_mixed_content]


def run_page_checks(page: PageResult) -> List[Finding]:
    findings: List[Finding] = []
    for check in ALL_PAGE_CHECKS:
        findings.extend(check(page))
    return findings
