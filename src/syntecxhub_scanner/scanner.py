"""Ties the permission gate, crawler and checks together into one scan run."""

from __future__ import annotations

import logging
from urllib.parse import urlparse

from .checks import PageResult, check_tls, run_page_checks
from .crawler import Crawler
from .findings import ScanResult
from .permission import check_permission

log = logging.getLogger("syntecxhub.scanner")


def scan(
    target: str,
    *,
    max_pages: int = 25,
    max_workers: int = 4,
    requests_per_second: float = 5.0,
    timeout: float = 8.0,
    respect_robots: bool = True,
    allow_public: bool = False,
    assume_yes: bool = False,
    confirm=input,
    check_tls_cert: bool = True,
) -> ScanResult:
    """Run a full passive scan of `target` and return a ScanResult. Raises PermissionDenied
    (from .permission) if the target was not confirmed as in-scope."""
    if not target.startswith(("http://", "https://")):
        target = "https://" + target
    check_permission(target, allow_public=allow_public, assume_yes=assume_yes, confirm=confirm)

    result = ScanResult(target=target)
    parsed = urlparse(target)

    if check_tls_cert and parsed.scheme == "https":
        port = parsed.port or 443
        for finding in check_tls(parsed.hostname, port, timeout=timeout):
            result.add(finding)

    crawler = Crawler(
        target,
        max_pages=max_pages,
        max_workers=max_workers,
        requests_per_second=requests_per_second,
        timeout=timeout,
        respect_robots=respect_robots,
    )

    def handle(response) -> None:
        page = PageResult(
            url=response.url,
            status_code=response.status_code,
            headers=dict(response.headers),
            text=response.text if "text" in response.headers.get("Content-Type", "text/") else "",
            is_https=response.url.startswith("https://"),
            set_cookie_headers=response.raw.headers.get_all("Set-Cookie") or []
            if hasattr(response.raw, "headers") and hasattr(response.raw.headers, "get_all")
            else ([response.headers["Set-Cookie"]] if "Set-Cookie" in response.headers else []),
        )
        for finding in run_page_checks(page):
            result.add(finding)
        log.info("scanned %s (%d) -> %d finding(s) so far", page.url, page.status_code, len(result.findings))

    try:
        result.pages_scanned = crawler.crawl(handle)
    finally:
        crawler.close()
    return result
