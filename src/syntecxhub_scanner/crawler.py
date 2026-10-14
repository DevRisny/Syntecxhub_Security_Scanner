"""A small, polite, same-origin crawler: respects robots.txt, stays on one host, rate-limits
itself, and hands each fetched page to the scanner. No forms are submitted and no input
fields are filled — pages are only requested and read."""

from __future__ import annotations

import threading
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from html.parser import HTMLParser
from typing import Callable, List, Optional, Set
from urllib.parse import urldefrag, urljoin, urlparse
from urllib.robotparser import RobotFileParser

import requests

USER_AGENT = "SyntecxhubSecurityScanner/1.0 (+passive security checks; see README)"
DEFAULT_TIMEOUT = 8.0


class _LinkExtractor(HTMLParser):
    """Pulls href/src targets out of an HTML page without needing a third-party HTML parser."""

    def __init__(self) -> None:
        super().__init__()
        self.links: List[str] = []

    def handle_starttag(self, tag: str, attrs) -> None:
        if tag not in ("a", "link", "script", "img", "iframe"):
            return
        for name, value in attrs:
            if name in ("href", "src") and value:
                self.links.append(value)


def extract_links(base_url: str, html: str) -> List[str]:
    parser = _LinkExtractor()
    try:
        parser.feed(html)
    except Exception:
        return []
    out = []
    for link in parser.links:
        if link.startswith(("javascript:", "mailto:", "tel:", "data:")):
            continue
        out.append(urldefrag(urljoin(base_url, link))[0])
    return out


class RateLimiter:
    """Caps requests to at most `per_second` per second, shared across worker threads."""

    def __init__(self, per_second: float) -> None:
        self._interval = 1.0 / per_second if per_second > 0 else 0.0
        self._lock = threading.Lock()
        self._next_slot = 0.0

    def wait(self) -> None:
        if self._interval <= 0:
            return
        with self._lock:
            now = time.monotonic()
            start = max(now, self._next_slot)
            self._next_slot = start + self._interval
        delay = start - time.monotonic()
        if delay > 0:
            time.sleep(delay)


class Crawler:
    """Crawls one site, same-origin only, up to `max_pages`, honoring robots.txt."""

    def __init__(
        self,
        start_url: str,
        max_pages: int = 25,
        max_workers: int = 4,
        requests_per_second: float = 5.0,
        timeout: float = DEFAULT_TIMEOUT,
        respect_robots: bool = True,
        session: Optional[requests.Session] = None,
    ) -> None:
        self.start_url = start_url
        self.origin = urlparse(start_url)
        self.max_pages = max_pages
        self.timeout = timeout
        self.limiter = RateLimiter(requests_per_second)
        self.session = session or requests.Session()
        self.session.headers["User-Agent"] = USER_AGENT
        self._max_workers = max_workers
        self._executor = ThreadPoolExecutor(max_workers=max_workers)
        self._robots = self._load_robots() if respect_robots else None

    def _load_robots(self) -> Optional[RobotFileParser]:
        robots_url = f"{self.origin.scheme}://{self.origin.netloc}/robots.txt"
        parser = RobotFileParser()
        parser.set_url(robots_url)
        try:
            self.limiter.wait()
            resp = self.session.get(robots_url, timeout=self.timeout)
            if resp.status_code >= 400:
                return None
            parser.parse(resp.text.splitlines())
            return parser
        except requests.RequestException:
            return None

    def _same_origin(self, url: str) -> bool:
        parsed = urlparse(url)
        return parsed.scheme in ("http", "https") and parsed.netloc == self.origin.netloc

    def _allowed(self, url: str) -> bool:
        if self._robots is None:
            return True
        return self._robots.can_fetch(USER_AGENT, url)

    def _fetch(self, url: str):
        self.limiter.wait()
        return self.session.get(url, timeout=self.timeout, allow_redirects=True)

    def crawl(self, on_page: Callable) -> int:
        """Breadth-first crawl. Calls on_page(response) for each fetched page. Returns count."""
        seen: Set[str] = set()
        queue: List[str] = [self.start_url]
        fetched = 0
        while queue and fetched < self.max_pages:
            batch = []
            room = self.max_pages - fetched
            while queue and len(batch) < self._max_workers and len(batch) < room:
                url = queue.pop(0)
                if url in seen or not self._same_origin(url) or not self._allowed(url):
                    continue
                seen.add(url)
                batch.append(url)
            if not batch:
                break
            futures = {self._executor.submit(self._fetch, url): url for url in batch}
            for future in as_completed(futures):
                url = futures[future]
                try:
                    response = future.result()
                except requests.RequestException:
                    continue
                fetched += 1
                on_page(response)
                content_type = response.headers.get("Content-Type", "")
                if "text/html" in content_type:
                    for link in extract_links(url, response.text):
                        if link not in seen:
                            queue.append(link)
        return fetched

    def close(self) -> None:
        self._executor.shutdown(wait=True)
        self.session.close()
