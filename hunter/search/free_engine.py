"""
Free search engine -- processes dork queries without API keys.

Supported engines:
  - DuckDuckGo (HTML)
  - Bing (HTML)
  - Yahoo (HTML)
  - Google (HTML -- with scraping)
  - Ask.com (HTML)

Rotates User-Agent headers and adds polite delays to avoid blocks.
"""

from __future__ import annotations

import asyncio
import random
import re
import urllib.parse
from collections.abc import Callable
from urllib.parse import urlparse

import httpx

from hunter.utils.logging import get_logger

logger = get_logger("free_search")

# ---------------------------------------------------------------------------
# User-Agent pool
# ---------------------------------------------------------------------------
_USER_AGENTS = [
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 "
    "(KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 "
    "(KHTML, like Gecko) Chrome/123.0.0.0 Safari/537.36",
    "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 "
    "(KHTML, like Gecko) Chrome/122.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:125.0) "
    "Gecko/20100101 Firefox/125.0",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10.15; rv:124.0) "
    "Gecko/20100101 Firefox/124.0",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 "
    "(KHTML, like Gecko) Chrome/125.0.0.0 Safari/537.36 Edg/125.0.0.0",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 "
    "(KHTML, like Gecko) Chrome/126.0.0.0 Safari/537.36",
    "Mozilla/5.0 (X11; Linux x86_64; rv:126.0) Gecko/20100101 Firefox/126.0",
]

# ---------------------------------------------------------------------------
# Engine URLs
# ---------------------------------------------------------------------------
_DDG_URL = "https://html.duckduckgo.com/html/"
_BING_URL = "https://www.bing.com/search"
_YAHOO_URL = "https://search.yahoo.com/search"
_GOOGLE_URL = "https://www.google.com/search"
_ASK_URL = "https://www.ask.com/web"

# ---------------------------------------------------------------------------
# Extraction regexes
# ---------------------------------------------------------------------------

_DDG_LINK_RE = re.compile(r'class="result__a"[^>]*href="([^"]+)"', re.I)
_DDG_UDDG_RE = re.compile(r"uddg=([^&]+)", re.I)

_BING_LINK_RE = re.compile(
    r'<li class="b_algo".*?<a\s+href="(https?://[^"]+)"', re.I | re.S,
)
_BING_LINK_RE2 = re.compile(
    r'<h2><a[^>]+href="(https?://(?!www\.bing\.com|r\.bing\.com)[^"]+)"', re.I,
)
_BING_JSON_RE = re.compile(
    r'"url"\s*:\s*"(https?://(?!www\.bing\.com|r\.bing\.com)[^"]+)"', re.I,
)

_YAHOO_LINK_RE = re.compile(
    r'class="[^"]*(?:ac-algo|algo-sr|td-u)[^"]*"[^>]*href="(https?://[^"]+)"',
    re.I | re.S,
)
_YAHOO_RU_RE = re.compile(r"RU=(https?[^/]+)", re.I)

_GOOGLE_LINK_RE = re.compile(
    r'<a[^>]+href="(https?://(?!www\.google\.)[^"]+)"[^>]*>',
    re.I,
)
_GOOGLE_CITE_RE = re.compile(
    r'<cite[^>]*>(https?://[^<]+)</cite>',
    re.I,
)

_ASK_LINK_RE = re.compile(
    r'class="PartialSearchResults-item-title-link result-link"[^>]*href="(https?://[^"]+)"',
    re.I,
)
_ASK_LINK_RE2 = re.compile(
    r'<a[^>]+class="[^"]*result-link[^"]*"[^>]+href="(https?://[^"]+)"',
    re.I,
)

OnResultsCallback = Callable[[list[str]], None] | None

AVAILABLE_ENGINES = ["duckduckgo", "bing", "yahoo", "google", "ask"]


def _random_ua() -> str:
    return random.choice(_USER_AGENTS)


# ---------------------------------------------------------------------------
# URL extraction functions
# ---------------------------------------------------------------------------

def _extract_ddg_urls(html: str) -> list[str]:
    urls: list[str] = []
    for match in _DDG_LINK_RE.finditer(html):
        raw = match.group(1)
        uddg = _DDG_UDDG_RE.search(raw)
        if uddg:
            try:
                decoded = urllib.parse.unquote(uddg.group(1))
                if decoded.startswith("http"):
                    urls.append(decoded)
            except Exception:
                pass
        elif raw.startswith("http"):
            urls.append(raw)
    return urls


def _extract_bing_urls(html: str) -> list[str]:
    seen: set[str] = set()
    urls: list[str] = []
    for pattern in [_BING_LINK_RE, _BING_LINK_RE2, _BING_JSON_RE]:
        for m in pattern.finditer(html):
            url = m.group(1)
            if url not in seen and "bing.com" not in url:
                seen.add(url)
                urls.append(url)
    return urls


def _extract_yahoo_urls(html: str) -> list[str]:
    urls: list[str] = []
    for match in _YAHOO_LINK_RE.finditer(html):
        raw = match.group(1)
        ru_match = _YAHOO_RU_RE.search(raw)
        if ru_match:
            try:
                decoded = urllib.parse.unquote(ru_match.group(1))
                if decoded.startswith("http"):
                    urls.append(decoded)
            except Exception:
                pass
        elif raw.startswith("http") and "yahoo.com" not in raw:
            urls.append(raw)
    if not urls:
        for match in _YAHOO_RU_RE.finditer(html):
            try:
                decoded = urllib.parse.unquote(match.group(1))
                if decoded.startswith("http") and "yahoo.com" not in decoded:
                    urls.append(decoded)
            except Exception:
                pass
    return urls


def _extract_google_urls(html: str) -> list[str]:
    urls: list[str] = []
    for match in _GOOGLE_CITE_RE.finditer(html):
        url = match.group(1).strip()
        if url.startswith("http"):
            urls.append(url)
    for match in _GOOGLE_LINK_RE.finditer(html):
        url = match.group(1)
        if (
            url.startswith("http")
            and "google.com" not in url
            and "googleapis.com" not in url
            and "gstatic.com" not in url
            and "/search?" not in url
            and "accounts.google" not in url
        ):
            urls.append(url)
    return urls


def _extract_ask_urls(html: str) -> list[str]:
    seen: set[str] = set()
    urls: list[str] = []
    for pattern in [_ASK_LINK_RE, _ASK_LINK_RE2]:
        for match in pattern.finditer(html):
            url = match.group(1)
            if url.startswith("http") and "ask.com" not in url and url not in seen:
                seen.add(url)
                urls.append(url)
    return urls


# ---------------------------------------------------------------------------
# URL filtering
# ---------------------------------------------------------------------------

_BLOCKED_DOMAINS = {
    "duckduckgo.com", "bing.com", "google.com", "youtube.com",
    "facebook.com", "twitter.com", "x.com", "reddit.com",
    "instagram.com", "tiktok.com", "wikipedia.org",
    "linkedin.com", "pinterest.com", "yahoo.com",
    "ask.com", "googleapis.com", "gstatic.com",
}


def _is_valid_url(url: str) -> bool:
    try:
        parsed = urlparse(url)
        host = parsed.netloc.lower()
    except Exception:
        return False
    if not host:
        return False
    for b in _BLOCKED_DOMAINS:
        if host == b or host.endswith(f".{b}"):
            return False
    return True


# ---------------------------------------------------------------------------
# FreeSearchEngine
# ---------------------------------------------------------------------------

class FreeSearchEngine:
    """Processes dork queries using free web search engines."""

    def __init__(
        self,
        queries: list[str] | None = None,
        engines: list[str] | None = None,
        pages_per_dork: int = 1,
    ) -> None:
        self._queries = queries or []
        self._engines = [
            e.lower() for e in (engines or ["duckduckgo", "bing"])
            if e.lower() in AVAILABLE_ENGINES
        ]
        if not self._engines:
            self._engines = ["duckduckgo", "bing"]
        self._pages_per_dork = max(1, pages_per_dork)
        self._seen_urls: set[str] = set()
        self._lock = asyncio.Lock()

    async def search_all(
        self,
        on_results: OnResultsCallback = None,
        max_concurrency: int = 3,
    ) -> list[str]:
        if not self._queries:
            logger.warning("No dork queries to process.")
            return []

        logger.info(
            "Free search: %d dorks x %d pages | engines: %s",
            len(self._queries),
            self._pages_per_dork,
            ", ".join(self._engines),
        )

        sem = asyncio.Semaphore(max_concurrency)
        completed = 0
        total = len(self._queries) * len(self._engines) * self._pages_per_dork

        async with httpx.AsyncClient(
            timeout=20,
            follow_redirects=True,
            verify=False,
        ) as client:

            async def _run_one(query: str, engine: str, page: int) -> list[str]:
                nonlocal completed
                async with sem:
                    urls = await self._search_one(client, query, engine, page)
                    completed += 1

                    if urls and on_results is not None:
                        async with self._lock:
                            on_results(urls)

                    if completed % 5 == 0 or completed == total:
                        logger.info(
                            "Free search progress: %d/%d | %d unique URLs",
                            completed, total, len(self._seen_urls),
                        )

                    await asyncio.sleep(random.uniform(1.5, 4.0))
                    return urls

            coros = []
            for query in self._queries:
                for engine in self._engines:
                    for page in range(1, self._pages_per_dork + 1):
                        coros.append(_run_one(query, engine, page))

            await asyncio.gather(*coros)

        logger.info(
            "Free search complete: %d unique URLs discovered.",
            len(self._seen_urls),
        )
        return sorted(self._seen_urls)

    async def _search_one(
        self, client: httpx.AsyncClient, query: str, engine: str, page: int,
    ) -> list[str]:
        dispatch = {
            "duckduckgo": self._search_ddg,
            "bing": self._search_bing,
            "yahoo": self._search_yahoo,
            "google": self._search_google,
            "ask": self._search_ask,
        }
        fn = dispatch.get(engine)
        if fn is None:
            logger.warning("Unknown engine: %s", engine)
            return []
        try:
            return await fn(client, query, page)
        except Exception as exc:
            logger.debug("%s search error for '%s': %s", engine, query[:50], exc)
            return []

    async def _search_ddg(
        self, client: httpx.AsyncClient, query: str, page: int,
    ) -> list[str]:
        headers = {
            "User-Agent": _random_ua(),
            "Accept": "text/html,application/xhtml+xml,*/*;q=0.8",
            "Accept-Language": "en-US,en;q=0.9",
            "Referer": "https://duckduckgo.com/",
        }
        data: dict = {"q": query, "b": ""}
        if page > 1:
            data["s"] = str((page - 1) * 30)
            data["nextParams"] = ""
            data["v"] = "l"
            data["o"] = "json"
            data["dc"] = str((page - 1) * 30 + 1)

        resp = await client.post(_DDG_URL, data=data, headers=headers)
        if resp.status_code != 200:
            return []
        return self._deduplicate(_extract_ddg_urls(resp.text))

    async def _search_bing(
        self, client: httpx.AsyncClient, query: str, page: int,
    ) -> list[str]:
        headers = {
            "User-Agent": _random_ua(),
            "Accept": "text/html,application/xhtml+xml,*/*;q=0.8",
            "Accept-Language": "en-US,en;q=0.9",
        }
        params: dict = {"q": query, "count": "50"}
        if page > 1:
            params["first"] = str((page - 1) * 50 + 1)

        resp = await client.get(_BING_URL, params=params, headers=headers)
        if resp.status_code != 200:
            return []
        return self._deduplicate(_extract_bing_urls(resp.text))

    async def _search_yahoo(
        self, client: httpx.AsyncClient, query: str, page: int,
    ) -> list[str]:
        headers = {
            "User-Agent": _random_ua(),
            "Accept": "text/html,application/xhtml+xml,*/*;q=0.8",
            "Accept-Language": "en-US,en;q=0.9",
        }
        params: dict = {"p": query, "n": "10"}
        if page > 1:
            params["b"] = str((page - 1) * 10 + 1)

        resp = await client.get(_YAHOO_URL, params=params, headers=headers)
        if resp.status_code != 200:
            return []
        return self._deduplicate(_extract_yahoo_urls(resp.text))

    async def _search_google(
        self, client: httpx.AsyncClient, query: str, page: int,
    ) -> list[str]:
        headers = {
            "User-Agent": _random_ua(),
            "Accept": "text/html,application/xhtml+xml,*/*;q=0.8",
            "Accept-Language": "en-US,en;q=0.9",
        }
        params: dict = {"q": query, "num": "50"}
        if page > 1:
            params["start"] = str((page - 1) * 50)

        resp = await client.get(_GOOGLE_URL, params=params, headers=headers)
        if resp.status_code != 200:
            return []
        return self._deduplicate(_extract_google_urls(resp.text))

    async def _search_ask(
        self, client: httpx.AsyncClient, query: str, page: int,
    ) -> list[str]:
        headers = {
            "User-Agent": _random_ua(),
            "Accept": "text/html,application/xhtml+xml,*/*;q=0.8",
            "Accept-Language": "en-US,en;q=0.9",
        }
        params: dict = {"q": query}
        if page > 1:
            params["page"] = str(page)

        resp = await client.get(_ASK_URL, params=params, headers=headers)
        if resp.status_code != 200:
            return []
        return self._deduplicate(_extract_ask_urls(resp.text))

    def _deduplicate(self, urls: list[str]) -> list[str]:
        results: list[str] = []
        for url in urls:
            url = url.split("#")[0].rstrip("/")
            if url and url not in self._seen_urls and _is_valid_url(url):
                self._seen_urls.add(url)
                results.append(url)
        return results

    @property
    def discovered_count(self) -> int:
        return len(self._seen_urls)

    @property
    def all_discovered_urls(self) -> list[str]:
        return sorted(self._seen_urls)
