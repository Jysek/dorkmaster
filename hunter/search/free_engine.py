"""
Free search engine -- processes dork queries without API keys.

Supported engines:
  - DuckDuckGo (HTML)
  - Bing (HTML)
  - Yahoo (HTML)
  - Google (HTML -- with scraping)
  - Ask.com (HTML)

Supports optional proxy rotation for all engines.
"""

from __future__ import annotations

import asyncio
import random
import re
import urllib.parse
from collections.abc import Callable
from typing import Optional
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

# DuckDuckGo: extract from result links
_DDG_LINK_RE = re.compile(r'class="result__a"[^>]*href="([^"]+)"', re.I)
_DDG_UDDG_RE = re.compile(r"uddg=([^&]+)", re.I)
# Fallback: extract from result snippets
_DDG_RESULT_URL_RE = re.compile(
    r'<a[^>]+class="result__url"[^>]*href="([^"]+)"', re.I
)

# Bing: multiple patterns for robustness
_BING_LINK_RE = re.compile(
    r'<li class="b_algo".*?<a\s+href="(https?://[^"]+)"', re.I | re.S,
)
_BING_LINK_RE2 = re.compile(
    r'<h2><a[^>]+href="(https?://(?!www\.bing\.com|r\.bing\.com)[^"]+)"', re.I,
)
_BING_CITE_RE = re.compile(
    r'<cite>(https?://[^<]+)</cite>', re.I,
)

# Yahoo: extract from redirect URLs and direct links
_YAHOO_LINK_RE = re.compile(
    r'class="[^"]*(?:ac-algo|algo-sr|td-u|fz-ms)[^"]*"[^>]*href="([^"]+)"',
    re.I | re.S,
)
_YAHOO_RU_RE = re.compile(r"RU=(https?[^/]+)", re.I)
_YAHOO_RU_FULL_RE = re.compile(r"RU=(https?://[^&/]+[^&]*)", re.I)

# Google: extract from result links and cite tags
_GOOGLE_LINK_RE = re.compile(
    r'<a[^>]+href="(https?://(?!www\.google\.)[^"]+)"[^>]*>',
    re.I,
)
_GOOGLE_CITE_RE = re.compile(
    r'<cite[^>]*>(https?://[^<]+)</cite>',
    re.I,
)
_GOOGLE_DATA_RE = re.compile(
    r'data-href="(https?://(?!www\.google\.)[^"]+)"',
    re.I,
)

# Ask.com: various patterns
_ASK_LINK_RE = re.compile(
    r'class="[^"]*result-link[^"]*"[^>]*href="(https?://[^"]+)"',
    re.I,
)
_ASK_LINK_RE2 = re.compile(
    r'<a[^>]+class="[^"]*PartialSearchResults[^"]*"[^>]+href="(https?://[^"]+)"',
    re.I,
)
_ASK_ALGO_RE = re.compile(
    r'<div class="PartialSearchResults-item".*?<a[^>]+href="(https?://[^"]+)"',
    re.I | re.S,
)

OnResultsCallback = Callable[[list[str]], None] | None

AVAILABLE_ENGINES = ["duckduckgo", "bing", "yahoo", "google", "ask"]


def _random_ua() -> str:
    return random.choice(_USER_AGENTS)


# ---------------------------------------------------------------------------
# URL extraction functions
# ---------------------------------------------------------------------------

def _extract_ddg_urls(html: str) -> list[str]:
    """Extract URLs from DuckDuckGo HTML results."""
    urls: list[str] = []

    # Primary: result__a links with uddg parameter
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

    # Fallback: result__url links
    if not urls:
        for match in _DDG_RESULT_URL_RE.finditer(html):
            raw = match.group(1)
            if raw.startswith("http"):
                urls.append(raw)
            elif raw.startswith("//"):
                urls.append("https:" + raw)

    return urls


def _extract_bing_urls(html: str) -> list[str]:
    """Extract URLs from Bing HTML results."""
    seen: set[str] = set()
    urls: list[str] = []

    # Try multiple patterns
    for pattern in [_BING_LINK_RE, _BING_LINK_RE2, _BING_CITE_RE]:
        for m in pattern.finditer(html):
            url = m.group(1).strip()
            if url.startswith("http") and url not in seen:
                # Filter Bing internal URLs
                if "bing.com" not in url and "microsoft.com" not in url:
                    seen.add(url)
                    urls.append(url)

    return urls


def _extract_yahoo_urls(html: str) -> list[str]:
    """Extract URLs from Yahoo HTML results."""
    urls: list[str] = []
    seen: set[str] = set()

    # Primary: extract from redirect URLs (RU= parameter)
    for match in _YAHOO_RU_FULL_RE.finditer(html):
        try:
            decoded = urllib.parse.unquote(match.group(1))
            if decoded.startswith("http") and "yahoo.com" not in decoded:
                if decoded not in seen:
                    seen.add(decoded)
                    urls.append(decoded)
        except Exception:
            pass

    # Fallback: direct links from algo results
    if not urls:
        for match in _YAHOO_LINK_RE.finditer(html):
            raw = match.group(1)
            # Check for RU redirect
            ru_match = _YAHOO_RU_RE.search(raw)
            if ru_match:
                try:
                    decoded = urllib.parse.unquote(ru_match.group(1))
                    if decoded.startswith("http") and "yahoo.com" not in decoded:
                        if decoded not in seen:
                            seen.add(decoded)
                            urls.append(decoded)
                except Exception:
                    pass
            elif raw.startswith("http") and "yahoo.com" not in raw:
                if raw not in seen:
                    seen.add(raw)
                    urls.append(raw)

    return urls


def _extract_google_urls(html: str) -> list[str]:
    """Extract URLs from Google HTML results."""
    urls: list[str] = []
    seen: set[str] = set()

    _skip_domains = {
        "google.com", "googleapis.com", "gstatic.com",
        "accounts.google.com", "maps.google.com",
        "support.google.com", "policies.google.com",
    }

    def _is_google_internal(u: str) -> bool:
        try:
            host = urlparse(u).netloc.lower()
            for d in _skip_domains:
                if host == d or host.endswith("." + d):
                    return True
            if "/search?" in u:
                return True
        except Exception:
            pass
        return False

    # Cite tags (most reliable for actual result URLs)
    for match in _GOOGLE_CITE_RE.finditer(html):
        url = match.group(1).strip()
        if url.startswith("http") and not _is_google_internal(url):
            if url not in seen:
                seen.add(url)
                urls.append(url)

    # Data-href attributes
    for match in _GOOGLE_DATA_RE.finditer(html):
        url = match.group(1)
        if url.startswith("http") and not _is_google_internal(url):
            if url not in seen:
                seen.add(url)
                urls.append(url)

    # Regular href links
    for match in _GOOGLE_LINK_RE.finditer(html):
        url = match.group(1)
        if url.startswith("http") and not _is_google_internal(url):
            if url not in seen:
                seen.add(url)
                urls.append(url)

    return urls


def _extract_ask_urls(html: str) -> list[str]:
    """Extract URLs from Ask.com HTML results."""
    seen: set[str] = set()
    urls: list[str] = []

    for pattern in [_ASK_LINK_RE, _ASK_LINK_RE2, _ASK_ALGO_RE]:
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
    """Check if a URL passes the blocked-domain filter."""
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
    """Processes dork queries using free web search engines.

    Supports optional proxy rotation for all requests.
    """

    def __init__(
        self,
        queries: Optional[list[str]] = None,
        engines: Optional[list[str]] = None,
        pages_per_dork: int = 1,
        proxies: Optional[list[str]] = None,
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
        self._proxies = proxies or []
        self._proxy_index = 0

    def _get_proxy(self) -> Optional[str]:
        """Get next proxy in rotation, or None if no proxies."""
        if not self._proxies:
            return None
        proxy = self._proxies[self._proxy_index % len(self._proxies)]
        self._proxy_index += 1
        # Ensure proxy has scheme
        if not proxy.startswith("http://") and not proxy.startswith("https://") and not proxy.startswith("socks"):
            proxy = "http://" + proxy
        return proxy

    def _make_client(self, proxy: Optional[str] = None) -> httpx.AsyncClient:
        """Create an httpx AsyncClient with optional proxy."""
        kwargs = {
            "timeout": 20,
            "follow_redirects": True,
            "verify": False,
        }
        if proxy:
            kwargs["proxy"] = proxy
        return httpx.AsyncClient(**kwargs)

    async def search_all(
        self,
        on_results: OnResultsCallback = None,
        max_concurrency: int = 3,
    ) -> list[str]:
        """Search all dorks across all selected engines.

        Args:
            on_results: Callback invoked with new URLs as they are discovered.
            max_concurrency: Max concurrent search requests.

        Returns:
            Sorted list of unique discovered URLs.
        """
        if not self._queries:
            logger.warning("No dork queries to process.")
            return []

        logger.info(
            "Free search: %d dorks x %d pages | engines: %s | proxies: %d",
            len(self._queries),
            self._pages_per_dork,
            ", ".join(self._engines),
            len(self._proxies),
        )

        sem = asyncio.Semaphore(max_concurrency)
        completed = 0
        total = len(self._queries) * len(self._engines) * self._pages_per_dork

        async def _run_one(query: str, engine: str, page: int) -> list[str]:
            nonlocal completed
            async with sem:
                proxy = self._get_proxy()
                try:
                    async with self._make_client(proxy) as client:
                        urls = await self._search_one(client, query, engine, page)
                except Exception as exc:
                    logger.debug(
                        "%s search error for '%s' (proxy=%s): %s",
                        engine, query[:50], proxy or "none", exc,
                    )
                    urls = []

                completed += 1

                if urls and on_results is not None:
                    async with self._lock:
                        on_results(urls)

                if completed % 5 == 0 or completed == total:
                    logger.info(
                        "Free search progress: %d/%d | %d unique URLs",
                        completed, total, len(self._seen_urls),
                    )

                # Polite delay to avoid rate limiting
                delay = random.uniform(1.0, 3.0) if not self._proxies else random.uniform(0.5, 1.5)
                await asyncio.sleep(delay)
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
        """Dispatch to the correct engine search method."""
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
        """Search DuckDuckGo using HTML endpoint."""
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
            logger.debug("DDG returned status %d for '%s'", resp.status_code, query[:40])
            return []
        return self._deduplicate(_extract_ddg_urls(resp.text))

    async def _search_bing(
        self, client: httpx.AsyncClient, query: str, page: int,
    ) -> list[str]:
        """Search Bing."""
        headers = {
            "User-Agent": _random_ua(),
            "Accept": "text/html,application/xhtml+xml,*/*;q=0.8",
            "Accept-Language": "en-US,en;q=0.9",
            "Referer": "https://www.bing.com/",
        }
        params: dict = {"q": query, "count": "50"}
        if page > 1:
            params["first"] = str((page - 1) * 50 + 1)

        resp = await client.get(_BING_URL, params=params, headers=headers)
        if resp.status_code != 200:
            logger.debug("Bing returned status %d for '%s'", resp.status_code, query[:40])
            return []
        return self._deduplicate(_extract_bing_urls(resp.text))

    async def _search_yahoo(
        self, client: httpx.AsyncClient, query: str, page: int,
    ) -> list[str]:
        """Search Yahoo."""
        headers = {
            "User-Agent": _random_ua(),
            "Accept": "text/html,application/xhtml+xml,*/*;q=0.8",
            "Accept-Language": "en-US,en;q=0.9",
            "Referer": "https://search.yahoo.com/",
        }
        params: dict = {"p": query, "n": "10"}
        if page > 1:
            params["b"] = str((page - 1) * 10 + 1)

        resp = await client.get(_YAHOO_URL, params=params, headers=headers)
        if resp.status_code != 200:
            logger.debug("Yahoo returned status %d for '%s'", resp.status_code, query[:40])
            return []
        return self._deduplicate(_extract_yahoo_urls(resp.text))

    async def _search_google(
        self, client: httpx.AsyncClient, query: str, page: int,
    ) -> list[str]:
        """Search Google.

        Note: Google is aggressive with bot detection.
        Use fewer results per page and longer delays.
        """
        headers = {
            "User-Agent": _random_ua(),
            "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
            "Accept-Language": "en-US,en;q=0.9",
            "Accept-Encoding": "gzip, deflate",
            "Referer": "https://www.google.com/",
            "DNT": "1",
        }
        params: dict = {"q": query, "num": "20"}
        if page > 1:
            params["start"] = str((page - 1) * 20)

        resp = await client.get(_GOOGLE_URL, params=params, headers=headers)
        if resp.status_code != 200:
            logger.debug("Google returned status %d for '%s'", resp.status_code, query[:40])
            return []
        return self._deduplicate(_extract_google_urls(resp.text))

    async def _search_ask(
        self, client: httpx.AsyncClient, query: str, page: int,
    ) -> list[str]:
        """Search Ask.com."""
        headers = {
            "User-Agent": _random_ua(),
            "Accept": "text/html,application/xhtml+xml,*/*;q=0.8",
            "Accept-Language": "en-US,en;q=0.9",
            "Referer": "https://www.ask.com/",
        }
        params: dict = {"q": query}
        if page > 1:
            params["page"] = str(page)

        resp = await client.get(_ASK_URL, params=params, headers=headers)
        if resp.status_code != 200:
            logger.debug("Ask returned status %d for '%s'", resp.status_code, query[:40])
            return []
        return self._deduplicate(_extract_ask_urls(resp.text))

    def _deduplicate(self, urls: list[str]) -> list[str]:
        """Deduplicate URLs against the global seen set."""
        results: list[str] = []
        for url in urls:
            # Normalize: remove fragment and trailing slash
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
