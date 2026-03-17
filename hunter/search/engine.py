"""
Serper.dev search client -- sends dork queries via the API.

Supports:
  - Loading dork queries from a TXT file
  - Multiple pages per dork for more results
  - Concurrent query execution
  - Real-time callback to stream discovered URLs
  - Optional proxy support (proxy-only or API+proxy)
"""

from __future__ import annotations

import asyncio
from collections.abc import Callable
from pathlib import Path
from typing import Optional

import httpx

from hunter.config import SerperConfig
from hunter.search.key_manager import KeyExhaustedError, KeyManager
from hunter.utils.logging import get_logger

logger = get_logger("search_engine")

ROTATE_STATUS_CODES = {403, 429}

OnResultsCallback = Callable[[list[str]], None] | None


def load_queries_from_file(path: str) -> list[str]:
    """Load dork queries from a TXT file (one per line).

    Blank lines and lines starting with '#' are ignored.
    """
    file_path = Path(path)
    if not file_path.exists():
        logger.error("Dorks file not found: %s", path)
        return []

    queries: list[str] = []
    with open(file_path, encoding="utf-8") as fh:
        for line in fh:
            stripped = line.strip()
            if stripped and not stripped.startswith("#"):
                queries.append(stripped)

    logger.info("Loaded %d dorks from %s", len(queries), path)
    return queries


class SearchEngine:
    """Sends dork queries to Serper.dev and collects unique result URLs.

    Supports optional proxy rotation for all API requests.
    """

    def __init__(
        self,
        config: SerperConfig,
        proxies: Optional[list[str]] = None,
    ) -> None:
        self._cfg = config
        self._km = KeyManager(config.api_keys)
        self._seen_urls: set[str] = set()
        self._lock = asyncio.Lock()
        self._proxies = proxies or []
        self._proxy_index = 0

    def _get_queries(self) -> list[str]:
        if self._cfg.queries_file:
            custom = load_queries_from_file(self._cfg.queries_file)
            if custom:
                return custom
            logger.warning("Dorks file was empty or missing.")
        return []

    def _get_proxy(self) -> Optional[str]:
        """Get next proxy in rotation, or None if no proxies."""
        if not self._proxies:
            return None
        proxy = self._proxies[self._proxy_index % len(self._proxies)]
        self._proxy_index += 1
        if not proxy.startswith(("http://", "https://", "socks")):
            proxy = "http://" + proxy
        return proxy

    def _make_client(self, proxy: Optional[str] = None) -> httpx.AsyncClient:
        """Create an httpx AsyncClient with optional proxy."""
        kwargs: dict = {
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
    ) -> list[str]:
        queries = self._get_queries()
        if not queries:
            logger.warning("No dork queries to process.")
            return []

        pages = max(1, self._cfg.pages_per_query)
        tasks_spec: list[tuple[str, int]] = []
        for query in queries:
            for page_num in range(1, pages + 1):
                tasks_spec.append((query, page_num))

        total_requests = len(tasks_spec)
        logger.info(
            "Search: %d dorks x %d pages = %d API requests (proxies: %d)",
            len(queries), pages, total_requests, len(self._proxies),
        )

        search_conc = self._cfg.search_concurrency or max(5, len(self._cfg.api_keys) * 2)
        sem = asyncio.Semaphore(search_conc)

        completed = 0
        aborted = False

        async def _run_one(query: str, page: int) -> list[str]:
            nonlocal completed, aborted
            if aborted:
                return []
            async with sem:
                if aborted:
                    return []
                proxy = self._get_proxy()
                try:
                    async with self._make_client(proxy) as client:
                        urls = await self._search(client, query, page=page)
                    completed += 1

                    if urls and on_results is not None:
                        async with self._lock:
                            on_results(urls)

                    if completed % 20 == 0 or completed == total_requests:
                        logger.info(
                            "Search progress: %d/%d requests done",
                            completed, total_requests,
                        )
                    return urls

                except KeyExhaustedError:
                    logger.error("All API keys exhausted -- aborting.")
                    aborted = True
                    return []
                except Exception as exc:
                    logger.error(
                        "Query failed (page %d, proxy=%s): %s -- %s",
                        page, proxy or "none", query[:60], exc,
                    )
                    completed += 1
                    return []

        coros = [_run_one(q, p) for q, p in tasks_spec]
        await asyncio.gather(*coros)

        logger.info("Search complete: %d unique URLs discovered.", len(self._seen_urls))
        return list(self._seen_urls)

    async def _search(
        self, client: httpx.AsyncClient, query: str, *, page: int = 1,
    ) -> list[str]:
        payload: dict = {"q": query, "num": self._cfg.results_per_query}
        if page > 1:
            payload["page"] = page

        attempt = 0
        max_attempts = max(self._km.alive_count, 1) * self._cfg.max_retries_per_key

        while attempt < max_attempts:
            attempt += 1
            try:
                key = self._km.current_key
            except KeyExhaustedError:
                raise

            headers = {"X-API-KEY": key, "Content-Type": "application/json"}
            try:
                resp = await client.post(
                    self._cfg.base_url, json=payload, headers=headers,
                )
                if resp.status_code in ROTATE_STATUS_CODES:
                    self._km.rotate(reason=f"HTTP {resp.status_code}")
                    continue

                resp.raise_for_status()
                self._km.mark_success()
                return self._parse_results(resp.json())

            except KeyExhaustedError:
                raise
            except httpx.HTTPStatusError as exc:
                logger.warning("HTTP error %s -- rotating key.", exc.response.status_code)
                try:
                    self._km.rotate(reason=str(exc))
                except KeyExhaustedError:
                    raise
            except httpx.RequestError as exc:
                logger.warning("Request error: %s", exc)
                await asyncio.sleep(0.5)

        logger.warning("Max attempts reached for dork: %s (page %d)", query[:60], page)
        return []

    def _parse_results(self, data: dict) -> list[str]:
        urls: list[str] = []
        for item in data.get("organic", []):
            url = item.get("link", "")
            if url and url not in self._seen_urls:
                self._seen_urls.add(url)
                urls.append(url)
        return urls

    @property
    def discovered_count(self) -> int:
        return len(self._seen_urls)

    @property
    def all_discovered_urls(self) -> list[str]:
        return sorted(self._seen_urls)
