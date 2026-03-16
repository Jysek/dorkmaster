"""
Central configuration for DorkMaster Hunter.

All settings can be overridden via environment variables or a .env file.
"""

from __future__ import annotations

import os
from dataclasses import dataclass, field
from pathlib import Path

try:
    from dotenv import load_dotenv
    load_dotenv()
except ImportError:
    pass

# ---------------------------------------------------------------------------
# Paths
# ---------------------------------------------------------------------------
BASE_DIR = Path(__file__).resolve().parent.parent
DATA_DIR = BASE_DIR / "data"
DATA_DIR.mkdir(exist_ok=True)


@dataclass
class SerperConfig:
    """Serper.dev search API settings (API mode)."""

    api_keys: list[str] = field(default_factory=list)
    base_url: str = "https://google.serper.dev/search"
    results_per_query: int = 100
    max_retries_per_key: int = 2
    pages_per_query: int = 1
    queries_file: str | None = None
    search_concurrency: int = 10

    def __post_init__(self) -> None:
        raw = os.getenv("SERPER_API_KEYS", "")
        if raw:
            self.api_keys = [k.strip() for k in raw.split(",") if k.strip()]
        pages = os.getenv("SERPER_PAGES_PER_QUERY")
        if pages:
            self.pages_per_query = max(1, int(pages))
        num = os.getenv("SERPER_RESULTS_PER_QUERY")
        if num:
            self.results_per_query = max(1, int(num))
        conc = os.getenv("SERPER_SEARCH_CONCURRENCY")
        if conc:
            self.search_concurrency = max(1, int(conc))
        self.queries_file = os.getenv("QUERIES_FILE", "dorks.txt") or None


@dataclass
class SearchConfig:
    """General search settings (shared by API and free modes)."""

    max_threads: int = 10
    timeout_ms: int = 15_000
    pages_per_dork: int = 1
    user_agent: str = (
        "Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
        "AppleWebKit/537.36 (KHTML, like Gecko) "
        "Chrome/124.0.0.0 Safari/537.36"
    )
    proxy_url: str | None = field(default=None)
    free_engines: list[str] = field(default_factory=lambda: ["duckduckgo", "bing"])

    def __post_init__(self) -> None:
        timeout = os.getenv("SEARCH_TIMEOUT_MS")
        if timeout:
            self.timeout_ms = int(timeout)
        threads = os.getenv("SEARCH_MAX_THREADS")
        if threads:
            self.max_threads = max(1, int(threads))
        self.proxy_url = os.getenv("PROXY_URL") or None
        engines = os.getenv("FREE_SEARCH_ENGINES")
        if engines:
            self.free_engines = [
                e.strip().lower() for e in engines.split(",") if e.strip()
            ]


@dataclass
class HunterConfig:
    """Top-level hunter config aggregating all sub-configs."""

    serper: SerperConfig = field(default_factory=SerperConfig)
    search: SearchConfig = field(default_factory=SearchConfig)
    data_dir: Path = DATA_DIR
    search_mode: str = "free"  # "api" or "free"
    output_format: str = "all"  # "txt", "json", "csv", "all"


# Singleton convenience
_config: HunterConfig | None = None


def get_hunter_config() -> HunterConfig:
    """Return (and lazily create) the global HunterConfig singleton."""
    global _config
    if _config is None:
        _config = HunterConfig()
    return _config
