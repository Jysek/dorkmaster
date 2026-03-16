"""
Central configuration for DorkMaster Hunter.

All settings can be overridden via environment variables, .env file,
or the web Settings page.
"""

from __future__ import annotations

import json
import os
from dataclasses import dataclass, field
from pathlib import Path
from typing import Optional

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
SETTINGS_FILE = DATA_DIR / "settings.json"


def _load_persisted_settings() -> dict:
    """Load settings from the persisted JSON file."""
    if SETTINGS_FILE.is_file():
        try:
            with open(SETTINGS_FILE, "r", encoding="utf-8") as f:
                return json.load(f)
        except (json.JSONDecodeError, OSError):
            pass
    return {}


def _save_persisted_settings(data: dict) -> None:
    """Save settings to the persisted JSON file."""
    DATA_DIR.mkdir(parents=True, exist_ok=True)
    with open(SETTINGS_FILE, "w", encoding="utf-8") as f:
        json.dump(data, f, indent=2)


# ---------------------------------------------------------------------------
# Engine Classification
# ---------------------------------------------------------------------------

# Free engines: no API key needed, scrape HTML directly
FREE_ENGINES = ["duckduckgo", "bing", "yahoo", "google", "ask"]

# API engines: require API keys
API_ENGINES = {
    "serper": {
        "name": "Serper.dev (Google)",
        "description": "Google search results via Serper.dev API",
        "env_key": "SERPER_API_KEYS",
        "base_url": "https://google.serper.dev/search",
    },
}

FREE_ENGINE_INFO = {
    "duckduckgo": {"name": "DuckDuckGo", "desc": "Most reliable, no API key needed"},
    "bing": {"name": "Bing", "desc": "Good results, fast, no API key needed"},
    "yahoo": {"name": "Yahoo", "desc": "Decent coverage, no API key needed"},
    "google": {"name": "Google", "desc": "Best results but may block scrapers"},
    "ask": {"name": "Ask.com", "desc": "Extra coverage, no API key needed"},
}


@dataclass
class SerperConfig:
    """Serper.dev search API settings (API mode)."""

    api_keys: list[str] = field(default_factory=list)
    base_url: str = "https://google.serper.dev/search"
    results_per_query: int = 100
    max_retries_per_key: int = 2
    pages_per_query: int = 1
    queries_file: Optional[str] = None
    search_concurrency: int = 10

    def __post_init__(self) -> None:
        persisted = _load_persisted_settings()

        # API keys: persisted > env > empty
        saved_keys = persisted.get("serper_api_keys", [])
        if saved_keys:
            self.api_keys = saved_keys
        else:
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
class ProxyConfig:
    """Proxy configuration."""

    enabled: bool = False
    proxies: list[str] = field(default_factory=list)

    def __post_init__(self) -> None:
        persisted = _load_persisted_settings()
        self.enabled = persisted.get("proxy_enabled", False)
        self.proxies = persisted.get("proxies", [])


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
    free_engines: list[str] = field(default_factory=lambda: ["duckduckgo", "bing"])

    def __post_init__(self) -> None:
        timeout = os.getenv("SEARCH_TIMEOUT_MS")
        if timeout:
            self.timeout_ms = int(timeout)
        threads = os.getenv("SEARCH_MAX_THREADS")
        if threads:
            self.max_threads = max(1, int(threads))
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
    proxy: ProxyConfig = field(default_factory=ProxyConfig)
    data_dir: Path = DATA_DIR
    search_mode: str = "free"  # "api" or "free"
    output_format: str = "all"


# Singleton convenience
_config: Optional[HunterConfig] = None


def get_hunter_config(force_reload: bool = False) -> HunterConfig:
    """Return (and lazily create) the global HunterConfig singleton."""
    global _config
    if _config is None or force_reload:
        _config = HunterConfig()
    return _config


def save_settings(data: dict) -> None:
    """Save settings from the web UI."""
    _save_persisted_settings(data)
    # Force reload on next access
    global _config
    _config = None


def get_current_settings() -> dict:
    """Get current settings for display in the UI."""
    persisted = _load_persisted_settings()
    cfg = get_hunter_config()

    return {
        "serper_api_keys": [
            k[:8] + "..." + k[-4:] if len(k) > 12 else "***"
            for k in cfg.serper.api_keys
        ],
        "serper_api_keys_count": len(cfg.serper.api_keys),
        "proxy_enabled": cfg.proxy.enabled,
        "proxy_count": len(cfg.proxy.proxies),
        "proxies": cfg.proxy.proxies,
        "free_engines": FREE_ENGINES,
        "api_engines": API_ENGINES,
        "free_engine_info": FREE_ENGINE_INFO,
        "search_timeout_ms": cfg.search.timeout_ms,
        "max_threads": cfg.search.max_threads,
    }
