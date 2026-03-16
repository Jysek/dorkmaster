"""
Orchestrator -- wires search and reporting together.

Simple pipeline: load dorks -> search -> save extracted URLs.
Supports both API (Serper.dev) and free (multi-engine) search modes.
"""

from __future__ import annotations

import json
from pathlib import Path

from hunter.config import HunterConfig, get_hunter_config
from hunter.reporting.exporter import (
    RealtimeExporter,
    export_csv,
    export_json,
    export_txt,
    summary_stats,
)
from hunter.search.engine import SearchEngine, load_queries_from_file
from hunter.search.free_engine import FreeSearchEngine
from hunter.utils.logging import get_logger

logger = get_logger("orchestrator")


def load_dorks_from_file(path: str) -> list[str]:
    """Load dork queries from a plain-text file (one per line)."""
    queries: list[str] = []
    p = Path(path)
    if not p.is_file():
        logger.error("Dorks file not found: %s", path)
        return queries
    with open(p, encoding="utf-8") as fh:
        for line in fh:
            stripped = line.strip()
            if stripped and not stripped.startswith("#"):
                queries.append(stripped)
    logger.info("Loaded %d dorks from %s", len(queries), path)
    return queries


def _export_all(urls: list[str], data_dir: Path, dork_count: int = 0) -> None:
    """Export URLs in all supported formats."""
    data_dir.mkdir(parents=True, exist_ok=True)
    export_txt(urls, data_dir / "urls.txt")
    export_json(urls, data_dir / "urls.json")
    export_csv(urls, data_dir / "urls.csv")
    stats = summary_stats(len(urls), dork_count)
    with open(data_dir / "stats.json", "w") as fh:
        json.dump(stats, fh, indent=2)
    logger.info(
        "Export complete: %d URLs saved to %s (txt, json, csv)", len(urls), data_dir,
    )


async def run_pipeline(
    config: HunterConfig | None = None,
    custom_dorks: list[str] | None = None,
) -> list[str]:
    """Execute the full search pipeline: load dorks -> search -> export."""
    cfg = config or get_hunter_config()
    rt_exporter = RealtimeExporter(cfg.data_dir)

    def _on_urls_found(new_urls: list[str]) -> None:
        rt_exporter.add_urls(new_urls)
        logger.info(
            "Realtime: %d total URLs extracted so far.", rt_exporter.url_count,
        )

    dorks = custom_dorks
    if not dorks and cfg.serper.queries_file:
        dorks = load_dorks_from_file(cfg.serper.queries_file)

    if not dorks:
        logger.warning("No dork queries to process -- check your configuration.")
        return []

    dork_count = len(dorks)
    logger.info("=== Search Phase: %d dorks (mode=%s) ===", dork_count, cfg.search_mode)

    if cfg.search_mode == "free":
        engine = FreeSearchEngine(
            queries=dorks,
            engines=cfg.search.free_engines,
            pages_per_dork=cfg.search.pages_per_dork,
        )
        urls = await engine.search_all(
            on_results=_on_urls_found,
            max_concurrency=cfg.search.max_threads,
        )
    else:
        api_engine = SearchEngine(cfg.serper)
        if custom_dorks:
            api_engine._get_queries = lambda: custom_dorks  # type: ignore[assignment]
        urls = await api_engine.search_all(on_results=_on_urls_found)

    rt_exporter.flush()

    if not urls:
        logger.warning("No URLs extracted -- check your dork queries.")
        return []

    _export_all(urls, cfg.data_dir, dork_count)

    logger.info(
        "Pipeline complete: %d unique URLs extracted from %d dorks.",
        len(urls), dork_count,
    )
    return urls
