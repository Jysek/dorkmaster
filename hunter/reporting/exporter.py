"""
Reporting module -- exports extracted URLs to TXT, JSON, and CSV formats.

Includes a RealtimeExporter for incremental file updates during
the search phase.
"""

from __future__ import annotations

import csv
import json
import threading
from datetime import datetime, timezone
from pathlib import Path

from hunter.utils.logging import get_logger

logger = get_logger("reporter")


# ---------------------------------------------------------------------------
# Batch exporters
# ---------------------------------------------------------------------------

def export_txt(urls: list[str], path: Path) -> Path:
    path.parent.mkdir(parents=True, exist_ok=True)
    with open(path, "w", encoding="utf-8") as fh:
        for url in urls:
            fh.write(url + "\n")
    logger.info("TXT report saved  -> %s (%d URLs)", path, len(urls))
    return path


def export_json(urls: list[str], path: Path) -> Path:
    path.parent.mkdir(parents=True, exist_ok=True)
    data = {
        "total": len(urls),
        "exported_at": datetime.now(timezone.utc).isoformat(),
        "urls": urls,
    }
    with open(path, "w", encoding="utf-8") as fh:
        json.dump(data, fh, indent=2, default=str)
    logger.info("JSON report saved -> %s (%d URLs)", path, len(urls))
    return path


def export_csv(urls: list[str], path: Path) -> Path:
    if not urls:
        logger.warning("No URLs to export.")
        return path
    path.parent.mkdir(parents=True, exist_ok=True)
    with open(path, "w", newline="", encoding="utf-8") as fh:
        writer = csv.writer(fh)
        writer.writerow(["#", "url"])
        for idx, url in enumerate(urls, 1):
            writer.writerow([idx, url])
    logger.info("CSV report saved  -> %s (%d URLs)", path, len(urls))
    return path


def summary_stats(total_urls: int, dork_count: int = 0) -> dict:
    return {
        "total_urls_extracted": total_urls,
        "total_dorks_processed": dork_count,
        "generated_at": datetime.now(timezone.utc).isoformat(),
    }


# ---------------------------------------------------------------------------
# Realtime exporter
# ---------------------------------------------------------------------------

class RealtimeExporter:
    """Thread-safe incremental file writer."""

    def __init__(self, data_dir: Path, flush_interval: int = 50) -> None:
        self._data_dir = data_dir
        self._data_dir.mkdir(parents=True, exist_ok=True)
        self._lock = threading.Lock()
        self._urls: list[str] = []
        self._txt_path = self._data_dir / "urls.txt"
        self._json_path = self._data_dir / "urls.json"
        self._csv_path = self._data_dir / "urls.csv"
        self._stats_path = self._data_dir / "stats.json"
        self._txt_path.write_text("", encoding="utf-8")
        self._json_path.write_text(
            json.dumps({"total": 0, "urls": []}), encoding="utf-8",
        )
        self._stats_path.write_text(
            json.dumps(summary_stats(0)), encoding="utf-8",
        )
        with open(self._csv_path, "w", newline="", encoding="utf-8") as fh:
            writer = csv.writer(fh)
            writer.writerow(["#", "url"])
        self._flush_counter = 0
        self._flush_interval = max(1, flush_interval)

    def add_urls(self, urls: list[str]) -> None:
        with self._lock:
            self._urls.extend(urls)
            with open(self._txt_path, "a", encoding="utf-8") as fh:
                for url in urls:
                    fh.write(url + "\n")
            self._flush_counter += len(urls)
            if self._flush_counter >= self._flush_interval:
                self._flush_files()
                self._flush_counter = 0

    def flush(self) -> None:
        with self._lock:
            self._flush_files()
            self._flush_counter = 0

    def _flush_files(self) -> None:
        data = {
            "total": len(self._urls),
            "exported_at": datetime.now(timezone.utc).isoformat(),
            "urls": self._urls,
        }
        with open(self._json_path, "w", encoding="utf-8") as fh:
            json.dump(data, fh, indent=2, default=str)
        with open(self._csv_path, "w", newline="", encoding="utf-8") as fh:
            writer = csv.writer(fh)
            writer.writerow(["#", "url"])
            for idx, url in enumerate(self._urls, 1):
                writer.writerow([idx, url])
        stats = summary_stats(len(self._urls))
        with open(self._stats_path, "w", encoding="utf-8") as fh:
            json.dump(stats, fh, indent=2)

    @property
    def urls(self) -> list[str]:
        with self._lock:
            return list(self._urls)

    @property
    def url_count(self) -> int:
        with self._lock:
            return len(self._urls)
