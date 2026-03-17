"""
Scan result exporter -- JSON, TXT, CSV output.

Produces structured reports suitable for CI pipelines,
dashboards, and manual review.
"""

from __future__ import annotations

import csv
import json
from pathlib import Path

from hunter.utils.logging import get_logger
from scanner.models import Confidence, ScanReport, ScanStatus

logger = get_logger("scanner.reporter")


# ---------------------------------------------------------------------------
# JSON
# ---------------------------------------------------------------------------

def export_json(report: ScanReport, path: Path) -> Path:
    """Write a full JSON report."""
    path.parent.mkdir(parents=True, exist_ok=True)
    with open(path, "w", encoding="utf-8") as fh:
        json.dump(report.to_dict(), fh, indent=2, default=str)
    logger.info("JSON scan report saved -> %s", path)
    return path


# ---------------------------------------------------------------------------
# TXT (human-readable)
# ---------------------------------------------------------------------------

def export_txt(report: ScanReport, path: Path) -> Path:
    """Write a human-readable TXT summary."""
    path.parent.mkdir(parents=True, exist_ok=True)
    lines: list[str] = []

    lines.append("=" * 70)
    lines.append("  DORKMASTER SECURITY SCAN REPORT")
    lines.append("=" * 70)
    lines.append("")
    lines.append(f"  Scanned URLs:   {report.total_urls}")
    lines.append(f"  Total Findings: {report.total_findings}")
    for vtype, count in sorted(report.vuln_counts.items()):
        lines.append(f"    - {vtype}: {count}")
    lines.append(f"  Started:  {report.started_at}")
    lines.append(f"  Finished: {report.finished_at}")
    lines.append("")
    lines.append("-" * 70)

    for res in report.results:
        if res.status == ScanStatus.CLEAN and not res.findings:
            continue
        lines.append("")
        lines.append(f"  URL: {res.url}")
        lines.append(f"  Status: {res.status.value}")
        if res.error:
            lines.append(f"  Error: {res.error}")
        for f in res.findings:
            lines.append(f"    [{f.confidence.value.upper():^6}] {f.vuln_type.value} "
                         f"| param={f.parameter} | HTTP {f.response_code} | "
                         f"{f.response_time_ms:.0f}ms")
            lines.append(f"           {f.evidence}")
        lines.append(f"  {'- ' * 35}")

    lines.append("")
    lines.append("=" * 70)

    with open(path, "w", encoding="utf-8") as fh:
        fh.write("\n".join(lines) + "\n")
    logger.info("TXT scan report saved -> %s", path)
    return path


# ---------------------------------------------------------------------------
# CSV
# ---------------------------------------------------------------------------

def export_csv(report: ScanReport, path: Path) -> Path:
    """Write findings as a flat CSV."""
    path.parent.mkdir(parents=True, exist_ok=True)
    with open(path, "w", newline="", encoding="utf-8") as fh:
        writer = csv.writer(fh)
        writer.writerow([
            "#", "url", "status", "vuln_type", "confidence",
            "parameter", "evidence", "http_code", "response_ms",
        ])
        idx = 0
        for res in report.results:
            if not res.findings:
                idx += 1
                writer.writerow([
                    idx, res.url, res.status.value,
                    "", "", "", "", "", "",
                ])
            else:
                for f in res.findings:
                    idx += 1
                    writer.writerow([
                        idx, f.url, res.status.value,
                        f.vuln_type.value, f.confidence.value,
                        f.parameter, f.evidence,
                        f.response_code, f"{f.response_time_ms:.2f}",
                    ])
    logger.info("CSV scan report saved -> %s", path)
    return path


# ---------------------------------------------------------------------------
# Convenience: export all formats
# ---------------------------------------------------------------------------

def export_all(report: ScanReport, output_dir: str | Path) -> dict[str, Path]:
    """Export report in JSON + TXT + CSV.  Returns dict of format -> path."""
    d = Path(output_dir)
    d.mkdir(parents=True, exist_ok=True)
    return {
        "json": export_json(report, d / "scan_report.json"),
        "txt": export_txt(report, d / "scan_report.txt"),
        "csv": export_csv(report, d / "scan_report.csv"),
    }
