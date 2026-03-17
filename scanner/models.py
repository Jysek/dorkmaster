"""
Data structures for the scanner module.

All models are pure dataclasses -- no I/O, no side effects.
Designed for serialisation to JSON and CLI display.
"""

from __future__ import annotations

import os
from dataclasses import dataclass, field
from datetime import datetime, timezone
from enum import Enum
from typing import Optional


# ---------------------------------------------------------------------------
# Enums
# ---------------------------------------------------------------------------

class VulnType(str, Enum):
    """Vulnerability classification."""
    SQLI = "SQLi"
    XSS = "XSS"


class Confidence(str, Enum):
    """Detection confidence level."""
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"


class ScanStatus(str, Enum):
    """Per-URL scan outcome."""
    VULNERABLE = "vulnerable"
    CLEAN = "clean"
    ERROR = "error"
    SKIPPED = "skipped"


# ---------------------------------------------------------------------------
# Scan Finding (one issue per parameter)
# ---------------------------------------------------------------------------

@dataclass
class Finding:
    """A single detected issue on a specific parameter."""

    vuln_type: VulnType
    confidence: Confidence
    parameter: str
    evidence: str           # human-readable reason (NO raw payloads)
    url: str
    response_code: int = 0
    response_time_ms: float = 0.0

    def to_dict(self) -> dict:
        return {
            "vuln_type": self.vuln_type.value,
            "confidence": self.confidence.value,
            "parameter": self.parameter,
            "evidence": self.evidence,
            "url": self.url,
            "response_code": self.response_code,
            "response_time_ms": round(self.response_time_ms, 2),
        }


# ---------------------------------------------------------------------------
# Per-URL scan result
# ---------------------------------------------------------------------------

@dataclass
class URLScanResult:
    """Aggregated result for a single URL."""

    url: str
    status: ScanStatus = ScanStatus.CLEAN
    findings: list[Finding] = field(default_factory=list)
    error: Optional[str] = None
    scan_duration_ms: float = 0.0

    def to_dict(self) -> dict:
        return {
            "url": self.url,
            "status": self.status.value,
            "findings": [f.to_dict() for f in self.findings],
            "error": self.error,
            "scan_duration_ms": round(self.scan_duration_ms, 2),
        }


# ---------------------------------------------------------------------------
# Full scan report
# ---------------------------------------------------------------------------

@dataclass
class ScanReport:
    """Complete scan report across all URLs."""

    results: list[URLScanResult] = field(default_factory=list)
    total_urls: int = 0
    total_findings: int = 0
    vuln_counts: dict[str, int] = field(default_factory=dict)
    started_at: str = ""
    finished_at: str = ""
    scan_config: Optional[dict] = None

    def to_dict(self) -> dict:
        return {
            "summary": {
                "total_urls": self.total_urls,
                "total_findings": self.total_findings,
                "vuln_counts": self.vuln_counts,
                "started_at": self.started_at,
                "finished_at": self.finished_at,
            },
            "config": self.scan_config or {},
            "results": [r.to_dict() for r in self.results],
        }


# ---------------------------------------------------------------------------
# Scanner configuration
# ---------------------------------------------------------------------------

@dataclass
class ScanConfig:
    """Runtime configuration for a scan session."""

    # Concurrency
    max_concurrency: int = 20
    timeout_seconds: float = 10.0

    # Rate-limiting
    rate_limit_rps: float = 50.0          # requests per second (0 = unlimited)
    delay_between_requests_ms: float = 0  # extra per-request delay

    # Detection toggles
    detect_sqli: bool = True
    detect_xss: bool = True

    # Network
    user_agent: str = (
        "Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
        "AppleWebKit/537.36 (KHTML, like Gecko) "
        "Chrome/124.0.0.0 Safari/537.36"
    )
    follow_redirects: bool = True
    verify_ssl: bool = False

    # Output
    output_dir: str = "scan_results"
    output_format: str = "all"            # "json", "txt", "csv", "all"
    verbose: bool = False

    def __post_init__(self) -> None:
        """Override from environment variables when available."""
        conc = os.getenv("SCAN_MAX_CONCURRENCY")
        if conc:
            self.max_concurrency = max(1, int(conc))
        timeout = os.getenv("SCAN_TIMEOUT")
        if timeout:
            self.timeout_seconds = max(1.0, float(timeout))
        rps = os.getenv("SCAN_RATE_LIMIT_RPS")
        if rps:
            self.rate_limit_rps = max(0, float(rps))

    def to_dict(self) -> dict:
        return {
            "max_concurrency": self.max_concurrency,
            "timeout_seconds": self.timeout_seconds,
            "rate_limit_rps": self.rate_limit_rps,
            "detect_sqli": self.detect_sqli,
            "detect_xss": self.detect_xss,
            "follow_redirects": self.follow_redirects,
            "verify_ssl": self.verify_ssl,
        }
