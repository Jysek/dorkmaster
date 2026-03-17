"""
Scanner Orchestrator -- async scan pipeline
=============================================

Responsibilities:
  1. Parse URLs and extract GET parameters
  2. Fetch baseline response (original URL unchanged)
  3. For each parameter:
       - Build a probed URL with a safe detection token
       - Fetch the probed response
       - Pass baseline + probed to every enabled detector
  4. Aggregate findings into a ScanReport
  5. Export results

Performance features:
  - asyncio + httpx for non-blocking I/O
  - Semaphore-based concurrency cap
  - Token-bucket rate limiter
  - Configurable timeout per request
  - Progress callback for CLI integration
"""

from __future__ import annotations

import asyncio
import random
import time
from datetime import datetime, timezone
from typing import Callable, Optional
from urllib.parse import parse_qs, urlencode, urlparse, urlunparse

import httpx

from hunter.utils.logging import get_logger
from scanner.detectors import get_detectors
from scanner.detectors.base import BaseDetector, HTTPResponse
from scanner.detectors.xss import generate_canary
from scanner.models import (
    Confidence,
    Finding,
    ScanConfig,
    ScanReport,
    ScanStatus,
    URLScanResult,
    VulnType,
)
from scanner.reporting.exporter import export_all

logger = get_logger("scanner.orchestrator")

# Type alias for progress callbacks
ProgressCallback = Optional[Callable[[int, int, str], None]]


# ---------------------------------------------------------------------------
# Token-bucket rate limiter
# ---------------------------------------------------------------------------

class _RateLimiter:
    """Simple async token-bucket rate limiter."""

    def __init__(self, rps: float) -> None:
        self._rps = rps
        self._interval = 1.0 / rps if rps > 0 else 0
        self._last = 0.0
        self._lock = asyncio.Lock()

    async def acquire(self) -> None:
        if self._interval <= 0:
            return
        async with self._lock:
            now = time.monotonic()
            wait = self._interval - (now - self._last)
            if wait > 0:
                await asyncio.sleep(wait)
            self._last = time.monotonic()


# ---------------------------------------------------------------------------
# URL helpers
# ---------------------------------------------------------------------------

def extract_params(url: str) -> dict[str, str]:
    """Extract GET parameters from a URL.  Returns {name: first_value}."""
    parsed = urlparse(url)
    qs = parse_qs(parsed.query, keep_blank_values=True)
    return {k: v[0] for k, v in qs.items()}


def _replace_param(url: str, param: str, new_value: str) -> str:
    """Return URL with *param* replaced by *new_value*."""
    parsed = urlparse(url)
    qs = parse_qs(parsed.query, keep_blank_values=True)
    qs[param] = [new_value]
    new_query = urlencode({k: v[0] for k, v in qs.items()}, quote_via=lambda s, *a, **k: s)
    return urlunparse(parsed._replace(query=new_query))


# ---------------------------------------------------------------------------
# Safe probe tokens
# ---------------------------------------------------------------------------
# These are the values injected into parameters for detection.
# They are deliberately NOT exploit payloads.

_SQLI_PROBE = "1'"                     # single-quote: triggers SQL errors
_SQLI_BOOL_TRUE = "1 AND 1=1"          # tautology (always true)
_SQLI_BOOL_FALSE = "1 AND 1=2"         # contradiction (always false)


def _build_xss_probe(canary: str) -> str:
    """Build a safe XSS probe: just the canary string (alphanumeric)."""
    return canary


# ---------------------------------------------------------------------------
# Orchestrator
# ---------------------------------------------------------------------------

class ScanOrchestrator:
    """Coordinates the full async scan pipeline.

    Supports optional proxy rotation for all outgoing requests.
    """

    def __init__(self, config: ScanConfig | None = None) -> None:
        self.config = config or ScanConfig()
        self._detectors: list[BaseDetector] = get_detectors(
            sqli=self.config.detect_sqli,
            xss=self.config.detect_xss,
        )
        self._rate_limiter = _RateLimiter(self.config.rate_limit_rps)
        self._semaphore: asyncio.Semaphore | None = None
        self._proxies = list(self.config.proxies) if self.config.use_proxy else []
        self._proxy_index = 0

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    async def scan(
        self,
        urls: list[str],
        on_progress: ProgressCallback = None,
    ) -> ScanReport:
        """Run the full scan on a list of URLs.

        Args:
            urls:        List of URLs with GET parameters.
            on_progress: Callback(current, total, url) for progress.

        Returns:
            Completed ScanReport.
        """
        started = datetime.now(timezone.utc).isoformat()
        self._semaphore = asyncio.Semaphore(self.config.max_concurrency)

        # Filter URLs that actually have parameters
        scannable = [(u, extract_params(u)) for u in urls]
        scannable = [(u, p) for u, p in scannable if p]

        skipped = len(urls) - len(scannable)
        if skipped:
            logger.info("Skipped %d URLs without GET parameters.", skipped)

        total = len(scannable)
        completed = 0
        results: list[URLScanResult] = []

        # Add skipped results for URLs without parameters
        for u in urls:
            if not extract_params(u):
                results.append(URLScanResult(url=u, status=ScanStatus.SKIPPED))

        async def _scan_one(url: str, params: dict[str, str]) -> URLScanResult:
            nonlocal completed
            async with self._semaphore:  # type: ignore[union-attr]
                result = await self._scan_url(url, params)
                completed += 1
                if on_progress:
                    on_progress(completed, total, url)
                return result

        coros = [_scan_one(u, p) for u, p in scannable]
        scan_results = await asyncio.gather(*coros, return_exceptions=True)

        for sr in scan_results:
            if isinstance(sr, Exception):
                results.append(
                    URLScanResult(url="unknown", status=ScanStatus.ERROR,
                                  error=str(sr))
                )
            else:
                results.append(sr)

        finished = datetime.now(timezone.utc).isoformat()

        # Build report
        report = self._build_report(results, started, finished)
        return report

    async def scan_and_export(
        self,
        urls: list[str],
        on_progress: ProgressCallback = None,
    ) -> ScanReport:
        """Scan + export results to disk."""
        report = await self.scan(urls, on_progress)
        export_all(report, self.config.output_dir)
        return report

    # ------------------------------------------------------------------
    # Internal: per-URL scan
    # ------------------------------------------------------------------

    async def _scan_url(
        self, url: str, params: dict[str, str],
    ) -> URLScanResult:
        """Scan a single URL across all its parameters."""
        t0 = time.monotonic()
        result = URLScanResult(url=url)

        try:
            # 1. Fetch baseline
            baseline = await self._fetch(url)
            if baseline.error:
                result.status = ScanStatus.ERROR
                result.error = baseline.error
                result.scan_duration_ms = (time.monotonic() - t0) * 1000
                return result

            # 2. For each parameter, run probes
            for param_name, original_value in params.items():
                findings = await self._probe_parameter(
                    url, param_name, original_value, baseline,
                )
                result.findings.extend(findings)

        except Exception as exc:
            result.status = ScanStatus.ERROR
            result.error = str(exc)
            logger.debug("Error scanning %s: %s", url[:80], exc)

        if result.findings:
            result.status = ScanStatus.VULNERABLE

        result.scan_duration_ms = (time.monotonic() - t0) * 1000
        return result

    async def _probe_parameter(
        self,
        url: str,
        param_name: str,
        original_value: str,
        baseline: HTTPResponse,
    ) -> list[Finding]:
        """Run all probes for a single parameter."""
        findings: list[Finding] = []

        # --- SQLi probes ---
        if self.config.detect_sqli:
            sqli_url = _replace_param(url, param_name, _SQLI_PROBE)
            sqli_resp = await self._fetch(sqli_url)

            for det in self._detectors:
                if det.name.startswith("SQLi"):
                    findings.extend(
                        det.analyse(url, param_name, baseline, sqli_resp)
                    )

        # --- XSS probe ---
        if self.config.detect_xss:
            canary = generate_canary()
            xss_url = _replace_param(url, param_name, _build_xss_probe(canary))
            xss_resp = await self._fetch(xss_url)

            for det in self._detectors:
                if det.name.startswith("XSS"):
                    findings.extend(
                        det.analyse(url, param_name, baseline, xss_resp)
                    )

        return findings

    # ------------------------------------------------------------------
    # Proxy support
    # ------------------------------------------------------------------

    def _get_proxy(self) -> Optional[str]:
        """Get next proxy in rotation, or None if no proxies."""
        if not self._proxies:
            return None
        proxy = self._proxies[self._proxy_index % len(self._proxies)]
        self._proxy_index += 1
        if not proxy.startswith(("http://", "https://", "socks")):
            proxy = "http://" + proxy
        return proxy

    # ------------------------------------------------------------------
    # HTTP layer
    # ------------------------------------------------------------------

    async def _fetch(self, url: str) -> HTTPResponse:
        """Fetch a URL with rate limiting and timeout."""
        await self._rate_limiter.acquire()
        proxy = self._get_proxy()

        try:
            client_kwargs: dict = {
                "timeout": self.config.timeout_seconds,
                "follow_redirects": self.config.follow_redirects,
                "verify": self.config.verify_ssl,
                "headers": {"User-Agent": self.config.user_agent},
            }
            if proxy:
                client_kwargs["proxy"] = proxy

            async with httpx.AsyncClient(**client_kwargs) as client:
                t0 = time.monotonic()
                resp = await client.get(url)
                elapsed = (time.monotonic() - t0) * 1000

                return HTTPResponse(
                    status_code=resp.status_code,
                    headers=dict(resp.headers),
                    body=resp.text,
                    elapsed_ms=elapsed,
                    url=str(resp.url),
                )

        except httpx.TimeoutException:
            return HTTPResponse(
                status_code=0, headers={}, body="",
                elapsed_ms=self.config.timeout_seconds * 1000,
                url=url, error="Request timed out",
            )
        except Exception as exc:
            return HTTPResponse(
                status_code=0, headers={}, body="",
                elapsed_ms=0, url=url, error=str(exc),
            )

    # ------------------------------------------------------------------
    # Report assembly
    # ------------------------------------------------------------------

    def _build_report(
        self,
        results: list[URLScanResult],
        started: str,
        finished: str,
    ) -> ScanReport:
        """Aggregate URLScanResults into a ScanReport."""
        total_findings = sum(len(r.findings) for r in results)
        vuln_counts: dict[str, int] = {}
        for r in results:
            for f in r.findings:
                key = f.vuln_type.value
                vuln_counts[key] = vuln_counts.get(key, 0) + 1

        return ScanReport(
            results=results,
            total_urls=len(results),
            total_findings=total_findings,
            vuln_counts=vuln_counts,
            started_at=started,
            finished_at=finished,
            scan_config=self.config.to_dict(),
        )
