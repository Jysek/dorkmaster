"""
DorkMaster Scanner - Comprehensive Test Suite
================================================

Tests for the security scanning module (SQLi + XSS detection).
All tests are self-contained and use synthetic data -- NO network calls.
"""

import asyncio
import json
import os
import sys
import tempfile
import unittest
from pathlib import Path
from unittest.mock import AsyncMock, MagicMock, patch

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from scanner.models import (
    Confidence,
    Finding,
    ScanConfig,
    ScanReport,
    ScanStatus,
    URLScanResult,
    VulnType,
)
from scanner.detectors.base import BaseDetector, HTTPResponse
from scanner.detectors.sqli import SQLiDetector
from scanner.detectors.xss import XSSDetector, generate_canary
from scanner.detectors import get_all_detectors, get_detectors
from scanner.orchestrator import (
    ScanOrchestrator,
    extract_params,
    _replace_param,
    _RateLimiter,
)
from scanner.reporting.exporter import export_json, export_txt, export_csv, export_all


# ===========================================================================
# Model Tests
# ===========================================================================

class TestModels(unittest.TestCase):
    """Test data structures and enums."""

    def test_vuln_type_values(self):
        self.assertEqual(VulnType.SQLI.value, "SQLi")
        self.assertEqual(VulnType.XSS.value, "XSS")

    def test_confidence_ordering(self):
        levels = [Confidence.HIGH, Confidence.MEDIUM, Confidence.LOW, Confidence.INFO]
        self.assertEqual(len(levels), 4)

    def test_finding_to_dict(self):
        f = Finding(
            vuln_type=VulnType.SQLI,
            confidence=Confidence.HIGH,
            parameter="id",
            evidence="SQL error pattern detected",
            url="http://example.com?id=1",
            response_code=500,
            response_time_ms=123.456,
        )
        d = f.to_dict()
        self.assertEqual(d["vuln_type"], "SQLi")
        self.assertEqual(d["confidence"], "high")
        self.assertEqual(d["parameter"], "id")
        self.assertEqual(d["response_code"], 500)
        self.assertAlmostEqual(d["response_time_ms"], 123.46, places=1)

    def test_url_scan_result_clean(self):
        r = URLScanResult(url="http://example.com")
        self.assertEqual(r.status, ScanStatus.CLEAN)
        self.assertEqual(len(r.findings), 0)
        d = r.to_dict()
        self.assertEqual(d["status"], "clean")

    def test_url_scan_result_with_findings(self):
        f = Finding(
            vuln_type=VulnType.XSS,
            confidence=Confidence.MEDIUM,
            parameter="q",
            evidence="reflected",
            url="http://example.com?q=test",
        )
        r = URLScanResult(url="http://example.com?q=test", findings=[f])
        r.status = ScanStatus.VULNERABLE
        d = r.to_dict()
        self.assertEqual(d["status"], "vulnerable")
        self.assertEqual(len(d["findings"]), 1)

    def test_scan_report_to_dict(self):
        report = ScanReport(
            total_urls=10,
            total_findings=2,
            vuln_counts={"SQLi": 1, "XSS": 1},
            started_at="2026-01-01T00:00:00Z",
            finished_at="2026-01-01T00:01:00Z",
        )
        d = report.to_dict()
        self.assertIn("summary", d)
        self.assertIn("results", d)
        self.assertEqual(d["summary"]["total_urls"], 10)

    def test_scan_config_defaults(self):
        cfg = ScanConfig()
        self.assertEqual(cfg.max_concurrency, 20)
        self.assertEqual(cfg.timeout_seconds, 10.0)
        self.assertTrue(cfg.detect_sqli)
        self.assertTrue(cfg.detect_xss)

    def test_scan_config_to_dict(self):
        cfg = ScanConfig(max_concurrency=5, detect_xss=False)
        d = cfg.to_dict()
        self.assertEqual(d["max_concurrency"], 5)
        self.assertFalse(d["detect_xss"])


# ===========================================================================
# SQLi Detector Tests
# ===========================================================================

class TestSQLiDetector(unittest.TestCase):
    """Test SQL injection heuristic detection."""

    def setUp(self):
        self.detector = SQLiDetector()

    def test_name(self):
        self.assertIn("SQLi", self.detector.name)

    def _make_resp(self, body="", status=200, elapsed=100.0):
        return HTTPResponse(
            status_code=status, headers={}, body=body,
            elapsed_ms=elapsed, url="http://test.com",
        )

    # --- Error-based ---

    def test_mysql_error_detected(self):
        resp = self._make_resp(
            body='<html>You have an error in your SQL syntax near "1\'" at line 1</html>',
            status=500,
        )
        baseline = self._make_resp(body="<html>OK</html>")
        findings = self.detector.analyse("http://test.com?id=1", "id", baseline, resp)
        sqli = [f for f in findings if f.vuln_type == VulnType.SQLI and f.confidence == Confidence.HIGH]
        self.assertGreater(len(sqli), 0)
        self.assertIn("SQL error pattern", sqli[0].evidence)

    def test_postgres_error_detected(self):
        resp = self._make_resp(body="PostgreSQL ERROR: unterminated quoted string at or near")
        baseline = self._make_resp(body="<html>OK</html>")
        findings = self.detector.analyse("http://test.com?id=1", "id", baseline, resp)
        sqli = [f for f in findings if f.confidence == Confidence.HIGH]
        self.assertGreater(len(sqli), 0)

    def test_oracle_error_detected(self):
        resp = self._make_resp(body="ORA-01756: quoted string not properly terminated")
        baseline = self._make_resp(body="<html>OK</html>")
        findings = self.detector.analyse("http://test.com?id=1", "id", baseline, resp)
        sqli = [f for f in findings if f.confidence == Confidence.HIGH]
        self.assertGreater(len(sqli), 0)

    def test_mssql_error_detected(self):
        resp = self._make_resp(body="Microsoft OLE DB Provider for SQL Server error '80040e14'")
        baseline = self._make_resp(body="<html>OK</html>")
        findings = self.detector.analyse("http://test.com?id=1", "id", baseline, resp)
        sqli = [f for f in findings if f.confidence == Confidence.HIGH]
        self.assertGreater(len(sqli), 0)

    def test_sqlite_error_detected(self):
        resp = self._make_resp(body='sqlite3.OperationalError: near "": syntax error')
        baseline = self._make_resp(body="<html>OK</html>")
        findings = self.detector.analyse("http://test.com?id=1", "id", baseline, resp)
        sqli = [f for f in findings if f.confidence == Confidence.HIGH]
        self.assertGreater(len(sqli), 0)

    def test_java_sql_error_detected(self):
        resp = self._make_resp(body="java.sql.SQLException: Column 'id' not found")
        baseline = self._make_resp(body="<html>OK</html>")
        findings = self.detector.analyse("http://test.com?id=1", "id", baseline, resp)
        self.assertTrue(any(f.confidence == Confidence.HIGH for f in findings))

    def test_pdo_error_detected(self):
        resp = self._make_resp(body="PDOException: SQLSTATE[42000]")
        baseline = self._make_resp(body="<html>OK</html>")
        findings = self.detector.analyse("http://test.com?id=1", "id", baseline, resp)
        self.assertTrue(any(f.confidence == Confidence.HIGH for f in findings))

    def test_no_error_clean_response(self):
        resp = self._make_resp(body="<html>Welcome to our site</html>")
        baseline = self._make_resp(body="<html>Welcome to our site</html>")
        findings = self.detector.analyse("http://test.com?id=1", "id", baseline, resp)
        high = [f for f in findings if f.confidence == Confidence.HIGH]
        self.assertEqual(len(high), 0)

    # --- Boolean differential ---

    def test_boolean_diff_detected(self):
        baseline = self._make_resp(body="A" * 1000)
        probed = self._make_resp(body="A" * 500)  # 50% diff
        findings = self.detector.analyse("http://test.com?id=1", "id", baseline, probed)
        medium = [f for f in findings if f.confidence == Confidence.MEDIUM]
        self.assertGreater(len(medium), 0)
        self.assertIn("Response size changed", medium[0].evidence)

    def test_boolean_diff_not_triggered_small_change(self):
        baseline = self._make_resp(body="A" * 1000)
        probed = self._make_resp(body="A" * 950)  # 5% diff
        findings = self.detector.analyse("http://test.com?id=1", "id", baseline, probed)
        medium = [f for f in findings if f.confidence == Confidence.MEDIUM]
        self.assertEqual(len(medium), 0)

    # --- Timing anomaly ---

    def test_timing_anomaly_detected(self):
        baseline = self._make_resp(elapsed=500.0)
        probed = self._make_resp(elapsed=5000.0)  # 10x
        findings = self.detector.analyse("http://test.com?id=1", "id", baseline, probed)
        timing = [f for f in findings if f.confidence == Confidence.LOW and "time" in f.evidence.lower()]
        self.assertGreater(len(timing), 0)

    def test_timing_not_triggered_normal(self):
        baseline = self._make_resp(elapsed=100.0)
        probed = self._make_resp(elapsed=200.0)  # 2x but under 2000ms
        findings = self.detector.analyse("http://test.com?id=1", "id", baseline, probed)
        timing = [f for f in findings if "time" in (f.evidence or "").lower()]
        self.assertEqual(len(timing), 0)

    def test_empty_body(self):
        baseline = self._make_resp(body="")
        probed = self._make_resp(body="")
        findings = self.detector.analyse("http://test.com?id=1", "id", baseline, probed)
        high = [f for f in findings if f.confidence == Confidence.HIGH]
        self.assertEqual(len(high), 0)


# ===========================================================================
# XSS Detector Tests
# ===========================================================================

class TestXSSDetector(unittest.TestCase):
    """Test XSS heuristic detection."""

    def setUp(self):
        self.detector = XSSDetector()

    def test_name(self):
        self.assertIn("XSS", self.detector.name)

    def _make_resp(self, body="", headers=None, url="http://test.com"):
        return HTTPResponse(
            status_code=200,
            headers=headers or {},
            body=body,
            elapsed_ms=50.0,
            url=url,
        )

    # --- Canary generation ---

    def test_canary_format(self):
        canary = generate_canary()
        self.assertTrue(canary.startswith("dmxss"))
        self.assertEqual(len(canary), 13)
        self.assertTrue(canary[5:].isalnum())

    def test_canary_uniqueness(self):
        canaries = {generate_canary() for _ in range(100)}
        self.assertEqual(len(canaries), 100)

    # --- Reflection in <script> ---

    def test_reflection_in_script(self):
        canary = "dmxss12345678"
        body = f'<html><script>var x = "{canary}";</script></html>'
        resp = self._make_resp(body=body, url=f"http://test.com?q={canary}")
        baseline = self._make_resp(headers={"Content-Security-Policy": "default-src 'self'",
                                            "X-Content-Type-Options": "nosniff",
                                            "X-XSS-Protection": "1; mode=block"})
        findings = self.detector.analyse("http://test.com?q=test", "q", baseline, resp)
        xss = [f for f in findings if f.vuln_type == VulnType.XSS and f.confidence == Confidence.HIGH]
        self.assertGreater(len(xss), 0)
        self.assertIn("script", xss[0].evidence.lower())

    # --- Reflection in attribute ---

    def test_reflection_in_attribute(self):
        canary = "dmxssabcdef12"
        body = f'<html><input value="{canary}"></html>'
        resp = self._make_resp(body=body, url=f"http://test.com?q={canary}")
        baseline = self._make_resp(headers={"Content-Security-Policy": "default-src 'self'",
                                            "X-Content-Type-Options": "nosniff",
                                            "X-XSS-Protection": "1; mode=block"})
        findings = self.detector.analyse("http://test.com?q=test", "q", baseline, resp)
        xss = [f for f in findings if f.vuln_type == VulnType.XSS and f.confidence == Confidence.HIGH]
        self.assertGreater(len(xss), 0)

    # --- Reflection in body ---

    def test_reflection_in_body(self):
        canary = "dmxss99887766"
        body = f'<html><body><p>You searched for: {canary}</p></body></html>'
        resp = self._make_resp(body=body, url=f"http://test.com?q={canary}")
        baseline = self._make_resp(headers={"Content-Security-Policy": "default-src 'self'",
                                            "X-Content-Type-Options": "nosniff",
                                            "X-XSS-Protection": "1; mode=block"})
        findings = self.detector.analyse("http://test.com?q=test", "q", baseline, resp)
        xss = [f for f in findings if f.vuln_type == VulnType.XSS]
        self.assertGreater(len(xss), 0)

    # --- No reflection ---

    def test_no_reflection_clean(self):
        resp = self._make_resp(
            body="<html><body>Safe page content</body></html>",
            url="http://test.com?q=dmxss00000000",
            headers={"Content-Security-Policy": "default-src 'self'",
                     "X-Content-Type-Options": "nosniff",
                     "X-XSS-Protection": "1; mode=block"},
        )
        baseline = self._make_resp(headers={"Content-Security-Policy": "default-src 'self'",
                                            "X-Content-Type-Options": "nosniff",
                                            "X-XSS-Protection": "1; mode=block"})
        findings = self.detector.analyse("http://test.com?q=test", "q", baseline, resp)
        reflection = [f for f in findings if "reflect" in (f.evidence or "").lower()]
        self.assertEqual(len(reflection), 0)

    # --- Missing headers ---

    def test_missing_security_headers(self):
        resp = self._make_resp(url="http://test.com?q=test")
        baseline = self._make_resp(headers={})  # No security headers
        findings = self.detector.analyse("http://test.com?q=test", "q", baseline, resp)
        info = [f for f in findings if f.confidence == Confidence.INFO]
        self.assertGreater(len(info), 0)
        self.assertIn("Missing security headers", info[0].evidence)

    def test_all_security_headers_present(self):
        headers = {
            "Content-Security-Policy": "default-src 'self'",
            "X-Content-Type-Options": "nosniff",
            "X-XSS-Protection": "1; mode=block",
        }
        resp = self._make_resp(url="http://test.com?q=test")
        baseline = self._make_resp(headers=headers)
        findings = self.detector.analyse("http://test.com?q=test", "q", baseline, resp)
        info = [f for f in findings if f.confidence == Confidence.INFO]
        self.assertEqual(len(info), 0)


# ===========================================================================
# Detector Registry Tests
# ===========================================================================

class TestDetectorRegistry(unittest.TestCase):

    def test_get_all_detectors(self):
        dets = get_all_detectors()
        self.assertEqual(len(dets), 2)
        names = [d.name for d in dets]
        self.assertTrue(any("SQLi" in n for n in names))
        self.assertTrue(any("XSS" in n for n in names))

    def test_get_detectors_sqli_only(self):
        dets = get_detectors(sqli=True, xss=False)
        self.assertEqual(len(dets), 1)
        self.assertIn("SQLi", dets[0].name)

    def test_get_detectors_xss_only(self):
        dets = get_detectors(sqli=False, xss=True)
        self.assertEqual(len(dets), 1)
        self.assertIn("XSS", dets[0].name)

    def test_get_detectors_none(self):
        dets = get_detectors(sqli=False, xss=False)
        self.assertEqual(len(dets), 0)


# ===========================================================================
# Orchestrator Utility Tests
# ===========================================================================

class TestOrchestratorUtils(unittest.TestCase):
    """Test URL parsing and manipulation."""

    def test_extract_params_basic(self):
        params = extract_params("http://example.com/page?id=1&name=test")
        self.assertEqual(params["id"], "1")
        self.assertEqual(params["name"], "test")

    def test_extract_params_empty_query(self):
        params = extract_params("http://example.com/page")
        self.assertEqual(params, {})

    def test_extract_params_blank_value(self):
        params = extract_params("http://example.com/page?key=")
        self.assertIn("key", params)
        self.assertEqual(params["key"], "")

    def test_extract_params_encoded(self):
        params = extract_params("http://example.com?q=hello%20world")
        self.assertEqual(params["q"], "hello world")

    def test_replace_param(self):
        url = _replace_param("http://example.com?id=1&name=test", "id", "REPLACED")
        self.assertIn("id=REPLACED", url)
        self.assertIn("name=test", url)

    def test_replace_param_preserves_others(self):
        url = _replace_param("http://example.com?a=1&b=2&c=3", "b", "NEW")
        self.assertIn("a=1", url)
        self.assertIn("b=NEW", url)
        self.assertIn("c=3", url)


# ===========================================================================
# Rate Limiter Tests
# ===========================================================================

class TestRateLimiter(unittest.TestCase):

    def test_unlimited(self):
        """RPS=0 means no limiting."""
        limiter = _RateLimiter(0)
        # Should complete instantly
        asyncio.run(limiter.acquire())

    def test_rate_limiting_enforced(self):
        """Basic test that limiter introduces delay."""
        import time
        limiter = _RateLimiter(100)  # 100 rps = 10ms interval

        async def _run():
            t0 = time.monotonic()
            for _ in range(5):
                await limiter.acquire()
            return (time.monotonic() - t0) * 1000

        elapsed = asyncio.run(_run())
        # 5 acquisitions at 100rps => ~40ms minimum (first is instant)
        self.assertGreater(elapsed, 20)


# ===========================================================================
# Orchestrator Integration Tests (mocked HTTP)
# ===========================================================================

class TestScanOrchestrator(unittest.TestCase):
    """Test the orchestrator with mocked HTTP responses."""

    def _make_orchestrator(self, **kwargs):
        config = ScanConfig(
            max_concurrency=5,
            timeout_seconds=5.0,
            rate_limit_rps=0,  # no limit for tests
            **kwargs,
        )
        return ScanOrchestrator(config)

    def test_skip_urls_without_params(self):
        orch = self._make_orchestrator()

        async def _run():
            # Mock _fetch to avoid real HTTP
            async def mock_fetch(url):
                return HTTPResponse(200, {}, "<html>OK</html>", 50.0, url)
            orch._fetch = mock_fetch
            report = await orch.scan(["http://example.com/no-params"])
            return report

        report = asyncio.run(_run())
        self.assertEqual(report.total_urls, 1)
        skipped = [r for r in report.results if r.status == ScanStatus.SKIPPED]
        self.assertEqual(len(skipped), 1)

    def test_scan_detects_sqli_error(self):
        orch = self._make_orchestrator(detect_xss=False)

        async def mock_fetch(url):
            if "'" in url or "1'" in url:
                return HTTPResponse(
                    500, {},
                    'You have an error in your SQL syntax near "1\'"',
                    100.0, url,
                )
            return HTTPResponse(200, {}, "<html>OK</html>", 50.0, url)

        async def _run():
            orch._fetch = mock_fetch
            report = await orch.scan(["http://example.com/page?id=1"])
            return report

        report = asyncio.run(_run())
        vuln = [r for r in report.results if r.status == ScanStatus.VULNERABLE]
        self.assertGreater(len(vuln), 0)
        self.assertIn("SQLi", report.vuln_counts)

    def test_scan_detects_xss_reflection(self):
        orch = self._make_orchestrator(detect_sqli=False)

        async def mock_fetch(url):
            if "dmxss" in url:
                # Reflect the canary back
                from urllib.parse import parse_qs, urlparse
                qs = parse_qs(urlparse(url).query)
                val = qs.get("q", [""])[0]
                return HTTPResponse(
                    200, {},
                    f'<html><p>Search: {val}</p></html>',
                    50.0, url,
                )
            return HTTPResponse(200, {}, "<html>OK</html>", 50.0, url)

        async def _run():
            orch._fetch = mock_fetch
            report = await orch.scan(["http://example.com/search?q=test"])
            return report

        report = asyncio.run(_run())
        vuln = [r for r in report.results if r.status == ScanStatus.VULNERABLE]
        self.assertGreater(len(vuln), 0)

    def test_scan_handles_timeout(self):
        orch = self._make_orchestrator()

        async def mock_fetch(url):
            return HTTPResponse(
                0, {}, "", 10000.0, url, error="Request timed out",
            )

        async def _run():
            orch._fetch = mock_fetch
            report = await orch.scan(["http://example.com?id=1"])
            return report

        report = asyncio.run(_run())
        errors = [r for r in report.results if r.status == ScanStatus.ERROR]
        self.assertGreater(len(errors), 0)

    def test_progress_callback(self):
        orch = self._make_orchestrator(detect_sqli=False, detect_xss=False)
        progress_calls = []

        async def mock_fetch(url):
            return HTTPResponse(200, {}, "<html>OK</html>", 50.0, url)

        async def _run():
            orch._fetch = mock_fetch
            orch._detectors = []  # no detectors
            def on_progress(current, total, url):
                progress_calls.append((current, total))
            report = await orch.scan(
                ["http://a.com?x=1", "http://b.com?y=2"],
                on_progress=on_progress,
            )
            return report

        asyncio.run(_run())
        self.assertGreater(len(progress_calls), 0)
        self.assertEqual(progress_calls[-1][0], progress_calls[-1][1])

    def test_multiple_params_scanned(self):
        orch = self._make_orchestrator(detect_xss=False)
        fetched_urls = []

        async def mock_fetch(url):
            fetched_urls.append(url)
            return HTTPResponse(200, {}, "<html>OK</html>", 50.0, url)

        async def _run():
            orch._fetch = mock_fetch
            report = await orch.scan(["http://example.com?a=1&b=2&c=3"])
            return report

        asyncio.run(_run())
        # Baseline + 1 probe per param (SQLi only) = 4 fetches
        self.assertGreaterEqual(len(fetched_urls), 4)


# ===========================================================================
# Reporting Tests
# ===========================================================================

class TestReporting(unittest.TestCase):
    """Test report exporters."""

    def _make_report(self):
        f = Finding(
            vuln_type=VulnType.SQLI,
            confidence=Confidence.HIGH,
            parameter="id",
            evidence="SQL error pattern detected",
            url="http://example.com?id=1",
            response_code=500,
            response_time_ms=123.0,
        )
        r = URLScanResult(
            url="http://example.com?id=1",
            status=ScanStatus.VULNERABLE,
            findings=[f],
        )
        return ScanReport(
            results=[r],
            total_urls=1,
            total_findings=1,
            vuln_counts={"SQLi": 1},
            started_at="2026-01-01T00:00:00Z",
            finished_at="2026-01-01T00:01:00Z",
            scan_config={"max_concurrency": 20},
        )

    def test_export_json(self):
        with tempfile.TemporaryDirectory() as td:
            path = Path(td) / "report.json"
            export_json(self._make_report(), path)
            self.assertTrue(path.exists())
            data = json.loads(path.read_text())
            self.assertEqual(data["summary"]["total_findings"], 1)
            self.assertEqual(len(data["results"]), 1)

    def test_export_txt(self):
        with tempfile.TemporaryDirectory() as td:
            path = Path(td) / "report.txt"
            export_txt(self._make_report(), path)
            self.assertTrue(path.exists())
            content = path.read_text()
            self.assertIn("SECURITY SCAN REPORT", content)
            self.assertIn("SQLi", content)

    def test_export_csv(self):
        with tempfile.TemporaryDirectory() as td:
            path = Path(td) / "report.csv"
            export_csv(self._make_report(), path)
            self.assertTrue(path.exists())
            content = path.read_text()
            self.assertIn("vuln_type", content)
            self.assertIn("SQLi", content)

    def test_export_all(self):
        with tempfile.TemporaryDirectory() as td:
            paths = export_all(self._make_report(), td)
            self.assertIn("json", paths)
            self.assertIn("txt", paths)
            self.assertIn("csv", paths)
            for p in paths.values():
                self.assertTrue(p.exists())


# ===========================================================================
# CLI Integration Smoke Test
# ===========================================================================

class TestCLIIntegration(unittest.TestCase):
    """Smoke-test that the CLI module imports without errors."""

    def test_cli_import(self):
        import cli
        self.assertTrue(hasattr(cli, 'main'))
        self.assertTrue(hasattr(cli, '_run_scan'))

    def test_scanner_module_import(self):
        import scanner
        self.assertEqual(scanner.__module_name__, "DorkMaster Scanner")


if __name__ == "__main__":
    unittest.main()
