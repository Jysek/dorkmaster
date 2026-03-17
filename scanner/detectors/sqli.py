"""
SQL Injection Heuristic Detector
==================================

Detection strategy (SAFE / non-invasive):

1. **Error-based detection**
   Inject a *syntactically benign* token (single-quote character) and look
   for well-known SQL error strings in the response body.  The single-quote
   is NOT an exploit -- it merely tests whether the application echoes a
   database error instead of handling the input safely.

2. **Boolean-differential detection**
   Send two semantically-opposite tautologies ("1 AND 1=1" vs "1 AND 1=2")
   and compare response lengths.  A significant divergence suggests the
   parameter is interpolated into a SQL predicate.

3. **Timing anomaly detection**
   Compare the probed response time against the baseline.  A large,
   *unexpected* increase may indicate back-end query changes.  This is
   advisory only (confidence = info/low).

All tokens are deliberately minimal and widely used in authorised
penetration-testing frameworks.  NO destructive payloads, UNION selects,
stacked queries, or data-exfiltration strings are used.
"""

from __future__ import annotations

import re

from scanner.detectors.base import BaseDetector, HTTPResponse
from scanner.models import Confidence, Finding, VulnType

# ---------------------------------------------------------------------------
# SQL error patterns (database-agnostic)
# ---------------------------------------------------------------------------
# These are *error strings* that a properly-configured application should
# never expose to end-users.  Matching any of them in the response body is
# evidence that raw SQL errors leak to the client.

_SQL_ERROR_PATTERNS: list[re.Pattern[str]] = [
    # Generic SQL / ODBC
    re.compile(r"you have an error in your sql syntax", re.I),
    re.compile(r"unclosed quotation mark after the character string", re.I),
    re.compile(r"quoted string not properly terminated", re.I),
    re.compile(r"sql syntax.*?error", re.I),
    re.compile(r"syntax error.*?sql", re.I),

    # MySQL
    re.compile(r"mysql_fetch|mysql_num_rows|mysql_query", re.I),
    re.compile(r"Warning.*?\bmysqli?\b", re.I),
    re.compile(r"MySqlException", re.I),

    # PostgreSQL
    re.compile(r"pg_query|pg_exec|pg_connect", re.I),
    re.compile(r"PostgreSQL.*?ERROR", re.I),
    re.compile(r"unterminated quoted string at or near", re.I),

    # Microsoft SQL Server
    re.compile(r"Microsoft OLE DB Provider for SQL Server", re.I),
    re.compile(r"\bODBC SQL Server Driver\b", re.I),
    re.compile(r"SqlException", re.I),
    re.compile(r"Unclosed quotation mark", re.I),

    # Oracle
    re.compile(r"ORA-\d{4,5}", re.I),
    re.compile(r"Oracle.*?Driver", re.I),
    re.compile(r"quoted string not properly terminated", re.I),

    # SQLite
    re.compile(r"SQLite3?::query", re.I),
    re.compile(r"sqlite3\.OperationalError", re.I),
    re.compile(r"near \".*?\": syntax error", re.I),

    # Generic JDBC / server errors
    re.compile(r"java\.sql\.SQLException", re.I),
    re.compile(r"JDBC.*?Exception", re.I),
    re.compile(r"PDOException", re.I),
    re.compile(r"System\.Data\.SqlClient", re.I),
]

# Threshold: if response size differs by more than this %, boolean diff
# detection is triggered.
_BOOLEAN_DIFF_THRESHOLD_PCT = 15.0

# Timing: if probed request takes >N times the baseline, flag timing anomaly.
_TIMING_FACTOR = 3.0


class SQLiDetector(BaseDetector):
    """Heuristic SQL injection detector (safe, detection-only)."""

    @property
    def name(self) -> str:
        return "SQLi Heuristic Detector"

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    def analyse(
        self,
        original_url: str,
        param_name: str,
        baseline: HTTPResponse,
        probed: HTTPResponse,
    ) -> list[Finding]:
        findings: list[Finding] = []

        # 1. Error-based: look for SQL errors in probed response
        findings.extend(
            self._check_error_patterns(original_url, param_name, probed)
        )

        # 2. Boolean differential: compare body lengths
        findings.extend(
            self._check_boolean_diff(original_url, param_name, baseline, probed)
        )

        # 3. Timing anomaly
        findings.extend(
            self._check_timing(original_url, param_name, baseline, probed)
        )

        return findings

    # ------------------------------------------------------------------
    # Detection helpers
    # ------------------------------------------------------------------

    def _check_error_patterns(
        self, url: str, param: str, resp: HTTPResponse,
    ) -> list[Finding]:
        """Scan response body for SQL error strings."""
        if not resp.body:
            return []

        for pattern in _SQL_ERROR_PATTERNS:
            match = pattern.search(resp.body)
            if match:
                return [
                    Finding(
                        vuln_type=VulnType.SQLI,
                        confidence=Confidence.HIGH,
                        parameter=param,
                        evidence=(
                            f"SQL error pattern detected in response: "
                            f"'{match.group(0)[:80]}'"
                        ),
                        url=url,
                        response_code=resp.status_code,
                        response_time_ms=resp.elapsed_ms,
                    )
                ]
        return []

    def _check_boolean_diff(
        self,
        url: str,
        param: str,
        baseline: HTTPResponse,
        probed: HTTPResponse,
    ) -> list[Finding]:
        """Detect significant response-size divergence."""
        base_len = len(baseline.body) if baseline.body else 0
        probe_len = len(probed.body) if probed.body else 0

        if base_len == 0:
            return []

        diff_pct = abs(probe_len - base_len) / base_len * 100

        if diff_pct > _BOOLEAN_DIFF_THRESHOLD_PCT:
            # Could be normal behaviour -- use MEDIUM confidence
            return [
                Finding(
                    vuln_type=VulnType.SQLI,
                    confidence=Confidence.MEDIUM,
                    parameter=param,
                    evidence=(
                        f"Response size changed by {diff_pct:.1f}% "
                        f"(baseline={base_len}, probed={probe_len}) -- "
                        f"parameter may influence SQL query"
                    ),
                    url=url,
                    response_code=probed.status_code,
                    response_time_ms=probed.elapsed_ms,
                )
            ]
        return []

    def _check_timing(
        self,
        url: str,
        param: str,
        baseline: HTTPResponse,
        probed: HTTPResponse,
    ) -> list[Finding]:
        """Flag large timing increases as potential indicators."""
        if baseline.elapsed_ms <= 0:
            return []

        factor = probed.elapsed_ms / baseline.elapsed_ms

        if factor >= _TIMING_FACTOR and probed.elapsed_ms > 2000:
            return [
                Finding(
                    vuln_type=VulnType.SQLI,
                    confidence=Confidence.LOW,
                    parameter=param,
                    evidence=(
                        f"Response time anomaly: {probed.elapsed_ms:.0f}ms "
                        f"vs baseline {baseline.elapsed_ms:.0f}ms "
                        f"(factor={factor:.1f}x)"
                    ),
                    url=url,
                    response_code=probed.status_code,
                    response_time_ms=probed.elapsed_ms,
                )
            ]
        return []
