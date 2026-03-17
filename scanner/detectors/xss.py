"""
Cross-Site Scripting (XSS) Heuristic Detector
================================================

Detection strategy (SAFE / non-invasive):

1. **Reflection detection**
   Inject a unique *harmless* canary string (alphanumeric, no HTML/JS) into
   the parameter and check whether it appears verbatim in the response body.
   If reflected, the application does not sanitise/encode user input.

2. **Context analysis**
   When a reflection is found, determine *where* the canary lands:
     - Inside an HTML tag attribute (href, src, value, etc.)
     - Inside a <script> block
     - Inside raw HTML body text
   The context determines confidence: reflection inside <script> or an
   event-handler attribute is HIGH; inside regular text is LOW.

3. **Header analysis**
   Check for missing security headers that would mitigate XSS:
     - Content-Security-Policy
     - X-Content-Type-Options
     - X-XSS-Protection (legacy but still informative)
   Missing headers raise an INFO-level finding.

All tokens are deliberately harmless.  NO executable JavaScript, NO
event handlers, NO encoded bypasses are injected.
"""

from __future__ import annotations

import re
import uuid

from scanner.detectors.base import BaseDetector, HTTPResponse
from scanner.models import Confidence, Finding, VulnType


# ---------------------------------------------------------------------------
# Safe canary generator
# ---------------------------------------------------------------------------

def _generate_canary() -> str:
    """Return a unique alphanumeric canary that cannot execute code.

    Format: ``dmxss<8-hex-chars>``  (always 13 chars, no special chars).
    """
    return "dmxss" + uuid.uuid4().hex[:8]


# ---------------------------------------------------------------------------
# Context patterns (where the canary appears in the response)
# ---------------------------------------------------------------------------

# Inside a <script> block
_IN_SCRIPT_RE = re.compile(
    r"<script[^>]*>[^<]*?{canary}[^<]*?</script>", re.I | re.S,
)

# Inside an HTML attribute (value="...", href="...", src="...", on*="...")
_IN_ATTR_RE = re.compile(
    r"""(?:value|href|src|action|data|style|on\w+)\s*=\s*["'][^"']*?{canary}""",
    re.I,
)

# Inside a raw HTML tag body (e.g. <div>...canary...</div>)
_IN_BODY_RE = re.compile(
    r">[^<]*?{canary}[^<]*?<", re.I | re.S,
)

# Security headers we check
_SECURITY_HEADERS = {
    "content-security-policy": "Content-Security-Policy",
    "x-content-type-options": "X-Content-Type-Options",
    "x-xss-protection": "X-XSS-Protection",
}


class XSSDetector(BaseDetector):
    """Heuristic XSS detector (safe, detection-only)."""

    @property
    def name(self) -> str:
        return "XSS Heuristic Detector"

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

        # 1. Reflection detection + context analysis
        findings.extend(
            self._check_reflection(original_url, param_name, probed)
        )

        # 2. Security header analysis (once per URL, on baseline)
        findings.extend(
            self._check_headers(original_url, param_name, baseline)
        )

        return findings

    # ------------------------------------------------------------------
    # Detection helpers
    # ------------------------------------------------------------------

    def _check_reflection(
        self, url: str, param: str, resp: HTTPResponse,
    ) -> list[Finding]:
        """Check whether the canary is reflected and in which context."""
        if not resp.body:
            return []

        # The orchestrator embeds the canary into the parameter value.
        # We extract it from the probed URL to know what to search for.
        canary = self._extract_canary(resp.url, param)
        if not canary:
            # Fallback: look for any dmxss canary pattern
            canary_match = re.search(r"dmxss[0-9a-f]{8}", resp.body)
            if canary_match:
                canary = canary_match.group(0)
            else:
                return []

        if canary not in resp.body:
            return []

        # Canary IS reflected -- determine context
        context, confidence = self._determine_context(resp.body, canary)

        return [
            Finding(
                vuln_type=VulnType.XSS,
                confidence=confidence,
                parameter=param,
                evidence=(
                    f"Input reflected in response ({context}). "
                    f"Parameter value appears unencoded in the HTML output."
                ),
                url=url,
                response_code=resp.status_code,
                response_time_ms=resp.elapsed_ms,
            )
        ]

    def _check_headers(
        self, url: str, param: str, resp: HTTPResponse,
    ) -> list[Finding]:
        """Flag missing XSS-mitigation headers."""
        if resp.headers is None:
            return []

        lower_headers = {k.lower(): v for k, v in resp.headers.items()}
        missing = []

        for hdr_lower, hdr_display in _SECURITY_HEADERS.items():
            if hdr_lower not in lower_headers:
                missing.append(hdr_display)

        if missing:
            return [
                Finding(
                    vuln_type=VulnType.XSS,
                    confidence=Confidence.INFO,
                    parameter=param,
                    evidence=(
                        f"Missing security headers: {', '.join(missing)}. "
                        f"These headers help mitigate XSS attacks."
                    ),
                    url=url,
                    response_code=resp.status_code,
                    response_time_ms=resp.elapsed_ms,
                )
            ]
        return []

    # ------------------------------------------------------------------
    # Helpers
    # ------------------------------------------------------------------

    @staticmethod
    def _extract_canary(probed_url: str, param: str) -> str | None:
        """Extract the canary value from the probed URL's query string."""
        from urllib.parse import parse_qs, urlparse

        try:
            qs = parse_qs(urlparse(probed_url).query)
            values = qs.get(param, [])
            for v in values:
                match = re.search(r"dmxss[0-9a-f]{8}", v)
                if match:
                    return match.group(0)
        except Exception:
            pass
        return None

    @staticmethod
    def _determine_context(body: str, canary: str) -> tuple[str, Confidence]:
        """Classify the reflection context and assign confidence."""
        # Check script context (highest risk)
        pattern = _IN_SCRIPT_RE.pattern.replace("{canary}", re.escape(canary))
        if re.search(pattern, body, re.I | re.S):
            return "inside <script> block", Confidence.HIGH

        # Check attribute context
        pattern = _IN_ATTR_RE.pattern.replace("{canary}", re.escape(canary))
        if re.search(pattern, body, re.I):
            return "inside HTML attribute", Confidence.HIGH

        # Check body context
        pattern = _IN_BODY_RE.pattern.replace("{canary}", re.escape(canary))
        if re.search(pattern, body, re.I | re.S):
            return "inside HTML body", Confidence.MEDIUM

        # Generic reflection (unclassified context)
        return "reflected in response", Confidence.LOW


# Module-level canary generator for the orchestrator
generate_canary = _generate_canary
