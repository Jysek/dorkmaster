"""
Abstract base class for all vulnerability detectors.

Every detector receives:
  - the original URL
  - the HTTP response (status, headers, body)
  - the parameter under test

And returns a list of Finding objects.
"""

from __future__ import annotations

import abc
from dataclasses import dataclass
from typing import Optional

from scanner.models import Finding


@dataclass
class HTTPResponse:
    """Lightweight wrapper for the data a detector needs."""

    status_code: int
    headers: dict[str, str]
    body: str
    elapsed_ms: float
    url: str                  # final URL (after redirects)
    error: Optional[str] = None


class BaseDetector(abc.ABC):
    """Interface every detector must implement."""

    @property
    @abc.abstractmethod
    def name(self) -> str:
        """Human-readable detector name."""
        ...

    @abc.abstractmethod
    def analyse(
        self,
        original_url: str,
        param_name: str,
        baseline: HTTPResponse,
        probed: HTTPResponse,
    ) -> list[Finding]:
        """Compare baseline vs probed response and return findings.

        Args:
            original_url:  The URL with its original query string.
            param_name:    The GET parameter being tested.
            baseline:      Response to the *unmodified* original request.
            probed:        Response after injecting a **safe** detection token.

        Returns:
            List of Finding objects (empty = nothing detected).
        """
        ...
