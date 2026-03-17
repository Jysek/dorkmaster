"""Detector registry -- collects all enabled detectors."""

from __future__ import annotations

from scanner.detectors.base import BaseDetector
from scanner.detectors.sqli import SQLiDetector
from scanner.detectors.xss import XSSDetector


def get_all_detectors() -> list[BaseDetector]:
    """Return one instance of every available detector."""
    return [SQLiDetector(), XSSDetector()]


def get_detectors(sqli: bool = True, xss: bool = True) -> list[BaseDetector]:
    """Return detectors based on feature toggles."""
    detectors: list[BaseDetector] = []
    if sqli:
        detectors.append(SQLiDetector())
    if xss:
        detectors.append(XSSDetector())
    return detectors
