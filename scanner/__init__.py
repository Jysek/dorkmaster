"""
DorkMaster Scanner -- Security Detection Module
=================================================

Safe, detection-based vulnerability scanner for SQLi and XSS.
Designed for scanning assets you own. Uses heuristic response
analysis -- NO exploit payloads, NO invasive techniques.

Architecture:
    scanner/
    +-- __init__.py          # Package exports & version
    +-- models.py            # Data structures (ScanResult, ScanConfig, enums)
    +-- orchestrator.py      # Async scan pipeline with concurrency control
    +-- detectors/
    |   +-- __init__.py      # Detector registry
    |   +-- base.py          # Abstract detector interface
    |   +-- sqli.py          # SQL Injection heuristic detector
    |   +-- xss.py           # Cross-Site Scripting heuristic detector
    +-- reporting/
        +-- __init__.py
        +-- exporter.py      # JSON / TXT / CSV scan report export
"""

__version__ = "2.0.0"
__module_name__ = "DorkMaster Scanner"
