"""
DorkMaster Web - API Routes
===============================

Handles JSON API endpoints for:
  - Generator: dork generation, counting, export, vuln_params
  - Hunter: search with real-time streaming (SSE), API+free+proxy modes
  - Scanner: security scan for SQLi/XSS with optional proxy
  - Settings: API keys, proxies, configuration
"""

import asyncio
import csv
import io
import json
import time

import httpx
from flask import Blueprint, Response, jsonify, request, stream_with_context

from core.engine import DorkConfig, DorkGenerator
from hunter.config import (
    HunterConfig,
    get_hunter_config,
    save_settings,
    get_current_settings,
    FREE_ENGINES,
    API_ENGINES,
    FREE_ENGINE_INFO,
    _load_persisted_settings,
)
from hunter.search.free_engine import FreeSearchEngine, AVAILABLE_ENGINES
from hunter.search.engine import SearchEngine
from hunter.search.key_manager import KeyManager, KeyExhaustedError
from scanner.models import ScanConfig, ScanStatus
from scanner.orchestrator import ScanOrchestrator

api_bp = Blueprint("api", __name__, url_prefix="/api")

# Lazy-initialized shared instances
_config: DorkConfig | None = None
_generator: DorkGenerator | None = None


def _get_config() -> DorkConfig:
    global _config
    if _config is None:
        _config = DorkConfig.get_instance()
    return _config


def _get_generator() -> DorkGenerator:
    global _generator
    if _generator is None:
        _generator = DorkGenerator(_get_config())
    return _generator


# ================================================================
# Generator API
# ================================================================

@api_bp.route("/config")
def get_config():
    """Return the current configuration for the frontend."""
    config = _get_config()
    engines = {}
    for eid in config.get_all_engine_ids():
        eng = config.get_engine(eid)
        if eng is None:
            continue
        engines[eid] = {
            "name": eng["name"],
            "operators": eng["operators"],
            "filetypes": eng.get("filetype_list", []),
            "boolean_operators": eng.get("boolean_operators", {}),
        }
    return jsonify({
        "engines": engines,
        "default_keywords": config.default_keywords,
        "rules": config.generation_rules,
        "vuln_params": config.vuln_params,
    })


@api_bp.route("/count", methods=["POST"])
def count():
    """Return estimated total combinations without generating dorks."""
    data = request.get_json(silent=True)
    if not data:
        return jsonify({"error": "No JSON data provided.", "count": 0}), 400

    keywords = data.get("keywords", [])
    if isinstance(keywords, str):
        keywords = [k.strip() for k in keywords.split("\n") if k.strip()]

    generator = _get_generator()
    total = generator.count_combinations(
        engine_id=data.get("engine", "google"),
        keywords=keywords,
        selected_operators=data.get("operators", []),
        selected_filetypes=data.get("filetypes", []),
        custom_site=data.get("site", ""),
        include_exclusions=data.get("exclusions", []),
    )
    return jsonify({"count": total})


@api_bp.route("/generate", methods=["POST"])
def generate():
    """Generate dork queries from user input."""
    data = request.get_json(silent=True)
    if not data:
        return jsonify({"error": "No JSON data provided."}), 400

    engine_id = data.get("engine", "google")
    keywords = data.get("keywords", [])
    selected_operators = data.get("operators", [])
    selected_filetypes = data.get("filetypes", [])
    custom_site = data.get("site", "")
    use_quotes = data.get("use_quotes", False)
    exclusions = data.get("exclusions", [])
    vuln_params = data.get("vuln_params", [])

    try:
        max_results = int(data.get("max_results", 100))
        if max_results < 0:
            max_results = 0
    except (ValueError, TypeError):
        max_results = 100

    if isinstance(keywords, str):
        keywords = [k.strip() for k in keywords.split("\n") if k.strip()]
    if isinstance(exclusions, str):
        exclusions = [e.strip() for e in exclusions.split("\n") if e.strip()]
    if isinstance(vuln_params, str):
        vuln_params = [v.strip() for v in vuln_params.split("\n") if v.strip()]

    generator = _get_generator()
    result = generator.generate(
        engine_id=engine_id,
        keywords=keywords,
        selected_operators=selected_operators,
        selected_filetypes=selected_filetypes,
        custom_site=custom_site,
        use_quotes=use_quotes,
        include_exclusions=exclusions,
        max_results=max_results,
        shuffle=True,
        selected_vuln_params=vuln_params,
    )
    return jsonify(result)


@api_bp.route("/export", methods=["POST"])
def export():
    """Export dorks in TXT, CSV, or JSON format."""
    data = request.get_json(silent=True)
    if not data:
        return jsonify({"error": "No JSON data provided."}), 400

    dorks = data.get("dorks", [])
    fmt = data.get("format", "txt")
    engine_name = data.get("engine_name", "DorkMaster")

    if not dorks:
        return jsonify({"error": "No dorks to export."}), 400

    if fmt == "txt":
        content = "\n".join(dorks) + "\n"
        return Response(
            content,
            mimetype="text/plain",
            headers={
                "Content-Disposition": "attachment; filename=dorkmaster_export.txt"
            },
        )

    if fmt == "csv":
        output = io.StringIO()
        writer = csv.writer(output)
        writer.writerow(["#", "Dork Query", "Engine"])
        for i, d in enumerate(dorks, 1):
            writer.writerow([i, d, engine_name])
        return Response(
            output.getvalue(),
            mimetype="text/csv",
            headers={
                "Content-Disposition": "attachment; filename=dorkmaster_export.csv"
            },
        )

    if fmt == "json":
        from core import __version__
        export_data = {
            "generator": "DorkMaster",
            "version": __version__,
            "engine": engine_name,
            "total": len(dorks),
            "dorks": dorks,
        }
        return Response(
            json.dumps(export_data, indent=2, ensure_ascii=False),
            mimetype="application/json",
            headers={
                "Content-Disposition": "attachment; filename=dorkmaster_export.json"
            },
        )

    return jsonify({"error": f"Unknown format: {fmt}"}), 400


# ================================================================
# Hunter API
# ================================================================

@api_bp.route("/hunter/engines")
def hunter_engines():
    """Return available search engines for the hunter, classified by type."""
    cfg = get_hunter_config()
    return jsonify({
        "free_engines": FREE_ENGINE_INFO,
        "api_engines": API_ENGINES,
        "available_free": FREE_ENGINES,
        "has_api_keys": len(cfg.serper.api_keys) > 0,
        "proxy_enabled": cfg.proxy.enabled,
        "proxy_count": len(cfg.proxy.proxies),
    })


@api_bp.route("/hunter/search", methods=["POST"])
def hunter_search():
    """Execute dork hunting and return results (non-streaming).

    Supports modes: free, api, free+proxy, api+proxy.
    """
    data = request.get_json(silent=True)
    if not data:
        return jsonify({"error": "No JSON data provided."}), 400

    dorks = data.get("dorks", [])
    if isinstance(dorks, str):
        dorks = [d.strip() for d in dorks.split("\n") if d.strip()]

    if not dorks:
        return jsonify({"error": "No dorks provided."}), 400

    search_mode = data.get("search_mode", "free")  # "free" or "api"
    engines = data.get("engines", ["duckduckgo", "bing"])
    pages = data.get("pages_per_dork", 1)
    max_conc = data.get("max_concurrency", 3)
    use_proxy = data.get("use_proxy", False)

    # Get proxies if requested
    proxies: list[str] = []
    if use_proxy:
        cfg = get_hunter_config()
        if cfg.proxy.enabled and cfg.proxy.proxies:
            proxies = list(cfg.proxy.proxies)

    try:
        pages = max(1, min(5, int(pages)))
        max_conc = max(1, min(10, int(max_conc)))
    except (ValueError, TypeError):
        pages = 1
        max_conc = 3

    loop = asyncio.new_event_loop()
    try:
        if search_mode == "api":
            # API mode
            cfg = get_hunter_config()
            if not cfg.serper.api_keys:
                return jsonify({"error": "No API keys configured. Add them in Settings."}), 400

            from hunter.config import SerperConfig
            serper_cfg = SerperConfig()
            serper_cfg.api_keys = cfg.serper.api_keys
            serper_cfg.pages_per_query = pages
            serper_cfg.search_concurrency = max_conc

            api_engine = SearchEngine(serper_cfg, proxies=proxies)
            api_engine._get_queries = lambda: dorks  # type: ignore[assignment]
            urls = loop.run_until_complete(api_engine.search_all())
        else:
            # Free mode
            valid_engines = [e for e in engines if e in AVAILABLE_ENGINES]
            if not valid_engines:
                valid_engines = ["duckduckgo", "bing"]

            search_engine = FreeSearchEngine(
                queries=dorks,
                engines=valid_engines,
                pages_per_dork=pages,
                proxies=proxies,
            )
            urls = loop.run_until_complete(
                search_engine.search_all(max_concurrency=max_conc)
            )
    finally:
        loop.close()

    return jsonify({
        "urls": urls,
        "total_urls": len(urls),
        "dorks_processed": len(dorks),
        "search_mode": search_mode,
        "proxy_used": len(proxies) > 0,
    })


@api_bp.route("/hunter/search/stream", methods=["POST"])
def hunter_search_stream():
    """Execute dork hunting with Server-Sent Events (SSE) for real-time results.

    Supports modes: free, api, free+proxy, api+proxy.
    """
    data = request.get_json(silent=True)
    if not data:
        return jsonify({"error": "No JSON data provided."}), 400

    dorks = data.get("dorks", [])
    if isinstance(dorks, str):
        dorks = [d.strip() for d in dorks.split("\n") if d.strip()]

    if not dorks:
        return jsonify({"error": "No dorks provided."}), 400

    search_mode = data.get("search_mode", "free")
    engines = data.get("engines", ["duckduckgo", "bing"])
    pages = data.get("pages_per_dork", 1)
    max_conc = data.get("max_concurrency", 3)
    use_proxy = data.get("use_proxy", False)

    try:
        pages = max(1, min(5, int(pages)))
        max_conc = max(1, min(10, int(max_conc)))
    except (ValueError, TypeError):
        pages = 1
        max_conc = 3

    # Get proxies if requested
    proxies: list[str] = []
    if use_proxy:
        cfg = get_hunter_config()
        if cfg.proxy.enabled and cfg.proxy.proxies:
            proxies = list(cfg.proxy.proxies)

    def generate_events():
        """Generator that yields SSE events."""
        import queue
        import threading

        result_queue: queue.Queue = queue.Queue()

        def on_results_callback(new_urls: list[str]) -> None:
            for url in new_urls:
                result_queue.put(("url", url))
            result_queue.put(("progress", {"total_urls": len(new_urls)}))

        def run_search():
            loop = asyncio.new_event_loop()
            try:
                if search_mode == "api":
                    cfg = get_hunter_config()
                    if not cfg.serper.api_keys:
                        result_queue.put(("error", "No API keys configured."))
                        result_queue.put(None)
                        return

                    from hunter.config import SerperConfig
                    serper_cfg = SerperConfig()
                    serper_cfg.api_keys = cfg.serper.api_keys
                    serper_cfg.pages_per_query = pages
                    serper_cfg.search_concurrency = max_conc

                    api_engine = SearchEngine(serper_cfg, proxies=proxies)
                    api_engine._get_queries = lambda: dorks  # type: ignore[assignment]

                    urls = loop.run_until_complete(
                        api_engine.search_all(on_results=on_results_callback)
                    )
                    result_queue.put(("done", {
                        "total_urls": api_engine.discovered_count,
                        "dorks_processed": len(dorks),
                        "search_mode": "api",
                    }))
                else:
                    valid_engines = [e for e in engines if e in AVAILABLE_ENGINES]
                    if not valid_engines:
                        valid_engines = ["duckduckgo", "bing"]

                    search_engine = FreeSearchEngine(
                        queries=dorks,
                        engines=valid_engines,
                        pages_per_dork=pages,
                        proxies=proxies,
                    )
                    loop.run_until_complete(
                        search_engine.search_all(
                            on_results=on_results_callback,
                            max_concurrency=max_conc,
                        )
                    )
                    result_queue.put(("done", {
                        "total_urls": search_engine.discovered_count,
                        "dorks_processed": len(dorks),
                        "engines_used": valid_engines if search_mode == "free" else ["serper"],
                    }))
            except Exception as exc:
                result_queue.put(("error", str(exc)))
            finally:
                result_queue.put(None)  # Sentinel
                loop.close()

        thread = threading.Thread(target=run_search, daemon=True)
        thread.start()

        while True:
            try:
                item = result_queue.get(timeout=120)
            except queue.Empty:
                yield "event: error\ndata: Timeout waiting for results\n\n"
                break

            if item is None:
                break

            event_type, event_data = item
            if event_type == "url":
                yield f"event: url\ndata: {json.dumps({'url': event_data})}\n\n"
            elif event_type == "progress":
                yield f"event: progress\ndata: {json.dumps(event_data)}\n\n"
            elif event_type == "done":
                yield f"event: done\ndata: {json.dumps(event_data)}\n\n"
            elif event_type == "error":
                yield f"event: error\ndata: {json.dumps({'error': event_data})}\n\n"

        thread.join(timeout=5)

    return Response(
        stream_with_context(generate_events()),
        mimetype="text/event-stream",
        headers={
            "Cache-Control": "no-cache",
            "Connection": "keep-alive",
            "X-Accel-Buffering": "no",
        },
    )


@api_bp.route("/hunter/export", methods=["POST"])
def hunter_export():
    """Export extracted URLs in various formats."""
    data = request.get_json(silent=True)
    if not data:
        return jsonify({"error": "No JSON data provided."}), 400

    urls = data.get("urls", [])
    fmt = data.get("format", "txt")

    if not urls:
        return jsonify({"error": "No URLs to export."}), 400

    if fmt == "txt":
        content = "\n".join(urls) + "\n"
        return Response(
            content,
            mimetype="text/plain",
            headers={
                "Content-Disposition": "attachment; filename=dorkmaster_urls.txt"
            },
        )

    if fmt == "csv":
        output = io.StringIO()
        writer = csv.writer(output)
        writer.writerow(["#", "URL"])
        for i, u in enumerate(urls, 1):
            writer.writerow([i, u])
        return Response(
            output.getvalue(),
            mimetype="text/csv",
            headers={
                "Content-Disposition": "attachment; filename=dorkmaster_urls.csv"
            },
        )

    if fmt == "json":
        from core import __version__
        export_data = {
            "tool": "DorkMaster Hunter",
            "version": __version__,
            "total": len(urls),
            "urls": urls,
        }
        return Response(
            json.dumps(export_data, indent=2, ensure_ascii=False),
            mimetype="application/json",
            headers={
                "Content-Disposition": "attachment; filename=dorkmaster_urls.json"
            },
        )

    return jsonify({"error": f"Unknown format: {fmt}"}), 400


# ================================================================
# Scanner API
# ================================================================

@api_bp.route("/scanner/scan", methods=["POST"])
def scanner_scan():
    """Run a security scan on provided URLs (SSE stream).

    Supports optional proxy mode.
    """
    data = request.get_json(silent=True)
    if not data:
        return jsonify({"error": "No JSON data provided."}), 400

    urls = data.get("urls", [])
    if isinstance(urls, str):
        urls = [u.strip() for u in urls.split("\n") if u.strip()]

    if not urls:
        return jsonify({"error": "No URLs provided."}), 400

    detect_sqli = data.get("detect_sqli", True)
    detect_xss = data.get("detect_xss", True)
    max_concurrency = data.get("max_concurrency", 20)
    timeout_seconds = data.get("timeout", 10)
    rate_limit_rps = data.get("rate_limit", 50)
    use_proxy = data.get("use_proxy", False)

    try:
        max_concurrency = max(1, min(50, int(max_concurrency)))
        timeout_seconds = max(1, min(60, int(timeout_seconds)))
        rate_limit_rps = max(0, min(200, int(rate_limit_rps)))
    except (ValueError, TypeError):
        max_concurrency = 20
        timeout_seconds = 10
        rate_limit_rps = 50

    # Get proxies if requested
    proxies: list[str] = []
    if use_proxy:
        cfg = get_hunter_config()
        if cfg.proxy.enabled and cfg.proxy.proxies:
            proxies = list(cfg.proxy.proxies)

    config = ScanConfig(
        max_concurrency=max_concurrency,
        timeout_seconds=float(timeout_seconds),
        rate_limit_rps=float(rate_limit_rps),
        detect_sqli=detect_sqli,
        detect_xss=detect_xss,
        output_dir="scan_results",
        use_proxy=bool(proxies),
        proxies=proxies,
    )

    def generate_events():
        """Generator that yields SSE events for scan progress."""
        import queue
        import threading

        result_queue: queue.Queue = queue.Queue()

        def on_progress(current: int, total: int, url: str) -> None:
            result_queue.put(("progress", {
                "current": current,
                "total": total,
                "url": url,
                "percent": round(current / total * 100, 1) if total else 0,
            }))

        def run_scan():
            loop = asyncio.new_event_loop()
            try:
                orchestrator = ScanOrchestrator(config)
                report = loop.run_until_complete(
                    orchestrator.scan(urls, on_progress=on_progress)
                )
                result_queue.put(("done", report.to_dict()))
            except Exception as exc:
                result_queue.put(("error", str(exc)))
            finally:
                result_queue.put(None)
                loop.close()

        thread = threading.Thread(target=run_scan, daemon=True)
        thread.start()

        while True:
            try:
                item = result_queue.get(timeout=300)
            except queue.Empty:
                yield 'event: error\ndata: {"error": "Scan timed out"}\n\n'
                break

            if item is None:
                break

            event_type, event_data = item
            if event_type == "progress":
                yield f"event: progress\ndata: {json.dumps(event_data)}\n\n"
            elif event_type == "done":
                yield f"event: done\ndata: {json.dumps(event_data)}\n\n"
            elif event_type == "error":
                yield f"event: error\ndata: {json.dumps({'error': event_data})}\n\n"

        thread.join(timeout=5)

    return Response(
        stream_with_context(generate_events()),
        mimetype="text/event-stream",
        headers={
            "Cache-Control": "no-cache",
            "Connection": "keep-alive",
            "X-Accel-Buffering": "no",
        },
    )


@api_bp.route("/scanner/scan/batch", methods=["POST"])
def scanner_scan_batch():
    """Run a security scan and return complete results (non-streaming)."""
    data = request.get_json(silent=True)
    if not data:
        return jsonify({"error": "No JSON data provided."}), 400

    urls = data.get("urls", [])
    if isinstance(urls, str):
        urls = [u.strip() for u in urls.split("\n") if u.strip()]

    if not urls:
        return jsonify({"error": "No URLs provided."}), 400

    detect_sqli = data.get("detect_sqli", True)
    detect_xss = data.get("detect_xss", True)
    max_concurrency = data.get("max_concurrency", 20)
    timeout_seconds = data.get("timeout", 10)
    rate_limit_rps = data.get("rate_limit", 50)
    use_proxy = data.get("use_proxy", False)

    try:
        max_concurrency = max(1, min(50, int(max_concurrency)))
        timeout_seconds = max(1, min(60, int(timeout_seconds)))
        rate_limit_rps = max(0, min(200, int(rate_limit_rps)))
    except (ValueError, TypeError):
        max_concurrency = 20
        timeout_seconds = 10
        rate_limit_rps = 50

    proxies: list[str] = []
    if use_proxy:
        cfg = get_hunter_config()
        if cfg.proxy.enabled and cfg.proxy.proxies:
            proxies = list(cfg.proxy.proxies)

    config = ScanConfig(
        max_concurrency=max_concurrency,
        timeout_seconds=float(timeout_seconds),
        rate_limit_rps=float(rate_limit_rps),
        detect_sqli=detect_sqli,
        detect_xss=detect_xss,
        output_dir="scan_results",
        use_proxy=bool(proxies),
        proxies=proxies,
    )

    loop = asyncio.new_event_loop()
    try:
        orchestrator = ScanOrchestrator(config)
        report = loop.run_until_complete(orchestrator.scan(urls))
    finally:
        loop.close()

    return jsonify(report.to_dict())


@api_bp.route("/scanner/export", methods=["POST"])
def scanner_export():
    """Export scan results in various formats."""
    data = request.get_json(silent=True)
    if not data:
        return jsonify({"error": "No JSON data provided."}), 400

    results = data.get("results", [])
    fmt = data.get("format", "json")

    if not results:
        return jsonify({"error": "No results to export."}), 400

    if fmt == "json":
        return Response(
            json.dumps(data, indent=2, ensure_ascii=False),
            mimetype="application/json",
            headers={
                "Content-Disposition": "attachment; filename=scan_report.json"
            },
        )

    if fmt == "txt":
        lines = ["=" * 70, "  DORKMASTER SECURITY SCAN REPORT", "=" * 70, ""]
        summary = data.get("summary", {})
        lines.append(f"  Scanned URLs:   {summary.get('total_urls', 0)}")
        lines.append(f"  Total Findings: {summary.get('total_findings', 0)}")
        for vtype, count in sorted(summary.get("vuln_counts", {}).items()):
            lines.append(f"    - {vtype}: {count}")
        lines.append("")
        lines.append("-" * 70)

        for res in results:
            if res.get("status") == "clean" and not res.get("findings"):
                continue
            lines.append("")
            lines.append(f"  URL: {res.get('url', 'N/A')}")
            lines.append(f"  Status: {res.get('status', 'N/A')}")
            if res.get("error"):
                lines.append(f"  Error: {res['error']}")
            for f in res.get("findings", []):
                lines.append(
                    f"    [{f.get('confidence', '?').upper():^6}] "
                    f"{f.get('vuln_type', '?')} | param={f.get('parameter', '?')}"
                )
                lines.append(f"           {f.get('evidence', '')}")
            lines.append(f"  {'- ' * 35}")

        lines.extend(["", "=" * 70])
        return Response(
            "\n".join(lines) + "\n",
            mimetype="text/plain",
            headers={
                "Content-Disposition": "attachment; filename=scan_report.txt"
            },
        )

    if fmt == "csv":
        output = io.StringIO()
        writer = csv.writer(output)
        writer.writerow([
            "#", "url", "status", "vuln_type", "confidence",
            "parameter", "evidence", "http_code", "response_ms",
        ])
        idx = 0
        for res in results:
            findings = res.get("findings", [])
            if not findings:
                idx += 1
                writer.writerow([
                    idx, res.get("url", ""), res.get("status", ""),
                    "", "", "", "", "", "",
                ])
            else:
                for f in findings:
                    idx += 1
                    writer.writerow([
                        idx, f.get("url", res.get("url", "")),
                        res.get("status", ""),
                        f.get("vuln_type", ""),
                        f.get("confidence", ""),
                        f.get("parameter", ""),
                        f.get("evidence", ""),
                        f.get("response_code", ""),
                        f.get("response_time_ms", ""),
                    ])
        return Response(
            output.getvalue(),
            mimetype="text/csv",
            headers={
                "Content-Disposition": "attachment; filename=scan_report.csv"
            },
        )

    return jsonify({"error": f"Unknown format: {fmt}"}), 400


# ================================================================
# Settings API
# ================================================================

@api_bp.route("/settings", methods=["GET"])
def get_settings():
    """Return current settings for display."""
    return jsonify(get_current_settings())


@api_bp.route("/settings/api-keys", methods=["POST"])
def save_api_keys():
    """Save API keys."""
    data = request.get_json(silent=True)
    if not data:
        return jsonify({"error": "No data provided."}), 400

    persisted = _load_persisted_settings()

    serper_keys = data.get("serper_api_keys", [])
    if isinstance(serper_keys, str):
        serper_keys = [k.strip() for k in serper_keys.split(",") if k.strip()]

    persisted["serper_api_keys"] = serper_keys
    save_settings(persisted)

    return jsonify({
        "status": "ok",
        "message": f"Saved {len(serper_keys)} Serper API key(s).",
        "count": len(serper_keys),
    })


@api_bp.route("/settings/proxies", methods=["POST"])
def save_proxies():
    """Save proxy list."""
    data = request.get_json(silent=True)
    if not data:
        return jsonify({"error": "No data provided."}), 400

    persisted = _load_persisted_settings()

    proxies = data.get("proxies", [])
    if isinstance(proxies, str):
        proxies = [p.strip() for p in proxies.split("\n") if p.strip()]

    enabled = data.get("enabled", False)

    persisted["proxies"] = proxies
    persisted["proxy_enabled"] = enabled
    save_settings(persisted)

    return jsonify({
        "status": "ok",
        "message": f"Saved {len(proxies)} proxies. Proxy mode: {'enabled' if enabled else 'disabled'}.",
        "count": len(proxies),
        "enabled": enabled,
    })


@api_bp.route("/settings/proxies/test", methods=["POST"])
def test_proxies():
    """Test a list of proxies and return only the working ones."""
    data = request.get_json(silent=True)
    if not data:
        return jsonify({"error": "No data provided."}), 400

    proxies = data.get("proxies", [])
    if isinstance(proxies, str):
        proxies = [p.strip() for p in proxies.split("\n") if p.strip()]

    if not proxies:
        return jsonify({"error": "No proxies to test."}), 400

    timeout = data.get("timeout", 10)
    test_url = "https://httpbin.org/ip"

    working: list[str] = []
    failed: list[str] = []

    loop = asyncio.new_event_loop()
    try:
        async def test_all():
            sem = asyncio.Semaphore(10)

            async def test_one(proxy_str: str):
                async with sem:
                    p = proxy_str.strip()
                    if not p.startswith(("http://", "https://", "socks")):
                        p = "http://" + p

                    try:
                        async with httpx.AsyncClient(
                            proxy=p,
                            timeout=timeout,
                            verify=False,
                        ) as client:
                            resp = await client.get(test_url)
                            if resp.status_code == 200:
                                working.append(proxy_str)
                            else:
                                failed.append(proxy_str)
                    except Exception:
                        failed.append(proxy_str)

            await asyncio.gather(*[test_one(p) for p in proxies])

        loop.run_until_complete(test_all())
    finally:
        loop.close()

    return jsonify({
        "working": working,
        "failed": failed,
        "total_tested": len(proxies),
        "total_working": len(working),
    })


@api_bp.route("/settings/proxies/save-working", methods=["POST"])
def save_working_proxies():
    """Save only the working proxies from a test."""
    data = request.get_json(silent=True)
    if not data:
        return jsonify({"error": "No data provided."}), 400

    working = data.get("working", [])
    persisted = _load_persisted_settings()
    persisted["proxies"] = working
    persisted["proxy_enabled"] = len(working) > 0
    save_settings(persisted)

    return jsonify({
        "status": "ok",
        "message": f"Saved {len(working)} working proxies.",
        "count": len(working),
    })
