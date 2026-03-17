"""
DorkMaster CLI - Interactive Command Line Interface
=====================================================

Unified CLI combining dork generation (DorkBoxer), dork hunting (DorkHunter),
and security scanning (SQLi/XSS) into a single interactive tool.

Features:
  - Settings menu for API keys, proxies, and configuration
  - Clear separation between FREE and PREMIUM search engines
  - API key quota tracking (2500 queries per key)
  - Proxy configuration and testing
"""

from __future__ import annotations

import asyncio
import json
import os
import re
import sys
from pathlib import Path
from urllib.parse import urlparse

# Ensure project root is on the path
sys.path.insert(0, str(Path(__file__).resolve().parent))

from core import __version__, __app_name__
from core.engine import DorkConfig, DorkGenerator
from hunter.config import (
    HunterConfig, get_hunter_config, save_settings,
    _load_persisted_settings, _save_persisted_settings,
    FREE_ENGINES, API_ENGINES, FREE_ENGINE_INFO,
    SETTINGS_FILE, DATA_DIR,
)
from hunter.search.free_engine import FreeSearchEngine, AVAILABLE_ENGINES
from hunter.search.engine import SearchEngine
from hunter.search.key_manager import KeyManager, KeyExhaustedError
from hunter.orchestrator import load_dorks_from_file
from scanner.models import ScanConfig, ScanReport, ScanStatus, Confidence
from scanner.orchestrator import ScanOrchestrator

# ---------------------------------------------------------------------------
# ANSI helpers
# ---------------------------------------------------------------------------
BOLD = "\033[1m"
DIM = "\033[2m"
CYAN = "\033[96m"
GREEN = "\033[92m"
YELLOW = "\033[93m"
RED = "\033[91m"
MAGENTA = "\033[95m"
BLUE = "\033[94m"
WHITE = "\033[97m"
RESET = "\033[0m"

LINE = f"{CYAN}{'=' * 62}{RESET}"
LINE_THIN = f"{DIM}{'-' * 52}{RESET}"

# API quota: each Serper.dev key = 2500 free queries
QUERIES_PER_KEY = 2500


def _clear() -> None:
    os.system("cls" if os.name == "nt" else "clear")


# ---------------------------------------------------------------------------
# Input helpers
# ---------------------------------------------------------------------------

def _ask(prompt: str, default: str = "") -> str:
    suffix = f" [{CYAN}{default}{YELLOW}]" if default else ""
    try:
        value = input(f"  {YELLOW}> {prompt}{suffix}: {RESET}").strip()
    except (EOFError, KeyboardInterrupt):
        print()
        return default
    return value or default


def _ask_int(prompt: str, default: int) -> int:
    while True:
        raw = _ask(prompt, str(default))
        try:
            val = int(raw)
            if val < 0:
                raise ValueError
            return val
        except ValueError:
            print(f"  {RED}  [!] Please enter a non-negative integer.{RESET}")


def _ask_yes_no(prompt: str, default: bool = True) -> bool:
    hint = "Y/n" if default else "y/N"
    raw = _ask(prompt, hint)
    if raw in ("Y/n", "y/N"):
        return default
    return raw.lower() in ("y", "yes", "si", "s", "1", "true")


# ---------------------------------------------------------------------------
# Quota Tracker
# ---------------------------------------------------------------------------

class QuotaTracker:
    """Tracks API query usage per key. Each key = 2500 free queries on Serper.dev."""

    def __init__(self) -> None:
        self._file = DATA_DIR / "quota.json"
        DATA_DIR.mkdir(parents=True, exist_ok=True)
        self._data: dict = self._load()

    def _load(self) -> dict:
        if self._file.is_file():
            try:
                with open(self._file, "r") as f:
                    return json.load(f)
            except (json.JSONDecodeError, OSError):
                pass
        return {"keys": {}}

    def _save(self) -> None:
        with open(self._file, "w") as f:
            json.dump(self._data, f, indent=2)

    def _mask(self, key: str) -> str:
        if len(key) > 12:
            return key[:6] + "..." + key[-4:]
        return "***"

    def record_usage(self, key: str, queries_used: int) -> None:
        """Record that queries were used on a key."""
        if key not in self._data["keys"]:
            self._data["keys"][key] = {"used": 0}
        self._data["keys"][key]["used"] += queries_used
        self._save()

    def get_usage(self, key: str) -> int:
        return self._data.get("keys", {}).get(key, {}).get("used", 0)

    def get_remaining(self, key: str) -> int:
        return max(0, QUERIES_PER_KEY - self.get_usage(key))

    def get_total_available(self, keys: list[str]) -> int:
        """Total remaining queries across all keys."""
        return sum(self.get_remaining(k) for k in keys)

    def get_total_used(self, keys: list[str]) -> int:
        return sum(self.get_usage(k) for k in keys)

    def reset_key(self, key: str) -> None:
        if key in self._data.get("keys", {}):
            self._data["keys"][key]["used"] = 0
            self._save()

    def show_status(self, keys: list[str]) -> None:
        """Print quota status for all keys."""
        if not keys:
            print(f"  {YELLOW}  No API keys configured.{RESET}")
            return

        total_avail = self.get_total_available(keys)
        total_used = self.get_total_used(keys)
        total_cap = len(keys) * QUERIES_PER_KEY

        print(f"  {WHITE}{BOLD}  API Key Quota ({QUERIES_PER_KEY} queries/key){RESET}")
        print(f"  {LINE_THIN}")
        print(f"    {WHITE}Total Keys:{RESET}       {GREEN}{len(keys)}{RESET}")
        print(f"    {WHITE}Total Capacity:{RESET}   {GREEN}{total_cap:,}{RESET} queries")
        print(f"    {WHITE}Used:{RESET}             {YELLOW}{total_used:,}{RESET} queries")
        print(f"    {WHITE}Remaining:{RESET}        {GREEN}{BOLD}{total_avail:,}{RESET} queries")
        print()

        for i, key in enumerate(keys, 1):
            used = self.get_usage(key)
            remaining = self.get_remaining(key)
            pct = (used / QUERIES_PER_KEY * 100) if QUERIES_PER_KEY else 0
            bar_len = 20
            filled = int(bar_len * used / QUERIES_PER_KEY)
            bar_color = GREEN if pct < 50 else (YELLOW if pct < 80 else RED)
            bar = f"{bar_color}{'#' * filled}{DIM}{'-' * (bar_len - filled)}{RESET}"
            status = f"{RED}EXHAUSTED{RESET}" if remaining == 0 else f"{remaining:,} left"
            print(
                f"    {DIM}Key {i}{RESET} {self._mask(key)}  "
                f"[{bar}] {pct:.0f}%  {status}"
            )


# Global tracker
_quota = QuotaTracker()


# ---------------------------------------------------------------------------
# URL Sanitizer
# ---------------------------------------------------------------------------

def _sanitize_url(url: str) -> str | None:
    """Clean and validate a URL, removing formatting artifacts."""
    url = url.strip()
    # Remove common formatting artifacts
    url = re.sub(r'^[\s\-\*\#\>]+', '', url)  # leading markdown chars
    url = re.sub(r'[\s\)\]\>]+$', '', url)  # trailing markdown chars
    url = url.strip('"').strip("'").strip('<').strip('>')
    url = url.split('#')[0]  # remove fragment
    url = url.rstrip('/')

    if not url:
        return None

    # Must have a valid scheme
    if not url.startswith(('http://', 'https://')):
        if url.startswith('//'):
            url = 'https:' + url
        elif '.' in url and '/' in url:
            url = 'https://' + url
        else:
            return None

    try:
        parsed = urlparse(url)
        if not parsed.netloc or '.' not in parsed.netloc:
            return None
        # Reconstruct clean URL
        clean = f"{parsed.scheme}://{parsed.netloc}{parsed.path}"
        if parsed.query:
            clean += f"?{parsed.query}"
        return clean
    except Exception:
        return None


# ---------------------------------------------------------------------------
# Banner
# ---------------------------------------------------------------------------

def _show_banner() -> None:
    _clear()
    print()
    print(f"  {LINE}")
    print()
    print(f"  {BOLD}{CYAN}  ██████╗  ██████╗ ██████╗ ██╗  ██╗{RESET}")
    print(f"  {BOLD}{CYAN}  ██╔══██╗██╔═══██╗██╔══██╗██║ ██╔╝{RESET}")
    print(f"  {BOLD}{CYAN}  ██║  ██║██║   ██║██████╔╝█████╔╝ {RESET}")
    print(f"  {BOLD}{CYAN}  ██║  ██║██║   ██║██╔══██╗██╔═██╗ {RESET}")
    print(f"  {BOLD}{CYAN}  ██████╔╝╚██████╔╝██║  ██║██║  ██╗{RESET}")
    print(f"  {BOLD}{CYAN}  ╚═════╝  ╚═════╝ ╚═╝  ╚═╝╚═╝  ╚═╝{RESET}")
    print()
    print(f"  {BOLD}{MAGENTA}  ███╗   ███╗ █████╗ ███████╗████████╗███████╗██████╗{RESET}")
    print(f"  {BOLD}{MAGENTA}  ████╗ ████║██╔══██╗██╔════╝╚══██╔══╝██╔════╝██╔══██╗{RESET}")
    print(f"  {BOLD}{MAGENTA}  ██╔████╔██║███████║███████╗   ██║   █████╗  ██████╔╝{RESET}")
    print(f"  {BOLD}{MAGENTA}  ██║╚██╔╝██║██╔══██║╚════██║   ██║   ██╔══╝  ██╔══██╗{RESET}")
    print(f"  {BOLD}{MAGENTA}  ██║ ╚═╝ ██║██║  ██║███████║   ██║   ███████╗██║  ██║{RESET}")
    print(f"  {BOLD}{MAGENTA}  ╚═╝     ╚═╝╚═╝  ╚═╝╚══════╝   ╚═╝   ╚══════╝╚═╝  ╚═╝{RESET}")
    print()
    print(f"  {BOLD}{WHITE}  Dork Generator & Hunter & Scanner{RESET}  {DIM}v{__version__}{RESET}")
    print(f"  {DIM}  Generate dorks, search engines, extract URLs, scan vulns{RESET}")
    print()
    print(f"  {LINE}")
    print()


# ---------------------------------------------------------------------------
# Main menu
# ---------------------------------------------------------------------------

def _show_menu() -> str:
    _show_banner()

    # Quick status bar
    cfg = get_hunter_config(force_reload=True)
    n_keys = len(cfg.serper.api_keys)
    total_remaining = _quota.get_total_available(cfg.serper.api_keys)
    proxy_status = f"{GREEN}ON ({len(cfg.proxy.proxies)}){RESET}" if cfg.proxy.enabled else f"{DIM}OFF{RESET}"

    print(f"  {WHITE}{BOLD}  STATUS{RESET}")
    print(f"  {LINE_THIN}")
    print(
        f"    {WHITE}API Keys:{RESET} {GREEN}{n_keys}{RESET}  "
        f"{WHITE}Queries Left:{RESET} {GREEN}{total_remaining:,}{RESET}  "
        f"{WHITE}Proxies:{RESET} {proxy_status}"
    )
    print()
    print(f"  {WHITE}{BOLD}  OPERATIONS{RESET}")
    print(f"  {LINE_THIN}")
    print()

    menu_items = [
        ("1", "Generate Dorks", "Create dork queries for any search engine"),
        ("2", "Hunt URLs (FREE)", "Scrape search engines directly, no API key"),
        ("3", "Hunt URLs (PREMIUM)", "Use Serper.dev API (requires API key)"),
        ("4", "Generate & Hunt", "Generate dorks then immediately hunt"),
        ("5", "Security Scan", "Scan URLs for SQLi / XSS vulnerabilities"),
        ("6", "Settings", "API keys, proxies, quota, configuration"),
        ("7", "Web Interface", "Launch the web UI in your browser"),
        ("8", "Help", "Usage guide & tips"),
    ]
    for num, label, desc in menu_items:
        color = GREEN
        if num == "3":
            color = MAGENTA
        elif num == "6":
            color = YELLOW
        print(
            f"  {color}{BOLD}  [{num}] {RESET}"
            f"{WHITE}{label:<22}{RESET} {DIM}{desc}{RESET}"
        )

    print()
    print(f"  {RED}{BOLD}  [0] {RESET} {DIM}Exit{RESET}")
    print()

    valid = {"0", "1", "2", "3", "4", "5", "6", "7", "8"}
    while True:
        choice = _ask("Select an operation")
        if choice in valid:
            return choice
        print(f"  {RED}  [!] Invalid choice. Enter 0-8.{RESET}")


# ---------------------------------------------------------------------------
# 1. Generate Dorks
# ---------------------------------------------------------------------------

def _run_generate() -> list[str]:
    print()
    print(f"  {CYAN}{BOLD}  Dork Generator{RESET}")
    print(f"  {LINE_THIN}")
    print()

    config = DorkConfig.get_instance()
    generator = DorkGenerator(config)

    # Engine selection
    engines = config.get_all_engine_ids()
    print(f"  {WHITE}  Available Engines:{RESET}")
    for i, eid in enumerate(engines, 1):
        name = config.get_engine_display_name(eid)
        ops = len(config.get_operators(eid))
        print(f"    {GREEN}{i:>2}{RESET}  {WHITE}{name:<15}{RESET} {DIM}({ops} operators){RESET}")
    print()

    raw = _ask("Select engine (number)", "1")
    try:
        idx = int(raw) - 1
        if 0 <= idx < len(engines):
            engine_id = engines[idx]
        else:
            engine_id = "google"
    except ValueError:
        engine_id = "google"
    print(f"  {GREEN}  [+] Engine: {config.get_engine_display_name(engine_id)}{RESET}")

    # Keywords
    print()
    print(f"  {WHITE}  Enter keywords (one per line, empty line to finish):{RESET}")
    keywords: list[str] = []
    while True:
        try:
            line = input(f"  {CYAN}  kw> {RESET}").strip()
        except (EOFError, KeyboardInterrupt):
            break
        if not line:
            break
        keywords.append(line)

    if not keywords:
        print(f"  {RED}  [!] No keywords entered.{RESET}")
        return []

    print(f"  {GREEN}  [+] {len(keywords)} keywords{RESET}")

    # Operators
    available_ops = config.get_operators(engine_id)
    op_keys = list(available_ops.keys())
    print()
    print(f"  {WHITE}  Available Operators:{RESET}")
    for i, op in enumerate(op_keys, 1):
        desc = available_ops[op].get("description", "")
        print(f"    {GREEN}{i:>2}{RESET}  {WHITE}{op + ':':<20}{RESET} {DIM}{desc}{RESET}")
    print(f"    {GREEN} A{RESET}  {WHITE}All{RESET}")
    print()

    raw = _ask("Select operators (comma-separated numbers, A for all)", "A")
    if raw.lower().strip() == "a":
        selected_ops = op_keys[:]
    else:
        selected_ops: list[str] = []
        for part in raw.split(","):
            part = part.strip()
            try:
                idx = int(part) - 1
                if 0 <= idx < len(op_keys):
                    selected_ops.append(op_keys[idx])
            except ValueError:
                pass
    if not selected_ops:
        selected_ops = op_keys[:3]
    print(f"  {GREEN}  [+] {len(selected_ops)} operators selected{RESET}")

    # Filetypes
    filetypes = config.get_filetypes(engine_id)
    selected_ft: list[str] = []
    if filetypes:
        use_ft = _ask_yes_no("Include file types?", default=False)
        if use_ft:
            print(f"  {DIM}  Available: {', '.join(filetypes[:20])}...{RESET}")
            raw = _ask("Enter filetypes (comma-separated, e.g. pdf,php,sql)", "pdf,php")
            selected_ft = [ft.strip() for ft in raw.split(",") if ft.strip() in filetypes]
            print(f"  {GREEN}  [+] {len(selected_ft)} filetypes{RESET}")

    # Options
    site = _ask("Site restriction (empty for none)", "")
    max_results = _ask_int("Max results (0 = all)", 100)

    print()
    print(f"  {CYAN}  Generating...{RESET}")

    result = generator.generate(
        engine_id=engine_id,
        keywords=keywords,
        selected_operators=selected_ops,
        selected_filetypes=selected_ft,
        custom_site=site if site else None,
        max_results=max_results,
        shuffle=True,
    )

    dorks = result["dorks"]

    print()
    print(f"  {LINE}")
    print(f"  {BOLD}{WHITE}  GENERATION RESULTS{RESET}")
    print(f"  {LINE_THIN}")
    print(f"    {WHITE}Engine:{RESET}          {GREEN}{result['engine_name']}{RESET}")
    print(f"    {WHITE}Generated:{RESET}       {GREEN}{BOLD}{result['total_generated']}{RESET}")
    print(f"    {WHITE}Total Possible:{RESET}  {result['total_possible']}")

    if result["warnings"]:
        for w in result["warnings"]:
            print(f"    {YELLOW}[!] {w}{RESET}")

    if dorks:
        print()
        print(f"  {CYAN}  Preview (first 10):{RESET}")
        for i, d in enumerate(dorks[:10], 1):
            print(f"    {DIM}{i:>3}.{RESET} {d[:75]}")
        if len(dorks) > 10:
            print(f"    {DIM}    ... and {len(dorks) - 10} more{RESET}")

        # Save option
        print()
        save = _ask_yes_no("Save to file?", default=True)
        if save:
            fname = _ask("Filename", "generated_dorks.txt")
            fpath = Path(fname)
            with open(fpath, "w", encoding="utf-8") as f:
                f.write("\n".join(dorks) + "\n")
            print(f"  {GREEN}  [+] Saved {len(dorks)} dorks to {fpath}{RESET}")

    print()
    return dorks


# ---------------------------------------------------------------------------
# 2. Hunt URLs (FREE) -- no API keys, no limits
# ---------------------------------------------------------------------------

def _run_hunt_free(dorks: list[str] | None = None) -> list[str]:
    print()
    print(f"  {CYAN}{BOLD}  Dork Hunter -- FREE Mode{RESET}")
    print(f"  {GREEN}{BOLD}  No API key needed. No query limits.{RESET}")
    print(f"  {LINE_THIN}")
    print()

    # Get dorks
    if not dorks:
        print(f"  {WHITE}  How to provide dorks:{RESET}")
        print(f"    {GREEN}1{RESET} Enter manually")
        print(f"    {GREEN}2{RESET} Load from file")
        print()

        choice = _ask("Select", "2")
        if choice == "1":
            print(f"  {WHITE}  Enter dorks (one per line, empty to finish):{RESET}")
            dorks = []
            while True:
                try:
                    line = input(f"  {CYAN}  dork> {RESET}").strip()
                except (EOFError, KeyboardInterrupt):
                    break
                if not line:
                    break
                dorks.append(line)
        else:
            fpath = _ask("Path to dorks file", "dorks.txt")
            p = Path(fpath).expanduser().resolve()
            if p.is_file():
                dorks = load_dorks_from_file(str(p))
            elif Path(fpath).is_file():
                dorks = load_dorks_from_file(fpath)
            else:
                print(f"  {RED}  [!] File not found: {fpath}{RESET}")
                return []

    if not dorks:
        print(f"  {RED}  [!] No dorks provided.{RESET}")
        return []

    print(f"  {GREEN}  [+] {len(dorks)} dorks loaded{RESET}")

    # Engine selection -- FREE ENGINES ONLY
    print()
    print(f"  {CYAN}{BOLD}  Select Free Search Engines{RESET}")
    print(f"  {GREEN}  All engines below are FREE -- no API key, no limits{RESET}")
    print(f"  {LINE_THIN}")

    for i, eng_id in enumerate(FREE_ENGINES, 1):
        info = FREE_ENGINE_INFO.get(eng_id, {"name": eng_id, "desc": ""})
        print(f"    {GREEN}{i}{RESET}  {WHITE}{info['name']:<15}{RESET} {DIM}{info['desc']}{RESET}")
    print(f"    {GREEN}A{RESET}  {WHITE}All Engines{RESET}")
    print()

    raw = _ask("Select engines (comma-separated, e.g. 1,2 or A)", "1,2")
    if raw.lower().strip() == "a":
        engines = list(FREE_ENGINES)
    else:
        engines: list[str] = []
        for part in raw.split(","):
            part = part.strip()
            try:
                idx = int(part) - 1
                if 0 <= idx < len(FREE_ENGINES):
                    engines.append(FREE_ENGINES[idx])
            except ValueError:
                if part.lower() in FREE_ENGINES:
                    engines.append(part.lower())
    if not engines:
        engines = ["duckduckgo", "bing"]

    names = [FREE_ENGINE_INFO.get(e, {"name": e})["name"] for e in engines]
    print(f"  {GREEN}  [+] Engines: {', '.join(names)}{RESET}")

    pages = _ask_int("Pages per dork", 1)
    concurrency = _ask_int("Max concurrency", 3)

    # Proxy option
    cfg = get_hunter_config()
    proxies: list[str] = []
    if cfg.proxy.enabled and cfg.proxy.proxies:
        use_proxy = _ask_yes_no(
            f"Use proxies? ({len(cfg.proxy.proxies)} configured)", default=False
        )
        if use_proxy:
            proxies = list(cfg.proxy.proxies)
            print(f"  {GREEN}  [+] Using {len(proxies)} proxies{RESET}")

    print()
    print(f"  {CYAN}  Starting FREE search (no API key used)...{RESET}")
    print()

    search_engine = FreeSearchEngine(
        queries=dorks,
        engines=engines,
        pages_per_dork=pages,
        proxies=proxies,
    )

    urls_raw = asyncio.run(search_engine.search_all(max_concurrency=concurrency))

    # Sanitize URLs
    urls = []
    for u in urls_raw:
        clean = _sanitize_url(u)
        if clean and clean not in urls:
            urls.append(clean)

    # Results
    print()
    print(f"  {LINE}")
    print(f"  {BOLD}{WHITE}  HUNT RESULTS (FREE){RESET}")
    print(f"  {LINE_THIN}")
    print(f"    {WHITE}Mode:{RESET}            {GREEN}{BOLD}FREE{RESET} (no API key used)")
    print(f"    {WHITE}Dorks Processed:{RESET}  {GREEN}{len(dorks)}{RESET}")
    print(f"    {WHITE}URLs Extracted:{RESET}   {GREEN}{BOLD}{len(urls)}{RESET}")
    print(f"    {WHITE}Engines:{RESET}          {', '.join(names)}")

    if urls:
        print()
        print(f"  {CYAN}  Preview (first 10):{RESET}")
        for i, url in enumerate(urls[:10], 1):
            print(f"    {DIM}{i:>3}.{RESET} {BLUE}{url[:80]}{RESET}")
        if len(urls) > 10:
            print(f"    {DIM}    ... and {len(urls) - 10} more{RESET}")

        # Save
        print()
        save = _ask_yes_no("Save to file?", default=True)
        if save:
            fname = _ask("Filename", "extracted_urls.txt")
            fpath = Path(fname)
            with open(fpath, "w", encoding="utf-8") as f:
                f.write("\n".join(urls) + "\n")
            print(f"  {GREEN}  [+] Saved {len(urls)} URLs to {fpath}{RESET}")
    else:
        print(f"  {YELLOW}  [*] No URLs extracted. Try different dorks or engines.{RESET}")

    print()
    return urls


# ---------------------------------------------------------------------------
# 3. Hunt URLs (PREMIUM) -- Serper.dev API with quota tracking
# ---------------------------------------------------------------------------

def _run_hunt_premium(dorks: list[str] | None = None) -> list[str]:
    print()
    print(f"  {MAGENTA}{BOLD}  Dork Hunter -- PREMIUM Mode (Serper.dev API){RESET}")
    print(f"  {LINE_THIN}")
    print()

    cfg = get_hunter_config(force_reload=True)

    # Check API keys
    if not cfg.serper.api_keys:
        print(f"  {RED}{BOLD}  [!] No API keys configured!{RESET}")
        print(f"  {YELLOW}  Go to option [6] Settings > API Keys to add Serper.dev keys.{RESET}")
        print(f"  {YELLOW}  Get free keys at: https://serper.dev{RESET}")
        print()
        return []

    # Show quota
    _quota.show_status(cfg.serper.api_keys)
    total_remaining = _quota.get_total_available(cfg.serper.api_keys)

    if total_remaining == 0:
        print(f"  {RED}{BOLD}  [!] All API keys exhausted (0 queries remaining)!{RESET}")
        print(f"  {YELLOW}  Add new keys in Settings or reset quota counters.{RESET}")
        print()
        return []

    print()

    # Get dorks
    if not dorks:
        print(f"  {WHITE}  How to provide dorks:{RESET}")
        print(f"    {GREEN}1{RESET} Enter manually")
        print(f"    {GREEN}2{RESET} Load from file")
        print()

        choice = _ask("Select", "2")
        if choice == "1":
            print(f"  {WHITE}  Enter dorks (one per line, empty to finish):{RESET}")
            dorks = []
            while True:
                try:
                    line = input(f"  {CYAN}  dork> {RESET}").strip()
                except (EOFError, KeyboardInterrupt):
                    break
                if not line:
                    break
                dorks.append(line)
        else:
            fpath = _ask("Path to dorks file", "dorks.txt")
            p = Path(fpath).expanduser().resolve()
            if p.is_file():
                dorks = load_dorks_from_file(str(p))
            elif Path(fpath).is_file():
                dorks = load_dorks_from_file(fpath)
            else:
                print(f"  {RED}  [!] File not found: {fpath}{RESET}")
                return []

    if not dorks:
        print(f"  {RED}  [!] No dorks provided.{RESET}")
        return []

    print(f"  {GREEN}  [+] {len(dorks)} dorks loaded{RESET}")

    pages = _ask_int("Pages per dork", 1)
    concurrency = _ask_int("Max concurrency", 5)

    # Calculate estimated queries
    estimated = len(dorks) * pages
    print()
    print(f"  {WHITE}  Estimated API queries: {YELLOW}{BOLD}{estimated}{RESET}")
    print(f"  {WHITE}  Queries remaining:     {GREEN}{BOLD}{total_remaining:,}{RESET}")

    if estimated > total_remaining:
        print(f"  {RED}{BOLD}  [!] Not enough queries! Need {estimated}, have {total_remaining}.{RESET}")
        cont = _ask_yes_no("Continue anyway? (will stop when exhausted)", default=False)
        if not cont:
            return []

    # Proxy option
    proxies: list[str] = []
    if cfg.proxy.enabled and cfg.proxy.proxies:
        use_proxy = _ask_yes_no(
            f"Use proxies? ({len(cfg.proxy.proxies)} configured)", default=False
        )
        if use_proxy:
            proxies = list(cfg.proxy.proxies)

    print()
    confirm = _ask_yes_no(f"Start PREMIUM search ({estimated} API queries)?", default=True)
    if not confirm:
        return []

    print()
    print(f"  {MAGENTA}  Starting PREMIUM search via Serper.dev API...{RESET}")
    print()

    from hunter.config import SerperConfig
    serper_cfg = SerperConfig()
    serper_cfg.api_keys = cfg.serper.api_keys
    serper_cfg.pages_per_query = pages
    serper_cfg.search_concurrency = concurrency

    api_engine = SearchEngine(serper_cfg, proxies=proxies)
    api_engine._get_queries = lambda: dorks  # type: ignore[assignment]

    urls_raw = asyncio.run(api_engine.search_all())

    # Record usage
    queries_made = len(dorks) * pages
    # Distribute usage across keys evenly
    if cfg.serper.api_keys:
        per_key = queries_made // len(cfg.serper.api_keys)
        remainder = queries_made % len(cfg.serper.api_keys)
        for i, key in enumerate(cfg.serper.api_keys):
            usage = per_key + (1 if i < remainder else 0)
            if usage > 0:
                _quota.record_usage(key, usage)

    # Sanitize URLs
    urls = []
    for u in urls_raw:
        clean = _sanitize_url(u)
        if clean and clean not in urls:
            urls.append(clean)

    # Updated quota
    new_remaining = _quota.get_total_available(cfg.serper.api_keys)

    # Results
    print()
    print(f"  {LINE}")
    print(f"  {BOLD}{WHITE}  HUNT RESULTS (PREMIUM){RESET}")
    print(f"  {LINE_THIN}")
    print(f"    {WHITE}Mode:{RESET}             {MAGENTA}{BOLD}PREMIUM{RESET} (Serper.dev API)")
    print(f"    {WHITE}Dorks Processed:{RESET}   {GREEN}{len(dorks)}{RESET}")
    print(f"    {WHITE}URLs Extracted:{RESET}    {GREEN}{BOLD}{len(urls)}{RESET}")
    print(f"    {WHITE}API Queries Used:{RESET}  {YELLOW}{queries_made}{RESET}")
    print(f"    {WHITE}Queries Left:{RESET}      {GREEN}{new_remaining:,}{RESET}")

    if urls:
        print()
        print(f"  {CYAN}  Preview (first 10):{RESET}")
        for i, url in enumerate(urls[:10], 1):
            print(f"    {DIM}{i:>3}.{RESET} {BLUE}{url[:80]}{RESET}")
        if len(urls) > 10:
            print(f"    {DIM}    ... and {len(urls) - 10} more{RESET}")

        print()
        save = _ask_yes_no("Save to file?", default=True)
        if save:
            fname = _ask("Filename", "extracted_urls.txt")
            fpath = Path(fname)
            with open(fpath, "w", encoding="utf-8") as f:
                f.write("\n".join(urls) + "\n")
            print(f"  {GREEN}  [+] Saved {len(urls)} URLs to {fpath}{RESET}")
    else:
        print(f"  {YELLOW}  [*] No URLs extracted. Try different dorks.{RESET}")

    print()
    return urls


# ---------------------------------------------------------------------------
# 4. Generate & Hunt
# ---------------------------------------------------------------------------

def _run_generate_and_hunt() -> None:
    dorks = _run_generate()
    if not dorks:
        return

    print()
    print(f"  {WHITE}  Choose hunting mode:{RESET}")
    print(f"    {GREEN}1{RESET}  {WHITE}FREE{RESET}    {DIM}(scrape engines, no API key){RESET}")
    print(f"    {MAGENTA}2{RESET}  {WHITE}PREMIUM{RESET} {DIM}(Serper.dev API, uses quota){RESET}")
    print()
    mode = _ask("Select mode", "1")

    if mode == "2":
        _run_hunt_premium(dorks)
    else:
        _run_hunt_free(dorks)


# ---------------------------------------------------------------------------
# 5. Security Scan
# ---------------------------------------------------------------------------

def _run_scan(urls: list[str] | None = None) -> None:
    print()
    print(f"  {CYAN}{BOLD}  Security Scanner (SQLi / XSS){RESET}")
    print(f"  {LINE_THIN}")
    print(f"  {DIM}  Safe detection mode -- no invasive payloads.{RESET}")
    print()

    # --- Get URLs ---
    if not urls:
        print(f"  {WHITE}  How to provide URLs:{RESET}")
        print(f"    {GREEN}1{RESET} Enter manually")
        print(f"    {GREEN}2{RESET} Load from file")
        print()

        choice = _ask("Select", "2")
        if choice == "1":
            print(f"  {WHITE}  Enter URLs (one per line, empty to finish):{RESET}")
            urls = []
            while True:
                try:
                    line = input(f"  {CYAN}  url> {RESET}").strip()
                except (EOFError, KeyboardInterrupt):
                    break
                if not line:
                    break
                clean = _sanitize_url(line)
                if clean:
                    urls.append(clean)
                else:
                    print(f"  {YELLOW}  [!] Skipped invalid URL: {line}{RESET}")
        else:
            fpath = _ask("Path to URLs file", "extracted_urls.txt")
            p = Path(fpath).expanduser().resolve()
            if p.is_file():
                raw_lines = [line.strip() for line in p.read_text().splitlines() if line.strip()]
                urls = []
                for line in raw_lines:
                    clean = _sanitize_url(line)
                    if clean:
                        urls.append(clean)
            elif Path(fpath).is_file():
                raw_lines = [line.strip() for line in Path(fpath).read_text().splitlines() if line.strip()]
                urls = []
                for line in raw_lines:
                    clean = _sanitize_url(line)
                    if clean:
                        urls.append(clean)
            else:
                print(f"  {RED}  [!] File not found: {fpath}{RESET}")
                return

    if not urls:
        print(f"  {RED}  [!] No URLs provided.{RESET}")
        return

    print(f"  {GREEN}  [+] {len(urls)} valid URLs loaded{RESET}")

    # --- Configuration ---
    print()
    print(f"  {CYAN}{BOLD}  Scan Configuration{RESET}")
    print(f"  {LINE_THIN}")

    concurrency = _ask_int("Max concurrency (threads)", 20)
    timeout = _ask_int("Timeout per request (seconds)", 10)
    rate_limit = _ask_int("Rate limit (requests/sec, 0=unlimited)", 50)
    detect_sqli = _ask_yes_no("Detect SQL Injection?", default=True)
    detect_xss = _ask_yes_no("Detect XSS?", default=True)
    output_dir = _ask("Output directory", "scan_results")

    # Proxy option
    cfg = get_hunter_config()
    proxies: list[str] = []
    if cfg.proxy.enabled and cfg.proxy.proxies:
        use_proxy = _ask_yes_no(
            f"Use proxies? ({len(cfg.proxy.proxies)} configured)", default=False
        )
        if use_proxy:
            proxies = list(cfg.proxy.proxies)

    config = ScanConfig(
        max_concurrency=concurrency,
        timeout_seconds=float(timeout),
        rate_limit_rps=float(rate_limit),
        detect_sqli=detect_sqli,
        detect_xss=detect_xss,
        output_dir=output_dir,
    )

    # --- Progress callback ---
    def _on_progress(current: int, total: int, url: str) -> None:
        bar_len = 30
        filled = int(bar_len * current / total) if total else 0
        bar = f"{GREEN}{'#' * filled}{DIM}{'-' * (bar_len - filled)}{RESET}"
        pct = (current / total * 100) if total else 0
        print(
            f"\r  [{bar}] {pct:5.1f}% ({current}/{total})  "
            f"{DIM}{url[:50]}{RESET}      ",
            end="", flush=True,
        )

    print()
    print(f"  {CYAN}  Starting security scan...{RESET}")
    print()

    orchestrator = ScanOrchestrator(config)
    report = asyncio.run(orchestrator.scan_and_export(urls, on_progress=_on_progress))

    # --- Results ---
    print()  # newline after progress bar
    print()
    print(f"  {LINE}")
    print(f"  {BOLD}{WHITE}  SECURITY SCAN RESULTS{RESET}")
    print(f"  {LINE_THIN}")
    print(f"    {WHITE}URLs Scanned:{RESET}     {GREEN}{report.total_urls}{RESET}")
    print(f"    {WHITE}Findings:{RESET}         {_colorize_count(report.total_findings)}")
    for vtype, count in sorted(report.vuln_counts.items()):
        print(f"      {WHITE}{vtype}:{RESET}  {_colorize_count(count)}")
    print(f"    {WHITE}Output:{RESET}           {GREEN}{output_dir}/{RESET}")

    # Show top findings
    vuln_results = [r for r in report.results if r.status == ScanStatus.VULNERABLE]
    if vuln_results:
        print()
        print(f"  {RED}{BOLD}  Vulnerable URLs:{RESET}")
        for r in vuln_results[:15]:
            print(f"    {RED}*{RESET} {r.url[:75]}")
            for f in r.findings:
                color = RED if f.confidence in (Confidence.HIGH, Confidence.MEDIUM) else YELLOW
                print(
                    f"      {color}[{f.confidence.value.upper():^6}]{RESET} "
                    f"{f.vuln_type.value} | param={f.parameter}"
                )
                print(f"             {DIM}{f.evidence[:80]}{RESET}")
        if len(vuln_results) > 15:
            print(f"    {DIM}    ... and {len(vuln_results) - 15} more{RESET}")
    else:
        print()
        print(f"  {GREEN}  No vulnerabilities detected.{RESET}")

    print()


def _colorize_count(n: int) -> str:
    if n == 0:
        return f"{GREEN}{BOLD}0{RESET}"
    return f"{RED}{BOLD}{n}{RESET}"


# ---------------------------------------------------------------------------
# 6. Settings
# ---------------------------------------------------------------------------

def _run_settings() -> None:
    while True:
        _clear()
        print()
        print(f"  {LINE}")
        print(f"  {YELLOW}{BOLD}  SETTINGS{RESET}")
        print(f"  {LINE}")
        print()

        cfg = get_hunter_config(force_reload=True)

        # Status overview
        n_keys = len(cfg.serper.api_keys)
        total_remaining = _quota.get_total_available(cfg.serper.api_keys)
        proxy_count = len(cfg.proxy.proxies)
        proxy_on = cfg.proxy.enabled

        print(f"  {WHITE}{BOLD}  Current Status{RESET}")
        print(f"  {LINE_THIN}")
        print(f"    {WHITE}Serper API Keys:{RESET}  {GREEN if n_keys else RED}{n_keys} key(s){RESET}")
        print(f"    {WHITE}Query Quota:{RESET}      {GREEN}{total_remaining:,}{RESET} / {n_keys * QUERIES_PER_KEY:,} remaining")
        print(f"    {WHITE}Proxy Mode:{RESET}       {'%sEnabled (%d proxies)%s' % (GREEN, proxy_count, RESET) if proxy_on else '%sDisabled%s' % (DIM, RESET)}")
        print()

        print(f"  {WHITE}{BOLD}  Options{RESET}")
        print(f"  {LINE_THIN}")
        print(f"    {YELLOW}{BOLD}[1]{RESET} {WHITE}Manage API Keys{RESET}       {DIM}Add/remove Serper.dev keys{RESET}")
        print(f"    {YELLOW}{BOLD}[2]{RESET} {WHITE}Manage Proxies{RESET}        {DIM}Add/test/toggle proxies{RESET}")
        print(f"    {YELLOW}{BOLD}[3]{RESET} {WHITE}View Quota Details{RESET}    {DIM}See per-key usage & remaining{RESET}")
        print(f"    {YELLOW}{BOLD}[4]{RESET} {WHITE}Reset Quota Counters{RESET}  {DIM}Reset all query counts to 0{RESET}")
        print()
        print(f"    {DIM}[0] Back to main menu{RESET}")
        print()

        choice = _ask("Select")
        if choice == "0" or not choice:
            break
        elif choice == "1":
            _settings_api_keys()
        elif choice == "2":
            _settings_proxies()
        elif choice == "3":
            _settings_quota()
        elif choice == "4":
            _settings_reset_quota()


def _settings_api_keys() -> None:
    """Manage Serper.dev API keys."""
    print()
    print(f"  {YELLOW}{BOLD}  API Key Management{RESET}")
    print(f"  {LINE_THIN}")
    print(f"  {DIM}  Serper.dev API keys for PREMIUM mode.{RESET}")
    print(f"  {DIM}  Get free keys at: https://serper.dev{RESET}")
    print(f"  {DIM}  Each key = {QUERIES_PER_KEY} free queries.{RESET}")
    print()

    cfg = get_hunter_config(force_reload=True)
    current_keys = cfg.serper.api_keys

    if current_keys:
        print(f"  {WHITE}  Current Keys ({len(current_keys)}):{RESET}")
        for i, key in enumerate(current_keys, 1):
            masked = key[:6] + "..." + key[-4:] if len(key) > 12 else "***"
            remaining = _quota.get_remaining(key)
            print(f"    {GREEN}{i}{RESET}  {masked}  {DIM}({remaining:,} queries left){RESET}")
        print()

    print(f"  {WHITE}  Options:{RESET}")
    print(f"    {GREEN}1{RESET}  Add new key(s)")
    print(f"    {GREEN}2{RESET}  Replace all keys")
    print(f"    {GREEN}3{RESET}  Remove a key")
    print(f"    {DIM}0  Back{RESET}")
    print()

    action = _ask("Select", "1")

    if action == "1":
        print(f"  {WHITE}  Enter API keys (one per line, empty to finish):{RESET}")
        new_keys = list(current_keys)
        while True:
            try:
                line = input(f"  {CYAN}  key> {RESET}").strip()
            except (EOFError, KeyboardInterrupt):
                break
            if not line:
                break
            if line not in new_keys:
                new_keys.append(line)
                print(f"  {GREEN}  [+] Added key ...{line[-6:]}{RESET}")
            else:
                print(f"  {YELLOW}  [!] Key already exists{RESET}")

        persisted = _load_persisted_settings()
        persisted["serper_api_keys"] = new_keys
        save_settings(persisted)
        print(f"  {GREEN}  [+] Saved {len(new_keys)} API key(s).{RESET}")

    elif action == "2":
        print(f"  {WHITE}  Enter all API keys (one per line, empty to finish):{RESET}")
        new_keys: list[str] = []
        while True:
            try:
                line = input(f"  {CYAN}  key> {RESET}").strip()
            except (EOFError, KeyboardInterrupt):
                break
            if not line:
                break
            if line not in new_keys:
                new_keys.append(line)

        if new_keys:
            persisted = _load_persisted_settings()
            persisted["serper_api_keys"] = new_keys
            save_settings(persisted)
            print(f"  {GREEN}  [+] Saved {len(new_keys)} API key(s).{RESET}")
        else:
            print(f"  {YELLOW}  [!] No keys entered, nothing changed.{RESET}")

    elif action == "3" and current_keys:
        idx = _ask_int("Key number to remove", 1)
        if 1 <= idx <= len(current_keys):
            removed = current_keys.pop(idx - 1)
            persisted = _load_persisted_settings()
            persisted["serper_api_keys"] = current_keys
            save_settings(persisted)
            print(f"  {RED}  [-] Removed key ...{removed[-6:]}{RESET}")

    print()
    input(f"  {DIM}  Press Enter to continue...{RESET}")


def _settings_proxies() -> None:
    """Manage proxy configuration."""
    print()
    print(f"  {YELLOW}{BOLD}  Proxy Configuration{RESET}")
    print(f"  {LINE_THIN}")
    print(f"  {DIM}  Format: ip:port or socks5://ip:port{RESET}")
    print()

    cfg = get_hunter_config(force_reload=True)

    print(f"  {WHITE}  Status:{RESET} {'%sEnabled%s' % (GREEN, RESET) if cfg.proxy.enabled else '%sDisabled%s' % (RED, RESET)}")
    print(f"  {WHITE}  Proxies:{RESET} {len(cfg.proxy.proxies)} configured")
    print()

    print(f"  {WHITE}  Options:{RESET}")
    print(f"    {GREEN}1{RESET}  {'Disable' if cfg.proxy.enabled else 'Enable'} proxy mode")
    print(f"    {GREEN}2{RESET}  Add proxies (manual)")
    print(f"    {GREEN}3{RESET}  Load proxies from file")
    print(f"    {GREEN}4{RESET}  View current proxies")
    print(f"    {GREEN}5{RESET}  Clear all proxies")
    print(f"    {DIM}0  Back{RESET}")
    print()

    action = _ask("Select", "1")

    if action == "1":
        persisted = _load_persisted_settings()
        new_state = not cfg.proxy.enabled
        persisted["proxy_enabled"] = new_state
        save_settings(persisted)
        print(f"  {GREEN}  [+] Proxy mode {'enabled' if new_state else 'disabled'}.{RESET}")

    elif action == "2":
        print(f"  {WHITE}  Enter proxies (one per line, empty to finish):{RESET}")
        proxies = list(cfg.proxy.proxies)
        while True:
            try:
                line = input(f"  {CYAN}  proxy> {RESET}").strip()
            except (EOFError, KeyboardInterrupt):
                break
            if not line:
                break
            if line not in proxies:
                proxies.append(line)
        persisted = _load_persisted_settings()
        persisted["proxies"] = proxies
        persisted["proxy_enabled"] = True
        save_settings(persisted)
        print(f"  {GREEN}  [+] Saved {len(proxies)} proxies. Proxy mode enabled.{RESET}")

    elif action == "3":
        fpath = _ask("Path to proxy file", "proxies.txt")
        p = Path(fpath).expanduser().resolve()
        if p.is_file():
            lines = [l.strip() for l in p.read_text().splitlines() if l.strip()]
            persisted = _load_persisted_settings()
            persisted["proxies"] = lines
            persisted["proxy_enabled"] = True
            save_settings(persisted)
            print(f"  {GREEN}  [+] Loaded {len(lines)} proxies. Proxy mode enabled.{RESET}")
        else:
            print(f"  {RED}  [!] File not found: {fpath}{RESET}")

    elif action == "4":
        if cfg.proxy.proxies:
            print(f"  {WHITE}  Current Proxies:{RESET}")
            for i, p in enumerate(cfg.proxy.proxies, 1):
                print(f"    {DIM}{i:>3}.{RESET} {p}")
        else:
            print(f"  {YELLOW}  No proxies configured.{RESET}")

    elif action == "5":
        persisted = _load_persisted_settings()
        persisted["proxies"] = []
        persisted["proxy_enabled"] = False
        save_settings(persisted)
        print(f"  {GREEN}  [+] All proxies cleared. Proxy mode disabled.{RESET}")

    print()
    input(f"  {DIM}  Press Enter to continue...{RESET}")


def _settings_quota() -> None:
    """View detailed quota information."""
    print()
    print(f"  {YELLOW}{BOLD}  API Quota Details{RESET}")
    print(f"  {LINE_THIN}")
    print()

    cfg = get_hunter_config(force_reload=True)
    _quota.show_status(cfg.serper.api_keys)

    print()
    input(f"  {DIM}  Press Enter to continue...{RESET}")


def _settings_reset_quota() -> None:
    """Reset all quota counters."""
    print()
    cfg = get_hunter_config(force_reload=True)

    if not cfg.serper.api_keys:
        print(f"  {YELLOW}  No API keys configured.{RESET}")
        input(f"  {DIM}  Press Enter to continue...{RESET}")
        return

    confirm = _ask_yes_no("Reset ALL quota counters to 0?", default=False)
    if confirm:
        for key in cfg.serper.api_keys:
            _quota.reset_key(key)
        print(f"  {GREEN}  [+] All quota counters reset to 0.{RESET}")
        print(f"  {GREEN}  [+] {len(cfg.serper.api_keys) * QUERIES_PER_KEY:,} total queries available.{RESET}")
    else:
        print(f"  {DIM}  Cancelled.{RESET}")

    print()
    input(f"  {DIM}  Press Enter to continue...{RESET}")


# ---------------------------------------------------------------------------
# 7. Web Interface
# ---------------------------------------------------------------------------

def _run_web() -> None:
    print()
    print(f"  {CYAN}{BOLD}  Web Interface{RESET}")
    print(f"  {LINE_THIN}")
    print()
    print(f"  {WHITE}  Starting Flask server...{RESET}")
    print(f"  {GREEN}  Open http://localhost:5000 in your browser{RESET}")
    print(f"  {DIM}  Press Ctrl+C to stop{RESET}")
    print()

    from app import app
    app.run(debug=False, host="0.0.0.0", port=5000)


# ---------------------------------------------------------------------------
# 8. Help
# ---------------------------------------------------------------------------

def _show_help() -> None:
    print()
    print(f"  {CYAN}{BOLD}  DorkMaster - Usage Guide{RESET}")
    print(f"  {LINE_THIN}")
    print()
    print(f"  {WHITE}{BOLD}  What is DorkMaster?{RESET}")
    print(f"  {DIM}  A unified tool combining dork generation, URL extraction,")
    print(f"  and security scanning.  Generate dorks, hunt URLs, scan for vulns.{RESET}")
    print()
    print(f"  {WHITE}{BOLD}  Generator:{RESET}")
    print(f"  {DIM}  - Supports: Google, Bing, DuckDuckGo, Yahoo, Yandex, Baidu, Shodan, GitHub")
    print(f"  - Combines operators, keywords, and filetypes")
    print(f"  - Validates syntax per engine")
    print(f"  - Export to TXT, CSV, JSON{RESET}")
    print()
    print(f"  {WHITE}{BOLD}  Hunter (FREE Mode):{RESET}")
    print(f"  {DIM}  - Engines: DuckDuckGo, Bing, Yahoo, Google, Ask.com")
    print(f"  - {GREEN}NO API KEY NEEDED{RESET}{DIM} -- scrape directly, no limits")
    print(f"  - Multi-page search for deeper coverage")
    print(f"  - Concurrent execution with proxy support{RESET}")
    print()
    print(f"  {WHITE}{BOLD}  Hunter (PREMIUM Mode):{RESET}")
    print(f"  {DIM}  - Engine: {MAGENTA}Serper.dev{RESET}{DIM} (Google results via API)")
    print(f"  - Requires API key (get at serper.dev)")
    print(f"  - {YELLOW}{QUERIES_PER_KEY} free queries per key{RESET}{DIM}")
    print(f"  - Built-in quota tracking per key{RESET}")
    print()
    print(f"  {WHITE}{BOLD}  Security Scanner:{RESET}")
    print(f"  {DIM}  - Safe, detection-based analysis (no exploit payloads)")
    print(f"  - SQL Injection (SQLi) heuristic detection")
    print(f"  - Cross-Site Scripting (XSS) reflection detection")
    print(f"  - Async with configurable concurrency & rate-limiting")
    print(f"  - Output: CLI + JSON + TXT + CSV reports{RESET}")
    print()
    print(f"  {WHITE}{BOLD}  Settings:{RESET}")
    print(f"  {DIM}  - Manage API keys (add/remove Serper.dev keys)")
    print(f"  - Configure proxies (add/load/test/toggle)")
    print(f"  - Monitor API quota usage per key")
    print(f"  - Reset quota counters{RESET}")
    print()
    input(f"  {DIM}  Press Enter to return...{RESET}")


# ---------------------------------------------------------------------------
# Entry-point
# ---------------------------------------------------------------------------

def main() -> None:
    while True:
        choice = _show_menu()

        if choice == "0":
            print()
            print(f"  {CYAN}  Goodbye!{RESET}")
            print()
            sys.exit(0)

        dispatch = {
            "1": lambda: _run_generate(),
            "2": lambda: _run_hunt_free(),
            "3": lambda: _run_hunt_premium(),
            "4": lambda: _run_generate_and_hunt(),
            "5": lambda: _run_scan(),
            "6": lambda: _run_settings(),
            "7": lambda: _run_web(),
            "8": lambda: _show_help(),
        }

        try:
            dispatch[choice]()
        except KeyboardInterrupt:
            print(f"\n  {YELLOW}  [*] Interrupted.{RESET}")
            continue
        except Exception as exc:
            print(f"\n  {RED}{BOLD}  Error: {exc}{RESET}")
            import traceback
            traceback.print_exc()
            continue

        if choice not in ("6", "7", "8", "0"):
            print()
            input(f"  {DIM}  Press Enter to return to the menu...{RESET}")


if __name__ == "__main__":
    main()
