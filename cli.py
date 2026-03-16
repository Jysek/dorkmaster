"""
DorkMaster CLI - Interactive Command Line Interface
=====================================================

Unified CLI combining dork generation (DorkBoxer) and
dork hunting (DorkHunter) into a single interactive tool.
"""

from __future__ import annotations

import asyncio
import os
import sys
from pathlib import Path

# Ensure project root is on the path
sys.path.insert(0, str(Path(__file__).resolve().parent))

from core import __version__, __app_name__
from core.engine import DorkConfig, DorkGenerator
from hunter.config import HunterConfig
from hunter.search.free_engine import FreeSearchEngine, AVAILABLE_ENGINES
from hunter.orchestrator import load_dorks_from_file

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
        sys.exit(0)
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
    print(f"  {BOLD}{WHITE}  Dork Generator & Hunter{RESET}  {DIM}v{__version__}{RESET}")
    print(f"  {DIM}  Generate dorks, search engines, extract URLs{RESET}")
    print()
    print(f"  {LINE}")
    print()


# ---------------------------------------------------------------------------
# Main menu
# ---------------------------------------------------------------------------

def _show_menu() -> str:
    _show_banner()

    print(f"  {BOLD}{WHITE}  OPERATIONS{RESET}")
    print(f"  {LINE_THIN}")
    print()

    menu_items = [
        ("1", "Generate Dorks", "Create dork queries for any search engine"),
        ("2", "Hunt URLs", "Search dorks and extract URLs (free engines)"),
        ("3", "Generate & Hunt", "Generate dorks then immediately hunt"),
        ("4", "Web Interface", "Launch the web UI in your browser"),
        ("5", "Help", "Usage guide & tips"),
    ]
    for num, label, desc in menu_items:
        print(
            f"  {GREEN}{BOLD}  [{num}] {RESET}"
            f"{WHITE}{label:<20}{RESET} {DIM}{desc}{RESET}"
        )

    print()
    print(f"  {RED}{BOLD}  [0] {RESET} {DIM}Exit{RESET}")
    print()

    valid = {"0", "1", "2", "3", "4", "5"}
    while True:
        choice = _ask("Select an operation")
        if choice in valid:
            return choice
        print(f"  {RED}  [!] Invalid choice. Enter 0-5.{RESET}")


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
    keywords = []
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
        selected_ops = []
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
    selected_ft = []
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
# 2. Hunt URLs
# ---------------------------------------------------------------------------

def _run_hunt(dorks: list[str] | None = None) -> list[str]:
    print()
    print(f"  {CYAN}{BOLD}  Dork Hunter{RESET}")
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
            else:
                # Try relative to CWD
                if Path(fpath).is_file():
                    dorks = load_dorks_from_file(fpath)
                else:
                    print(f"  {RED}  [!] File not found: {fpath}{RESET}")
                    return []

    if not dorks:
        print(f"  {RED}  [!] No dorks provided.{RESET}")
        return []

    print(f"  {GREEN}  [+] {len(dorks)} dorks loaded{RESET}")

    # Engine selection
    print()
    print(f"  {CYAN}{BOLD}  Select Search Engines{RESET}")
    print(f"  {LINE_THIN}")
    engine_info = {
        "duckduckgo": ("DuckDuckGo", "Most reliable, no JS needed"),
        "bing": ("Bing", "Good results, fast"),
        "yahoo": ("Yahoo", "Decent coverage"),
        "google": ("Google", "Best results but may block scrapers"),
        "ask": ("Ask.com", "Extra coverage"),
    }
    for i, eng in enumerate(AVAILABLE_ENGINES, 1):
        name, desc = engine_info.get(eng, (eng, ""))
        print(f"    {GREEN}{i}{RESET}  {WHITE}{name:<15}{RESET} {DIM}{desc}{RESET}")
    print(f"    {GREEN}A{RESET}  {WHITE}All Engines{RESET}")
    print()

    raw = _ask("Select engines (comma-separated, e.g. 1,2 or A)", "1,2")
    if raw.lower().strip() == "a":
        engines = list(AVAILABLE_ENGINES)
    else:
        engines = []
        for part in raw.split(","):
            part = part.strip()
            try:
                idx = int(part) - 1
                if 0 <= idx < len(AVAILABLE_ENGINES):
                    engines.append(AVAILABLE_ENGINES[idx])
            except ValueError:
                if part.lower() in AVAILABLE_ENGINES:
                    engines.append(part.lower())
    if not engines:
        engines = ["duckduckgo", "bing"]

    names = [engine_info.get(e, (e, ""))[0] for e in engines]
    print(f"  {GREEN}  [+] Engines: {', '.join(names)}{RESET}")

    pages = _ask_int("Pages per dork", 1)
    concurrency = _ask_int("Max concurrency", 3)

    print()
    print(f"  {CYAN}  Starting search...{RESET}")
    print()

    search_engine = FreeSearchEngine(
        queries=dorks,
        engines=engines,
        pages_per_dork=pages,
    )

    urls = asyncio.run(search_engine.search_all(max_concurrency=concurrency))

    # Results
    print()
    print(f"  {LINE}")
    print(f"  {BOLD}{WHITE}  HUNT RESULTS{RESET}")
    print(f"  {LINE_THIN}")
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
# 3. Generate & Hunt
# ---------------------------------------------------------------------------

def _run_generate_and_hunt() -> None:
    dorks = _run_generate()
    if not dorks:
        return

    print()
    hunt = _ask_yes_no("Send these dorks to the Hunter?", default=True)
    if hunt:
        _run_hunt(dorks)


# ---------------------------------------------------------------------------
# 4. Web Interface
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
# 5. Help
# ---------------------------------------------------------------------------

def _show_help() -> None:
    print()
    print(f"  {CYAN}{BOLD}  DorkMaster - Usage Guide{RESET}")
    print(f"  {LINE_THIN}")
    print()
    print(f"  {WHITE}{BOLD}  What is DorkMaster?{RESET}")
    print(f"  {DIM}  A unified tool combining dork generation and URL extraction.")
    print(f"  Generate dork queries for 8 search engines, then hunt for URLs.{RESET}")
    print()
    print(f"  {WHITE}{BOLD}  Generator:{RESET}")
    print(f"  {DIM}  - Supports: Google, Bing, DuckDuckGo, Yahoo, Yandex, Baidu, Shodan, GitHub")
    print(f"  - Combines operators, keywords, and filetypes")
    print(f"  - Validates syntax per engine")
    print(f"  - Export to TXT, CSV, JSON{RESET}")
    print()
    print(f"  {WHITE}{BOLD}  Hunter:{RESET}")
    print(f"  {DIM}  - Free mode: DuckDuckGo, Bing, Yahoo, Google, Ask.com")
    print(f"  - Multi-page search for deeper coverage")
    print(f"  - Concurrent execution")
    print(f"  - De-duplication and junk filtering")
    print(f"  - Export URLs to TXT, CSV, JSON{RESET}")
    print()
    print(f"  {WHITE}{BOLD}  Web Interface:{RESET}")
    print(f"  {DIM}  - Modern dark UI with tabbed Generator/Hunter")
    print(f"  - Real-time combination counter")
    print(f"  - Send generated dorks directly to Hunter")
    print(f"  - Syntax highlighting for dork queries{RESET}")
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
            "2": lambda: _run_hunt(),
            "3": lambda: _run_generate_and_hunt(),
            "4": lambda: _run_web(),
            "5": lambda: _show_help(),
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

        if choice not in ("4", "5", "0"):
            print()
            input(f"  {DIM}  Press Enter to return to the menu...{RESET}")


if __name__ == "__main__":
    main()
