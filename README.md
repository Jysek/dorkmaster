# DorkMaster

Unified dork generation, URL extraction, and security scanning tool. Combines **DorkBoxer** (dork generator), **DorkHunter** (URL extractor), and **Scanner** (SQLi/XSS detector) into one powerful tool with both CLI and Web interfaces.

## Features

### Dork Generator
- **8 Search Engines**: Google, Bing, DuckDuckGo, Yahoo, Yandex, Baidu, Shodan, GitHub
- **Smart Syntax**: Correct operator syntax per engine (auto-quoting, boolean operators)
- **Combinatorial Generation**: Operators + keywords + filetypes = massive dork lists
- **Preset Categories**: Credentials, Infrastructure, Configuration, Error Pages, IoT, Cloud
- **Validation**: Mutually exclusive operators, length limits, duplicate detection
- **Export**: TXT, CSV, JSON

### Dork Hunter
- **5 Free Search Engines**: DuckDuckGo, Bing, Yahoo, Google, Ask.com
- **No API Keys Needed**: Free mode scrapes search engines directly
- **API Mode**: Optional Serper.dev API support with key rotation
- **Concurrent Execution**: Configurable parallelism
- **De-duplication**: Automatic URL dedup and junk filtering
- **Real-time Updates**: URLs saved as discovered

### Security Scanner
- **SQL Injection (SQLi)**: Error-based, boolean-differential, and timing detection
- **Cross-Site Scripting (XSS)**: Reflection detection with context analysis
- **Safe Detection**: No invasive payloads, heuristic analysis only
- **Async Pipeline**: Configurable concurrency and rate limiting
- **Missing Headers**: Flags absent security headers (CSP, X-XSS-Protection, etc.)
- **Export**: JSON, TXT, CSV scan reports

### Unified Interface
- **Web UI**: Modern dark theme with tabbed Generator/Hunter/Scanner/Settings
- **CLI**: Interactive terminal with ASCII art banner and 6 operations
- **Generate & Hunt**: Generate dorks then immediately search them
- **Hunt & Scan**: Extract URLs then scan them for vulnerabilities
- **Send to Hunter/Scanner**: One-click transfer between tabs

## Project Structure

```
dorkmaster/
├── app.py                      # Flask web application entry point
├── cli.py                      # Interactive CLI entry point
├── core/
│   ├── __init__.py             # Version info
│   └── engine.py               # Dork generation engine
├── config/
│   └── default_config.json     # Engine operators, filetypes, keywords, rules
├── hunter/
│   ├── config.py               # Hunter configuration (env-driven)
│   ├── orchestrator.py         # Search pipeline orchestrator
│   ├── search/
│   │   ├── engine.py           # Serper.dev API client
│   │   ├── free_engine.py      # Free multi-engine search
│   │   └── key_manager.py      # API key pool & rotation
│   ├── reporting/
│   │   └── exporter.py         # TXT/JSON/CSV export + realtime exporter
│   └── utils/
│       └── logging.py          # Structured logging
├── scanner/
│   ├── __init__.py             # Package exports
│   ├── models.py               # Data structures (ScanResult, ScanConfig, enums)
│   ├── orchestrator.py         # Async scan pipeline with concurrency control
│   ├── detectors/
│   │   ├── __init__.py         # Detector registry
│   │   ├── base.py             # Abstract detector interface
│   │   ├── sqli.py             # SQL Injection heuristic detector
│   │   └── xss.py              # Cross-Site Scripting heuristic detector
│   └── reporting/
│       └── exporter.py         # JSON / TXT / CSV scan report export
├── web/
│   ├── api.py                  # REST API endpoints (generator + hunter + scanner)
│   ├── views.py                # Page rendering routes
│   ├── routes.py               # Blueprint registration
│   ├── templates/
│   │   └── index.html          # Main UI template (tabbed interface)
│   └── static/
│       ├── css/style.css       # Dark theme styles
│       ├── js/app.js           # Frontend logic
│       └── favicon.svg
├── tests/
│   ├── test_dorkmaster.py      # Generator, Flask API, Hunter tests
│   └── test_scanner.py         # Scanner models, detectors, orchestrator tests
├── dorks.txt                   # Sample dork queries
├── requirements.txt
├── .env.example
└── .gitignore
```

## Quick Start

### Install

```bash
git clone https://github.com/Jysek/dorkmaster.git
cd dorkmaster
pip install -r requirements.txt
```

### Web Interface

```bash
python app.py
# Open http://localhost:5000
```

### CLI Interface

```bash
python cli.py
```

### Menu Options

| # | Operation | Description |
|---|-----------|-------------|
| 1 | **Generate Dorks** | Create dork queries for any search engine |
| 2 | **Hunt URLs** | Search dorks and extract URLs (free engines) |
| 3 | **Generate & Hunt** | Generate dorks then immediately hunt |
| 4 | **Security Scan** | Scan URLs for SQLi / XSS vulnerabilities |
| 5 | **Web Interface** | Launch the web UI |
| 6 | **Help** | Usage guide |

## Web UI Workflow

1. **Generator Tab**: Select engine, enter keywords, pick operators/filetypes, generate dorks
2. **Send to Hunter**: Click "Hunt" to transfer dorks to Hunter tab
3. **Hunter Tab**: Select search engines, extract URLs from dork queries
4. **Send to Scanner**: Click "Scan" to transfer URLs to Scanner tab
5. **Scanner Tab**: Configure detection options, scan URLs for SQLi/XSS
6. **Export**: Download results from any tab as TXT, CSV, or JSON

## Configuration

Environment variables (or `.env` file):

| Variable | Default | Description |
|---|---|---|
| `SERPER_API_KEYS` | *(optional)* | Comma-separated Serper.dev API keys |
| `QUERIES_FILE` | `dorks.txt` | Path to dork queries file |
| `FREE_SEARCH_ENGINES` | `duckduckgo,bing` | Default engines for free mode |
| `SEARCH_MAX_THREADS` | `10` | Max concurrent threads |
| `SCAN_MAX_CONCURRENCY` | `20` | Max concurrent scan requests |
| `SCAN_TIMEOUT` | `10` | Per-request timeout (seconds) |
| `SCAN_RATE_LIMIT_RPS` | `50` | Rate limit (requests/sec, 0=unlimited) |

## Tests

```bash
python -m pytest tests/ -v
```

All 95+ tests pass covering: config, builder, validator, generator, Flask API, hunter modules, scanner models, SQLi detector, XSS detector, orchestrator, reporting, scanner API endpoints.

## License

MIT
