# DorkMaster

Unified dork generation and URL extraction tool. Combines **DorkBoxer** (dork generator) and **DorkHunter** (URL extractor) into one powerful tool with both CLI and Web interfaces.

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

### Unified Interface
- **Web UI**: Modern dark theme with tabbed Generator/Hunter
- **CLI**: Interactive terminal with ASCII art banner
- **Generate & Hunt**: Generate dorks then immediately search them
- **Send to Hunter**: One-click transfer from Generator to Hunter

## Project Structure

```
dorkmaster/
├── app.py                      # Flask web application entry point
├── cli.py                      # Interactive CLI entry point
├── core/
│   ├── __init__.py             # Version info
│   └── engine.py               # Dork generation engine (config, builder, validator, generator)
├── config/
│   └── default_config.json     # Engine operators, filetypes, keywords, rules
├── hunter/
│   ├── config.py               # Hunter configuration (env-driven)
│   ├── orchestrator.py         # Search pipeline orchestrator
│   ├── search/
│   │   ├── engine.py           # Serper.dev API client
│   │   ├── free_engine.py      # Free multi-engine search (DDG/Bing/Yahoo/Google/Ask)
│   │   └── key_manager.py      # API key pool & rotation
│   ├── reporting/
│   │   └── exporter.py         # TXT/JSON/CSV export + realtime exporter
│   └── utils/
│       └── logging.py          # Structured logging
├── web/
│   ├── api.py                  # REST API endpoints (generator + hunter)
│   ├── views.py                # Page rendering routes
│   ├── routes.py               # Blueprint registration
│   ├── templates/
│   │   └── index.html          # Main UI template (tabbed Generator/Hunter)
│   └── static/
│       ├── css/style.css       # Dark theme styles
│       ├── js/app.js           # Frontend logic
│       └── favicon.svg
├── tests/
│   └── test_dorkmaster.py      # 34 tests (all passing)
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

## Web UI Features

- **Generator Tab**: Select engine, enter keywords, pick operators/filetypes, generate dorks
- **Hunter Tab**: Enter dorks, select search engines, extract URLs
- **Send to Hunter**: Button to transfer generated dorks directly to Hunter tab
- **Syntax Highlighting**: Color-coded operators, keywords, filetypes
- **Virtual Scrolling**: Handles 500K+ dorks without lag
- **Export**: Download results as TXT, CSV, or JSON

## Configuration

Environment variables (or `.env` file):

| Variable | Default | Description |
|---|---|---|
| `SERPER_API_KEYS` | *(optional)* | Comma-separated Serper.dev API keys |
| `QUERIES_FILE` | `dorks.txt` | Path to dork queries file |
| `FREE_SEARCH_ENGINES` | `duckduckgo,bing` | Default engines for free mode |
| `SEARCH_MAX_THREADS` | `10` | Max concurrent threads |

### Scanner Environment Variables

| Variable | Default | Description |
|---|---|---|
| `SCAN_MAX_CONCURRENCY` | `20` | Max concurrent scan requests |
| `SCAN_TIMEOUT` | `10` | Per-request timeout (seconds) |
| `SCAN_RATE_LIMIT_RPS` | `50` | Rate limit (requests/sec, 0=unlimited) |

## Tests

```bash
python -m pytest tests/ -v
```

All 80+ tests pass covering: config, builder, validator, generator, Flask API, hunter modules, scanner models, SQLi detector, XSS detector, orchestrator, reporting.

## License

MIT
