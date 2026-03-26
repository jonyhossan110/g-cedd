# G-CEDD: Git & Config Exposure Deep-Dive

[![CI](https://github.com/jonyhossan110/g-cedd/actions/workflows/ci.yml/badge.svg)](https://github.com/jonyhossan110/g-cedd/actions/workflows/ci.yml)
[![PyPI version](https://badge.fury.io/py/g-codd.svg)](https://pypi.org/project/g-codd/)
[![Python 3.11+](https://img.shields.io/badge/python-3.11+-blue.svg)](https://www.python.org/downloads/)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)
[![Code style: ruff](https://img.shields.io/badge/code%20style-ruff-000000.svg)](https://github.com/charliermarsh/ruff)

**Defensive Web Configuration Auditor** for internal compliance and security auditing.

G-CEDD helps DevOps and security teams detect accidentally exposed configuration files (`.git/`, `.env`, database dumps, etc.) on internal staging/production servers, and scan local files for leaked secrets using Shannon Entropy analysis combined with regex pattern matching.

## Table of Contents

- [Features](#features)
- [Installation](#installation)
- [Quick Start](#quick-start)
- [Commands](#commands)
- [Configuration](#configuration-options)
- [Reports](#reports)
- [Development](#development)
- [Architecture](#architecture)
- [Contributing](#contributing)
- [License](#license)

## Features

- **Async Path Checker** - High-speed concurrent scanning of web servers for exposed config paths using `aiohttp`
- **Smart Secret Analyzer** - Dual-method detection combining regex patterns with Shannon Entropy to catch both known and novel secret formats
- **Blind Git Extractor** - Extract complete git repositories from exposed `.git` directories
- **Protocol Compliance Auditor** - HTTP method compliance testing (HEAD/OPTIONS) to detect misconfigured access controls
- **Go Fast Scanner** - High-performance Go-based scanner for massive-scale auditing (future integration)
- **Rich CLI Output** - Beautiful terminal reporting via the `rich` library with severity/confidence classification
- **HTML Dashboard** - Interactive web-based reports with severity-colored tables and embedded JSON data
- **JSON Export** - Structured machine-readable reports for integration with CI/CD pipelines
- **REST API Server** - Web service for serving scan results and integrating with other tools

## Quick Start

```bash
# Install G-CEDD
pip install g-codd

# Scan a server for exposed paths
g-cedd scan --targets https://example.com

# Check local files for secrets
g-cedd secrets --dir ./project

# Extract git repo from exposed .git
g-cedd extract --target https://example.com

# Start web dashboard
g-cedd serve --results-dir ./results
```

## Installation

### From PyPI (Recommended)

```bash
pip install g-codd
```

### From Source

```bash
# Clone the repository
git clone https://github.com/jonyhossan110/g-cedd.git
cd g-cedd

# Install with pip
pip install -e .

# Or install with dev dependencies
pip install -e ".[dev]"
```

### Requirements

- Python 3.11+
- pip (latest version recommended)

## Usage

### Check a staging server for exposed paths

```bash
g-cedd scan --targets http://staging.internal.example.com
```

### Scan multiple servers

```bash
g-cedd scan --targets http://server1.example.com http://server2.example.com
```

### Scan a local file for leaked secrets

```bash
g-cedd secrets --file .env.backup
```

### Scan a directory recursively

```bash
g-cedd secrets --dir ./config
```

### Extract git repository from exposed .git

```bash
g-cedd extract --target http://staging.example.com
```

### Protocol compliance audit

```bash
g-cedd protocol --targets http://staging.example.com
```

### Generate Go scanner scaffold

```bash
g-cedd go-scaffold --output-dir ./go_scanner
```

### Start REST API server

```bash
g-cedd serve --results-dir ./results
```

### Full audit with HTML report

```bash
g-cedd scan --targets http://staging.example.com --secrets-file .env --output report.json
```

### Scan specific file types in a directory

```bash
g-cedd secrets --dir ./project --extensions .env .yml .json .toml
```

## Commands

### `scan` - Path Exposure Scanner
Check target servers for exposed configuration paths with concurrent requests and rate limiting.

### `secrets` - Secret Analyzer
Scan local files or directories for leaked secrets using entropy analysis and pattern matching.

### `extract` - Git Extractor
Blind extraction of git repositories from servers with exposed `.git` directories.

### `protocol` - Protocol Compliance
HTTP method compliance auditing to detect misconfigured access controls and RFC violations.

### `go-scaffold` - Go Scanner Generator
Generate Go project scaffold for high-performance scanning (future: compiled binary integration).

### `serve` - REST API Server
Start a FastAPI server to expose scan results via REST endpoints.

## Configuration Options

### Path Scanner (`scan`)

| Option | Default | Description |
|--------|---------|-------------|
| `--targets` | (required) | Base URL(s) to scan |
| `--timeout` | 10.0 | HTTP request timeout (seconds) |
| `--concurrency` | 10 | Max concurrent requests |
| `--rate-limit` | 0.1 | Delay between requests (seconds) |
| `--secrets-file` | - | Also scan a local file for secrets |
| `--output` | timestamped | JSON report output path |

### Secret Scanner (`secrets`)

| Option | Default | Description |
|--------|---------|-------------|
| `--file` | - | Single file to scan |
| `--dir` | - | Directory to scan recursively |
| `--extensions` | all | File extensions to include |
| `--output` | timestamped | JSON report output path |

### Git Extractor (`extract`)

| Option | Default | Description |
|--------|---------|-------------|
| `--target` | (required) | Base URL of target server |
| `--max-depth` | 5 | Maximum git object graph depth |
| `--concurrency` | 10 | Max concurrent requests |
| `--workspace` | /tmp/gcedd_workspace | Object extraction directory |
| `--output` | timestamped | JSON report output path |

### Protocol Auditor (`protocol`)

| Option | Default | Description |
|--------|---------|-------------|
| `--targets` | (required) | Base URL(s) to test |
| `--paths` | common paths | Specific paths to test |
| `--timeout` | 10.0 | HTTP request timeout (seconds) |
| `--concurrency` | 10 | Max concurrent requests |
| `--output` | timestamped | JSON report output path |

## Detected Secret Types

- AWS Access/Secret Keys
- GitHub Tokens (`ghp_`, `gho_`, etc.)
- Slack Tokens (`xoxb-`, `xoxp-`, etc.)
- Stripe Live/Test Keys (`sk_live_`, `sk_test_`)
- JWT Tokens
- Private Key Blocks (RSA, EC, DSA, OPENSSH)
- Database Connection URLs (PostgreSQL, MySQL, MongoDB, Redis)
- Generic API Keys and Passwords
- SendGrid / Twilio Keys
- Bearer Tokens
- High-entropy strings (via Shannon Entropy analysis)

## Checked Paths

The scanner checks 20+ commonly exposed paths including:

- `/.git/HEAD`, `/.git/config`, `/.git/logs/`
- `/.env`, `/.env.local`, `/.env.production`
- `/docker-compose.yml`, `/Dockerfile`
- `/wp-config.php`, `/wp-config.php.bak`
- `/.htpasswd`, `/.htaccess`
- `/backup.sql`, `/dump.sql`
- `/server-status`, `/phpinfo.php`
- And more...

## Reports

### JSON Reports
Structured machine-readable reports with full scan details, suitable for CI/CD integration.

### HTML Dashboards
Interactive web reports with:
- Summary metric cards
- Severity-colored data tables
- Expandable JSON data viewer
- Responsive design
- Standalone (no external dependencies)

### REST API
FastAPI-based server exposing:
- Scan result listings
- Individual report retrieval
- JSON/CSV export endpoints
- Web dashboard interface

## Development

```bash
# Install dev dependencies
pip install -e ".[dev]"

# Run linter
ruff check g_cedd/

# Run type checker
mypy g_cedd/

# Run tests
pytest

# Build Go scanner (future)
cd go_scanner && go build -o gcedd-fast-scanner ./cmd/scanner
```

## Architecture

```
g_cedd/
├── cli.py              # Command-line interface
├── modules/
│   ├── banner.py       # ASCII art banner
│   ├── path_checker.py # Async HTTP path scanner
│   ├── secret_analyzer.py # Entropy + regex secret detection
│   ├── git_extractor.py # Blind git repository extraction
│   ├── protocol_checker.py # HTTP method compliance
│   ├── html_report.py  # Interactive HTML dashboards
│   ├── reporter.py     # Rich CLI output + JSON export
│   ├── serve.py        # FastAPI REST server
│   ├── workspace.py    # Organized report directories
│   └── go_scanner_stub.py # Go integration interface
└── utils/              # Future utilities
```

## Contributing

We welcome contributions! Please see our [Contributing Guide](CONTRIBUTING.md) for details on:

- Setting up a development environment
- Coding standards and style guidelines
- Testing requirements
- Submitting pull requests
- Reporting issues

## License

MIT
