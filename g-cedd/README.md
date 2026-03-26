# G-CEDD: Git & Config Exposure Deep-Dive

**Defensive Web Configuration Auditor** for internal compliance and security auditing.

G-CEDD helps DevOps and security teams detect accidentally exposed configuration files (`.git/`, `.env`, database dumps, etc.) on internal staging/production servers, and scan local files for leaked secrets using Shannon Entropy analysis combined with regex pattern matching.

## Features

- **Async Path Checker** - High-speed concurrent scanning of web servers for exposed config paths using `aiohttp`
- **Smart Secret Analyzer** - Dual-method detection combining regex patterns with Shannon Entropy to catch both known and novel secret formats
- **Rich CLI Output** - Beautiful terminal reporting via the `rich` library with severity/confidence classification
- **JSON Export** - Structured machine-readable reports for integration with CI/CD pipelines

## Installation

```bash
# Clone the repository
git clone https://github.com/jonyhossan110/g-cedd.git
cd g-cedd

# Install with pip
pip install -e .

# Or install with dev dependencies
pip install -e ".[dev]"
```

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

### Full audit with JSON report

```bash
g-cedd scan --targets http://staging.example.com --secrets-file .env --output report.json
```

### Scan specific file types in a directory

```bash
g-cedd secrets --dir ./project --extensions .env .yml .json .toml
```

## Configuration Options

### Path Scanner (`scan`)

| Option | Default | Description |
|--------|---------|-------------|
| `--targets` | (required) | Base URL(s) to scan |
| `--timeout` | 10.0 | HTTP request timeout (seconds) |
| `--concurrency` | 10 | Max concurrent requests |
| `--rate-limit` | 0.1 | Delay between requests (seconds) |
| `--secrets-file` | - | Also scan a local file for secrets |
| `--output` | g-cedd-report.json | JSON report output path |

### Secret Scanner (`secrets`)

| Option | Default | Description |
|--------|---------|-------------|
| `--file` | - | Single file to scan |
| `--dir` | - | Directory to scan recursively |
| `--extensions` | all | File extensions to include |
| `--output` | g-cedd-report.json | JSON report output path |

## Detected Secret Types

- AWS Access/Secret Keys
- GitHub Tokens (`ghp_`, `gho_`, etc.)
- Slack Tokens (`xoxb-`, `xoxp-`, etc.)
- Stripe Live Keys (`sk_live_`)
- JWT Tokens
- Private Key Blocks (RSA, EC, DSA, OPENSSH)
- Database Connection URLs (PostgreSQL, MySQL, MongoDB, Redis)
- Generic API Keys and Passwords
- SendGrid / Twilio Keys
- Bearer Tokens
- High-entropy strings (via Shannon Entropy analysis)

## Checked Paths

The scanner checks 20+ commonly exposed paths including:

- `/.git/HEAD`, `/.git/config`
- `/.env`, `/.env.local`, `/.env.production`
- `/docker-compose.yml`, `/Dockerfile`
- `/wp-config.php.bak`
- `/.htpasswd`, `/.htaccess`
- `/backup.sql`, `/dump.sql`
- And more...

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
```

## License

MIT
