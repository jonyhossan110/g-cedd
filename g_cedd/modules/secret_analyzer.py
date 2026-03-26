"""Module 2: Static Secret Analyzer - Shannon Entropy + regex-based secret detection."""

from __future__ import annotations

import math
import re
from collections.abc import Sequence
from dataclasses import dataclass
from pathlib import Path

# Pre-compiled regex patterns for known secret formats
SECRET_PATTERNS: dict[str, re.Pattern[str]] = {
    "AWS Access Key": re.compile(r"(?:^|[^A-Z0-9])([A-Z0-9]{20})(?:$|[^A-Z0-9])", re.MULTILINE),
    "AWS Secret Key": re.compile(
        r"""(?:aws_secret_access_key|secret_key|aws_secret)\s*[=:]\s*['"]?([A-Za-z0-9/+=]{40})['"]?""",
        re.IGNORECASE,
    ),
    "Generic API Key": re.compile(
        r"""(?:api[_-]?key|apikey|api[_-]?secret|api[_-]?token)\s*[=:]\s*['"]?([A-Za-z0-9_\-]{16,64})['"]?""",
        re.IGNORECASE,
    ),
    "GitHub Token": re.compile(r"(gh[pousr]_[A-Za-z0-9_]{36,255})"),
    "Slack Token": re.compile(r"(xox[bposatr]-[A-Za-z0-9\-]{10,250})"),
    "Stripe Key": re.compile(r"(sk_live_[A-Za-z0-9]{20,100})"),
    "JWT Token": re.compile(r"(eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,})"),
    "Private Key Block": re.compile(
        r"(-----BEGIN (?:RSA |EC |DSA |OPENSSH )?PRIVATE KEY-----)", re.MULTILINE
    ),
    "Database URL": re.compile(
        r"""((?:postgres|mysql|mongodb|redis|amqp)://[^\s'"]{10,})""", re.IGNORECASE
    ),
    "Password Assignment": re.compile(
        r"""(?:password|passwd|pwd|db_pass|secret)\s*[=:]\s*['"]([^'"]{8,128})['"]""",
        re.IGNORECASE,
    ),
    "Bearer Token": re.compile(
        r"""(?:bearer|authorization)\s*[=:]\s*['"]?(?:Bearer\s+)?([A-Za-z0-9_\-.]{20,})['"]?""",
        re.IGNORECASE,
    ),
    "Heroku API Key": re.compile(
        r"""(?:heroku[_-]?api[_-]?key)\s*[=:]\s*['"]?([0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12})['"]?""",
        re.IGNORECASE,
    ),
    "SendGrid Key": re.compile(r"(SG\.[A-Za-z0-9_-]{22}\.[A-Za-z0-9_-]{43})"),
    "Twilio Key": re.compile(r"(SK[0-9a-fA-F]{32})"),
}

# Minimum Shannon entropy threshold for flagging a string as potentially secret
ENTROPY_THRESHOLD = 4.0

# Minimum length for entropy-based detection
MIN_ENTROPY_STRING_LENGTH = 16

# Characters that high-entropy secrets typically use
HIGH_ENTROPY_CHARSET = re.compile(r"[A-Za-z0-9+/=_\-]{16,}")

# Common false positives to exclude
FALSE_POSITIVE_PATTERNS: list[re.Pattern[str]] = [
    re.compile(r"^[a-f0-9]{32}$"),  # MD5 hashes (often non-secret)
    re.compile(r"^https?://"),  # URLs (not secrets)
    re.compile(r"^[A-Z_]{16,}$"),  # All-caps constants (env var names)
    re.compile(r"^[a-z_]{16,}$"),  # All-lowercase (likely variable names)
    re.compile(r"^(true|false|null|none|undefined){2,}$", re.IGNORECASE),
    re.compile(r"^[0-9]+$"),  # Pure numbers
    re.compile(r"placeholder|example|changeme|fixme|todo", re.IGNORECASE),
]


@dataclass
class SecretFinding:
    """A single detected secret finding."""

    file_path: str
    line_number: int
    line_content: str
    secret_type: str
    matched_value: str
    entropy: float
    confidence: str  # "high", "medium", "low"

    def to_dict(self) -> dict[str, str | int | float]:
        return {
            "file_path": self.file_path,
            "line_number": self.line_number,
            "line_content": self.line_content,
            "secret_type": self.secret_type,
            "matched_value": _redact(self.matched_value),
            "entropy": round(self.entropy, 3),
            "confidence": self.confidence,
        }


def _redact(value: str, visible_chars: int = 6) -> str:
    """Redact a secret value, showing only the first few characters."""
    if len(value) <= visible_chars:
        return "*" * len(value)
    return value[:visible_chars] + "*" * (len(value) - visible_chars)


def shannon_entropy(data: str) -> float:
    """
    Calculate the Shannon entropy of a string.

    Higher entropy means more randomness (passwords, API keys).
    English text typically has entropy ~3.5-4.5 bits/char.
    Random base64 strings have entropy ~5.5-6.0 bits/char.
    """
    if not data:
        return 0.0

    frequency: dict[str, int] = {}
    for char in data:
        frequency[char] = frequency.get(char, 0) + 1

    length = len(data)
    entropy = 0.0
    for count in frequency.values():
        probability = count / length
        if probability > 0:
            entropy -= probability * math.log2(probability)

    return entropy


def _is_false_positive(value: str) -> bool:
    """Check if a matched value is a common false positive."""
    return any(pattern.match(value) for pattern in FALSE_POSITIVE_PATTERNS)


def _classify_confidence(entropy: float, has_regex_match: bool) -> str:
    """Classify finding confidence based on entropy and detection method."""
    if has_regex_match and entropy >= 4.5:
        return "high"
    if has_regex_match or entropy >= 5.0:
        return "medium"
    return "low"


def _scan_line_regex(line: str) -> list[tuple[str, str]]:
    """Scan a single line for regex-matched secrets. Returns (type, value) pairs."""
    findings: list[tuple[str, str]] = []
    for secret_type, pattern in SECRET_PATTERNS.items():
        for match in pattern.finditer(line):
            value = match.group(1) if match.lastindex else match.group(0)
            if not _is_false_positive(value):
                findings.append((secret_type, value))
    return findings


def _scan_line_entropy(line: str) -> list[tuple[str, str]]:
    """Scan a single line for high-entropy strings. Returns ("High Entropy String", value) pairs."""
    findings: list[tuple[str, str]] = []
    for match in HIGH_ENTROPY_CHARSET.finditer(line):
        value = match.group(0)
        if len(value) >= MIN_ENTROPY_STRING_LENGTH:
            entropy = shannon_entropy(value)
            if entropy >= ENTROPY_THRESHOLD and not _is_false_positive(value):
                findings.append(("High Entropy String", value))
    return findings


def analyze_text(content: str, file_path: str = "<stdin>") -> list[SecretFinding]:
    """
    Analyze text content for potential secrets using regex + entropy.

    Args:
        content: The text content to scan.
        file_path: The source file path (for reporting).

    Returns:
        List of SecretFinding objects.
    """
    results: list[SecretFinding] = []
    seen_values: set[str] = set()

    for line_number, line in enumerate(content.splitlines(), start=1):
        stripped = line.strip()
        if not stripped or stripped.startswith("#") or stripped.startswith("//"):
            continue

        # Regex-based detection
        regex_hits = _scan_line_regex(stripped)
        for secret_type, value in regex_hits:
            if value in seen_values:
                continue
            seen_values.add(value)
            entropy = shannon_entropy(value)
            results.append(
                SecretFinding(
                    file_path=file_path,
                    line_number=line_number,
                    line_content=stripped,
                    secret_type=secret_type,
                    matched_value=value,
                    entropy=entropy,
                    confidence=_classify_confidence(entropy, has_regex_match=True),
                )
            )

        # Entropy-based detection (catches things regex might miss)
        entropy_hits = _scan_line_entropy(stripped)
        for secret_type, value in entropy_hits:
            if value in seen_values:
                continue
            seen_values.add(value)
            entropy = shannon_entropy(value)
            results.append(
                SecretFinding(
                    file_path=file_path,
                    line_number=line_number,
                    line_content=stripped,
                    secret_type=secret_type,
                    matched_value=value,
                    entropy=entropy,
                    confidence=_classify_confidence(entropy, has_regex_match=False),
                )
            )

    return results


def analyze_file(file_path: str | Path) -> list[SecretFinding]:
    """
    Analyze a file for potential secrets.

    Args:
        file_path: Path to the file to scan.

    Returns:
        List of SecretFinding objects.
    """
    path = Path(file_path)
    if not path.is_file():
        raise FileNotFoundError(f"File not found: {file_path}")

    try:
        content = path.read_text(encoding="utf-8", errors="replace")
    except (OSError, UnicodeDecodeError) as exc:
        raise OSError(f"Cannot read file {file_path}: {exc}") from exc

    return analyze_text(content, file_path=str(path))


def analyze_directory(
    directory: str | Path,
    extensions: Sequence[str] | None = None,
    exclude_dirs: Sequence[str] | None = None,
) -> list[SecretFinding]:
    """
    Recursively analyze files in a directory for potential secrets.

    Args:
        directory: Path to the directory to scan.
        extensions: File extensions to include (e.g., [".env", ".yml"]). None = all files.
        exclude_dirs: Directory names to exclude (e.g., ["node_modules", ".git"]).

    Returns:
        List of SecretFinding objects from all scanned files.
    """
    dir_path = Path(directory)
    if not dir_path.is_dir():
        raise NotADirectoryError(f"Not a directory: {directory}")

    if exclude_dirs is None:
        exclude_dirs = [".git", "node_modules", "__pycache__", ".venv", "venv", ".tox"]

    all_findings: list[SecretFinding] = []

    for file_path in dir_path.rglob("*"):
        if not file_path.is_file():
            continue
        if any(excluded in file_path.parts for excluded in exclude_dirs):
            continue
        if extensions and file_path.suffix not in extensions:
            continue
        # Skip binary files
        try:
            content = file_path.read_text(encoding="utf-8", errors="strict")
        except (UnicodeDecodeError, OSError):
            continue

        findings = analyze_text(content, file_path=str(file_path))
        all_findings.extend(findings)

    return all_findings
