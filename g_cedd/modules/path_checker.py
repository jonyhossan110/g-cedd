"""Module 1: Async Path Checker - Probes internal servers for exposed config paths."""

from __future__ import annotations

import asyncio
import random
from collections.abc import Sequence
from dataclasses import dataclass, field

import aiohttp

# Paths that should never be publicly accessible on a web server
DEFAULT_PATHS: list[str] = [
    "/.git/HEAD",
    "/.git/config",
    "/.env",
    "/.env.local",
    "/.env.production",
    "/.env.staging",
    "/docker-compose.yml",
    "/docker-compose.override.yml",
    "/wp-config.php.bak",
    "/.htpasswd",
    "/.htaccess",
    "/server-status",
    "/phpinfo.php",
    "/.DS_Store",
    "/config.yml",
    "/config.json",
    "/database.yml",
    "/.npmrc",
    "/.dockerenv",
    "/Dockerfile",
    "/backup.sql",
    "/dump.sql",
]

USER_AGENTS: list[str] = [
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 Chrome/120.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 14_0) AppleWebKit/537.36 Safari/537.36",
    "Mozilla/5.0 (X11; Linux x86_64; rv:121.0) Gecko/20100101 Firefox/121.0",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:121.0) Gecko/20100101 Firefox/121.0",
]


@dataclass
class PathResult:
    """Result of checking a single path on a target."""

    url: str
    path: str
    status_code: int
    content_length: int
    content_snippet: str
    exposed: bool
    severity: str  # "critical", "high", "medium", "low", "info"

    def to_dict(self) -> dict[str, str | int | bool]:
        return {
            "url": self.url,
            "path": self.path,
            "status_code": self.status_code,
            "content_length": self.content_length,
            "content_snippet": self.content_snippet,
            "exposed": self.exposed,
            "severity": self.severity,
        }


@dataclass
class PathCheckerConfig:
    """Configuration for the path checker."""

    paths: list[str] = field(default_factory=lambda: list(DEFAULT_PATHS))
    timeout: float = 10.0
    max_concurrent: int = 10
    rate_limit_delay: float = 0.1
    rotate_user_agent: bool = True


SEVERITY_MAP: dict[str, str] = {
    "/.git/HEAD": "critical",
    "/.git/config": "critical",
    "/.env": "critical",
    "/.env.local": "critical",
    "/.env.production": "critical",
    "/.env.staging": "critical",
    "/.htpasswd": "critical",
    "/wp-config.php.bak": "critical",
    "/backup.sql": "critical",
    "/dump.sql": "critical",
    "/docker-compose.yml": "high",
    "/docker-compose.override.yml": "high",
    "/Dockerfile": "high",
    "/database.yml": "high",
    "/.npmrc": "high",
    "/.htaccess": "medium",
    "/server-status": "medium",
    "/phpinfo.php": "medium",
    "/config.yml": "medium",
    "/config.json": "medium",
    "/.dockerenv": "medium",
    "/.DS_Store": "low",
}


def _classify_severity(path: str) -> str:
    """Classify the severity of an exposed path."""
    return SEVERITY_MAP.get(path, "info")


def _is_likely_exposed(status_code: int, content: str, path: str) -> bool:
    """Determine if a path is genuinely exposed (not a generic error/redirect page)."""
    if status_code != 200:
        return False

    # Heuristic: Check for known content signatures
    if path == "/.git/HEAD" and "ref: refs/heads/" in content:
        return True
    if path == "/.git/config" and "[core]" in content:
        return True
    if path.endswith(".env") and "=" in content:
        # .env files contain KEY=VALUE pairs
        lines_with_equals = sum(
            1 for line in content.splitlines()
            if "=" in line and not line.startswith("#")
        )
        return lines_with_equals >= 1
    if path.endswith((".yml", ".yaml")) and (":" in content or "version:" in content):
        return True
    sql_keywords = ["CREATE", "INSERT", "DROP", "SELECT"]
    if path.endswith(".sql") and any(kw in content.upper() for kw in sql_keywords):
        return True
    if path.endswith((".php", ".php.bak")) and ("<?php" in content or "DB_" in content):
        return True

    # If status is 200 and content is non-trivial, flag it
    return len(content.strip()) > 20


async def _check_single_path(
    session: aiohttp.ClientSession,
    base_url: str,
    path: str,
    config: PathCheckerConfig,
    semaphore: asyncio.Semaphore,
) -> PathResult:
    """Check a single path on the target server."""
    url = f"{base_url.rstrip('/')}{path}"
    headers: dict[str, str] = {}
    if config.rotate_user_agent:
        headers["User-Agent"] = random.choice(USER_AGENTS)

    async with semaphore:
        # Rate limiting
        if config.rate_limit_delay > 0:
            await asyncio.sleep(config.rate_limit_delay)

        try:
            timeout = aiohttp.ClientTimeout(total=config.timeout)
            async with session.get(url, headers=headers, timeout=timeout, ssl=False) as response:
                content = await response.text(errors="replace")
                snippet = content[:300].strip() if content else ""
                exposed = _is_likely_exposed(response.status, content, path)
                severity = _classify_severity(path) if exposed else "info"

                return PathResult(
                    url=url,
                    path=path,
                    status_code=response.status,
                    content_length=len(content),
                    content_snippet=snippet,
                    exposed=exposed,
                    severity=severity,
                )
        except (aiohttp.ClientError, TimeoutError, OSError) as exc:
            return PathResult(
                url=url,
                path=path,
                status_code=0,
                content_length=0,
                content_snippet=f"Connection error: {type(exc).__name__}",
                exposed=False,
                severity="info",
            )


async def check_paths(
    targets: Sequence[str],
    config: PathCheckerConfig | None = None,
) -> list[PathResult]:
    """
    Asynchronously check multiple targets for exposed configuration paths.

    Args:
        targets: List of base URLs to check (e.g., ["http://staging.internal.example.com"]).
        config: Optional configuration overriding defaults.

    Returns:
        List of PathResult objects for all checked paths.
    """
    if config is None:
        config = PathCheckerConfig()

    semaphore = asyncio.Semaphore(config.max_concurrent)
    results: list[PathResult] = []

    connector = aiohttp.TCPConnector(limit=config.max_concurrent, force_close=True)
    async with aiohttp.ClientSession(connector=connector) as session:
        tasks: list[asyncio.Task[PathResult]] = []
        for target in targets:
            for path in config.paths:
                task = asyncio.create_task(
                    _check_single_path(session, target, path, config, semaphore)
                )
                tasks.append(task)

        results = await asyncio.gather(*tasks)

    return list(results)
