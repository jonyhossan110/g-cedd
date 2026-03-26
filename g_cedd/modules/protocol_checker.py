"""Config Error & Protocol Testing - HTTP method compliance auditing."""

from __future__ import annotations

import asyncio
from collections.abc import Sequence
from dataclasses import dataclass, field

import aiohttp

# Standard HTTP methods to test for compliance
AUDIT_METHODS: list[str] = ["GET", "HEAD", "OPTIONS"]


@dataclass
class MethodResponse:
    """Response from a single HTTP method test."""

    method: str
    status_code: int
    headers: dict[str, str] = field(default_factory=dict)
    error: str = ""

    def to_dict(self) -> dict[str, str | int | dict[str, str]]:
        return {
            "method": self.method,
            "status_code": self.status_code,
            "headers": self.headers,
            "error": self.error,
        }


@dataclass
class ProtocolCheckResult:
    """Result of protocol compliance testing on a single path."""

    url: str
    path: str
    responses: list[MethodResponse] = field(default_factory=list)
    inconsistent: bool = False
    notes: list[str] = field(default_factory=list)

    def to_dict(
        self,
    ) -> dict[str, str | bool | list[str] | list[dict[str, str | int | dict[str, str]]]]:
        return {
            "url": self.url,
            "path": self.path,
            "responses": [r.to_dict() for r in self.responses],
            "inconsistent": self.inconsistent,
            "notes": self.notes,
        }


def _analyze_inconsistencies(result: ProtocolCheckResult) -> None:
    """Check for protocol-level misconfigurations in the responses."""
    status_map: dict[str, int] = {}
    for resp in result.responses:
        if resp.error:
            continue
        status_map[resp.method] = resp.status_code

    if not status_map:
        return

    get_status = status_map.get("GET")
    head_status = status_map.get("HEAD")
    options_status = status_map.get("OPTIONS")

    # HEAD should return same status as GET (RFC 9110 section 9.3.2)
    if get_status and head_status and get_status != head_status:
        result.inconsistent = True
        result.notes.append(
            f"HEAD returns {head_status} but GET returns {get_status} "
            f"(RFC 9110 violation)"
        )

    # OPTIONS revealing allowed methods
    if options_status == 200:
        for resp in result.responses:
            if resp.method == "OPTIONS" and "Allow" in resp.headers:
                allowed = resp.headers["Allow"]
                result.notes.append(
                    f"OPTIONS exposes allowed methods: {allowed}"
                )

    # Server responding differently per method could indicate
    # misconfigured access controls
    unique_statuses = set(status_map.values())
    if len(unique_statuses) > 1:
        result.inconsistent = True
        summary = ", ".join(
            f"{m}={s}" for m, s in sorted(status_map.items())
        )
        result.notes.append(
            f"Inconsistent status codes across methods: {summary}"
        )


async def _test_method(
    session: aiohttp.ClientSession,
    url: str,
    method: str,
    timeout: float,
) -> MethodResponse:
    """Send a single HTTP method request and capture the response."""
    try:
        req_timeout = aiohttp.ClientTimeout(total=timeout)
        async with session.request(
            method, url, timeout=req_timeout, ssl=False
        ) as resp:
            headers = {k: v for k, v in resp.headers.items()}
            return MethodResponse(
                method=method,
                status_code=resp.status,
                headers=headers,
            )
    except (aiohttp.ClientError, TimeoutError, OSError) as exc:
        return MethodResponse(
            method=method,
            status_code=0,
            error=f"{type(exc).__name__}: {exc}",
        )


async def check_protocol_compliance(
    targets: Sequence[str],
    paths: Sequence[str] | None = None,
    methods: Sequence[str] | None = None,
    timeout: float = 10.0,
    max_concurrent: int = 10,
) -> list[ProtocolCheckResult]:
    """Test HTTP method compliance on target paths.

    For each target+path combination, sends GET, HEAD, and OPTIONS
    requests and flags inconsistencies that indicate misconfigured
    access controls or protocol violations.

    Args:
        targets: Base URLs to test.
        paths: Paths to check. Defaults to common config paths.
        methods: HTTP methods to test. Defaults to GET, HEAD, OPTIONS.
        timeout: HTTP request timeout in seconds.
        max_concurrent: Maximum concurrent requests.

    Returns:
        List of ProtocolCheckResult for each target+path combination.
    """
    if paths is None:
        paths = [
            "/.git/HEAD",
            "/.git/config",
            "/.env",
            "/.htaccess",
            "/server-status",
        ]

    if methods is None:
        methods = list(AUDIT_METHODS)

    semaphore = asyncio.Semaphore(max_concurrent)
    connector = aiohttp.TCPConnector(
        limit=max_concurrent, force_close=True
    )

    results: list[ProtocolCheckResult] = []

    async with aiohttp.ClientSession(connector=connector) as session:
        for target in targets:
            for path in paths:
                url = f"{target.rstrip('/')}{path}"
                result = ProtocolCheckResult(url=url, path=path)

                async def _bounded_test(
                    m: str, u: str = url
                ) -> MethodResponse:
                    async with semaphore:
                        return await _test_method(
                            session, u, m, timeout
                        )

                tasks = [_bounded_test(m) for m in methods]
                responses = await asyncio.gather(*tasks)
                result.responses = list(responses)
                _analyze_inconsistencies(result)
                results.append(result)

    return results
