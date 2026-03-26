"""Workspace Organization - Auto-generate target-based report directories."""

from __future__ import annotations

import re
from datetime import UTC, datetime
from pathlib import Path


def _sanitize_target(target: str) -> str:
    """Convert a target URL to a safe directory name.

    E.g., "https://example.com" -> "example_com"
    """
    # Strip scheme
    name = re.sub(r"^https?://", "", target)
    # Replace non-alphanumeric chars with underscores
    name = re.sub(r"[^a-zA-Z0-9]", "_", name)
    # Collapse consecutive underscores and strip trailing ones
    name = re.sub(r"_+", "_", name).strip("_")
    return name.lower()


def create_target_workspace(
    target: str,
    base_dir: Path | None = None,
) -> Path:
    """Create a timestamped workspace directory for a scan target.

    Directory layout:
        reports/example_com_20260326_071500/
            results.json
            report.html
            extracted/       (for JS files, blobs, etc.)

    Args:
        target: The target URL being scanned.
        base_dir: Parent directory for reports. Defaults to ./reports.

    Returns:
        Path to the created workspace directory.
    """
    if base_dir is None:
        base_dir = Path("reports")

    sanitized = _sanitize_target(target)
    ts = datetime.now(UTC).strftime("%Y%m%d_%H%M%S")
    workspace = base_dir / f"{sanitized}_{ts}"

    workspace.mkdir(parents=True, exist_ok=True)
    # Pre-create subdirectory for extracted files
    (workspace / "extracted").mkdir(exist_ok=True)

    return workspace
