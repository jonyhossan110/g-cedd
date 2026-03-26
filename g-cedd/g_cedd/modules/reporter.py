"""Module 3: Reporting Engine - Rich CLI output + JSON export."""

from __future__ import annotations

import json
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from rich.console import Console
from rich.panel import Panel
from rich.table import Table
from rich.text import Text

from g_cedd.modules.git_extractor import ExtractionResult
from g_cedd.modules.path_checker import PathResult
from g_cedd.modules.secret_analyzer import SecretFinding, _redact

console = Console()

SEVERITY_COLORS: dict[str, str] = {
    "critical": "bold red",
    "high": "red",
    "medium": "yellow",
    "low": "cyan",
    "info": "dim",
}

CONFIDENCE_COLORS: dict[str, str] = {
    "high": "bold red",
    "medium": "yellow",
    "low": "cyan",
}


def _severity_icon(severity: str) -> str:
    """Return a text icon for a severity level."""
    icons = {
        "critical": "[!]",
        "high": "[H]",
        "medium": "[M]",
        "low": "[L]",
        "info": "[i]",
    }
    return icons.get(severity, "[ ]")


def print_banner() -> None:
    """Print the G-CEDD banner."""
    banner = Text()
    banner.append("G-CEDD", style="bold cyan")
    banner.append(" - Git & Config Exposure Deep-Dive\n", style="bold white")
    banner.append("Defensive Web Configuration Auditor", style="dim")
    console.print(Panel(banner, border_style="cyan", padding=(1, 2)))


def print_path_results(results: list[PathResult]) -> None:
    """Print path checking results in a formatted table."""
    exposed = [r for r in results if r.exposed]
    safe = [r for r in results if not r.exposed and r.status_code != 0]
    errors = [r for r in results if r.status_code == 0]

    console.print()
    console.print("[bold cyan]PATH EXPOSURE SCAN RESULTS[/bold cyan]")
    console.print(f"  Total checked: {len(results)}")
    console.print(f"  [bold red]Exposed: {len(exposed)}[/bold red]")
    console.print(f"  Safe: {len(safe)}")
    console.print(f"  Errors: {len(errors)}")
    console.print()

    if exposed:
        table = Table(
            title="Exposed Paths",
            title_style="bold red",
            show_lines=True,
            border_style="red",
        )
        table.add_column("Severity", style="bold", width=10)
        table.add_column("Path", style="white", min_width=25)
        table.add_column("Status", justify="center", width=8)
        table.add_column("Size", justify="right", width=10)
        table.add_column("Content Preview", max_width=50)

        # Sort by severity
        severity_order = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}
        exposed.sort(key=lambda r: severity_order.get(r.severity, 99))

        for result in exposed:
            color = SEVERITY_COLORS.get(result.severity, "white")
            severity_text = Text(f"{_severity_icon(result.severity)} {result.severity.upper()}")
            severity_text.stylize(color)

            snippet = result.content_snippet[:80].replace("\n", " ")
            table.add_row(
                severity_text,
                result.path,
                str(result.status_code),
                f"{result.content_length:,}",
                snippet,
            )

        console.print(table)
    else:
        console.print("[bold green]No exposed paths found.[/bold green]")


def print_secret_findings(findings: list[SecretFinding]) -> None:
    """Print secret analysis findings in a formatted table."""
    console.print()
    console.print("[bold cyan]SECRET ANALYSIS RESULTS[/bold cyan]")
    console.print(f"  Total findings: {len(findings)}")

    high_count = sum(1 for f in findings if f.confidence == "high")
    medium_count = sum(1 for f in findings if f.confidence == "medium")
    low_count = sum(1 for f in findings if f.confidence == "low")

    console.print(f"  [bold red]High confidence: {high_count}[/bold red]")
    console.print(f"  [yellow]Medium confidence: {medium_count}[/yellow]")
    console.print(f"  [cyan]Low confidence: {low_count}[/cyan]")
    console.print()

    if findings:
        table = Table(
            title="Detected Secrets",
            title_style="bold red",
            show_lines=True,
            border_style="red",
        )
        table.add_column("Confidence", style="bold", width=12)
        table.add_column("Type", style="white", min_width=20)
        table.add_column("File", min_width=20)
        table.add_column("Line", justify="center", width=6)
        table.add_column("Redacted Value", max_width=40)
        table.add_column("Entropy", justify="right", width=8)

        # Sort by confidence
        confidence_order = {"high": 0, "medium": 1, "low": 2}
        findings.sort(key=lambda f: confidence_order.get(f.confidence, 99))

        for finding in findings:
            color = CONFIDENCE_COLORS.get(finding.confidence, "white")
            conf_text = Text(finding.confidence.upper())
            conf_text.stylize(color)

            table.add_row(
                conf_text,
                finding.secret_type,
                finding.file_path,
                str(finding.line_number),
                _redact(finding.matched_value),
                f"{finding.entropy:.2f}",
            )

        console.print(table)
    else:
        console.print("[bold green]No secrets detected.[/bold green]")


def print_extraction_results(result: ExtractionResult) -> None:
    """Print git extraction results."""
    console.print()
    console.print("[bold cyan]GIT EXTRACTION RESULTS[/bold cyan]")
    console.print(f"  Target: {result.target}")
    console.print(f"  HEAD ref: {result.head_ref or 'N/A'}")
    console.print(f"  Commit SHA: {result.commit_sha or 'N/A'}")
    console.print(f"  Objects found: {result.objects_found}")
    console.print(f"  Files extracted: {len(result.files_extracted)}")
    console.print()

    if result.objects:
        table = Table(
            title="Extracted Git Objects",
            title_style="bold cyan",
            show_lines=True,
            border_style="cyan",
        )
        table.add_column("SHA", style="white", min_width=12)
        table.add_column("Type", style="bold", width=10)
        table.add_column("Size", justify="right", width=10)
        table.add_column("Source URL", max_width=60)

        for obj in result.objects:
            type_color = {
                "commit": "yellow",
                "tree": "cyan",
                "blob": "green",
            }.get(obj.obj_type, "white")
            type_text = Text(obj.obj_type)
            type_text.stylize(type_color)

            table.add_row(
                obj.sha[:12] + "...",
                type_text,
                f"{obj.size:,}",
                obj.source_url,
            )

        console.print(table)

    if result.errors:
        for err in result.errors:
            console.print(f"  [bold red]Error:[/bold red] {err}")


def print_summary(
    path_results: list[PathResult] | None = None,
    secret_findings: list[SecretFinding] | None = None,
    extraction_result: ExtractionResult | None = None,
) -> None:
    """Print a final summary panel."""
    console.print()

    total_issues = 0
    lines: list[str] = []

    if path_results is not None:
        exposed_count = sum(1 for r in path_results if r.exposed)
        total_issues += exposed_count
        critical = sum(1 for r in path_results if r.exposed and r.severity == "critical")
        lines.append(f"Path Scan: {exposed_count} exposed ({critical} critical)")

    if secret_findings is not None:
        total_issues += len(secret_findings)
        high = sum(1 for f in secret_findings if f.confidence == "high")
        lines.append(f"Secrets Scan: {len(secret_findings)} findings ({high} high confidence)")

    if extraction_result is not None:
        lines.append(
            f"Git Extraction: {extraction_result.objects_found} objects, "
            f"{len(extraction_result.files_extracted)} files"
        )
        if extraction_result.objects_found > 0:
            total_issues += 1

    if total_issues > 0:
        color = "red"
        header = f"AUDIT COMPLETE - {total_issues} ISSUE(S) FOUND"
    else:
        color = "green"
        header = "AUDIT COMPLETE - NO ISSUES FOUND"

    summary_text = Text(header + "\n\n", style=f"bold {color}")
    for line in lines:
        summary_text.append(f"  {line}\n")

    console.print(Panel(summary_text, border_style=color, padding=(1, 2)))


def _make_timestamped_path(output_dir: Path) -> Path:
    """Generate a timestamped result filename."""
    ts = datetime.now(UTC).strftime("%Y%m%d_%H%M%S")
    return output_dir / f"results_{ts}.json"


def generate_json_report(
    path_results: list[PathResult] | None = None,
    secret_findings: list[SecretFinding] | None = None,
    extraction_result: ExtractionResult | None = None,
    output_path: str | Path | None = None,
    output_dir: Path | None = None,
) -> Path:
    """
    Generate a structured JSON report.

    If output_path is None, generates a timestamped filename in output_dir
    (defaults to current directory).

    Args:
        path_results: Results from path checking.
        secret_findings: Results from secret analysis.
        extraction_result: Results from git extraction.
        output_path: Explicit output path (overrides timestamped naming).
        output_dir: Directory for timestamped output files.

    Returns:
        Path to the generated report file.
    """
    report: dict[str, Any] = {
        "tool": "G-CEDD",
        "version": "1.0.0",
        "generated_at": datetime.now(UTC).isoformat(),
        "summary": {
            "total_issues": 0,
            "exposed_paths": 0,
            "secrets_found": 0,
            "git_objects_found": 0,
        },
        "path_scan": [],
        "secret_scan": [],
        "git_extraction": None,
    }

    if path_results is not None:
        exposed = [r for r in path_results if r.exposed]
        report["summary"]["exposed_paths"] = len(exposed)
        report["summary"]["total_issues"] += len(exposed)
        report["path_scan"] = [r.to_dict() for r in path_results]

    if secret_findings is not None:
        report["summary"]["secrets_found"] = len(secret_findings)
        report["summary"]["total_issues"] += len(secret_findings)
        report["secret_scan"] = [f.to_dict() for f in secret_findings]

    if extraction_result is not None:
        report["summary"]["git_objects_found"] = extraction_result.objects_found
        if extraction_result.objects_found > 0:
            report["summary"]["total_issues"] += 1
        report["git_extraction"] = extraction_result.to_dict()

    if output_path is not None:
        out = Path(output_path)
    else:
        dir_path = output_dir or Path(".")
        dir_path.mkdir(parents=True, exist_ok=True)
        out = _make_timestamped_path(dir_path)

    out.write_text(json.dumps(report, indent=2, default=str), encoding="utf-8")
    console.print(f"\n[bold green]JSON report saved to:[/bold green] {out.resolve()}")
    return out
