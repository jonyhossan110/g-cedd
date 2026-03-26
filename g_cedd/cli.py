"""G-CEDD CLI entrypoint - ties all modules together."""

from __future__ import annotations

import argparse
import asyncio
import sys

from g_cedd.modules.path_checker import PathCheckerConfig, check_paths
from g_cedd.modules.reporter import (
    console,
    generate_json_report,
    print_banner,
    print_path_results,
    print_secret_findings,
    print_summary,
)
from g_cedd.modules.secret_analyzer import analyze_directory, analyze_file


def build_parser() -> argparse.ArgumentParser:
    """Build the CLI argument parser."""
    parser = argparse.ArgumentParser(
        prog="g-cedd",
        description="G-CEDD: Defensive Web Configuration Auditor",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""\
Examples:
  # Check a staging server for exposed config paths
  g-cedd scan --targets http://staging.internal.example.com

  # Scan a local file for leaked secrets
  g-cedd secrets --file .env.backup

  # Scan a directory recursively for secrets
  g-cedd secrets --dir ./config

  # Full audit: path check + secret scan with JSON report
  g-cedd scan --targets http://staging.example.com --secrets-file .env --output report.json
""",
    )

    subparsers = parser.add_subparsers(dest="command", help="Available commands")

    # --- scan command ---
    scan_parser = subparsers.add_parser(
        "scan",
        help="Check target servers for exposed configuration paths",
    )
    scan_parser.add_argument(
        "--targets",
        nargs="+",
        required=True,
        metavar="URL",
        help="Base URL(s) of servers to check (e.g., http://staging.internal.example.com)",
    )
    scan_parser.add_argument(
        "--timeout",
        type=float,
        default=10.0,
        help="HTTP request timeout in seconds (default: 10)",
    )
    scan_parser.add_argument(
        "--concurrency",
        type=int,
        default=10,
        help="Maximum concurrent requests (default: 10)",
    )
    scan_parser.add_argument(
        "--rate-limit",
        type=float,
        default=0.1,
        dest="rate_limit",
        help="Delay between requests in seconds (default: 0.1)",
    )
    scan_parser.add_argument(
        "--secrets-file",
        dest="secrets_file",
        metavar="FILE",
        help="Also scan a local file for secrets after path checking",
    )
    scan_parser.add_argument(
        "--output",
        "-o",
        default="g-cedd-report.json",
        metavar="FILE",
        help="Output JSON report path (default: g-cedd-report.json)",
    )

    # --- secrets command ---
    secrets_parser = subparsers.add_parser(
        "secrets",
        help="Scan local files or directories for leaked secrets",
    )
    secrets_group = secrets_parser.add_mutually_exclusive_group(required=True)
    secrets_group.add_argument(
        "--file",
        "-f",
        dest="file",
        metavar="FILE",
        help="Path to a single file to scan",
    )
    secrets_group.add_argument(
        "--dir",
        "-d",
        dest="directory",
        metavar="DIR",
        help="Path to a directory to scan recursively",
    )
    secrets_parser.add_argument(
        "--extensions",
        nargs="*",
        metavar="EXT",
        help="File extensions to include when scanning a directory (e.g., .env .yml .json)",
    )
    secrets_parser.add_argument(
        "--output",
        "-o",
        default="g-cedd-report.json",
        metavar="FILE",
        help="Output JSON report path (default: g-cedd-report.json)",
    )

    return parser


def run_scan(args: argparse.Namespace) -> int:
    """Execute the path scan command."""
    config = PathCheckerConfig(
        timeout=args.timeout,
        max_concurrent=args.concurrency,
        rate_limit_delay=args.rate_limit,
    )

    console.print(f"\n[bold]Scanning {len(args.targets)} target(s)...[/bold]\n")

    path_results = asyncio.run(check_paths(args.targets, config))
    print_path_results(path_results)

    secret_findings = None
    if args.secrets_file:
        console.print(f"\n[bold]Scanning file for secrets: {args.secrets_file}[/bold]\n")
        try:
            secret_findings = analyze_file(args.secrets_file)
            print_secret_findings(secret_findings)
        except (FileNotFoundError, OSError) as exc:
            console.print(f"[bold red]Error:[/bold red] {exc}")
            return 1

    print_summary(path_results=path_results, secret_findings=secret_findings)
    generate_json_report(
        path_results=path_results,
        secret_findings=secret_findings,
        output_path=args.output,
    )

    exposed_count = sum(1 for r in path_results if r.exposed)
    return 1 if exposed_count > 0 else 0


def run_secrets(args: argparse.Namespace) -> int:
    """Execute the secrets scan command."""
    try:
        if args.file:
            console.print(f"\n[bold]Scanning file: {args.file}[/bold]\n")
            findings = analyze_file(args.file)
        else:
            console.print(f"\n[bold]Scanning directory: {args.directory}[/bold]\n")
            extensions = args.extensions if args.extensions else None
            findings = analyze_directory(args.directory, extensions=extensions)
    except (FileNotFoundError, NotADirectoryError, OSError) as exc:
        console.print(f"[bold red]Error:[/bold red] {exc}")
        return 1

    print_secret_findings(findings)
    print_summary(secret_findings=findings)
    generate_json_report(secret_findings=findings, output_path=args.output)

    return 1 if findings else 0


def main() -> None:
    """Main CLI entrypoint."""
    print_banner()

    parser = build_parser()
    args = parser.parse_args()

    if args.command is None:
        parser.print_help()
        sys.exit(0)

    if args.command == "scan":
        exit_code = run_scan(args)
    elif args.command == "secrets":
        exit_code = run_secrets(args)
    else:
        parser.print_help()
        exit_code = 0

    sys.exit(exit_code)


if __name__ == "__main__":
    main()
