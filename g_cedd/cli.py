"""G-CEDD CLI entrypoint - ties all modules together."""

from __future__ import annotations

import argparse
import asyncio
import sys
from pathlib import Path

from g_cedd.modules.banner import print_banner
from g_cedd.modules.git_extractor import extract_git_objects
from g_cedd.modules.path_checker import PathCheckerConfig, check_paths
from g_cedd.modules.reporter import (
    console,
    generate_json_report,
    print_extraction_results,
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

  # Blind git extraction from a target
  g-cedd extract --target http://staging.internal.example.com

  # Start the REST API server to expose scan results
  g-cedd serve --results-dir ./results

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
        help="Base URL(s) of servers to check",
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
        default=None,
        metavar="FILE",
        help="Output JSON report path (default: timestamped results_*.json)",
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
        default=None,
        metavar="FILE",
        help="Output JSON report path (default: timestamped results_*.json)",
    )

    # --- extract command ---
    extract_parser = subparsers.add_parser(
        "extract",
        help="Blind git graph extraction from a target with exposed .git",
    )
    extract_parser.add_argument(
        "--target",
        required=True,
        metavar="URL",
        help="Base URL of the target server",
    )
    extract_parser.add_argument(
        "--max-depth",
        type=int,
        default=5,
        dest="max_depth",
        help="Maximum depth to traverse the object graph (default: 5)",
    )
    extract_parser.add_argument(
        "--concurrency",
        type=int,
        default=10,
        help="Maximum concurrent requests (default: 10)",
    )
    extract_parser.add_argument(
        "--workspace",
        default="/tmp/gcedd_workspace",
        metavar="DIR",
        help="Directory to dump extracted objects (default: /tmp/gcedd_workspace)",
    )
    extract_parser.add_argument(
        "--output",
        "-o",
        default=None,
        metavar="FILE",
        help="Output JSON report path (default: timestamped results_*.json)",
    )

    # --- serve command ---
    serve_parser = subparsers.add_parser(
        "serve",
        help="Start a local REST API server exposing scan results",
    )
    serve_parser.add_argument(
        "--results-dir",
        default=".",
        dest="results_dir",
        metavar="DIR",
        help="Directory containing JSON result files (default: current dir)",
    )
    serve_parser.add_argument(
        "--host",
        default="0.0.0.0",
        help="Host to bind to (default: 0.0.0.0)",
    )
    serve_parser.add_argument(
        "--port",
        type=int,
        default=8000,
        help="Port to listen on (default: 8000)",
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


def run_extract(args: argparse.Namespace) -> int:
    """Execute the blind git extraction command."""
    workspace = Path(args.workspace)
    console.print(f"\n[bold]Extracting git objects from: {args.target}[/bold]")
    console.print(f"[bold]Workspace: {workspace.resolve()}[/bold]\n")

    result = asyncio.run(
        extract_git_objects(
            target=args.target,
            workspace_dir=workspace,
            max_depth=args.max_depth,
            max_concurrent=args.concurrency,
        )
    )

    print_extraction_results(result)
    print_summary(extraction_result=result)
    generate_json_report(extraction_result=result, output_path=args.output)

    return 0 if result.success else 1


def run_serve(args: argparse.Namespace) -> None:
    """Execute the serve command to start the REST API."""
    from g_cedd.modules.serve import run_server

    results_dir = Path(args.results_dir)
    if not results_dir.is_dir():
        console.print(f"[bold red]Error:[/bold red] Results directory not found: {results_dir}")
        sys.exit(1)

    run_server(results_dir=results_dir, host=args.host, port=args.port)


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
    elif args.command == "extract":
        exit_code = run_extract(args)
    elif args.command == "serve":
        run_serve(args)
        exit_code = 0
    else:
        parser.print_help()
        exit_code = 0

    sys.exit(exit_code)


if __name__ == "__main__":
    main()
