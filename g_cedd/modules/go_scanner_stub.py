"""Go Scanner Stub - Architecture for high-performance Go integration.

This module provides the Python interface for a future Go-based
high-performance scanner. The Go binary will handle raw network I/O
while Python orchestrates the workflow and processes results.

Architecture:
    Python (orchestrator) -> subprocess -> Go binary (fast I/O)
    Go binary writes JSON results to stdout
    Python reads and aggregates them

To build the Go scanner:
    cd go_scanner/ && go build -o gcedd-fast-scanner ./cmd/scanner
"""

from __future__ import annotations

import json
import subprocess
from dataclasses import dataclass, field
from pathlib import Path

# Default path where the compiled Go binary would be installed
DEFAULT_GO_BINARY = "gcedd-fast-scanner"


@dataclass
class GoScanResult:
    """Result from the Go fast scanner."""

    target: str
    paths_checked: int
    responses: list[dict[str, str | int]] = field(default_factory=list)
    elapsed_ms: float = 0.0
    error: str = ""

    def to_dict(self) -> dict[str, str | int | float | list[dict[str, str | int]]]:
        return {
            "target": self.target,
            "paths_checked": self.paths_checked,
            "responses": self.responses,
            "elapsed_ms": self.elapsed_ms,
            "error": self.error,
        }


def is_go_scanner_available(binary: str = DEFAULT_GO_BINARY) -> bool:
    """Check if the Go fast scanner binary is available on PATH."""
    try:
        result = subprocess.run(
            [binary, "--version"],
            capture_output=True,
            timeout=5,
            check=False,
        )
        return result.returncode == 0
    except (FileNotFoundError, subprocess.TimeoutExpired):
        return False


def run_go_scanner(
    targets: list[str],
    paths: list[str] | None = None,
    concurrency: int = 100,
    timeout_ms: int = 5000,
    binary: str = DEFAULT_GO_BINARY,
) -> list[GoScanResult]:
    """Run the Go fast scanner against targets.

    The Go binary accepts JSON configuration on stdin and writes
    JSON results to stdout.

    Args:
        targets: List of base URLs to scan.
        paths: Paths to check on each target.
        concurrency: Number of concurrent goroutines.
        timeout_ms: Per-request timeout in milliseconds.
        binary: Path to the Go scanner binary.

    Returns:
        List of GoScanResult objects.

    Raises:
        FileNotFoundError: If the Go binary is not found.
    """
    if not is_go_scanner_available(binary):
        raise FileNotFoundError(
            f"Go scanner binary not found: {binary}\n"
            f"Build it with: cd go_scanner && go build -o {binary} "
            f"./cmd/scanner"
        )

    config = {
        "targets": targets,
        "paths": paths or [],
        "concurrency": concurrency,
        "timeout_ms": timeout_ms,
    }

    try:
        proc = subprocess.run(
            [binary, "--json"],
            input=json.dumps(config),
            capture_output=True,
            text=True,
            timeout=300,
            check=False,
        )
    except subprocess.TimeoutExpired:
        return [
            GoScanResult(
                target=t, paths_checked=0,
                error="Go scanner timed out",
            )
            for t in targets
        ]

    if proc.returncode != 0:
        return [
            GoScanResult(
                target=t, paths_checked=0,
                error=f"Go scanner exited {proc.returncode}: {proc.stderr}",
            )
            for t in targets
        ]

    results: list[GoScanResult] = []
    try:
        data = json.loads(proc.stdout)
        for entry in data.get("results", []):
            results.append(
                GoScanResult(
                    target=entry.get("target", ""),
                    paths_checked=entry.get("paths_checked", 0),
                    responses=entry.get("responses", []),
                    elapsed_ms=entry.get("elapsed_ms", 0.0),
                )
            )
    except (json.JSONDecodeError, KeyError) as exc:
        results.append(
            GoScanResult(
                target=targets[0] if targets else "",
                paths_checked=0,
                error=f"Failed to parse Go scanner output: {exc}",
            )
        )

    return results


def generate_go_scaffold(output_dir: Path | None = None) -> Path:
    """Generate the Go scanner project scaffold.

    Creates the directory structure and source files needed to
    build the Go fast scanner binary.

    Args:
        output_dir: Where to create the scaffold. Defaults to ./go_scanner.

    Returns:
        Path to the created Go project directory.
    """
    if output_dir is None:
        output_dir = Path("go_scanner")

    output_dir.mkdir(parents=True, exist_ok=True)
    cmd_dir = output_dir / "cmd" / "scanner"
    cmd_dir.mkdir(parents=True, exist_ok=True)

    # go.mod
    go_mod = output_dir / "go.mod"
    go_mod.write_text(
        "module github.com/hexacyberlab/gcedd-fast-scanner\n\n"
        "go 1.22\n",
        encoding="utf-8",
    )

    # main.go stub
    main_go = cmd_dir / "main.go"
    main_go.write_text(
        _GO_MAIN_TEMPLATE,
        encoding="utf-8",
    )

    # README
    readme = output_dir / "README.md"
    readme.write_text(
        "# G-CEDD Fast Scanner (Go)\n\n"
        "High-performance HTTP path checker for G-CEDD.\n\n"
        "## Build\n\n"
        "```bash\n"
        "cd go_scanner\n"
        "go build -o gcedd-fast-scanner ./cmd/scanner\n"
        "```\n\n"
        "## Usage\n\n"
        "The binary reads JSON config from stdin and writes "
        "JSON results to stdout.\n\n"
        "```bash\n"
        'echo \'{"targets":["http://example.com"],'
        '"paths":["/.git/HEAD"],'
        '"concurrency":50,"timeout_ms":5000}\' | '
        "./gcedd-fast-scanner --json\n"
        "```\n",
        encoding="utf-8",
    )

    return output_dir


_GO_MAIN_TEMPLATE = """\
package main

import (
\t"encoding/json"
\t"fmt"
\t"io"
\t"net/http"
\t"os"
\t"sync"
\t"time"
)

// Config represents the input configuration from Python.
type Config struct {
\tTargets     []string `json:"targets"`
\tPaths       []string `json:"paths"`
\tConcurrency int      `json:"concurrency"`
\tTimeoutMs   int      `json:"timeout_ms"`
}

// Response represents a single HTTP check result.
type Response struct {
\tURL        string `json:"url"`
\tPath       string `json:"path"`
\tStatusCode int    `json:"status_code"`
\tSizeBytes  int    `json:"size_bytes"`
}

// ScanResult represents results for a single target.
type ScanResult struct {
\tTarget       string     `json:"target"`
\tPathsChecked int        `json:"paths_checked"`
\tResponses    []Response `json:"responses"`
\tElapsedMs    float64    `json:"elapsed_ms"`
}

// Output is the top-level JSON output.
type Output struct {
\tResults []ScanResult `json:"results"`
}

func main() {
\tif len(os.Args) < 2 || os.Args[1] != "--json" {
\t\tfmt.Fprintln(os.Stderr, "Usage: gcedd-fast-scanner --json")
\t\tfmt.Fprintln(os.Stderr, "Reads JSON config from stdin")
\t\tos.Exit(1)
\t}

\t// Show version
\tfor _, arg := range os.Args[1:] {
\t\tif arg == "--version" {
\t\t\tfmt.Println("gcedd-fast-scanner v0.1.0")
\t\t\tos.Exit(0)
\t\t}
\t}

\tinputBytes, err := io.ReadAll(os.Stdin)
\tif err != nil {
\t\tfmt.Fprintf(os.Stderr, "Error reading stdin: %v\\n", err)
\t\tos.Exit(1)
\t}

\tvar cfg Config
\tif err := json.Unmarshal(inputBytes, &cfg); err != nil {
\t\tfmt.Fprintf(os.Stderr, "Error parsing config: %v\\n", err)
\t\tos.Exit(1)
\t}

\tif cfg.Concurrency <= 0 {
\t\tcfg.Concurrency = 50
\t}
\tif cfg.TimeoutMs <= 0 {
\t\tcfg.TimeoutMs = 5000
\t}

\tclient := &http.Client{
\t\tTimeout: time.Duration(cfg.TimeoutMs) * time.Millisecond,
\t}

\tvar output Output

\tfor _, target := range cfg.Targets {
\t\tstart := time.Now()
\t\tvar (
\t\t\tmu        sync.Mutex
\t\t\tresponses []Response
\t\t\twg        sync.WaitGroup
\t\t\tsem       = make(chan struct{}, cfg.Concurrency)
\t\t)

\t\tfor _, path := range cfg.Paths {
\t\t\twg.Add(1)
\t\t\tgo func(p string) {
\t\t\t\tdefer wg.Done()
\t\t\t\tsem <- struct{}{}
\t\t\t\tdefer func() { <-sem }()

\t\t\t\turl := target + p
\t\t\t\tresp, err := client.Get(url)
\t\t\t\tif err != nil {
\t\t\t\t\tmu.Lock()
\t\t\t\t\tresponses = append(responses, Response{
\t\t\t\t\t\tURL: url, Path: p, StatusCode: 0,
\t\t\t\t\t})
\t\t\t\t\tmu.Unlock()
\t\t\t\t\treturn
\t\t\t\t}
\t\t\t\tdefer resp.Body.Close()
\t\t\t\tbody, _ := io.ReadAll(resp.Body)

\t\t\t\tmu.Lock()
\t\t\t\tresponses = append(responses, Response{
\t\t\t\t\tURL:        url,
\t\t\t\t\tPath:       p,
\t\t\t\t\tStatusCode: resp.StatusCode,
\t\t\t\t\tSizeBytes:  len(body),
\t\t\t\t})
\t\t\t\tmu.Unlock()
\t\t\t}(path)
\t\t}
\t\twg.Wait()

\t\toutput.Results = append(output.Results, ScanResult{
\t\t\tTarget:       target,
\t\t\tPathsChecked: len(cfg.Paths),
\t\t\tResponses:    responses,
\t\t\tElapsedMs:    float64(time.Since(start).Milliseconds()),
\t\t})
\t}

\tenc := json.NewEncoder(os.Stdout)
\tenc.SetIndent("", "  ")
\tif err := enc.Encode(output); err != nil {
\t\tfmt.Fprintf(os.Stderr, "Error encoding output: %v\\n", err)
\t\tos.Exit(1)
\t}
}
"""
