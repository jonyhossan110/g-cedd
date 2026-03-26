"""FastAPI REST API server for exposing G-CEDD scan results."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from fastapi import FastAPI, HTTPException
from fastapi.responses import JSONResponse

RESULTS_DIR = Path(".")


def create_app(results_dir: Path | None = None) -> FastAPI:
    """
    Create and configure the FastAPI application.

    Args:
        results_dir: Directory where JSON result files are stored.

    Returns:
        Configured FastAPI app instance.
    """
    if results_dir is not None:
        global RESULTS_DIR  # noqa: PLW0603
        RESULTS_DIR = results_dir

    app = FastAPI(
        title="G-CEDD API",
        description="Git & Config Exposure Deep-Dive - Scan Results API",
        version="1.0.0",
    )

    @app.get("/")
    async def root() -> dict[str, str]:
        """Health check endpoint."""
        return {"status": "ok", "tool": "G-CEDD", "version": "1.0.0"}

    @app.get("/results")
    async def list_results() -> dict[str, list[str]]:
        """List all available scan result files."""
        result_files = sorted(RESULTS_DIR.glob("results_*.json"), reverse=True)
        return {"files": [f.name for f in result_files]}

    @app.get("/results/{filename}")
    async def get_result(filename: str) -> JSONResponse:
        """Retrieve a specific scan result by filename."""
        if not filename.startswith("results_") or not filename.endswith(".json"):
            raise HTTPException(status_code=400, detail="Invalid result filename format")

        file_path = RESULTS_DIR / filename
        if not file_path.is_file():
            raise HTTPException(status_code=404, detail=f"Result file not found: {filename}")

        try:
            content = file_path.read_text(encoding="utf-8")
            data: dict[str, Any] = json.loads(content)
        except (json.JSONDecodeError, OSError) as exc:
            raise HTTPException(
                status_code=500, detail=f"Error reading result file: {exc}"
            ) from exc

        return JSONResponse(content=data)

    @app.get("/results/latest/summary")
    async def latest_summary() -> JSONResponse:
        """Get the summary from the most recent scan result."""
        result_files = sorted(RESULTS_DIR.glob("results_*.json"), reverse=True)
        if not result_files:
            raise HTTPException(status_code=404, detail="No scan results found")

        try:
            content = result_files[0].read_text(encoding="utf-8")
            data: dict[str, Any] = json.loads(content)
        except (json.JSONDecodeError, OSError) as exc:
            raise HTTPException(
                status_code=500, detail=f"Error reading result file: {exc}"
            ) from exc

        return JSONResponse(
            content={
                "file": result_files[0].name,
                "summary": data.get("summary", {}),
                "generated_at": data.get("generated_at", "unknown"),
            }
        )

    return app


def run_server(results_dir: Path, host: str = "0.0.0.0", port: int = 8000) -> None:
    """
    Start the FastAPI server.

    Args:
        results_dir: Directory containing scan result JSON files.
        host: Host to bind to.
        port: Port to listen on.
    """
    import uvicorn

    app = create_app(results_dir)
    print(f"\n[G-CEDD API] Serving scan results from: {results_dir.resolve()}")
    print(f"[G-CEDD API] Listening on http://{host}:{port}")
    print("[G-CEDD API] Endpoints:")
    print("  GET /              - Health check")
    print("  GET /results       - List all scan results")
    print("  GET /results/{file} - Get specific result")
    print("  GET /results/latest/summary - Latest scan summary")
    print()
    uvicorn.run(app, host=host, port=port)
