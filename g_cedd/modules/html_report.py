"""Interactive HTML Dashboard - Standalone severity-colored report generator."""

from __future__ import annotations

import html
import json
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from g_cedd.modules.git_extractor import ExtractionResult
from g_cedd.modules.path_checker import PathResult
from g_cedd.modules.protocol_checker import ProtocolCheckResult
from g_cedd.modules.secret_analyzer import SecretFinding, _redact

# Severity color mapping (CSS)
_SEV_CSS: dict[str, tuple[str, str]] = {
    "critical": ("#dc2626", "#fef2f2"),  # red
    "high": ("#ea580c", "#fff7ed"),       # orange
    "medium": ("#ca8a04", "#fefce8"),     # yellow
    "low": ("#2563eb", "#eff6ff"),        # blue
    "info": ("#6b7280", "#f9fafb"),       # gray
}

_CONF_CSS: dict[str, str] = {
    "high": "#dc2626",
    "medium": "#ca8a04",
    "low": "#2563eb",
}


def _esc(text: str) -> str:
    """HTML-escape a string."""
    return html.escape(str(text))


def _severity_badge(severity: str) -> str:
    """Generate an inline severity badge."""
    fg, bg = _SEV_CSS.get(severity, ("#6b7280", "#f9fafb"))
    return (
        f'<span style="background:{bg};color:{fg};'
        f'padding:2px 8px;border-radius:4px;font-weight:700;'
        f'font-size:0.85em;text-transform:uppercase">'
        f"{_esc(severity)}</span>"
    )


def _confidence_badge(conf: str) -> str:
    """Generate an inline confidence badge."""
    color = _CONF_CSS.get(conf, "#6b7280")
    return (
        f'<span style="color:{color};font-weight:700;'
        f'text-transform:uppercase">{_esc(conf)}</span>'
    )


def _build_summary_cards(
    path_results: list[PathResult] | None,
    secret_findings: list[SecretFinding] | None,
    extraction_result: ExtractionResult | None,
    protocol_results: list[ProtocolCheckResult] | None,
) -> str:
    """Build the summary card row."""
    cards: list[str] = []

    if path_results is not None:
        exposed = sum(1 for r in path_results if r.exposed)
        critical = sum(
            1 for r in path_results
            if r.exposed and r.severity == "critical"
        )
        color = "#dc2626" if exposed else "#16a34a"
        cards.append(
            f'<div class="card">'
            f'<div class="card-num" style="color:{color}">'
            f"{exposed}</div>"
            f'<div class="card-label">Exposed Paths</div>'
            f'<div class="card-sub">{critical} critical</div></div>'
        )

    if secret_findings is not None:
        high = sum(1 for f in secret_findings if f.confidence == "high")
        color = "#dc2626" if secret_findings else "#16a34a"
        cards.append(
            f'<div class="card">'
            f'<div class="card-num" style="color:{color}">'
            f"{len(secret_findings)}</div>"
            f'<div class="card-label">Secrets Found</div>'
            f'<div class="card-sub">{high} high confidence</div></div>'
        )

    if extraction_result is not None:
        n = extraction_result.objects_found
        color = "#ea580c" if n else "#16a34a"
        cards.append(
            f'<div class="card">'
            f'<div class="card-num" style="color:{color}">{n}</div>'
            f'<div class="card-label">Git Objects</div>'
            f'<div class="card-sub">'
            f"{len(extraction_result.files_extracted)} files</div></div>"
        )

    if protocol_results is not None:
        inconsistent = sum(1 for r in protocol_results if r.inconsistent)
        color = "#ca8a04" if inconsistent else "#16a34a"
        cards.append(
            f'<div class="card">'
            f'<div class="card-num" style="color:{color}">'
            f"{inconsistent}</div>"
            f'<div class="card-label">Protocol Issues</div>'
            f'<div class="card-sub">'
            f"{len(protocol_results)} paths tested</div></div>"
        )

    return '<div class="cards">' + "".join(cards) + "</div>"


def _build_path_table(results: list[PathResult]) -> str:
    """Build the exposed paths HTML table."""
    exposed = [r for r in results if r.exposed]
    if not exposed:
        return '<p class="ok">No exposed paths detected.</p>'

    severity_order = {
        "critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4,
    }
    exposed.sort(key=lambda r: severity_order.get(r.severity, 99))

    rows: list[str] = []
    for r in exposed:
        snippet = _esc(r.content_snippet[:120].replace("\n", " "))
        rows.append(
            f"<tr><td>{_severity_badge(r.severity)}</td>"
            f"<td><code>{_esc(r.path)}</code></td>"
            f"<td>{r.status_code}</td>"
            f"<td>{r.content_length:,}</td>"
            f"<td class='snippet'>{snippet}</td></tr>"
        )

    return (
        "<table><thead><tr>"
        "<th>Severity</th><th>Path</th><th>Status</th>"
        "<th>Size</th><th>Preview</th>"
        "</tr></thead><tbody>"
        + "".join(rows)
        + "</tbody></table>"
    )


def _build_secrets_table(findings: list[SecretFinding]) -> str:
    """Build the secrets findings HTML table."""
    if not findings:
        return '<p class="ok">No secrets detected.</p>'

    confidence_order = {"high": 0, "medium": 1, "low": 2}
    findings_sorted = sorted(
        findings, key=lambda f: confidence_order.get(f.confidence, 99)
    )

    rows: list[str] = []
    for f in findings_sorted:
        rows.append(
            f"<tr><td>{_confidence_badge(f.confidence)}</td>"
            f"<td>{_esc(f.secret_type)}</td>"
            f"<td><code>{_esc(f.file_path)}</code></td>"
            f"<td>{f.line_number}</td>"
            f"<td><code>{_esc(_redact(f.matched_value))}</code></td>"
            f"<td>{f.entropy:.2f}</td></tr>"
        )

    return (
        "<table><thead><tr>"
        "<th>Confidence</th><th>Type</th><th>File</th>"
        "<th>Line</th><th>Redacted Value</th><th>Entropy</th>"
        "</tr></thead><tbody>"
        + "".join(rows)
        + "</tbody></table>"
    )


def _build_extraction_section(result: ExtractionResult) -> str:
    """Build the git extraction section."""
    info = (
        f"<p><strong>Target:</strong> {_esc(result.target)}<br>"
        f"<strong>HEAD ref:</strong> {_esc(result.head_ref or 'N/A')}<br>"
        f"<strong>Commit SHA:</strong> "
        f"<code>{_esc(result.commit_sha or 'N/A')}</code></p>"
    )

    if not result.objects:
        return info + '<p class="ok">No objects extracted.</p>'

    rows: list[str] = []
    for obj in result.objects:
        rows.append(
            f"<tr><td><code>{_esc(obj.sha[:12])}...</code></td>"
            f"<td>{_esc(obj.obj_type)}</td>"
            f"<td>{obj.size:,}</td></tr>"
        )

    table = (
        "<table><thead><tr>"
        "<th>SHA</th><th>Type</th><th>Size</th>"
        "</tr></thead><tbody>"
        + "".join(rows)
        + "</tbody></table>"
    )

    return info + table


def _build_protocol_section(
    results: list[ProtocolCheckResult],
) -> str:
    """Build the protocol compliance section."""
    if not results:
        return '<p class="ok">No protocol tests performed.</p>'

    rows: list[str] = []
    for r in results:
        status_parts: list[str] = []
        for resp in r.responses:
            if resp.error:
                status_parts.append(f"{resp.method}=ERR")
            else:
                status_parts.append(f"{resp.method}={resp.status_code}")
        statuses = ", ".join(status_parts)

        flag = _severity_badge("medium") if r.inconsistent else ""
        notes_html = "<br>".join(_esc(n) for n in r.notes) if r.notes else ""

        rows.append(
            f"<tr><td><code>{_esc(r.path)}</code></td>"
            f"<td>{statuses}</td>"
            f"<td>{flag}</td>"
            f"<td class='snippet'>{notes_html}</td></tr>"
        )

    return (
        "<table><thead><tr>"
        "<th>Path</th><th>Method Responses</th>"
        "<th>Issue</th><th>Notes</th>"
        "</tr></thead><tbody>"
        + "".join(rows)
        + "</tbody></table>"
    )


def generate_html_report(
    path_results: list[PathResult] | None = None,
    secret_findings: list[SecretFinding] | None = None,
    extraction_result: ExtractionResult | None = None,
    protocol_results: list[ProtocolCheckResult] | None = None,
    output_path: Path | None = None,
    target: str = "",
) -> Path:
    """Generate a standalone HTML dashboard report.

    Args:
        path_results: Results from path checking.
        secret_findings: Results from secret analysis.
        extraction_result: Results from git extraction.
        protocol_results: Results from protocol compliance testing.
        output_path: Where to save the HTML file.
        target: The target URL for the report title.

    Returns:
        Path to the generated HTML file.
    """
    if output_path is None:
        output_path = Path("report.html")

    ts = datetime.now(UTC).strftime("%Y-%m-%d %H:%M:%S UTC")
    target_display = _esc(target) if target else "Multiple Targets"

    summary_cards = _build_summary_cards(
        path_results, secret_findings,
        extraction_result, protocol_results,
    )

    sections: list[str] = []

    if path_results is not None:
        sections.append(
            '<div class="section">'
            "<h2>Path Exposure Scan</h2>"
            + _build_path_table(path_results)
            + "</div>"
        )

    if secret_findings is not None:
        sections.append(
            '<div class="section">'
            "<h2>Secret Analysis</h2>"
            + _build_secrets_table(secret_findings)
            + "</div>"
        )

    if extraction_result is not None:
        sections.append(
            '<div class="section">'
            "<h2>Git Object Extraction</h2>"
            + _build_extraction_section(extraction_result)
            + "</div>"
        )

    if protocol_results is not None:
        sections.append(
            '<div class="section">'
            "<h2>Protocol Compliance</h2>"
            + _build_protocol_section(protocol_results)
            + "</div>"
        )

    # Also embed raw JSON data for machine consumption
    raw_data: dict[str, Any] = {}
    if path_results is not None:
        raw_data["path_scan"] = [r.to_dict() for r in path_results]
    if secret_findings is not None:
        raw_data["secret_scan"] = [f.to_dict() for f in secret_findings]
    if extraction_result is not None:
        raw_data["git_extraction"] = extraction_result.to_dict()
    if protocol_results is not None:
        raw_data["protocol_check"] = [r.to_dict() for r in protocol_results]

    json_block = json.dumps(raw_data, indent=2, default=str)

    page = _HTML_TEMPLATE.format(
        title=f"G-CEDD Report - {target_display}",
        target=target_display,
        timestamp=ts,
        summary_cards=summary_cards,
        sections="\n".join(sections),
        json_data=_esc(json_block),
    )

    output_path.parent.mkdir(parents=True, exist_ok=True)
    output_path.write_text(page, encoding="utf-8")

    return output_path


_HTML_TEMPLATE = """\
<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>{title}</title>
<style>
*{{margin:0;padding:0;box-sizing:border-box}}
body{{font-family:-apple-system,BlinkMacSystemFont,"Segoe UI",
Roboto,sans-serif;background:#0f172a;color:#e2e8f0;
line-height:1.6;padding:20px}}
.container{{max-width:1200px;margin:0 auto}}
header{{background:linear-gradient(135deg,#1e293b,#334155);
border-radius:12px;padding:30px;margin-bottom:24px;
border:1px solid #475569}}
header h1{{font-size:1.8em;color:#22d3ee}}
header .meta{{color:#94a3b8;font-size:0.9em;margin-top:8px}}
.legend{{display:flex;gap:16px;margin:16px 0;flex-wrap:wrap}}
.legend span{{font-size:0.85em}}
.leg-critical{{color:#dc2626}} .leg-high{{color:#ea580c}}
.leg-medium{{color:#ca8a04}} .leg-low{{color:#2563eb}}
.cards{{display:grid;grid-template-columns:repeat(auto-fit,
minmax(200px,1fr));gap:16px;margin-bottom:24px}}
.card{{background:#1e293b;border-radius:10px;padding:20px;
text-align:center;border:1px solid #334155}}
.card-num{{font-size:2.4em;font-weight:800}}
.card-label{{font-size:1em;color:#94a3b8;margin-top:4px}}
.card-sub{{font-size:0.85em;color:#64748b;margin-top:2px}}
.section{{background:#1e293b;border-radius:10px;padding:24px;
margin-bottom:20px;border:1px solid #334155}}
.section h2{{color:#22d3ee;margin-bottom:16px;font-size:1.3em}}
table{{width:100%;border-collapse:collapse;font-size:0.9em}}
th{{background:#334155;color:#e2e8f0;padding:10px 12px;
text-align:left;font-weight:600;position:sticky;top:0}}
td{{padding:8px 12px;border-bottom:1px solid #334155}}
tr:hover td{{background:#334155}}
code{{background:#0f172a;padding:2px 6px;border-radius:3px;
font-size:0.9em;word-break:break-all}}
.snippet{{max-width:300px;overflow:hidden;text-overflow:ellipsis;
white-space:nowrap}}
.ok{{color:#16a34a;font-weight:600;padding:12px}}
.json-toggle{{background:#334155;color:#22d3ee;border:none;
padding:8px 16px;border-radius:6px;cursor:pointer;
font-size:0.9em;margin-bottom:12px}}
.json-block{{display:none;background:#0f172a;padding:16px;
border-radius:8px;overflow-x:auto;font-size:0.8em;
max-height:400px;overflow-y:auto;white-space:pre}}
footer{{text-align:center;color:#475569;font-size:0.85em;
margin-top:30px;padding:20px}}
footer a{{color:#22d3ee;text-decoration:none}}
</style>
</head>
<body>
<div class="container">
<header>
  <h1>G-CEDD Audit Report</h1>
  <div class="meta">
    Target: <strong>{target}</strong> &bull; Generated: {timestamp}
  </div>
  <div class="legend">
    <span class="leg-critical">&#9679; Critical</span>
    <span class="leg-high">&#9679; High</span>
    <span class="leg-medium">&#9679; Medium</span>
    <span class="leg-low">&#9679; Low / Info</span>
  </div>
</header>
{summary_cards}
{sections}
<div class="section">
  <h2>Raw JSON Data</h2>
  <button class="json-toggle"
    onclick="var b=this.nextElementSibling;
    b.style.display=b.style.display==='block'?'none':'block'">
    Show / Hide JSON</button>
  <pre class="json-block">{json_data}</pre>
</div>
<footer>
  Generated by <strong>G-CEDD</strong> &mdash;
  Git &amp; Config Exposure Deep-Dive Auditor<br>
  Created by Md. Jony Hassain (HexaCyberLab) &bull;
  <a href="https://www.linkedin.com/in/md-jony-hassain/"
  target="_blank">LinkedIn</a>
</footer>
</div>
</body>
</html>
"""
