"""Offline single-file HTML report. Stdlib only, no CDN, no JS.

Sections: header -> summary counts -> fix-first-12 -> endpoint inventory
-> findings (Critical/High open, rest collapsed). Findings arrive ranked.
"""
from __future__ import annotations

import html
from pathlib import Path

from repoguard.models import Report
from repoguard.ranking import TOP_N
from repoguard.utils.debug import dprint

_CSS = (
    "body{font-family:system-ui,-apple-system,Segoe UI,Roboto,sans-serif;margin:2rem;max-width:1000px}"
    "table{border-collapse:collapse;width:100%}"
    "th,td{border:1px solid #ccc;padding:.4rem .6rem;text-align:left;font-size:.9rem}"
    ".badge{display:inline-block;padding:.1rem .5rem;border-radius:999px;font-size:.75rem;font-weight:700}"
    ".Critical{background:#7f1d1d;color:#fff}.High{background:#c2410c;color:#fff}"
    ".Medium{background:#a16207;color:#fff}.Low{background:#1d4ed8;color:#fff}.Info{background:#475569;color:#fff}"
    ".protected{background:#166534;color:#fff}.open{background:#7f1d1d;color:#fff}"
    ".allowany-default{background:#a16207;color:#fff}.unknown{background:#475569;color:#fff}"
    "pre{background:#f1f5f9;padding:.6rem;overflow:auto;font-size:.8rem}"
    "code{background:#f1f5f9;padding:.1rem .3rem}"
    ".fixfirst{background:#fffbeb;border:1px solid #f59e0b;padding:.6rem 1rem}"
    "details{margin:.4rem 0}summary{cursor:pointer;font-weight:600}"
)


def _esc(s: object) -> str:
    return html.escape("" if s is None else str(s))


def write_html(report: Report, dest: Path) -> Path:
    dprint("html_writer.write findings=", len(report.findings))  # [DEBUG] REMOVE in T6
    dest = Path(dest)
    dest.parent.mkdir(parents=True, exist_ok=True)
    counts = report.summary.get("counts", {})

    first = report.findings[:TOP_N]
    panel = "".join(
        f"<li><b>#{i}</b> <span class='badge {_esc(f.severity)}'>{_esc(f.severity)}</span> "
        f"<a href='#f-{i}'>{_esc(f.title)}</a> <small>{_esc(f.id)} · {_esc(f.where)}</small><br>"
        f"Fix: <code>{_esc(f.fix)}</code></li>"
        for i, f in enumerate(first, 1)
    )

    rows = "".join(
        f"<tr><td>{_esc(f.severity)}</td><td>{_esc(f.id)}</td><td>{_esc(f.title)}</td>"
        f"<td>{_esc(f.where)}</td><td>{_esc(f.tool)}</td><td>{_esc(f.owasp)}</td></tr>"
        for f in report.findings
    )
    cards = "".join(
        f"<details{' open' if f.severity in ('Critical', 'High') else ''}>"
        f"<summary><span class='badge {_esc(f.severity)}'>{_esc(f.severity)}</span> "
        f"{_esc(f.title)} <small>{_esc(f.id)}</small></summary>"
        f"<section id='f-{i}'>"
        f"<p><b>Where:</b> <code>{_esc(f.where)}</code> &nbsp; <b>Tool:</b> {_esc(f.tool)} "
        f"&nbsp; <b>OWASP:</b> {_esc(f.owasp)}</p>"
        f"<pre>{_esc(f.evidence)}</pre>"
        f"<p><b>Fix:</b> <code>{_esc(f.fix)}</code></p></section></details>"
        for i, f in enumerate(report.findings, 1)
    )
    ep_rows = "".join(
        f"<tr><td>{_esc(','.join(e.methods))}</td><td>{_esc(e.path)}</td>"
        f"<td>{_esc(e.view)}</td><td>{_esc(','.join(e.auth))}</td>"
        f"<td><span class='badge {_esc(e.protection)}'>{_esc(e.protection)}</span></td></tr>"
        for e in report.endpoints
    )

    page = f"""<!doctype html>
<meta charset="utf-8">
<title>RepoGuard report — {_esc(report.target)}</title>
<style>{_CSS}</style>
<h1>RepoGuard report</h1>
<p>Target: <code>{_esc(report.target)}</code><br>
Generated: {_esc(report.generated_at)}<br>
Base URL: {_esc(report.base_url)}<br>
Scanner status: {_esc(report.scanner_status)}</p>
<h2>Summary</h2>
<table><tr><th>Critical</th><th>High</th><th>Medium</th><th>Low</th><th>Info</th><th>Total</th></tr>
<tr><td>{counts.get('Critical', 0)}</td><td>{counts.get('High', 0)}</td>
<td>{counts.get('Medium', 0)}</td><td>{counts.get('Low', 0)}</td>
<td>{counts.get('Info', 0)}</td><td>{report.summary.get('total', 0)}</td></tr></table>
<h2>Fix first ({min(len(report.findings), TOP_N)} of {len(report.findings)})</h2>
<div class='fixfirst'><ol>{panel or '<li>No findings — nothing to fix.</li>'}</ol></div>
<h2>Endpoint inventory ({len(report.endpoints)})</h2>
<table><tr><th>Methods</th><th>Path</th><th>View</th><th>Auth</th><th>Protection</th></tr>
{ep_rows or '<tr><td colspan="5">No endpoints discovered.</td></tr>'}</table>
<h2>Findings ({len(report.findings)})</h2>
<table><tr><th>Severity</th><th>ID</th><th>Title</th><th>Where</th><th>Tool</th><th>OWASP</th></tr>
{rows or '<tr><td colspan="6">No findings.</td></tr>'}</table>
{cards}
<footer><p>Schema v{report.schema_version} · offline single file · ranked fix-first.</p></footer>
"""
    dest.write_text(page, encoding="utf-8")
    return dest
