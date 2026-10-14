"""Turn a ScanResult into JSON, CSV or a self-contained HTML report."""

from __future__ import annotations

import csv
import io
import json
from datetime import datetime, timezone
from html import escape

from .findings import ScanResult, Severity


def to_dict(result: ScanResult) -> dict:
    return {
        "target": result.target,
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "pages_scanned": result.pages_scanned,
        "summary": {str(sev): count for sev, count in result.by_severity().items()},
        "findings": [f.to_dict() for f in result.sorted_findings()],
    }


def to_json(result: ScanResult, indent: int = 2) -> str:
    return json.dumps(to_dict(result), indent=indent)


def to_csv(result: ScanResult) -> str:
    buffer = io.StringIO()
    writer = csv.DictWriter(
        buffer, fieldnames=["severity", "check_id", "title", "url", "evidence", "remediation", "category"]
    )
    writer.writeheader()
    for finding in result.sorted_findings():
        row = finding.to_dict()
        row["severity"] = row.pop("severity")
        writer.writerow(row)
    return buffer.getvalue()


_SEVERITY_COLOR = {
    Severity.CRITICAL: "#7f1d1d",
    Severity.HIGH: "#b91c1c",
    Severity.MEDIUM: "#b45309",
    Severity.LOW: "#1d4ed8",
    Severity.INFO: "#374151",
}

_HTML_TEMPLATE = """<!doctype html>
<html lang="en"><head><meta charset="utf-8">
<title>Security scan report - {target}</title>
<style>
 body {{ font-family: -apple-system, Segoe UI, Roboto, sans-serif; margin: 2rem; color: #111827; }}
 h1 {{ font-size: 1.4rem; }}
 .meta {{ color: #6b7280; margin-bottom: 1.5rem; }}
 .summary {{ display: flex; gap: .75rem; margin-bottom: 1.5rem; flex-wrap: wrap; }}
 .pill {{ color: #fff; padding: .35rem .75rem; border-radius: 999px; font-size: .85rem; }}
 table {{ border-collapse: collapse; width: 100%; }}
 th, td {{ text-align: left; padding: .5rem .6rem; border-bottom: 1px solid #e5e7eb; vertical-align: top; }}
 th {{ background: #f9fafb; }}
 .sev {{ color: #fff; padding: .15rem .5rem; border-radius: .35rem; font-size: .78rem; white-space: nowrap; }}
 code {{ background: #f3f4f6; padding: .1rem .3rem; border-radius: .25rem; font-size: .85em; }}
</style></head><body>
<h1>Security scan report</h1>
<div class="meta">Target: <code>{target}</code> &middot; {pages_scanned} page(s) scanned
&middot; generated {generated_at}</div>
<div class="summary">{summary_pills}</div>
<table>
<tr><th>Severity</th><th>Finding</th><th>URL</th><th>Evidence</th><th>Remediation</th></tr>
{rows}
</table>
</body></html>
"""


def _row_html(f) -> str:
    color = _SEVERITY_COLOR[f.severity]
    severity = escape(str(f.severity))
    title = escape(f.title)
    check_id = escape(f.check_id)
    category = escape(f.category)
    url = escape(f.url)
    evidence = escape(f.evidence)
    remediation = escape(f.remediation)
    return (
        f'<tr><td><span class="sev" style="background:{color}">{severity}</span></td>'
        f"<td><b>{title}</b><br><small>{check_id} &middot; {category}</small></td>"
        f"<td>{url}</td><td><code>{evidence}</code></td><td>{remediation}</td></tr>\n"
    )


def to_html(result: ScanResult) -> str:
    data = to_dict(result)
    pills = (
        "".join(
            f'<span class="pill" style="background:{_SEVERITY_COLOR[sev]}">{sev.name}: {count}</span>'
            for sev, count in result.by_severity().items()
            if count
        )
        or '<span class="pill" style="background:#047857">No findings</span>'
    )
    rows = "".join(_row_html(f) for f in result.sorted_findings())
    return _HTML_TEMPLATE.format(
        target=escape(result.target),
        pages_scanned=result.pages_scanned,
        generated_at=data["generated_at"],
        summary_pills=pills,
        rows=rows or "<tr><td colspan=5>No findings.</td></tr>",
    )


def print_summary(result: ScanResult) -> None:
    print(f"Target: {result.target}  ({result.pages_scanned} page(s) scanned)")
    counts = result.by_severity()
    print(
        "  " + "  ".join(f"{sev.name}:{count}" for sev, count in counts.items() if count) or "  No findings"
    )
    for finding in result.sorted_findings():
        print(f"  [{finding.severity}] {finding.title}  -  {finding.url}")
