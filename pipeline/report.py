"""Report formatting: JSON and Markdown rendering."""

from __future__ import annotations

import json
from datetime import datetime, timezone
from pathlib import Path

from models.result import Report, ReportEntry


def report_to_json(report: Report) -> str:
    return json.dumps(report.to_dict(), ensure_ascii=False, indent=2)


def report_to_markdown(report: Report) -> str:
    lines: list[str] = []
    lines.append("# Vulnerability Analysis Report")
    lines.append("")
    lines.append(f"- **Target**: `{report.target or 'N/A'}`")
    lines.append(f"- **Generated**: {report.generated_at or 'N/A'}")
    if report.meta:
        lines.append(f"- **Candidates**: {report.meta.get('candidates', 0)}  "
                     f"**Verified**: {report.meta.get('verified', 0)}")
    lines.append("")

    if not report.entries:
        lines.append("_No findings._")
        return "\n".join(lines)

    lines.append("| Status | CVE | Service | Version | Confidence |")
    lines.append("| --- | --- | --- | --- | --- |")
    for e in report.entries:
        lines.append(
            f"| `{e.final_status}` | {e.cve or '-'} | {e.service or '-'} | "
            f"{e.version or '-'} | {e.confidence:.2f} |"
        )
    lines.append("")

    for e in report.entries:
        lines.append(f"## {e.cve or 'No CVE'} - `{e.final_status}`")
        lines.append("")
        lines.append(f"- **Target**: `{e.target}`")
        lines.append(f"- **Service**: {e.service or 'N/A'}")
        lines.append(f"- **Version**: {e.version or 'N/A'}")
        lines.append(f"- **Description**: {e.description or 'N/A'}")
        lines.append(f"- **Verification method**: {e.verification_method or 'N/A'}")
        lines.append(f"- **Verification result**: {e.verification_result or 'N/A'}")
        lines.append(f"- **Confidence**: {e.confidence:.2f}")
        if e.evidence:
            lines.append(f"- **Evidence**: {e.evidence}")
        lines.append("")
    return "\n".join(lines)


def write_report(report: Report, path: str | Path, fmt: str | None = None) -> Path:
    """Write the report as JSON (``.json``) or Markdown (``.md``)."""
    path = Path(path)
    fmt = fmt or path.suffix.lstrip(".") or "md"
    if fmt == "json":
        content = report_to_json(report)
    else:
        content = report_to_markdown(report)
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(content, encoding="utf-8")
    return path


def new_report(asset_target: str) -> Report:
    return Report(
        target=asset_target,
        generated_at=datetime.now(timezone.utc).isoformat(),
    )
