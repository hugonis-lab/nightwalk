"""Atomic nightly Markdown report and calm read-first status panel writers (zero emojis)."""

from __future__ import annotations

import json
import os
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from .models import RunSummary


def _atomic_write_text(path: Path, text: str, mode: int = 0o644) -> Path:
    path.parent.mkdir(parents=True, exist_ok=True)
    tmp = path.with_name(f".{path.name}.tmp.{os.getpid()}")
    tmp.write_text(text, encoding="utf-8")
    os.chmod(tmp, mode)
    tmp.replace(path)
    return path


def render_markdown_report(summary: RunSummary) -> str:
    """Render a clean, linkable Markdown report of the dogfooding run."""
    date_str = summary.started_at[:10]
    status_label = "CLEAN" if summary.unique_defects == 0 else f"{summary.unique_defects} DEFECT(S)"
    lines = [
        "---",
        f"title: Nightwalk Customer-Zero Dogfooding Report ({date_str})",
        f"run_id: {summary.run_id}",
        f"started_at: {summary.started_at}",
        f"finished_at: {summary.finished_at}",
        f"status: {status_label}",
        f"dry_run: {str(summary.dry_run).lower()}",
        f"vision_model: {summary.vision_model or 'disabled'}",
        "---",
        "",
        f"# Nightwalk Dogfooding Report — {date_str}",
        "",
        f"- **Status**: `{status_label}` (`{summary.flows_passed}/{summary.flows_run}` flows clean across `{summary.targets_run}` target(s))",
        f"- **Elapsed**: `{summary.elapsed_ms / 1000.0:.1f}s` | **Engine**: `{summary.engine}` | **Vision**: `{summary.vision_model if summary.vision_enabled else 'disabled'}`",
        f"- **Screenshots**: `{summary.screenshots_captured}` | **Defects**: `{summary.unique_defects}` unique (`{summary.total_defects}` raw)",
        f"- **Tickets**: `{summary.tickets_filed}` filed, `{summary.tickets_deduped}` deduplicated",
        f"- **Artifacts**: `{summary.artifacts_dir}`",
        "",
        "## Flow Matrix",
        "",
        "| Target | Flow | Viewport | Status | Console Err | Failed Net | Slow (>300ms) | Broken Links | Vision |",
        "| --- | --- | --- | --- | ---: | ---: | ---: | ---: | --- |",
    ]

    for fr in summary.flow_results:
        vis_str = "skip"
        if fr.vision:
            verdicts = [
                f"{v.verdict}({v.score_10:.0f}/10)" if v.score_10 is not None else v.verdict
                for v in fr.vision
            ]
            vis_str = ", ".join(verdicts)
        lines.append(
            f"| `{fr.target}` | `{fr.flow}` | `{fr.viewport}` ({fr.viewport_px}) | "
            f"{'PASS' if fr.ok else 'FAIL'} | {len(fr.console_errors)} | "
            f"{len(fr.failed_requests)} | {len(fr.slow_endpoints)} | "
            f"{len(fr.broken_links)}/{fr.links_checked} | {vis_str} |"
        )

    if summary.defects:
        lines.extend(["", "## Unique Defects", ""])
        for d in summary.defects:
            lines.append(f"### [{d.severity.upper()}] {d.title} (`{d.fingerprint}`)")
            lines.append("")
            lines.append(f"- **Category**: `{d.category}` | **Flow**: `{d.flow}` | **Viewport**: `{d.viewport}`")
            lines.append(f"- **Summary**: {d.summary}")
            if d.screenshots:
                lines.append("- **Screenshots**: " + ", ".join(f"`{s}`" for s in d.screenshots[:4]))
            lines.append("")

    if summary.ticket_actions:
        lines.extend(
            [
                "## Ticket Filing Summary",
                "",
                "| Fingerprint | Action | Task ID | Title | Detail |",
                "| --- | --- | --- | --- | --- |",
            ]
        )
        for ta in summary.ticket_actions:
            tid = f"#{ta.task_id}" if ta.task_id is not None else "--"
            lines.append(f"| `{ta.fingerprint}` | `{ta.action}` | {tid} | {ta.title} | {ta.reason} |")

    lines.append("")
    return "\n".join(lines)


def write_markdown_report(report_dir: Path, summary: RunSummary) -> Path:
    date_str = summary.started_at[:10]
    path = report_dir / f"{date_str}-nightwalk.md"
    return _atomic_write_text(path, render_markdown_report(summary), mode=0o644)


def write_status_panel(panel_path: Path, summary: RunSummary) -> Path:
    """Write a calm, read-first panel.schema.json-compliant JSON panel (strictly zero emojis)."""
    if summary.unique_defects == 0:
        badge = "ALL CLEAR"
        tone = "ok"
    elif any(d.severity == "critical" for d in summary.defects):
        badge = f"{summary.unique_defects} CRITICAL"
        tone = "danger"
    else:
        badge = f"{summary.unique_defects} DEFECTS"
        tone = "warn"

    md_lines = [
        f"**Last run**: `{summary.started_at[:16].replace('T', ' ')} UTC` · **Engine**: `{summary.engine}` · **Vision**: `{summary.vision_model if summary.vision_enabled else 'off'}`",
        f"**Flows**: `{summary.flows_passed}/{summary.flows_run}` passed · **Screenshots**: `{summary.screenshots_captured}` · **Tickets**: `{summary.tickets_filed}` filed, `{summary.tickets_deduped}` deduped",
    ]
    if summary.defects:
        md_lines.append("")
        md_lines.append("**Top Findings**")
        for d in summary.defects[:4]:
            md_lines.append(f"- **[{d.severity.upper()}] {d.title}** (`{d.category}` · `{d.viewport}`)")
    else:
        md_lines.append("")
        md_lines.append("All customer-zero flows passed with zero console errors, broken links, slow endpoints, or major visual regressions.")

    payload: dict[str, Any] = {
        "id": "nightwalk-dogfood",
        "title": "Customer-Zero QA",
        "subtitle": "Nightly interactive dogfooding & Vision QA",
        "badge": badge,
        "badgeTone": tone,
        "updatedAt": datetime.now(timezone.utc).isoformat(timespec="seconds"),
        "metrics": [
            {"label": "Flows", "value": f"{summary.flows_passed}/{summary.flows_run}", "tone": "ok" if summary.flows_passed == summary.flows_run else "warn"},
            {"label": "Defects", "value": summary.unique_defects, "tone": "ok" if summary.unique_defects == 0 else "warn"},
            {"label": "Filed", "value": summary.tickets_filed, "tone": "info" if summary.tickets_filed > 0 else "muted"},
            {"label": "Shots", "value": summary.screenshots_captured, "tone": "muted"},
        ],
        "markdown": "\n".join(md_lines),
    }
    return _atomic_write_text(panel_path, json.dumps(payload, indent=2) + "\n", mode=0o644)
