"""Deduplicated, screenshot-backed P2 bug ticket filing into vega-pulse (or compatible CLI)."""

from __future__ import annotations

import json
import re
import subprocess
from typing import Any

from .config import NightwalkConfig
from .dedupe import StateStore
from .models import Defect, TicketAction
from .redact import redact_text

_OPEN_STATUSES = frozenset({"queued", "scheduled", "running", "needs_mikey"})
_FP_TAG_RE = re.compile(r"\[dogfood:([a-f0-9]{8,16})\]", re.IGNORECASE)


def deduplicate_defects_in_run(defects: list[Defect]) -> list[Defect]:
    """Merge duplicate defects discovered across multiple viewports/flows in one run."""
    merged: dict[str, Defect] = {}
    for d in defects:
        existing = merged.get(d.fingerprint)
        if existing is None:
            merged[d.fingerprint] = Defect(
                fingerprint=d.fingerprint,
                target=d.target,
                target_repo=d.target_repo,
                flow=d.flow,
                viewport=d.viewport,
                category=d.category,
                severity=d.severity,
                title=d.title,
                summary=d.summary,
                evidence=dict(d.evidence),
                screenshots=list(dict.fromkeys(d.screenshots)),
                repro_steps=list(d.repro_steps),
            )
            continue

        # Preserve highest severity and merge viewports + screenshot evidence
        rank = {"critical": 3, "major": 2, "minor": 1}
        if rank.get(d.severity, 0) > rank.get(existing.severity, 0):
            existing.severity = d.severity
        if d.viewport and d.viewport not in existing.viewport:
            existing.viewport = f"{existing.viewport}, {d.viewport}"
        if d.flow and d.flow not in existing.flow:
            existing.flow = f"{existing.flow}, {d.flow}"
        for shot in d.screenshots:
            if shot not in existing.screenshots:
                existing.screenshots.append(shot)

    return list(merged.values())


def fetch_open_pulse_tickets(list_cmd: list[str]) -> tuple[dict[str, int], dict[str, int]]:
    """Query open backlog tickets and index them by [dogfood:<fp>] tag and normalized title."""
    if not list_cmd:
        return ({}, {})
    try:
        proc = subprocess.run(list_cmd, capture_output=True, text=True, timeout=15, check=False)
        if proc.returncode != 0:
            return ({}, {})
        raw = json.loads(proc.stdout)
    except Exception:
        return ({}, {})

    tasks = raw.get("tasks", raw) if isinstance(raw, dict) else raw
    if not isinstance(tasks, list):
        return ({}, {})

    by_fp: dict[str, int] = {}
    by_title: dict[str, int] = {}
    for t in tasks:
        if not isinstance(t, dict):
            continue
        status = str(t.get("status") or "").strip().lower()
        if status not in _OPEN_STATUSES:
            continue
        tid = t.get("id")
        if tid is None:
            continue
        task_id = int(tid)
        title = str(t.get("title") or "")
        desc = str(t.get("description") or "")
        by_title[title.strip().lower()] = task_id
        for match in _FP_TAG_RE.finditer(f"{title}\n{desc}"):
            by_fp[match.group(1).lower()] = task_id
    return (by_fp, by_title)


def build_ticket_description(defect: Defect, run_id: str, report_path: str) -> str:
    """Build a crisp, screenshot-backed, secret-redacted bug description for vega-pulse."""
    lines = [
        f"Automated Customer-Zero dogfood finding [dogfood:{defect.fingerprint}] from run `{run_id}`.",
        f"- Target: `{defect.target}`",
        f"- Category: `{defect.category}` | Severity: `{defect.severity}`",
        f"- Flow(s): `{defect.flow}`",
        f"- Viewport(s): `{defect.viewport}`",
        f"- Summary: {redact_text(defect.summary)}",
    ]
    if defect.repro_steps:
        lines.append("- Reproduction steps:")
        for step in defect.repro_steps[:10]:
            lines.append(f"  {redact_text(step)}")
    if defect.screenshots:
        lines.append("- Screenshot evidence:")
        for shot in defect.screenshots[:4]:
            lines.append(f"  - `{shot}`")
    if report_path:
        lines.append(f"- Full nightly report: `{report_path}`")
    if defect.evidence:
        ev_str = redact_text(json.dumps(defect.evidence, ensure_ascii=True))[:700]
        lines.append(f"- Telemetry excerpt: `{ev_str}`")
    lines.append("Fix the root cause cleanly, add regression test coverage, and verify across Fold 8 folded/unfolded + desktop viewports.")
    return "\n".join(lines)


def _submit_pulse_ticket(
    add_cmd: list[str],
    *,
    title: str,
    description: str,
    priority: str,
    target_repo: str,
) -> tuple[bool, int | None, str]:
    cmd = list(add_cmd) + [
        title,
        "--priority",
        priority,
        "--mode",
        "autonomous",
        "--origin",
        "scout",
        "--desc",
        description,
        "--json",
    ]
    if target_repo:
        cmd.extend(["--repo", target_repo])
    try:
        proc = subprocess.run(cmd, capture_output=True, text=True, timeout=20, check=False)
    except Exception as exc:
        return (False, None, f"Failed to invoke ticket CLI: {exc}")

    if proc.returncode != 0:
        err = (proc.stderr or proc.stdout or "").strip()[:300]
        return (False, None, f"Ticket CLI exited {proc.returncode}: {err}")

    try:
        parsed = json.loads(proc.stdout)
        task_obj = parsed.get("task", parsed) if isinstance(parsed, dict) else {}
        tid = task_obj.get("id") if isinstance(task_obj, dict) else None
        return (True, int(tid) if tid is not None else None, "")
    except Exception:
        return (True, None, "")


def process_defect_tickets(
    *,
    cfg: NightwalkConfig,
    store: StateStore,
    defects: list[Defect],
    run_id: str,
    report_path: str,
    dry_run: bool = False,
) -> list[TicketAction]:
    """Deduplicate against live vega-pulse + SQLite cooldown and auto-file P2 bug tickets."""
    unique = deduplicate_defects_in_run(defects)
    if not unique:
        return []

    open_by_fp, open_by_title = fetch_open_pulse_tickets(cfg.ticket_list_cmd)
    actions: list[TicketAction] = []
    filed_count = 0

    for defect in unique:
        store.record_defect_seen(defect)
        title = redact_text(f"Dogfood: {defect.title}")[:180]

        if defect.severity == "minor":
            actions.append(
                TicketAction(
                    fingerprint=defect.fingerprint,
                    action="skipped_minor",
                    title=title,
                    reason="Minor severity logged to report only",
                )
            )
            continue

        # Layer 1: Live open ticket dedupe in vega-pulse
        existing_open = open_by_fp.get(defect.fingerprint.lower()) or open_by_title.get(title.strip().lower())
        if existing_open is not None:
            actions.append(
                TicketAction(
                    fingerprint=defect.fingerprint,
                    action="deduped_open",
                    title=title,
                    task_id=existing_open,
                    reason=f"Already open in backlog as #{existing_open}",
                )
            )
            continue

        # Layer 2: Persistent SQLite cooldown dedupe
        in_cooldown, prev_tid = store.is_within_cooldown(defect.fingerprint, cfg.ticket_cooldown_hours)
        if in_cooldown:
            actions.append(
                TicketAction(
                    fingerprint=defect.fingerprint,
                    action="deduped_cooldown",
                    title=title,
                    task_id=prev_tid,
                    reason=f"Filed within cooldown ({int(cfg.ticket_cooldown_hours)}h), previous #{prev_tid or '?'}",
                )
            )
            continue

        if dry_run or not cfg.auto_file_tickets or not cfg.ticket_add_cmd:
            actions.append(
                TicketAction(
                    fingerprint=defect.fingerprint,
                    action="dry_run",
                    title=title,
                    reason="Dry-run or auto-filing disabled",
                )
            )
            continue

        if filed_count >= cfg.max_tickets_per_run:
            actions.append(
                TicketAction(
                    fingerprint=defect.fingerprint,
                    action="capped",
                    title=title,
                    reason=f"Reached max_tickets_per_run ({cfg.max_tickets_per_run})",
                )
            )
            continue

        desc = build_ticket_description(defect, run_id=run_id, report_path=report_path)
        ok, task_id, err = _submit_pulse_ticket(
            cfg.ticket_add_cmd,
            title=title,
            description=desc,
            priority=cfg.ticket_priority,
            target_repo=defect.target_repo,
        )
        if ok:
            filed_count += 1
            store.mark_defect_filed(defect.fingerprint, task_id)
            open_by_fp[defect.fingerprint.lower()] = task_id or -1
            actions.append(
                TicketAction(
                    fingerprint=defect.fingerprint,
                    action="filed",
                    title=title,
                    task_id=task_id,
                    reason=f"Filed {cfg.ticket_priority} ticket" + (f" #{task_id}" if task_id else ""),
                )
            )
        else:
            actions.append(
                TicketAction(
                    fingerprint=defect.fingerprint,
                    action="error",
                    title=title,
                    reason=err,
                )
            )

    return actions
