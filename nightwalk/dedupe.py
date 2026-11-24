"""Persistent SQLite WAL ledger for defect deduplication, ticket cooldowns, and run history."""

from __future__ import annotations

import json
import os
import shutil
import sqlite3
import time
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from .models import Defect, RunSummary


def _iso_now() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="seconds")


class StateStore:
    """SQLite WAL store (mode 0600) tracking dogfood runs and deduplicated defect fingerprints."""

    def __init__(self, db_path: Path) -> None:
        self.db_path = db_path
        self.db_path.parent.mkdir(parents=True, exist_ok=True)
        self._init_schema()

    def _connect(self) -> sqlite3.Connection:
        con = sqlite3.connect(str(self.db_path), timeout=10.0)
        con.row_factory = sqlite3.Row
        con.execute("PRAGMA journal_mode=WAL")
        con.execute("PRAGMA foreign_keys=ON")
        return con

    def _init_schema(self) -> None:
        with self._connect() as con:
            con.executescript(
                """
                CREATE TABLE IF NOT EXISTS runs (
                    run_id TEXT PRIMARY KEY,
                    started_at TEXT NOT NULL,
                    finished_at TEXT NOT NULL,
                    elapsed_ms REAL NOT NULL,
                    dry_run INTEGER NOT NULL,
                    engine TEXT NOT NULL,
                    vision_model TEXT NOT NULL,
                    targets_run INTEGER NOT NULL,
                    flows_run INTEGER NOT NULL,
                    flows_passed INTEGER NOT NULL,
                    screenshots_captured INTEGER NOT NULL,
                    total_defects INTEGER NOT NULL,
                    unique_defects INTEGER NOT NULL,
                    tickets_filed INTEGER NOT NULL,
                    tickets_deduped INTEGER NOT NULL,
                    report_path TEXT NOT NULL,
                    artifacts_dir TEXT NOT NULL
                );

                CREATE TABLE IF NOT EXISTS defects (
                    fingerprint TEXT PRIMARY KEY,
                    target TEXT NOT NULL,
                    target_repo TEXT NOT NULL,
                    category TEXT NOT NULL,
                    severity TEXT NOT NULL,
                    title TEXT NOT NULL,
                    summary TEXT NOT NULL,
                    first_seen_at TEXT NOT NULL,
                    last_seen_at TEXT NOT NULL,
                    last_seen_epoch REAL NOT NULL,
                    occurrences INTEGER NOT NULL DEFAULT 1,
                    last_filed_at TEXT,
                    last_filed_epoch REAL,
                    pulse_task_id INTEGER,
                    latest_screenshots_json TEXT NOT NULL DEFAULT '[]'
                );
                """
            )
        if self.db_path.exists():
            os.chmod(self.db_path, 0o600)

    def get_defect(self, fingerprint: str) -> dict[str, Any] | None:
        with self._connect() as con:
            row = con.execute("SELECT * FROM defects WHERE fingerprint = ?", (fingerprint,)).fetchone()
            return dict(row) if row is not None else None

    def record_defect_seen(self, defect: Defect) -> dict[str, Any]:
        now_iso = _iso_now()
        now_epoch = time.time()
        shots_json = json.dumps(defect.screenshots[:6])
        with self._connect() as con:
            existing = con.execute(
                "SELECT * FROM defects WHERE fingerprint = ?",
                (defect.fingerprint,),
            ).fetchone()
            if existing is None:
                con.execute(
                    """
                    INSERT INTO defects (
                        fingerprint, target, target_repo, category, severity,
                        title, summary, first_seen_at, last_seen_at, last_seen_epoch,
                        occurrences, latest_screenshots_json
                    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, 1, ?)
                    """,
                    (
                        defect.fingerprint,
                        defect.target,
                        defect.target_repo,
                        defect.category,
                        defect.severity,
                        defect.title,
                        defect.summary,
                        now_iso,
                        now_iso,
                        now_epoch,
                        shots_json,
                    ),
                )
            else:
                con.execute(
                    """
                    UPDATE defects
                    SET severity = ?, title = ?, summary = ?, last_seen_at = ?, last_seen_epoch = ?,
                        occurrences = occurrences + 1, latest_screenshots_json = ?
                    WHERE fingerprint = ?
                    """,
                    (
                        defect.severity,
                        defect.title,
                        defect.summary,
                        now_iso,
                        now_epoch,
                        shots_json,
                        defect.fingerprint,
                    ),
                )
            row = con.execute("SELECT * FROM defects WHERE fingerprint = ?", (defect.fingerprint,)).fetchone()
            assert row is not None
            return dict(row)

    def mark_defect_filed(self, fingerprint: str, task_id: int | None) -> None:
        now_iso = _iso_now()
        now_epoch = time.time()
        with self._connect() as con:
            con.execute(
                """
                UPDATE defects
                SET last_filed_at = ?, last_filed_epoch = ?, pulse_task_id = COALESCE(?, pulse_task_id)
                WHERE fingerprint = ?
                """,
                (now_iso, now_epoch, task_id, fingerprint),
            )

    def is_within_cooldown(self, fingerprint: str, cooldown_hours: float) -> tuple[bool, int | None]:
        row = self.get_defect(fingerprint)
        if not row or not row.get("last_filed_epoch"):
            return (False, None)
        age_hours = (time.time() - float(row["last_filed_epoch"])) / 3600.0
        if age_hours < cooldown_hours:
            return (True, row.get("pulse_task_id"))
        return (False, row.get("pulse_task_id"))

    def record_run(self, summary: RunSummary) -> None:
        with self._connect() as con:
            con.execute(
                """
                INSERT OR REPLACE INTO runs (
                    run_id, started_at, finished_at, elapsed_ms, dry_run,
                    engine, vision_model, targets_run, flows_run, flows_passed,
                    screenshots_captured, total_defects, unique_defects,
                    tickets_filed, tickets_deduped, report_path, artifacts_dir
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    summary.run_id,
                    summary.started_at,
                    summary.finished_at,
                    summary.elapsed_ms,
                    1 if summary.dry_run else 0,
                    summary.engine,
                    summary.vision_model,
                    summary.targets_run,
                    summary.flows_run,
                    summary.flows_passed,
                    summary.screenshots_captured,
                    summary.total_defects,
                    summary.unique_defects,
                    summary.tickets_filed,
                    summary.tickets_deduped,
                    summary.report_path,
                    summary.artifacts_dir,
                ),
            )

    def list_runs(self, limit: int = 10) -> list[dict[str, Any]]:
        with self._connect() as con:
            rows = con.execute(
                "SELECT * FROM runs ORDER BY started_at DESC LIMIT ?",
                (max(1, int(limit)),),
            ).fetchall()
            return [dict(r) for r in rows]

    def list_defects(self, limit: int = 30) -> list[dict[str, Any]]:
        with self._connect() as con:
            rows = con.execute(
                "SELECT * FROM defects ORDER BY last_seen_epoch DESC LIMIT ?",
                (max(1, int(limit)),),
            ).fetchall()
            return [dict(r) for r in rows]


def prune_old_artifacts(runs_dir: Path, retention_days: int) -> int:
    """Remove run artifact directories older than retention_days."""
    if retention_days <= 0 or not runs_dir.is_dir():
        return 0
    cutoff = time.time() - (retention_days * 86400.0)
    removed = 0
    for child in runs_dir.iterdir():
        if not child.is_dir():
            continue
        try:
            if child.stat().st_mtime < cutoff:
                shutil.rmtree(child, ignore_errors=True)
                removed += 1
        except OSError:
            continue
    return removed
