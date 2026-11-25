"""Unit tests for SQLite StateStore resource safety and Markdown/panel rendering."""

from __future__ import annotations

import contextlib
import gc
import json
import os
import re
import sqlite3
import tempfile
import time
import unittest
import warnings
from pathlib import Path
from unittest.mock import patch

from nightwalk.dedupe import StateStore, prune_old_artifacts
from nightwalk.models import Defect, FlowRunResult, RunSummary, TicketAction, VisionAssessment
from nightwalk.report import (
    _atomic_write_text,
    render_markdown_report,
    write_markdown_report,
    write_status_panel,
)

EMOJI_RE = re.compile(
    "[\U0001F000-\U0001FAFF\U00002600-\U000027BF\U00002300-\U000023FF\U00002B00-\U00002BFF\U0000FE00-\U0000FE0F]"
)


def _make_defect(
    fingerprint: str = "fp_test_001",
    severity: str = "major",
    title: str = "Overflowing button",
    summary: str = "Button text overflows container",
    screenshots: list[str] | None = None,
) -> Defect:
    return Defect(
        fingerprint=fingerprint,
        target="local-app",
        target_repo="/tmp/fake-repo",
        flow="signup",
        viewport="fold-folded",
        category="layout_defect",
        severity=severity,
        title=title,
        summary=summary,
        evidence={"screenshot": "/tmp/fake-shot"},
        screenshots=screenshots or [],
        repro_steps=["open signup"],
    )


def _make_summary(
    run_id: str = "run_test_01",
    unique_defects: int = 0,
    total_defects: int = 0,
    vision_enabled: bool = False,
    vision_model: str = "",
    dry_run: bool = True,
    flows_run: int = 2,
    flows_passed: int = 2,
    defects: list[Defect] | None = None,
    ticket_actions: list[TicketAction] | None = None,
    flow_results: list[FlowRunResult] | None = None,
    started_at: str = "2026-06-01T03:00:00+00:00",
    screenshots_captured: int = 4,
    tickets_filed: int = 0,
    tickets_deduped: int = 0,
) -> RunSummary:
    return RunSummary(
        run_id=run_id,
        started_at=started_at,
        finished_at="2026-06-01T03:05:00+00:00",
        elapsed_ms=42000.0,
        dry_run=dry_run,
        engine="chromium",
        vision_enabled=vision_enabled,
        vision_model=vision_model,
        targets_run=1,
        flows_run=flows_run,
        flows_passed=flows_passed,
        screenshots_captured=screenshots_captured,
        total_defects=total_defects,
        unique_defects=unique_defects,
        tickets_filed=tickets_filed,
        tickets_deduped=tickets_deduped,
        report_path="/tmp/report.md",
        panel_path="/tmp/panel.json",
        artifacts_dir="/tmp/artifacts",
        flow_results=flow_results or [],
        defects=defects or [],
        ticket_actions=ticket_actions or [],
    )


class TestStateStore(unittest.TestCase):
    def setUp(self) -> None:
        self._tmp = tempfile.TemporaryDirectory()
        self.root = Path(self._tmp.name)

    def tearDown(self) -> None:
        self._tmp.cleanup()

    def test_init_creates_parents_wal_mode_and_mode_0600(self) -> None:
        db_path = self.root / "nested" / "deep" / "state.db"
        store = StateStore(db_path)
        self.assertTrue(db_path.is_file())
        self.assertTrue(db_path.parent.is_dir())
        self.assertEqual(os.stat(db_path).st_mode & 0o777, 0o600)
        with contextlib.closing(store._connect()) as con:
            journal = con.execute("PRAGMA journal_mode").fetchone()[0]
            fk = con.execute("PRAGMA foreign_keys").fetchone()[0]
        self.assertEqual(journal.lower(), "wal")
        self.assertEqual(fk, 1)

    def test_get_defect_unknown_returns_none(self) -> None:
        store = StateStore(self.root / "state.db")
        self.assertIsNone(store.get_defect("fp_does_not_exist"))

    def test_record_defect_seen_insert_and_update(self) -> None:
        store = StateStore(self.root / "state.db")
        shots = [f"shot_{i}.png" for i in range(8)]
        defect = _make_defect(screenshots=shots)
        row = store.record_defect_seen(defect)
        self.assertEqual(row["occurrences"], 1)
        self.assertEqual(row["first_seen_at"], row["last_seen_at"])
        self.assertEqual(json.loads(row["latest_screenshots_json"]), shots[:6])
        self.assertEqual(row["severity"], "major")

        time.sleep(0.01)
        updated = _make_defect(
            severity="critical",
            title="Revised title",
            summary="Revised summary",
            screenshots=["new_shot_1.png"],
        )
        row2 = store.record_defect_seen(updated)
        self.assertEqual(row2["occurrences"], 2)
        self.assertEqual(row2["severity"], "critical")
        self.assertEqual(row2["title"], "Revised title")
        self.assertEqual(row2["summary"], "Revised summary")
        self.assertEqual(json.loads(row2["latest_screenshots_json"]), ["new_shot_1.png"])
        self.assertEqual(row2["first_seen_at"], row["first_seen_at"])
        self.assertTrue(row2["last_seen_epoch"] >= row["last_seen_epoch"])
        # filing metadata preserved (never set at record time)
        self.assertIsNone(row2["last_filed_at"])
        self.assertIsNone(row2["pulse_task_id"])

    def test_mark_defect_filed_sets_fields_and_coalesce(self) -> None:
        store = StateStore(self.root / "state.db")
        store.record_defect_seen(_make_defect())
        store.mark_defect_filed("fp_test_001", 1234)
        row = store.get_defect("fp_test_001")
        self.assertIsNotNone(row)
        self.assertIsNotNone(row["last_filed_at"])
        self.assertIsNotNone(row["last_filed_epoch"])
        self.assertEqual(row["pulse_task_id"], 1234)

        # task_id=None preserves existing pulse_task_id via COALESCE
        store.mark_defect_filed("fp_test_001", None)
        row = store.get_defect("fp_test_001")
        self.assertEqual(row["pulse_task_id"], 1234)

        # new int updates it
        store.mark_defect_filed("fp_test_001", 5678)
        row = store.get_defect("fp_test_001")
        self.assertEqual(row["pulse_task_id"], 5678)

    def test_is_within_cooldown_states(self) -> None:
        store = StateStore(self.root / "state.db")
        self.assertEqual(store.is_within_cooldown("fp_missing", 24.0), (False, None))

        store.record_defect_seen(_make_defect())
        self.assertEqual(store.is_within_cooldown("fp_test_001", 24.0), (False, None))

        store.mark_defect_filed("fp_test_001", 4321)
        within, tid = store.is_within_cooldown("fp_test_001", 24.0)
        self.assertTrue(within)
        self.assertEqual(tid, 4321)

        # force the filing to look expired
        with contextlib.closing(sqlite3.connect(str(self.root / "state.db"))) as con, con:
            con.execute(
                "UPDATE defects SET last_filed_epoch = ? WHERE fingerprint = ?",
                (time.time() - 4 * 3600, "fp_test_001"),
            )
        within, tid = store.is_within_cooldown("fp_test_001", 1.0)
        self.assertFalse(within)
        self.assertEqual(tid, 4321)

    def test_record_run_insert_replace_and_list_runs(self) -> None:
        store = StateStore(self.root / "state.db")
        s1 = _make_summary(run_id="run_1", started_at="2026-06-01T01:00:00+00:00", dry_run=True)
        s2 = _make_summary(run_id="run_2", started_at="2026-06-02T01:00:00+00:00", dry_run=False)
        s3 = _make_summary(run_id="run_3", started_at="2026-06-03T01:00:00+00:00", dry_run=True)
        store.record_run(s1)
        store.record_run(s2)
        store.record_run(s3)

        runs = store.list_runs(10)
        self.assertEqual([r["run_id"] for r in runs], ["run_3", "run_2", "run_1"])
        self.assertEqual(runs[0]["dry_run"], 1)
        self.assertEqual(runs[1]["dry_run"], 0)

        # INSERT OR REPLACE: same run_id replaces and reorders
        s1b = _make_summary(run_id="run_1", started_at="2026-06-04T01:00:00+00:00", dry_run=False)
        store.record_run(s1b)
        runs = store.list_runs(10)
        self.assertEqual([r["run_id"] for r in runs], ["run_1", "run_3", "run_2"])
        self.assertEqual(runs[0]["dry_run"], 0)

        # limit clamp <= 0 -> 1
        runs = store.list_runs(0)
        self.assertEqual(len(runs), 1)

    def test_list_defects_orders_desc_and_clamps_limit(self) -> None:
        store = StateStore(self.root / "state.db")

        for fp in ["fp_a", "fp_b", "fp_c"]:
            store.record_defect_seen(_make_defect(fingerprint=fp))
            time.sleep(0.02)

        defects = store.list_defects(10)
        self.assertEqual([d["fingerprint"] for d in defects], ["fp_c", "fp_b", "fp_a"])
        defects = store.list_defects(0)
        self.assertEqual(len(defects), 1)
        self.assertEqual(defects[0]["fingerprint"], "fp_c")

    def test_init_skips_chmod_when_db_file_missing(self) -> None:
        with patch.object(Path, "exists", return_value=False):
            store = StateStore(self.root / "state.db")
        self.assertTrue((self.root / "state.db").is_file())
        self.assertIsNotNone(store)

    def test_all_methods_close_connection_on_exception(self) -> None:
        class _RaisingConnection(sqlite3.Connection):
            def execute(self, *args, **kwargs):
                raise RuntimeError("boom")

            def executescript(self, *args, **kwargs):
                raise RuntimeError("boom")

        def raising_connect(self):
            return _RaisingConnection(str(self.db_path))

        with warnings.catch_warnings(record=True) as caught:
            warnings.simplefilter("always", ResourceWarning)
            with patch.object(StateStore, "_connect", new=raising_connect):
                with self.assertRaises(RuntimeError):
                    StateStore(self.root / "nested" / "state.db")

            store = StateStore(self.root / "state.db")
            with patch.object(StateStore, "_connect", new=raising_connect):
                with self.assertRaises(RuntimeError):
                    store.get_defect("fp_test_001")
                with self.assertRaises(RuntimeError):
                    store.record_defect_seen(_make_defect())
                with self.assertRaises(RuntimeError):
                    store.mark_defect_filed("fp_test_001", 1)
                with self.assertRaises(RuntimeError):
                    store.record_run(_make_summary())
                with self.assertRaises(RuntimeError):
                    store.list_runs()
                with self.assertRaises(RuntimeError):
                    store.list_defects()
            gc.collect()
        resource_warnings = [w for w in caught if issubclass(w.category, ResourceWarning)]
        self.assertEqual(resource_warnings, [], f"ResourceWarnings: {resource_warnings}")

    def test_prune_old_artifacts_skips_unstatable_children(self) -> None:
        runs_dir = self.root / "runs"
        runs_dir.mkdir()
        doomed = runs_dir / "doomed"
        doomed.mkdir()
        recent = runs_dir / "recent"
        recent.mkdir()

        real_stat = Path.stat

        def flaky_stat(self, *args, **kwargs):
            # is_dir() uses os.path.isdir, so the only Path.stat call is the
            # one inside the try in prune_old_artifacts; raise there
            if self.name == "doomed":
                raise OSError("boom")
            return real_stat(self, *args, **kwargs)

        with patch.object(Path, "stat", flaky_stat):
            removed = prune_old_artifacts(runs_dir, 14)

        self.assertEqual(removed, 0)
        self.assertTrue(doomed.is_dir())
        self.assertTrue(recent.is_dir())

    def test_prune_old_artifacts(self) -> None:
        # retention_days <= 0 -> no-op
        runs_dir = self.root / "runs"
        runs_dir.mkdir()
        self.assertEqual(prune_old_artifacts(runs_dir, 0), 0)

        # missing directory -> 0
        self.assertEqual(prune_old_artifacts(self.root / "missing", 14), 0)

        old_dir = runs_dir / "2026-05-01-old"
        old_dir.mkdir()
        recent_dir = runs_dir / "2026-06-01-recent"
        recent_dir.mkdir()
        regular_file = runs_dir / "stray-file.txt"
        regular_file.write_text("x")
        old_time = time.time() - 30 * 86400
        os.utime(old_dir, (old_time, old_time))

        removed = prune_old_artifacts(runs_dir, 14)
        self.assertEqual(removed, 1)
        self.assertFalse(old_dir.exists())
        self.assertTrue(recent_dir.exists())
        self.assertTrue(regular_file.exists())

    def test_state_store_emits_no_resource_warnings(self) -> None:
        with warnings.catch_warnings(record=True) as caught:
            warnings.simplefilter("always", ResourceWarning)
            with tempfile.TemporaryDirectory() as td:
                store = StateStore(Path(td) / "state.db")
                store.record_defect_seen(_make_defect(screenshots=[f"s{i}" for i in range(7)]))
                store.get_defect("fp_test_001")
                store.mark_defect_filed("fp_test_001", 111)
                store.is_within_cooldown("fp_test_001", 24.0)
                store.record_run(_make_summary())
                store.list_runs(5)
                store.list_defects(5)
                gc.collect()
        resource_warnings = [w for w in caught if issubclass(w.category, ResourceWarning)]
        self.assertEqual(resource_warnings, [], f"ResourceWarnings: {resource_warnings}")


class TestReportHelpers(unittest.TestCase):
    def setUp(self) -> None:
        self._tmp = tempfile.TemporaryDirectory()
        self.root = Path(self._tmp.name)

    def tearDown(self) -> None:
        self._tmp.cleanup()

    def test_atomic_write_text_creates_parents_sets_mode_replaces_and_cleans_tmp(self) -> None:
        target = self.root / "sub" / "dir" / "file.md"
        result = _atomic_write_text(target, "hello", mode=0o640)
        self.assertEqual(result, target)
        self.assertEqual(target.read_text(), "hello")
        self.assertEqual(os.stat(target).st_mode & 0o777, 0o640)

        # atomically replaces existing file
        _atomic_write_text(target, "world", mode=0o644)
        self.assertEqual(target.read_text(), "world")
        self.assertEqual(os.stat(target).st_mode & 0o777, 0o644)

        leftovers = [p.name for p in target.parent.glob(".*.tmp.*")]
        self.assertEqual(leftovers, [])


class TestMarkdownReport(unittest.TestCase):
    def setUp(self) -> None:
        self._tmp = tempfile.TemporaryDirectory()
        self.root = Path(self._tmp.name)

    def tearDown(self) -> None:
        self._tmp.cleanup()

    def test_clean_run(self) -> None:
        summary = _make_summary(
            unique_defects=0,
            total_defects=0,
            vision_enabled=False,
            vision_model="",
            flows_run=2,
            flows_passed=2,
            flow_results=[
                FlowRunResult(
                    target="local-app",
                    flow="signup",
                    viewport="fold-folded",
                    viewport_px="374x844",
                    ok=True,
                    elapsed_ms=1200.0,
                ),
            ],
        )
        text = render_markdown_report(summary)
        self.assertIn("status: CLEAN", text)
        self.assertIn("vision_model: disabled", text)
        self.assertIn("## Flow Matrix", text)
        self.assertIn("| `local-app` | `signup`", text)
        self.assertIn("PASS", text)
        self.assertIn("skip", text)
        self.assertNotIn("## Unique Defects", text)
        self.assertNotIn("## Ticket Filing Summary", text)

        text2 = render_markdown_report(_make_summary(unique_defects=0, flow_results=[]))
        self.assertIn("status: CLEAN", text2)
        self.assertNotIn("## Unique Defects", text2)
        self.assertFalse(EMOJI_RE.search(text2))

    def test_defect_run_renders_sections_and_caps(self) -> None:
        defects = [
            _make_defect(
                fingerprint="fp_critical",
                severity="critical",
                title="Blank screen",
                summary="Screen is blank",
                screenshots=[f"shot_{i}.png" for i in range(6)],
            ),
            _make_defect(
                fingerprint="fp_minor",
                severity="minor",
                title="Slight spacing nit",
                summary="Tight spacing",
                screenshots=[],
            ),
        ]
        ticket_actions = [
            TicketAction(fingerprint="fp_critical", action="filed", title="Blank screen", task_id=42, reason="new"),
            TicketAction(fingerprint="fp_minor", action="deduped_cooldown", title="Slight spacing nit", task_id=None, reason="cooldown"),
        ]
        flows = [
            FlowRunResult(
                target="local-app",
                flow="signup",
                viewport="fold-folded",
                viewport_px="374x844",
                ok=True,
                elapsed_ms=1500.0,
                vision=[
                    VisionAssessment(screenshot_path="/tmp/a.png", verdict="PASS", score_10=8.0, elapsed_ms=300.0, model="test-vlm", summary="ok"),
                    VisionAssessment(screenshot_path="/tmp/b.png", verdict="WARN", score_10=None, elapsed_ms=400.0, model="test-vlm", summary="meh"),
                ],
            ),
            FlowRunResult(
                target="local-app",
                flow="checkout",
                viewport="desktop",
                viewport_px="1280x800",
                ok=False,
                elapsed_ms=9000.0,
                console_errors=[],
            ),
        ]
        summary = _make_summary(
            unique_defects=2,
            total_defects=3,
            vision_enabled=True,
            vision_model="test-vlm",
            dry_run=True,
            flows_run=2,
            flows_passed=1,
            defects=defects,
            ticket_actions=ticket_actions,
            flow_results=flows,
            screenshots_captured=6,
            tickets_filed=1,
            tickets_deduped=1,
        )
        text = render_markdown_report(summary)

        # frontmatter + status
        self.assertIn("status: 2 DEFECT(S)", text)
        self.assertIn("dry_run: true", text)
        self.assertIn("vision_model: test-vlm", text)
        self.assertIn("## Unique Defects", text)
        self.assertIn("## Ticket Filing Summary", text)
        self.assertIn("PASS(8/10)", text)
        self.assertIn("WARN", text)
        # PASS and FAIL rows
        self.assertIn("| `local-app` | `signup`", text)
        self.assertIn("| `local-app` | `checkout`", text)
        self.assertIn("PASS", text)
        self.assertIn("FAIL", text)
        # 6 screenshots capped to 4
        self.assertIn("shot_0.png", text)
        self.assertIn("shot_3.png", text)
        self.assertNotIn("shot_4.png", text)
        self.assertNotIn("shot_5.png", text)
        # minor defect with no screenshots renders without a Screenshots line
        self.assertIn("fp_minor", text)
        # ticket action with task_id and one with None -> '--'
        self.assertIn("#42", text)
        self.assertIn("| `fp_minor` | `deduped_cooldown` | -- | Slight spacing nit | cooldown |", text)
        # zero emojis
        self.assertEqual(EMOJI_RE.findall(text), [])

    def test_write_markdown_report_filename_and_mode(self) -> None:
        summary = _make_summary(started_at="2026-06-01T03:00:00+00:00", flow_results=[])
        out = write_markdown_report(self.root / "reports", summary)
        self.assertEqual(out.name, "2026-06-01-nightwalk.md")
        self.assertEqual(out.parent.name, "reports")
        self.assertEqual(os.stat(out).st_mode & 0o777, 0o644)
        self.assertIn("status: CLEAN", out.read_text())

    def test_status_panel_all_clear(self) -> None:
        summary = _make_summary(
            unique_defects=0,
            total_defects=0,
            flows_run=2,
            flows_passed=2,
            defects=[],
            ticket_actions=[],
            flow_results=[
                FlowRunResult(target="local-app", flow="signup", viewport="desktop", viewport_px="1280x800", ok=True, elapsed_ms=1000.0),
                FlowRunResult(target="local-app", flow="checkout", viewport="desktop", viewport_px="1280x800", ok=True, elapsed_ms=1100.0),
            ],
        )
        panel = write_status_panel(self.root / "panels" / "panel.json", summary)
        self.assertEqual(os.stat(panel).st_mode & 0o777, 0o644)
        data = json.loads(panel.read_text())
        self.assertEqual(data["badge"], "ALL CLEAR")
        self.assertEqual(data["badgeTone"], "ok")
        self.assertEqual(data["id"], "nightwalk-dogfood")
        self.assertEqual(data["title"], "Customer-Zero QA")
        tones = {m["label"]: m["tone"] for m in data["metrics"]}
        self.assertEqual(tones["Flows"], "ok")
        self.assertEqual(tones["Defects"], "ok")
        self.assertEqual(tones["Filed"], "muted")
        self.assertEqual(tones["Shots"], "muted")
        self.assertFalse(EMOJI_RE.search(data["markdown"]))
        leftovers = list(panel.parent.glob(".*.tmp.*"))
        self.assertEqual(leftovers, [])

    def test_status_panel_critical(self) -> None:
        defects = [
            _make_defect(fingerprint=f"fp_{i}", severity="critical", title=f"Critical issue {i}")
            for i in range(5)
        ]
        summary = _make_summary(
            unique_defects=5,
            total_defects=6,
            flows_run=2,
            flows_passed=2,
            defects=defects,
            tickets_filed=3,
            tickets_deduped=1,
            screenshots_captured=10,
            flow_results=[],
        )
        panel = write_status_panel(self.root / "panel.json", summary)
        data = json.loads(panel.read_text())
        self.assertEqual(data["badge"], "5 CRITICAL")
        self.assertEqual(data["badgeTone"], "danger")
        tones = {m["label"]: m["tone"] for m in data["metrics"]}
        self.assertEqual(tones["Flows"], "ok")
        self.assertEqual(tones["Defects"], "warn")
        self.assertEqual(tones["Filed"], "info")
        self.assertEqual(tones["Shots"], "muted")
        # Top Findings capped to 4 of 5 defects
        md = data["markdown"]
        self.assertEqual(md.count("**[CRITICAL]"), 4)
        self.assertIn("Critical issue 0", md)
        self.assertIn("Critical issue 3", md)
        self.assertNotIn("Critical issue 4", md)
        self.assertFalse(EMOJI_RE.search(md))

    def test_status_panel_defects_warn_with_partial_flows(self) -> None:
        defects = [
            _make_defect(fingerprint="fp_major", severity="major", title="Major issue"),
            _make_defect(fingerprint="fp_minor", severity="minor", title="Minor issue"),
        ]
        summary = _make_summary(
            unique_defects=2,
            total_defects=3,
            flows_run=3,
            flows_passed=2,
            defects=defects,
            tickets_filed=0,
            tickets_deduped=0,
            flow_results=[],
        )
        panel = write_status_panel(self.root / "panel.json", summary)
        data = json.loads(panel.read_text())
        self.assertEqual(data["badge"], "2 DEFECTS")
        self.assertEqual(data["badgeTone"], "warn")
        tones = {m["label"]: m["tone"] for m in data["metrics"]}
        self.assertEqual(tones["Flows"], "warn")
        self.assertEqual(tones["Defects"], "warn")
        self.assertEqual(tones["Filed"], "muted")
        self.assertFalse(EMOJI_RE.search(data["markdown"]))
        leftovers = list(panel.parent.glob(".*.tmp.*"))
        self.assertEqual(leftovers, [])


if __name__ == "__main__":
    unittest.main()
