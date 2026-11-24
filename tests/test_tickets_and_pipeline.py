"""Unit tests for SQLite deduplication, P2 ticket filing, and report/panel generation."""

from __future__ import annotations

import json
import sys
import tempfile
import unittest
from pathlib import Path

from nightwalk.config import NightwalkConfig
from nightwalk.dedupe import StateStore
from nightwalk.models import Defect, RunSummary
from nightwalk.report import write_markdown_report, write_status_panel
from nightwalk.tickets import deduplicate_defects_in_run, process_defect_tickets


def _make_fake_pulse_script(path: Path, state_file: Path) -> None:
    """Create a tiny standalone fake vega-pulse CLI for deterministic offline testing."""
    script = f"""#!{sys.executable}
import json, sys
from pathlib import Path

state_path = Path({str(state_file)!r})
tasks = json.loads(state_path.read_text()) if state_path.exists() else []
args = sys.argv[1:]
if args and args[0] == "list":
    print(json.dumps({{"tasks": tasks}}))
    sys.exit(0)
if args and args[0] == "add":
    title = args[1]
    desc = ""
    prio = "P2"
    repo = ""
    i = 2
    while i < len(args):
        if args[i] == "--desc" and i + 1 < len(args):
            desc = args[i + 1]; i += 2
        elif args[i] == "--priority" and i + 1 < len(args):
            prio = args[i + 1]; i += 2
        elif args[i] == "--repo" and i + 1 < len(args):
            repo = args[i + 1]; i += 2
        else:
            i += 1
    tid = len(tasks) + 100
    task = {{"id": tid, "title": title, "description": desc, "priority": prio, "status": "queued", "target_repo": repo}}
    tasks.append(task)
    state_path.write_text(json.dumps(tasks))
    print(json.dumps({{"ok": True, "task": task}}))
    sys.exit(0)
sys.exit(1)
"""
    path.write_text(script, encoding="utf-8")
    path.chmod(0o755)


class TestTicketsAndReports(unittest.TestCase):
    def test_in_run_dedup_merges_viewports_and_screenshots(self) -> None:
        d1 = Defect(
            fingerprint="abcdef123456",
            target="app",
            target_repo="app",
            flow="home",
            viewport="fold-folded (374x844)",
            category="slow_endpoint",
            severity="major",
            title="[app] Slow endpoint GET /api/data",
            summary="420ms",
            screenshots=["/tmp/a.png"],
        )
        d2 = Defect(
            fingerprint="abcdef123456",
            target="app",
            target_repo="app",
            flow="home",
            viewport="desktop (1280x800)",
            category="slow_endpoint",
            severity="critical",
            title="[app] Slow endpoint GET /api/data",
            summary="510ms",
            screenshots=["/tmp/b.png"],
        )
        merged = deduplicate_defects_in_run([d1, d2])
        self.assertEqual(len(merged), 1)
        self.assertEqual(merged[0].severity, "critical")
        self.assertIn("374x844", merged[0].viewport)
        self.assertIn("1280x800", merged[0].viewport)
        self.assertEqual(merged[0].screenshots, ["/tmp/a.png", "/tmp/b.png"])

    def test_two_layer_deduplication_and_ticket_filing(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            pulse_state = root / "pulse.json"
            fake_pulse = root / "fake-pulse"
            _make_fake_pulse_script(fake_pulse, pulse_state)

            cfg = NightwalkConfig(
                config_path=root / "config.json",
                state_dir=root / "state",
                report_dir=root / "reports",
                ticket_list_cmd=[str(fake_pulse), "list", "--all", "--json"],
                ticket_add_cmd=[str(fake_pulse), "add"],
                ticket_priority="P2",
                ticket_cooldown_hours=72.0,
                max_tickets_per_run=5,
            )
            store = StateStore(cfg.db_path)

            defect = Defect(
                fingerprint="deadbeef1234",
                target="demo",
                target_repo="demo",
                flow="o11y-scrub",
                viewport="fold-folded (374x844)",
                category="slow_endpoint",
                severity="major",
                title="[demo] Slow endpoint GET /api/series (412ms > 300ms)",
                summary="Exceeded 300ms budget.",
                screenshots=[str(root / "shot1.png")],
                repro_steps=["1. Open status", "2. Scrub chart"],
            )

            # First run: files a P2 ticket with screenshot evidence + fingerprint tag
            a1 = process_defect_tickets(
                cfg=cfg,
                store=store,
                defects=[defect],
                run_id="nw-run1",
                report_path=str(root / "reports" / "r1.md"),
                dry_run=False,
            )
            self.assertEqual(len(a1), 1)
            self.assertEqual(a1[0].action, "filed")
            self.assertEqual(a1[0].task_id, 100)

            saved_tasks = json.loads(pulse_state.read_text())
            self.assertEqual(len(saved_tasks), 1)
            self.assertEqual(saved_tasks[0]["priority"], "P2")
            self.assertIn("[dogfood:deadbeef1234]", saved_tasks[0]["description"])
            self.assertIn("shot1.png", saved_tasks[0]["description"])

            # Second run while ticket is open: deduplicated by live backlog
            a2 = process_defect_tickets(
                cfg=cfg,
                store=store,
                defects=[defect],
                run_id="nw-run2",
                report_path=str(root / "reports" / "r2.md"),
                dry_run=False,
            )
            self.assertEqual(a2[0].action, "deduped_open")
            self.assertEqual(a2[0].task_id, 100)

            # Mark ticket done in fake pulse; third run is still suppressed by 72h SQLite cooldown
            saved_tasks[0]["status"] = "done"
            pulse_state.write_text(json.dumps(saved_tasks))
            a3 = process_defect_tickets(
                cfg=cfg,
                store=store,
                defects=[defect],
                run_id="nw-run3",
                report_path=str(root / "reports" / "r3.md"),
                dry_run=False,
            )
            self.assertEqual(a3[0].action, "deduped_cooldown")
            self.assertEqual(a3[0].task_id, 100)

    def test_report_and_zero_emoji_status_panel(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            summary = RunSummary(
                run_id="nw-20261124-023000",
                started_at="2026-11-24T08:30:00+00:00",
                finished_at="2026-11-24T08:31:15+00:00",
                elapsed_ms=75000.0,
                dry_run=False,
                engine="chromium",
                vision_enabled=True,
                vision_model="test-vlm",
                targets_run=3,
                flows_run=9,
                flows_passed=9,
                screenshots_captured=18,
                total_defects=0,
                unique_defects=0,
                tickets_filed=0,
                tickets_deduped=0,
                artifacts_dir=str(root / "artifacts"),
            )
            rpath = write_markdown_report(root / "reports", summary)
            ppath = write_status_panel(root / "panels" / "12-dogfood.json", summary)
            self.assertTrue(rpath.is_file())
            self.assertTrue(ppath.is_file())

            panel = json.loads(ppath.read_text(encoding="utf-8"))
            self.assertEqual(panel["badge"], "ALL CLEAR")
            self.assertEqual(panel["badgeTone"], "ok")
            self.assertEqual(len(panel["metrics"]), 4)


if __name__ == "__main__":
    unittest.main()
