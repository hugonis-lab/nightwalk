"""Command-line interface for nightwalk."""

from __future__ import annotations

import argparse
import json
import sys
from typing import Sequence

from . import __version__
from .config import default_config_path, load_config, write_example_config
from .dedupe import StateStore
from .pipeline import check_environment, run_dogfood


def _build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="nightwalk",
        description="Nightly customer-zero interactive dogfooding and Vision QA runner.",
    )
    p.add_argument("--version", action="version", version=f"%(prog)s {__version__}")
    p.add_argument("--config", help="Override path to config.json")
    sub = p.add_subparsers(dest="command", required=True)

    p_init = sub.add_parser("init-config", help="Write a starter 0600 config.json outside source control")
    p_init.add_argument("--overwrite", action="store_true", help="Overwrite existing config.json")

    p_check = sub.add_parser("check", help="Check browser pool, Vision QA VLM, and target reachability")
    p_check.add_argument("--json", action="store_true", help="Emit JSON output")

    p_run = sub.add_parser("run", help="Run interactive dogfooding flows across configured targets and viewports")
    p_run.add_argument("--dry-run", action="store_true", help="Skip ticket filing and status panel update")
    p_run.add_argument("--no-vision", action="store_true", help="Disable multimodal Vision QA")
    p_run.add_argument("--no-tickets", action="store_true", help="Disable ticket auto-filing")
    p_run.add_argument("--engine", choices=("chromium", "obscura"), help="Override browser pool engine")
    p_run.add_argument("--target", action="append", help="Filter to specific target name (repeatable)")
    p_run.add_argument("--viewport", action="append", help="Filter to specific viewport name (repeatable)")
    p_run.add_argument("--flow", action="append", help="Filter to specific flow name (repeatable)")
    p_run.add_argument("--json", action="store_true", help="Emit full JSON summary")

    p_status = sub.add_parser("status", help="Show latest dogfood run status")
    p_status.add_argument("--json", action="store_true", help="Emit JSON output")

    p_hist = sub.add_parser("history", help="Show recent dogfood run history")
    p_hist.add_argument("--limit", type=int, default=10, help="Number of runs to display")
    p_hist.add_argument("--json", action="store_true", help="Emit JSON output")

    p_def = sub.add_parser("defects", help="List tracked defect fingerprints in SQLite state")
    p_def.add_argument("--limit", type=int, default=20, help="Number of defects to display")
    p_def.add_argument("--json", action="store_true", help="Emit JSON output")

    return p


def main(argv: Sequence[str] | None = None) -> int:
    parser = _build_parser()
    args = parser.parse_args(argv)

    if args.command == "init-config":
        path = default_config_path() if not args.config else load_config(args.config).config_path
        written = write_example_config(path, overwrite=bool(args.overwrite))
        print(f"Config ready at {written}")
        return 0

    cfg = load_config(args.config)

    if args.command == "check":
        res = check_environment(cfg)
        if args.json:
            print(json.dumps(res, indent=2))
        else:
            print(f"Config:   {res['config_path']} ({'found' if res['config_exists'] else 'missing'})")
            print(f"Browser:  {res['browser_url']} ({'OK' if res['browser_ok'] else 'ERROR'})")
            print(f"Vision:   {res['vlm_model'] or 'unset'} ({'OK' if res['vlm_ok'] else res['vlm_detail']})")
            print(f"Targets:  {len(res['targets'])}")
            for t in res["targets"]:
                print(f"  - {t['name']}: {t['base_url']} [{'OK' if t['reachable'] else 'DOWN'}] ({t['detail']}, {t['flows']} flows)")
        return 0 if res["ok"] else 1

    if args.command == "run":
        if args.engine:
            cfg.browser_engine = args.engine
        summary = run_dogfood(
            cfg,
            dry_run=bool(args.dry_run),
            vision_enabled=not bool(args.no_vision),
            file_tickets=not bool(args.no_tickets),
            target_filter=args.target,
            viewport_filter=args.viewport,
            flow_filter=args.flow,
        )
        if args.json:
            print(json.dumps(summary.to_dict(), indent=2))
        else:
            print(
                f"Nightwalk {summary.run_id}: {summary.flows_passed}/{summary.flows_run} flows clean | "
                f"{summary.unique_defects} unique defects | {summary.tickets_filed} filed, "
                f"{summary.tickets_deduped} deduped | {summary.screenshots_captured} screenshots "
                f"({summary.elapsed_ms / 1000.0:.1f}s)"
            )
            print(f"Report: {summary.report_path}")
            if summary.defects:
                for d in summary.defects:
                    print(f"  - [{d.severity.upper()}] {d.title} ({d.fingerprint})")
        return 0

    store = StateStore(cfg.db_path)

    if args.command == "status":
        runs = store.list_runs(limit=1)
        if args.json:
            print(json.dumps(runs[0] if runs else None, indent=2))
        elif not runs:
            print("No nightwalk runs recorded yet.")
        else:
            r = runs[0]
            print(
                f"Latest run {r['run_id']} ({r['started_at']}): "
                f"{r['flows_passed']}/{r['flows_run']} flows passed, "
                f"{r['unique_defects']} defects, {r['tickets_filed']} filed"
            )
            print(f"Report: {r['report_path']}")
        return 0

    if args.command == "history":
        runs = store.list_runs(limit=args.limit)
        if args.json:
            print(json.dumps(runs, indent=2))
        else:
            for r in runs:
                print(
                    f"{r['run_id']}  {r['started_at']}  {r['flows_passed']}/{r['flows_run']} ok  "
                    f"defects={r['unique_defects']}  filed={r['tickets_filed']}  deduped={r['tickets_deduped']}"
                )
        return 0

    if args.command == "defects":
        rows = store.list_defects(limit=args.limit)
        if args.json:
            print(json.dumps(rows, indent=2))
        else:
            for row in rows:
                tid = f"#{row['pulse_task_id']}" if row.get("pulse_task_id") else "--"
                print(
                    f"{row['fingerprint']}  [{row['severity']}]  seen={row['occurrences']}  "
                    f"ticket={tid}  {row['title']}"
                )
        return 0

    return 1


if __name__ == "__main__":
    sys.exit(main())
