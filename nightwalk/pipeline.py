"""End-to-end nightly dogfooding pipeline orchestration."""

from __future__ import annotations

import json
import re
import signal
import time
import urllib.request
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from .browser import VegaBrowserClient
from .cdp import CDPClient
from .checks import compute_fingerprint
from .config import NightwalkConfig, load_target_auth_token
from .dedupe import StateStore, prune_old_artifacts
from .flows import run_flow
from .models import Defect, FlowRunResult, RunSummary, TargetSpec, ViewportSpec
from .redact import ensure_loopback_url, redact_text
from .report import write_markdown_report, write_status_panel
from .tickets import deduplicate_defects_in_run, process_defect_tickets


def _utc_now() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="seconds")


def _probe_target_reachable(target: TargetSpec, auth_token: str, timeout: float = 5.0) -> tuple[bool, str]:
    """Quick read-only GET reachability check so an offline service collapses into 1 crisp defect."""
    headers = {"Accept": "text/html,application/json,*/*"}
    if auth_token:
        if target.auth_cookie_name:
            headers["Cookie"] = f"{target.auth_cookie_name}={auth_token}"
        headers["Authorization"] = f"{target.auth_header_prefix}{auth_token}"
    req = urllib.request.Request(target.base_url + "/", headers=headers, method="GET")
    try:
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            status = int(resp.status)
            resp.read(256)
            return (status < 500, f"HTTP {status}")
    except Exception as exc:
        return (False, redact_text(str(exc)[:220]))


def check_environment(cfg: NightwalkConfig) -> dict[str, Any]:
    """Verify browser pool health, VLM reachability, and configured targets without mutating state."""
    browser_ok = False
    browser_detail: Any = None
    try:
        browser = VegaBrowserClient(cfg.browser_url)
        browser_detail = browser.health()
        browser_ok = bool(browser_detail.get("ok"))
    except Exception as exc:
        browser_detail = str(exc)

    vlm_ok = False
    vlm_detail: str = "not configured"
    if cfg.vlm_url and cfg.vlm_model:
        try:
            models_url = cfg.vlm_url.rstrip("/")
            if not models_url.endswith("/models"):
                models_url = f"{models_url}/models"
            req = urllib.request.Request(models_url, method="GET")
            if cfg.vlm_api_key:
                req.add_header("Authorization", f"Bearer {cfg.vlm_api_key}")
            with urllib.request.urlopen(req, timeout=5.0) as resp:
                vlm_ok = resp.status == 200
                vlm_detail = f"HTTP {resp.status} ({cfg.vlm_model})"
        except Exception as exc:
            vlm_detail = str(exc)[:200]

    target_checks: list[dict[str, Any]] = []
    for t in cfg.targets:
        token = load_target_auth_token(t)
        ok, detail = _probe_target_reachable(t, token, timeout=4.0)
        target_checks.append(
            {
                "name": t.name,
                "base_url": t.base_url,
                "flows": len(t.flows),
                "auth_configured": bool(token),
                "reachable": ok,
                "detail": detail,
            }
        )

    return {
        "ok": browser_ok and all(tc["reachable"] for tc in target_checks),
        "config_path": str(cfg.config_path),
        "config_exists": cfg.config_path.is_file(),
        "browser_url": cfg.browser_url,
        "browser_ok": browser_ok,
        "browser_detail": browser_detail if not browser_ok else {"service": browser_detail.get("service"), "activeInstances": browser_detail.get("activeInstanceCount")},
        "vlm_ok": vlm_ok,
        "vlm_model": cfg.vlm_model,
        "vlm_detail": vlm_detail,
        "viewports": [v.to_dict() for v in cfg.viewports],
        "targets": target_checks,
    }


def run_dogfood(
    cfg: NightwalkConfig,
    *,
    dry_run: bool = False,
    vision_enabled: bool = True,
    file_tickets: bool = True,
    target_filter: list[str] | None = None,
    viewport_filter: list[str] | None = None,
    flow_filter: list[str] | None = None,
) -> RunSummary:
    """Execute the full customer-zero dogfooding suite across targets, flows, and viewports."""
    t_run0 = time.perf_counter()
    started_at = _utc_now()
    run_id = f"nw-{datetime.now(timezone.utc).strftime('%Y%m%d-%H%M%S')}"

    artifacts_dir = cfg.runs_dir / run_id
    screenshots_dir = artifacts_dir / "screenshots"
    screenshots_dir.mkdir(parents=True, exist_ok=True)
    prune_old_artifacts(cfg.runs_dir, cfg.artifact_retention_days)

    selected_targets = [
        t for t in cfg.targets if not target_filter or t.name in target_filter
    ]
    selected_viewports: list[ViewportSpec] = [
        v for v in cfg.viewports if not viewport_filter or v.name in viewport_filter
    ]

    for t in selected_targets:
        if cfg.loopback_only:
            ensure_loopback_url(t.base_url, context=f"target {t.name!r} base_url")

    browser = VegaBrowserClient(cfg.browser_url)
    store = StateStore(cfg.db_path)

    flow_results: list[FlowRunResult] = []
    raw_defects: list[Defect] = []
    active_browser_id: str | None = None
    active_cdp: CDPClient | None = None
    used_engine = cfg.browser_engine

    def _on_signal(signum: int, _frame: Any) -> None:
        raise KeyboardInterrupt(f"Interrupted by signal {signum}")

    prev_sigterm = signal.getsignal(signal.SIGTERM)
    try:
        signal.signal(signal.SIGTERM, _on_signal)
    except Exception:
        prev_sigterm = None

    try:
        for target in selected_targets:
            auth_token = load_target_auth_token(target)
            reachable, reach_detail = _probe_target_reachable(target, auth_token, timeout=5.0)
            if not reachable:
                fp = compute_fingerprint(target.name, "service_down", target.base_url)
                down_defect = Defect(
                    fingerprint=fp,
                    target=target.name,
                    target_repo=target.target_repo,
                    flow="reachability",
                    viewport="all",
                    category="service_down",
                    severity="critical",
                    title=f"[{target.name}] Service unreachable ({reach_detail})",
                    summary=f"Loopback preflight GET {target.base_url}/ failed: {reach_detail}",
                    evidence={"base_url": target.base_url, "error": reach_detail},
                    repro_steps=[f"1. GET {target.base_url}/"],
                )
                raw_defects.append(down_defect)
                flow_results.append(
                    FlowRunResult(
                        target=target.name,
                        flow="reachability",
                        viewport="all",
                        viewport_px="--",
                        ok=False,
                        elapsed_ms=0.0,
                        defects=[down_defect],
                    )
                )
                continue

            if not selected_viewports:
                continue

            # Isolate one ephemeral browser instance + profile per target app to prevent
            # cross-origin Service Worker, cookie, or SiteInstance renderer interference.
            slug = re.sub(r"[^a-zA-Z0-9]+", "-", target.name).strip("-").lower()[:24] or "app"
            bid = f"{run_id}-{slug}"[:60]
            handle = None
            cdp: CDPClient | None = None
            try:
                handle = browser.spawn_instance(
                    browser_id=bid,
                    label=f"Nightwalk {target.name}",
                    engine=cfg.browser_engine,
                    headless=cfg.browser_headless,
                    start_url="about:blank",
                )
                active_browser_id = handle.browser_id
                used_engine = handle.engine
                cdp = CDPClient(handle.cdp_url, extra_secrets=(auth_token,) if auth_token else ())
                cdp.connect(timeout=12.0)
                active_cdp = cdp

                for vp in selected_viewports:
                    for flow in target.flows:
                        if flow_filter and flow.name not in flow_filter:
                            continue
                        if flow.viewports and vp.name not in flow.viewports:
                            continue
                        try:
                            fr = run_flow(
                                cfg=cfg,
                                target=target,
                                flow=flow,
                                viewport=vp,
                                cdp=cdp,
                                browser=browser,
                                browser_id=handle.browser_id,
                                screenshots_dir=screenshots_dir,
                                auth_token=auth_token,
                                vision_enabled=vision_enabled,
                            )
                        except Exception as exc:
                            err_msg = redact_text(str(exc)[:260], (auth_token,) if auth_token else ())
                            fp = compute_fingerprint(target.name, "flow_error", f"{flow.name}|{err_msg}")
                            err_defect = Defect(
                                fingerprint=fp,
                                target=target.name,
                                target_repo=target.target_repo,
                                flow=flow.name,
                                viewport=f"{vp.name} ({vp.label})",
                                category="flow_error",
                                severity="major",
                                title=f"[{target.name}] Flow '{flow.name}' crashed: {err_msg[:80]}",
                                summary=err_msg,
                                evidence={"exception": err_msg},
                            )
                            fr = FlowRunResult(
                                target=target.name,
                                flow=flow.name,
                                viewport=vp.name,
                                viewport_px=vp.label,
                                ok=False,
                                elapsed_ms=0.0,
                                defects=[err_defect],
                            )
                            # Reconnect CDP cleanly so subsequent flows continue unaffected
                            try:
                                cdp.close()
                                cdp.connect(timeout=10.0)
                            except Exception:
                                pass
                        flow_results.append(fr)
                        raw_defects.extend(fr.defects)
            finally:
                if cdp is not None:
                    cdp.close()
                active_cdp = None
                if handle is not None:
                    browser.delete_instance(handle.browser_id, purge_profile=True)
                active_browser_id = None
    finally:
        if prev_sigterm is not None:
            try:
                signal.signal(signal.SIGTERM, prev_sigterm)
            except Exception:
                pass
        if active_cdp is not None:
            active_cdp.close()
        if active_browser_id is not None:
            browser.delete_instance(active_browser_id, purge_profile=True)

    unique_defects = deduplicate_defects_in_run(raw_defects)
    finished_at = _utc_now()
    elapsed_ms = (time.perf_counter() - t_run0) * 1000.0
    total_shots = sum(len(fr.screenshots) for fr in flow_results)
    flows_passed = sum(1 for fr in flow_results if fr.ok)

    # Pre-compute expected report path so filed tickets can reference it directly
    expected_report_path = cfg.report_dir / f"{started_at[:10]}-nightwalk.md"
    effective_dry_run = dry_run or not file_tickets
    ticket_actions = process_defect_tickets(
        cfg=cfg,
        store=store,
        defects=unique_defects,
        run_id=run_id,
        report_path=str(expected_report_path),
        dry_run=effective_dry_run,
    )

    tickets_filed = sum(1 for ta in ticket_actions if ta.action == "filed")
    tickets_deduped = sum(1 for ta in ticket_actions if ta.action in ("deduped_open", "deduped_cooldown"))

    summary = RunSummary(
        run_id=run_id,
        started_at=started_at,
        finished_at=finished_at,
        elapsed_ms=elapsed_ms,
        dry_run=dry_run,
        engine=used_engine,
        vision_enabled=vision_enabled and bool(cfg.vlm_url and cfg.vlm_model),
        vision_model=cfg.vlm_model if vision_enabled else "",
        targets_run=len(selected_targets),
        flows_run=len(flow_results),
        flows_passed=flows_passed,
        screenshots_captured=total_shots,
        total_defects=len(raw_defects),
        unique_defects=len(unique_defects),
        tickets_filed=tickets_filed,
        tickets_deduped=tickets_deduped,
        report_path=str(expected_report_path),
        panel_path=str(cfg.panel_path) if cfg.panel_path else "",
        artifacts_dir=str(artifacts_dir),
        flow_results=flow_results,
        defects=unique_defects,
        ticket_actions=ticket_actions,
    )

    # Persist run JSON artifact, Markdown report, SQLite summary, and calm status panel
    (artifacts_dir / "summary.json").write_text(json.dumps(summary.to_dict(), indent=2) + "\n", encoding="utf-8")
    report_path = write_markdown_report(cfg.report_dir, summary)
    summary.report_path = str(report_path)
    if cfg.panel_path is not None and not dry_run:
        panel_path = write_status_panel(cfg.panel_path, summary)
        summary.panel_path = str(panel_path)
    store.record_run(summary)
    return summary
