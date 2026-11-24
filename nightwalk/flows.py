"""Composable, pluggable interactive flow runner driving real CDP events."""

from __future__ import annotations

import json
import re
import time
import urllib.parse
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Callable

from .browser import VegaBrowserClient
from .cdp import CDPClient
from .checks import (
    analyze_network,
    audit_dom_layout,
    build_defects_from_flow,
    check_same_origin_links,
    merge_console_errors,
)
from .config import NightwalkConfig
from .models import (
    FlowRunResult,
    FlowSpec,
    FlowStep,
    LinkCheckResult,
    StepOutcome,
    TargetSpec,
    ViewportSpec,
    VisionAssessment,
)
from .redact import ensure_loopback_url, redact_text, redact_url
from .vision import inspect_screenshot


def _slugify(value: str) -> str:
    cleaned = re.sub(r"[^a-zA-Z0-9]+", "-", (value or "").strip().lower()).strip("-")
    return cleaned[:48] or "item"


@dataclass
class FlowContext:
    """Mutable per-flow runtime context passed to step handlers."""

    cfg: NightwalkConfig
    target: TargetSpec
    flow: FlowSpec
    viewport: ViewportSpec
    cdp: CDPClient
    browser: VegaBrowserClient
    browser_id: str
    screenshots_dir: Path
    auth_token: str = ""
    vision_enabled: bool = True
    screenshots: list[str] = field(default_factory=list)
    vision_targets: list[tuple[Path, str]] = field(default_factory=list)
    links_checked: int = 0
    broken_links: list[LinkCheckResult] = field(default_factory=list)
    layout_metrics: dict[str, Any] = field(default_factory=dict)
    step_errors: list[str] = field(default_factory=list)
    repro_steps: list[str] = field(default_factory=list)
    _shot_seq: int = 0

    def capture_shot(self, tag: str, *, mark_vision: bool = False) -> Path:
        self._shot_seq += 1
        fname = f"{_slugify(self.target.name)}_{_slugify(self.flow.name)}_{_slugify(self.viewport.name)}_{self._shot_seq:02d}_{_slugify(tag)}.png"
        out_path = self.screenshots_dir / fname
        out_path.parent.mkdir(parents=True, exist_ok=True)
        try:
            raw = self.cdp.capture_screenshot(fmt="png")
        except Exception:
            raw = self.browser.capture_screenshot(self.browser_id)
            out_path = out_path.with_suffix(".jpg")
        out_path.write_bytes(raw)
        self.screenshots.append(str(out_path))
        if mark_vision:
            self.vision_targets.append((out_path, tag))
        return out_path


StepHandler = Callable[[FlowContext, FlowStep], tuple[bool, str, str]]
STEP_REGISTRY: dict[str, StepHandler] = {}


def register_step(action: str, handler: StepHandler | None = None) -> Callable[[StepHandler], StepHandler] | StepHandler:
    """Register a custom read-only step handler in STEP_REGISTRY."""
    key = action.strip().lower()

    def _decorator(fn: StepHandler) -> StepHandler:
        STEP_REGISTRY[key] = fn
        return fn

    if handler is not None:
        return _decorator(handler)
    return _decorator


def _find_visible_rect(cdp: CDPClient, selector: str) -> dict[str, Any] | None:
    expr = (
        "(() => {"
        f"const els = Array.from(document.querySelectorAll({json.dumps(selector)}));"
        "for (const el of els) {"
        "  if (el.closest('[hidden], .hidden')) continue;"
        "  const st = window.getComputedStyle(el);"
        "  if (st.display === 'none' || st.visibility === 'hidden' || parseFloat(st.opacity || '1') === 0) continue;"
        "  const r = el.getBoundingClientRect();"
        "  if (r.width >= 2 && r.height >= 2) {"
        "    el.scrollIntoView({block: 'center', inline: 'center', behavior: 'instant'});"
        "    const r2 = el.getBoundingClientRect();"
        "    return {x: r2.left + r2.width / 2, y: r2.top + r2.height / 2, left: r2.left, top: r2.top, width: r2.width, height: r2.height, tag: el.tagName.toLowerCase(), text: (el.textContent || '').trim().slice(0, 60)};"
        "  }"
        "}"
        "return null;"
        "})()"
    )
    res = cdp.evaluate(expr, timeout=5.0)
    return res if isinstance(res, dict) else None


def _wait_for_visible(cdp: CDPClient, selectors: list[str], timeout_ms: int) -> tuple[str, dict[str, Any]] | None:
    deadline = time.monotonic() + max(0.2, timeout_ms / 1000.0)
    while time.monotonic() < deadline:
        for sel in selectors:
            rect = _find_visible_rect(cdp, sel)
            if rect is not None:
                return (sel, rect)
        time.sleep(0.1)
    return None


@register_step("goto")
def _step_goto(ctx: FlowContext, step: FlowStep) -> tuple[bool, str, str]:
    if step.url:
        target_url = step.url
    else:
        path = step.path or "/"
        target_url = urllib.parse.urljoin(ctx.target.base_url + "/", path.lstrip("/"))
    if ctx.cfg.loopback_only:
        ensure_loopback_url(target_url, context="navigation URL")
    ctx.cdp.navigate(target_url, timeout=max(10.0, step.timeout_ms / 1000.0), settle_ms=max(300, step.ms))
    return (True, f"Loaded {redact_url(target_url)}", "")


@register_step("wait_for")
def _step_wait_for(ctx: FlowContext, step: FlowStep) -> tuple[bool, str, str]:
    deadline = time.monotonic() + max(0.2, step.timeout_ms / 1000.0)
    selectors = [step.selector] if step.selector else list(step.selectors)
    while time.monotonic() < deadline:
        if selectors:
            for sel in selectors:
                if _find_visible_rect(ctx.cdp, sel) is not None:
                    return (True, f"Visible: {sel}", "")
        elif step.expr:
            val = ctx.cdp.evaluate(f"Boolean(({step.expr}))", timeout=5.0)
            if bool(val):
                return (True, "Predicate truthy", "")
        time.sleep(0.1)
    target_desc = ", ".join(selectors) if selectors else step.expr
    return (False, "", f"Timed out waiting for {target_desc} after {step.timeout_ms}ms")


@register_step("click")
def _step_click(ctx: FlowContext, step: FlowStep) -> tuple[bool, str, str]:
    selectors = [step.selector] if step.selector else list(step.selectors)
    found = _wait_for_visible(ctx.cdp, selectors, step.timeout_ms)
    if found is None:
        return (False, "", f"Element not visible for click: {', '.join(selectors)}")
    sel, rect = found
    ctx.cdp.mouse_click(float(rect["x"]), float(rect["y"]))
    if step.ms > 0:
        time.sleep(step.ms / 1000.0)
    ctx.cdp.wait_network_quiet(quiet_ms=250, max_wait_s=3.0)
    return (True, f"Clicked {sel} ({rect.get('text', '')[:32]})", "")


@register_step("click_first")
def _step_click_first(ctx: FlowContext, step: FlowStep) -> tuple[bool, str, str]:
    return _step_click(ctx, step)


@register_step("scrub")
def _step_scrub(ctx: FlowContext, step: FlowStep) -> tuple[bool, str, str]:
    """Scrub pointer across an interactive chart (e.g., SVG time-series) and verify readout/cursor response."""
    selectors = [step.selector] if step.selector else list(step.selectors)
    found = _wait_for_visible(ctx.cdp, selectors, step.timeout_ms)
    if found is None:
        return (False, "", f"Scrub target not visible: {', '.join(selectors)}")
    sel, rect = found

    def _readout() -> str:
        if not step.readout_selector:
            return ""
        val = ctx.cdp.evaluate(
            f"(() => {{ const el = document.querySelector({json.dumps(step.readout_selector)}); return el ? (el.textContent || '').trim() : ''; }})()"
        )
        return str(val or "")

    before = _readout()
    left = float(rect["left"])
    width = float(rect["width"])
    cy = float(rect["top"]) + float(rect["height"]) * 0.5

    observed_readouts: set[str] = {before} if before else set()
    cursor_seen = False
    mid_shot_path = ""
    fracs = [0.15 + (0.70 * i / max(1, step.steps - 1)) for i in range(step.steps)]
    mid_idx = len(fracs) // 2

    for idx, frac in enumerate(fracs):
        x = left + width * frac
        # Dispatch real CDP mouse move + pointermove event for full desktop/touch parity
        ctx.cdp.mouse_move(x, cy, buttons=1 if idx > 0 else 0)
        ctx.cdp.evaluate(
            "(() => {"
            f"const el = document.querySelector({json.dumps(sel)});"
            "if (!el) return;"
            f"el.dispatchEvent(new PointerEvent('pointermove', {{bubbles: true, clientX: {x:.1f}, clientY: {cy:.1f}, pointerType: 'mouse'}}));"
            "})()"
        )
        time.sleep(0.08)
        cur = _readout()
        if cur:
            observed_readouts.add(cur)
        if step.cursor_selector:
            has_cur = bool(
                ctx.cdp.evaluate(f"Boolean(document.querySelector({json.dumps(step.cursor_selector)}))")
            )
            if has_cur:
                cursor_seen = True
        if idx == mid_idx and step.tag:
            p = ctx.capture_shot(step.tag, mark_vision=step.vision)
            mid_shot_path = str(p)

    # Leave chart cleanly
    ctx.cdp.evaluate(
        "(() => {"
        f"const el = document.querySelector({json.dumps(sel)});"
        "if (el) el.dispatchEvent(new PointerEvent('pointerleave', {bubbles: true}));"
        "})()"
    )
    time.sleep(0.08)

    changed = len(observed_readouts) > 1 or cursor_seen
    detail = f"Scrubbed {sel} ({len(observed_readouts)} readout states, cursor={cursor_seen})"
    if mid_shot_path:
        detail += f" [shot={Path(mid_shot_path).name}]"
    if step.expect_change and not changed:
        return (False, detail, f"Chart scrub on {sel} did not update readout or render cursor")
    return (True, detail, "")


@register_step("type")
def _step_type(ctx: FlowContext, step: FlowStep) -> tuple[bool, str, str]:
    selectors = [step.selector] if step.selector else list(step.selectors)
    found = _wait_for_visible(ctx.cdp, selectors, step.timeout_ms)
    if found is None:
        return (False, "", f"Input not visible for type: {', '.join(selectors)}")
    sel, rect = found
    ctx.cdp.mouse_click(float(rect["x"]), float(rect["y"]))
    ctx.cdp.evaluate(
        "(() => {"
        f"const el = document.querySelector({json.dumps(sel)});"
        "if (el && 'value' in el) { el.focus(); el.value = ''; el.dispatchEvent(new Event('input', {bubbles: true})); }"
        "})()"
    )
    if step.text:
        ctx.cdp.insert_text(step.text)
    if step.ms > 0:
        time.sleep(step.ms / 1000.0)
    return (True, f"Typed into {sel}", "")


@register_step("clear_input")
def _step_clear_input(ctx: FlowContext, step: FlowStep) -> tuple[bool, str, str]:
    sel = step.selector or (step.selectors[0] if step.selectors else "")
    if not sel:
        return (False, "", "clear_input requires 'selector'")
    ctx.cdp.evaluate(
        "(() => {"
        f"const el = document.querySelector({json.dumps(sel)});"
        "if (el && 'value' in el) { el.value = ''; el.dispatchEvent(new Event('input', {bubbles: true})); }"
        "})()"
    )
    if step.ms > 0:
        time.sleep(step.ms / 1000.0)
    return (True, f"Cleared {sel}", "")


@register_step("key")
def _step_key(ctx: FlowContext, step: FlowStep) -> tuple[bool, str, str]:
    if not step.key:
        return (False, "", "key step requires 'key'")
    ctx.cdp.dispatch_key(step.key, modifiers=step.modifiers)
    if step.ms > 0:
        time.sleep(step.ms / 1000.0)
    return (True, f"Pressed {step.key}", "")


@register_step("assert_js")
def _step_assert_js(ctx: FlowContext, step: FlowStep) -> tuple[bool, str, str]:
    if not step.expr:
        return (False, "", "assert_js requires 'expr'")
    val = ctx.cdp.evaluate(f"Boolean(({step.expr}))", timeout=max(5.0, step.timeout_ms / 1000.0))
    if not bool(val):
        return (False, "", f"Assertion failed ({step.label or step.expr})")
    return (True, f"Passed: {step.label or 'assert_js'}", "")


@register_step("check_links")
def _step_check_links(ctx: FlowContext, step: FlowStep) -> tuple[bool, str, str]:
    checked, broken = check_same_origin_links(
        ctx.cdp,
        ctx.target,
        auth_token=ctx.auth_token,
        max_links=step.max_links,
        timeout_sec=ctx.cfg.link_check_timeout_sec,
        loopback_only=ctx.cfg.loopback_only,
    )
    ctx.links_checked += checked
    seen = {(b.kind, b.url) for b in ctx.broken_links}
    for b in broken:
        if (b.kind, b.url) not in seen:
            ctx.broken_links.append(b)
            seen.add((b.kind, b.url))
    return (True, f"Probed {checked} same-origin links/images ({len(broken)} broken)", "")


@register_step("check_layout")
def _step_check_layout(ctx: FlowContext, step: FlowStep) -> tuple[bool, str, str]:
    metrics = audit_dom_layout(ctx.cdp)
    ctx.layout_metrics = metrics
    ov = int(metrics.get("horizontalOverflowPx") or 0)
    em = len(metrics.get("emojiNodes") or [])
    return (True, f"Layout audit: overflow={ov}px, emojis={em}, textLen={metrics.get('visibleTextLen', 0)}", "")


@register_step("screenshot")
def _step_screenshot(ctx: FlowContext, step: FlowStep) -> tuple[bool, str, str]:
    tag = step.tag or step.label or "view"
    path = ctx.capture_shot(tag, mark_vision=step.vision)
    return (True, f"Saved {path.name}", str(path))


@register_step("sleep")
def _step_sleep(ctx: FlowContext, step: FlowStep) -> tuple[bool, str, str]:
    time.sleep(max(0.0, step.ms / 1000.0))
    return (True, f"Settled {step.ms}ms", "")


def run_flow(
    *,
    cfg: NightwalkConfig,
    target: TargetSpec,
    flow: FlowSpec,
    viewport: ViewportSpec,
    cdp: CDPClient,
    browser: VegaBrowserClient,
    browser_id: str,
    screenshots_dir: Path,
    auth_token: str = "",
    vision_enabled: bool = True,
) -> FlowRunResult:
    """Execute one declarative interactive flow at one viewport and collect all telemetry."""
    t_flow0 = time.perf_counter()
    cdp.clear_telemetry()
    browser.clear_devtools(browser_id)
    cdp.set_viewport(
        viewport.width,
        viewport.height,
        mobile=viewport.mobile,
        device_scale_factor=viewport.device_scale_factor,
    )

    if auth_token and target.auth_cookie_name:
        cdp.set_cookie(
            name=target.auth_cookie_name,
            value=auth_token,
            url=target.base_url + "/",
            http_only=True,
            same_site="Lax",
        )

    ctx = FlowContext(
        cfg=cfg,
        target=target,
        flow=flow,
        viewport=viewport,
        cdp=cdp,
        browser=browser,
        browser_id=browser_id,
        screenshots_dir=screenshots_dir,
        auth_token=auth_token,
        vision_enabled=vision_enabled,
    )

    outcomes: list[StepOutcome] = []
    did_link_check = False
    did_layout_check = False

    for idx, step in enumerate(flow.steps):
        label = step.label or f"{step.action} {step.selector or step.path or step.tag}".strip()
        if step.viewports and viewport.name not in step.viewports:
            outcomes.append(
                StepOutcome(
                    index=idx,
                    action=step.action,
                    label=label,
                    ok=True,
                    elapsed_ms=0.0,
                    detail=f"Skipped on viewport {viewport.name}",
                    skipped=True,
                )
            )
            continue

        handler = STEP_REGISTRY.get(step.action)
        if handler is None:
            err = f"Unknown flow step action: {step.action!r}"
            ctx.step_errors.append(err)
            outcomes.append(StepOutcome(index=idx, action=step.action, label=label, ok=False, elapsed_ms=0.0, error=err))
            continue

        ctx.repro_steps.append(f"{idx + 1}. {label}")
        t0 = time.perf_counter()
        shot_path = ""
        try:
            ok, detail, extra = handler(ctx, step)
            elapsed_ms = (time.perf_counter() - t0) * 1000.0
            if step.action == "check_links":
                did_link_check = True
            elif step.action == "check_layout":
                did_layout_check = True
            elif step.action == "screenshot" and ok:
                shot_path = extra

            if ok:
                outcomes.append(
                    StepOutcome(
                        index=idx,
                        action=step.action,
                        label=label,
                        ok=True,
                        elapsed_ms=elapsed_ms,
                        detail=detail,
                        screenshot_path=shot_path,
                    )
                )
            elif step.optional:
                outcomes.append(
                    StepOutcome(
                        index=idx,
                        action=step.action,
                        label=label,
                        ok=True,
                        elapsed_ms=elapsed_ms,
                        detail=f"Optional step skipped: {extra}",
                        skipped=True,
                    )
                )
            else:
                err_msg = redact_text(extra or f"Step '{label}' failed")
                ctx.step_errors.append(err_msg)
                try:
                    fail_shot = ctx.capture_shot(f"fail-{idx + 1}", mark_vision=False)
                    shot_path = str(fail_shot)
                except Exception:
                    pass
                outcomes.append(
                    StepOutcome(
                        index=idx,
                        action=step.action,
                        label=label,
                        ok=False,
                        elapsed_ms=elapsed_ms,
                        detail=detail,
                        error=err_msg,
                        screenshot_path=shot_path,
                    )
                )
                # Abort remaining dependent steps on hard navigation/wait failure
                if step.action == "goto":
                    break
        except Exception as exc:
            elapsed_ms = (time.perf_counter() - t0) * 1000.0
            err_msg = redact_text(f"{label}: {exc}")
            if step.optional:
                outcomes.append(
                    StepOutcome(
                        index=idx,
                        action=step.action,
                        label=label,
                        ok=True,
                        elapsed_ms=elapsed_ms,
                        detail=f"Optional step error ignored: {err_msg}",
                        skipped=True,
                    )
                )
            else:
                ctx.step_errors.append(err_msg)
                try:
                    fail_shot = ctx.capture_shot(f"err-{idx + 1}", mark_vision=False)
                    shot_path = str(fail_shot)
                except Exception:
                    pass
                outcomes.append(
                    StepOutcome(
                        index=idx,
                        action=step.action,
                        label=label,
                        ok=False,
                        elapsed_ms=elapsed_ms,
                        error=err_msg,
                        screenshot_path=shot_path,
                    )
                )
                if step.action == "goto":
                    break

    # Automatic final checks if enabled on flow and not already executed
    if flow.check_layout and not did_layout_check and not any(o.action == "goto" and not o.ok for o in outcomes):
        try:
            ctx.layout_metrics = audit_dom_layout(cdp)
        except Exception:
            pass

    if flow.check_links and not did_link_check and not any(o.action == "goto" and not o.ok for o in outcomes):
        try:
            checked, broken = check_same_origin_links(
                cdp,
                target,
                auth_token=auth_token,
                timeout_sec=cfg.link_check_timeout_sec,
                loopback_only=cfg.loopback_only,
            )
            ctx.links_checked += checked
            ctx.broken_links.extend(broken)
        except Exception:
            pass

    if not ctx.screenshots:
        try:
            ctx.capture_shot("final", mark_vision=flow.vision_qa)
        except Exception:
            pass
    elif flow.vision_qa and not ctx.vision_targets:
        ctx.vision_targets.append((Path(ctx.screenshots[-1]), "final"))

    # Collect & analyze telemetry from both direct CDP and vega-browser DevTools pool
    extra_secrets = (auth_token,) if auth_token else ()
    direct_console, direct_net = cdp.snapshot_telemetry()
    pool_console, pool_net = browser.get_devtools(browser_id, extra_secrets=extra_secrets)

    console_errors = merge_console_errors(direct_console, pool_console, target.ignore_console_patterns)
    slow_budget = target.slow_endpoint_ms if target.slow_endpoint_ms is not None else cfg.slow_endpoint_ms
    failed_requests, slow_endpoints = analyze_network(
        direct_net,
        pool_net,
        slow_threshold_ms=slow_budget,
        ignore_slow_patterns=target.ignore_slow_patterns,
        ignore_network_patterns=target.ignore_network_patterns,
    )

    # Multimodal Vision QA on marked screenshots
    vision_results: list[VisionAssessment] = []
    if vision_enabled and flow.vision_qa and ctx.vision_targets:
        telemetry_ctx = {
            "console_errors": len(console_errors),
            "failed_requests": len(failed_requests),
            "slow_endpoints": len(slow_endpoints),
            "broken_links": len(ctx.broken_links),
            "horizontal_overflow_px": ctx.layout_metrics.get("horizontalOverflowPx", 0),
        }
        for shot_path, tag in ctx.vision_targets:
            va = inspect_screenshot(
                cfg,
                shot_path,
                target_name=target.name,
                flow_name=f"{flow.name}:{tag}",
                viewport=viewport,
                telemetry_context=telemetry_ctx,
            )
            vision_results.append(va)

    defects = build_defects_from_flow(
        target=target,
        flow_name=flow.name,
        viewport=viewport,
        step_errors=ctx.step_errors,
        console_errors=console_errors,
        failed_requests=failed_requests,
        slow_endpoints=slow_endpoints,
        broken_links=ctx.broken_links,
        layout_metrics=ctx.layout_metrics,
        vision_assessments=vision_results,
        screenshots=ctx.screenshots,
        slow_threshold_ms=slow_budget,
        repro_steps=ctx.repro_steps,
    )

    flow_ok = len(defects) == 0
    return FlowRunResult(
        target=target.name,
        flow=flow.name,
        viewport=viewport.name,
        viewport_px=viewport.label,
        ok=flow_ok,
        elapsed_ms=(time.perf_counter() - t_flow0) * 1000.0,
        steps=outcomes,
        screenshots=ctx.screenshots,
        console_errors=console_errors,
        failed_requests=failed_requests,
        slow_endpoints=slow_endpoints,
        broken_links=ctx.broken_links,
        links_checked=ctx.links_checked,
        layout_metrics=ctx.layout_metrics,
        vision=vision_results,
        defects=defects,
    )
