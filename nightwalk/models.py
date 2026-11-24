"""Structured data models for nightwalk dogfooding runs."""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any


@dataclass(frozen=True)
class ViewportSpec:
    """Target viewport geometry (e.g., Fold 8 folded/unfolded or desktop)."""

    name: str
    width: int
    height: int
    mobile: bool = False
    device_scale_factor: float = 1.0

    @property
    def label(self) -> str:
        return f"{self.width}x{self.height}"

    def to_dict(self) -> dict[str, Any]:
        return {
            "name": self.name,
            "width": self.width,
            "height": self.height,
            "mobile": self.mobile,
            "device_scale_factor": self.device_scale_factor,
        }

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> "ViewportSpec":
        width = int(data["width"])
        height = int(data["height"])
        if width <= 0 or height <= 0:
            raise ValueError(f"Viewport dimensions must be positive: {width}x{height}")
        return cls(
            name=str(data.get("name") or f"{width}x{height}").strip(),
            width=width,
            height=height,
            mobile=bool(data.get("mobile", width < 900)),
            device_scale_factor=float(data.get("device_scale_factor", 2.0 if width < 900 else 1.0)),
        )


@dataclass
class FlowStep:
    """One read-only interactive step inside a FlowSpec."""

    action: str
    label: str = ""
    path: str = ""
    url: str = ""
    selector: str = ""
    selectors: list[str] = field(default_factory=list)
    readout_selector: str = ""
    cursor_selector: str = ""
    text: str = ""
    key: str = ""
    modifiers: list[str] = field(default_factory=list)
    expr: str = ""
    ms: int = 300
    timeout_ms: int = 8000
    optional: bool = False
    viewports: list[str] = field(default_factory=list)
    tag: str = ""
    vision: bool = False
    max_links: int = 30
    steps: int = 5
    expect_change: bool = True

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> "FlowStep":
        action = str(data.get("action") or "").strip().lower()
        if not action:
            raise ValueError("FlowStep requires non-empty 'action'")
        selectors = [str(s) for s in (data.get("selectors") or []) if str(s).strip()]
        modifiers = [str(m).lower() for m in (data.get("modifiers") or []) if str(m).strip()]
        viewports = [str(v).strip() for v in (data.get("viewports") or []) if str(v).strip()]
        return cls(
            action=action,
            label=str(data.get("label") or "").strip(),
            path=str(data.get("path") or "").strip(),
            url=str(data.get("url") or "").strip(),
            selector=str(data.get("selector") or "").strip(),
            selectors=selectors,
            readout_selector=str(data.get("readout_selector") or "").strip(),
            cursor_selector=str(data.get("cursor_selector") or "").strip(),
            text=str(data.get("text") or ""),
            key=str(data.get("key") or "").strip(),
            modifiers=modifiers,
            expr=str(data.get("expr") or "").strip(),
            ms=int(data.get("ms", 300)),
            timeout_ms=int(data.get("timeout_ms", 8000)),
            optional=bool(data.get("optional", False)),
            viewports=viewports,
            tag=str(data.get("tag") or "").strip(),
            vision=bool(data.get("vision", False)),
            max_links=int(data.get("max_links", 30)),
            steps=max(2, int(data.get("steps", 5))),
            expect_change=bool(data.get("expect_change", True)),
        )


@dataclass
class FlowSpec:
    """Declarative multi-step interactive customer-zero flow."""

    name: str
    description: str = ""
    steps: list[FlowStep] = field(default_factory=list)
    viewports: list[str] = field(default_factory=list)
    check_links: bool = True
    check_layout: bool = True
    vision_qa: bool = True

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> "FlowSpec":
        name = str(data.get("name") or "").strip()
        if not name:
            raise ValueError("FlowSpec requires non-empty 'name'")
        raw_steps = data.get("steps") or []
        if not isinstance(raw_steps, list) or not raw_steps:
            raise ValueError(f"FlowSpec {name!r} requires at least one step")
        return cls(
            name=name,
            description=str(data.get("description") or "").strip(),
            steps=[FlowStep.from_dict(s) for s in raw_steps],
            viewports=[str(v).strip() for v in (data.get("viewports") or []) if str(v).strip()],
            check_links=bool(data.get("check_links", True)),
            check_layout=bool(data.get("check_layout", True)),
            vision_qa=bool(data.get("vision_qa", True)),
        )


@dataclass
class TargetSpec:
    """Web application target to dogfood (strictly read-only)."""

    name: str
    base_url: str
    target_repo: str = ""
    description: str = ""
    auth_cookie_name: str = ""
    auth_token_file: str = ""
    auth_token_env: str = ""
    auth_header_prefix: str = "Bearer "
    slow_endpoint_ms: float | None = None
    ignore_slow_patterns: list[str] = field(default_factory=list)
    ignore_console_patterns: list[str] = field(default_factory=list)
    ignore_network_patterns: list[str] = field(default_factory=list)
    flows: list[FlowSpec] = field(default_factory=list)

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> "TargetSpec":
        name = str(data.get("name") or "").strip()
        base_url = str(data.get("base_url") or "").strip().rstrip("/")
        if not name or not base_url:
            raise ValueError("TargetSpec requires non-empty 'name' and 'base_url'")
        raw_flows = data.get("flows") or []
        return cls(
            name=name,
            base_url=base_url,
            target_repo=str(data.get("target_repo") or "").strip(),
            description=str(data.get("description") or "").strip(),
            auth_cookie_name=str(data.get("auth_cookie_name") or "").strip(),
            auth_token_file=str(data.get("auth_token_file") or "").strip(),
            auth_token_env=str(data.get("auth_token_env") or "").strip(),
            auth_header_prefix=str(data.get("auth_header_prefix", "Bearer ")),
            slow_endpoint_ms=(
                float(data["slow_endpoint_ms"])
                if data.get("slow_endpoint_ms") is not None
                else None
            ),
            ignore_slow_patterns=[str(p) for p in (data.get("ignore_slow_patterns") or []) if str(p).strip()],
            ignore_console_patterns=[str(p) for p in (data.get("ignore_console_patterns") or []) if str(p).strip()],
            ignore_network_patterns=[str(p) for p in (data.get("ignore_network_patterns") or []) if str(p).strip()],
            flows=[FlowSpec.from_dict(f) for f in raw_flows],
        )


@dataclass
class NetworkRecord:
    """Single HTTP request observed during a flow."""

    method: str
    url: str
    status: int | None
    ok: bool | None
    duration_ms: float | None
    resource_type: str = ""
    mime_type: str = ""
    error_text: str | None = None
    canceled: bool = False
    streaming: bool = False

    def to_dict(self) -> dict[str, Any]:
        return {
            "method": self.method,
            "url": self.url,
            "status": self.status,
            "ok": self.ok,
            "duration_ms": self.duration_ms,
            "resource_type": self.resource_type,
            "mime_type": self.mime_type,
            "error_text": self.error_text,
            "canceled": self.canceled,
            "streaming": self.streaming,
        }


@dataclass
class ConsoleRecord:
    """Single browser console error or uncaught exception."""

    level: str
    source: str
    text: str
    url: str = ""
    line: int | None = None

    def to_dict(self) -> dict[str, Any]:
        return {
            "level": self.level,
            "source": self.source,
            "text": self.text,
            "url": self.url,
            "line": self.line,
        }


@dataclass
class LinkCheckResult:
    """Outcome of a read-only same-origin link or image asset probe."""

    url: str
    kind: str  # "link" | "image"
    status: int | None
    ok: bool
    duration_ms: float
    error: str = ""

    def to_dict(self) -> dict[str, Any]:
        return {
            "url": self.url,
            "kind": self.kind,
            "status": self.status,
            "ok": self.ok,
            "duration_ms": round(self.duration_ms, 1),
            "error": self.error,
        }


@dataclass
class VisionIssue:
    """Localized defect surfaced by multimodal Vision QA."""

    severity: str  # "critical" | "major" | "minor"
    category: str
    element: str
    description: str
    suggested_fix: str = ""

    def to_dict(self) -> dict[str, Any]:
        return {
            "severity": self.severity,
            "category": self.category,
            "element": self.element,
            "description": self.description,
            "suggested_fix": self.suggested_fix,
        }


@dataclass
class VisionAssessment:
    """Structured multimodal Vision QA verdict for a single screenshot."""

    screenshot_path: str
    verdict: str  # "PASS" | "WARN" | "FAIL" | "SKIP"
    score_10: float | None = None
    elapsed_ms: float = 0.0
    model: str = ""
    summary: str = ""
    issues: list[VisionIssue] = field(default_factory=list)
    error: str = ""

    def to_dict(self) -> dict[str, Any]:
        return {
            "screenshot_path": self.screenshot_path,
            "verdict": self.verdict,
            "score_10": self.score_10,
            "elapsed_ms": round(self.elapsed_ms, 1),
            "model": self.model,
            "summary": self.summary,
            "issues": [i.to_dict() for i in self.issues],
            "error": self.error,
        }


@dataclass
class StepOutcome:
    """Execution telemetry for one step in a flow."""

    index: int
    action: str
    label: str
    ok: bool
    elapsed_ms: float
    detail: str = ""
    error: str = ""
    skipped: bool = False
    screenshot_path: str = ""

    def to_dict(self) -> dict[str, Any]:
        return {
            "index": self.index,
            "action": self.action,
            "label": self.label,
            "ok": self.ok,
            "elapsed_ms": round(self.elapsed_ms, 1),
            "detail": self.detail,
            "error": self.error,
            "skipped": self.skipped,
            "screenshot_path": self.screenshot_path,
        }


@dataclass
class Defect:
    """Normalized, deduplicatable customer-zero bug candidate."""

    fingerprint: str
    target: str
    target_repo: str
    flow: str
    viewport: str
    category: str  # flow_error | console_error | slow_endpoint | broken_link | network_error | layout_defect | vision_defect | service_down
    severity: str  # critical | major | minor
    title: str
    summary: str
    evidence: dict[str, Any] = field(default_factory=dict)
    screenshots: list[str] = field(default_factory=list)
    repro_steps: list[str] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        return {
            "fingerprint": self.fingerprint,
            "target": self.target,
            "target_repo": self.target_repo,
            "flow": self.flow,
            "viewport": self.viewport,
            "category": self.category,
            "severity": self.severity,
            "title": self.title,
            "summary": self.summary,
            "evidence": self.evidence,
            "screenshots": list(self.screenshots),
            "repro_steps": list(self.repro_steps),
        }


@dataclass
class FlowRunResult:
    """Complete result for running one flow on one target at one viewport."""

    target: str
    flow: str
    viewport: str
    viewport_px: str
    ok: bool
    elapsed_ms: float
    steps: list[StepOutcome] = field(default_factory=list)
    screenshots: list[str] = field(default_factory=list)
    console_errors: list[ConsoleRecord] = field(default_factory=list)
    failed_requests: list[NetworkRecord] = field(default_factory=list)
    slow_endpoints: list[NetworkRecord] = field(default_factory=list)
    broken_links: list[LinkCheckResult] = field(default_factory=list)
    links_checked: int = 0
    layout_metrics: dict[str, Any] = field(default_factory=dict)
    vision: list[VisionAssessment] = field(default_factory=list)
    defects: list[Defect] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        return {
            "target": self.target,
            "flow": self.flow,
            "viewport": self.viewport,
            "viewport_px": self.viewport_px,
            "ok": self.ok,
            "elapsed_ms": round(self.elapsed_ms, 1),
            "steps": [s.to_dict() for s in self.steps],
            "screenshots": list(self.screenshots),
            "console_errors": [c.to_dict() for c in self.console_errors],
            "failed_requests": [r.to_dict() for r in self.failed_requests],
            "slow_endpoints": [r.to_dict() for r in self.slow_endpoints],
            "broken_links": [b.to_dict() for b in self.broken_links],
            "links_checked": self.links_checked,
            "layout_metrics": self.layout_metrics,
            "vision": [v.to_dict() for v in self.vision],
            "defects": [d.to_dict() for d in self.defects],
        }


@dataclass
class TicketAction:
    """Outcome of processing a defect through deduplication and ticket filing."""

    fingerprint: str
    action: str  # "filed" | "deduped_open" | "deduped_cooldown" | "dry_run" | "capped" | "skipped_minor" | "error"
    title: str
    task_id: int | None = None
    reason: str = ""

    def to_dict(self) -> dict[str, Any]:
        return {
            "fingerprint": self.fingerprint,
            "action": self.action,
            "title": self.title,
            "task_id": self.task_id,
            "reason": self.reason,
        }


@dataclass
class RunSummary:
    """Top-level result of a full nightwalk run."""

    run_id: str
    started_at: str
    finished_at: str
    elapsed_ms: float
    dry_run: bool
    engine: str
    vision_enabled: bool
    vision_model: str
    targets_run: int
    flows_run: int
    flows_passed: int
    screenshots_captured: int
    total_defects: int
    unique_defects: int
    tickets_filed: int
    tickets_deduped: int
    report_path: str = ""
    panel_path: str = ""
    artifacts_dir: str = ""
    flow_results: list[FlowRunResult] = field(default_factory=list)
    defects: list[Defect] = field(default_factory=list)
    ticket_actions: list[TicketAction] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        return {
            "run_id": self.run_id,
            "started_at": self.started_at,
            "finished_at": self.finished_at,
            "elapsed_ms": round(self.elapsed_ms, 1),
            "dry_run": self.dry_run,
            "engine": self.engine,
            "vision_enabled": self.vision_enabled,
            "vision_model": self.vision_model,
            "targets_run": self.targets_run,
            "flows_run": self.flows_run,
            "flows_passed": self.flows_passed,
            "screenshots_captured": self.screenshots_captured,
            "total_defects": self.total_defects,
            "unique_defects": self.unique_defects,
            "tickets_filed": self.tickets_filed,
            "tickets_deduped": self.tickets_deduped,
            "report_path": self.report_path,
            "panel_path": self.panel_path,
            "artifacts_dir": self.artifacts_dir,
            "flow_results": [f.to_dict() for f in self.flow_results],
            "defects": [d.to_dict() for d in self.defects],
            "ticket_actions": [t.to_dict() for t in self.ticket_actions],
        }
