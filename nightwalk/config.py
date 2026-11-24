"""12-Factor runtime configuration loader for nightwalk.

Zero hardcoded usernames, hostnames, private IPs, or machine-specific paths.
Resolution priority (highest first):
  1. Explicit CLI overrides
  2. Environment variables (`NIGHTWALK_*`, `VEGA_BROWSER_URL`, `VEGA_PANELS_DIR`)
  3. Machine-local config JSON (`$XDG_CONFIG_HOME/nightwalk/config.json`, mode 0600, outside Git)
  4. Generic portable built-in defaults
"""

from __future__ import annotations

import json
import os
import shlex
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from .models import FlowSpec, FlowStep, TargetSpec, ViewportSpec

DEFAULT_BROWSER_URL = "http://127.0.0.1:8490"
DEFAULT_BROWSER_ENGINE = "chromium"
DEFAULT_SLOW_ENDPOINT_MS = 300.0
DEFAULT_VLM_PROFILE = "tactical"
DEFAULT_VLM_REASONING_EFFORT = "low"
DEFAULT_VLM_TIMEOUT_SEC = 120.0
DEFAULT_VLM_MAX_TOKENS = 2048
DEFAULT_VLM_CONCURRENCY = 3
DEFAULT_TICKET_PRIORITY = "P2"
DEFAULT_TICKET_COOLDOWN_HOURS = 72.0
DEFAULT_MAX_TICKETS_PER_RUN = 8
DEFAULT_LINK_CHECK_TIMEOUT_SEC = 5.0
DEFAULT_ARTIFACT_RETENTION_DAYS = 14


def xdg_config_home(env: dict[str, str] | None = None) -> Path:
    e = env if env is not None else os.environ
    raw = (e.get("XDG_CONFIG_HOME") or "").strip()
    if raw:
        return Path(raw).expanduser()
    home = Path((e.get("HOME") or str(Path.home()))).expanduser()
    return home / ".config"


def xdg_state_home(env: dict[str, str] | None = None) -> Path:
    e = env if env is not None else os.environ
    raw = (e.get("XDG_STATE_HOME") or "").strip()
    if raw:
        return Path(raw).expanduser()
    home = Path((e.get("HOME") or str(Path.home()))).expanduser()
    return home / ".local" / "state"


def default_config_path(env: dict[str, str] | None = None) -> Path:
    e = env if env is not None else os.environ
    raw = (e.get("NIGHTWALK_CONFIG") or "").strip()
    if raw:
        return Path(raw).expanduser()
    return xdg_config_home(e) / "nightwalk" / "config.json"


def default_viewports() -> list[ViewportSpec]:
    """Portable mobile-folded, foldable-unfolded, and desktop viewport suite."""
    return [
        ViewportSpec(name="fold-folded", width=374, height=844, mobile=True, device_scale_factor=2.0),
        ViewportSpec(name="fold-unfolded", width=768, height=720, mobile=True, device_scale_factor=2.0),
        ViewportSpec(name="desktop", width=1280, height=800, mobile=False, device_scale_factor=1.0),
    ]


def default_example_targets() -> list[TargetSpec]:
    """Portable example target (loopback-only) for `init-config`."""
    return [
        TargetSpec(
            name="local-app",
            base_url="http://127.0.0.1:8080",
            target_repo="",
            description="Example loopback web application target",
            flows=[
                FlowSpec(
                    name="home-smoke",
                    description="Load landing page, check links and layout, and capture Vision QA frame",
                    steps=[
                        FlowStep(action="goto", path="/", label="Open home page"),
                        FlowStep(action="wait_for", selector="body", label="Wait for body"),
                        FlowStep(action="check_links", label="Verify same-origin links", max_links=25),
                        FlowStep(action="check_layout", label="Verify layout and zero-emoji invariants"),
                        FlowStep(action="screenshot", tag="home", vision=True, label="Capture home view"),
                    ],
                )
            ],
        )
    ]


def _parse_bool(raw: Any, default: bool) -> bool:
    if raw is None or raw == "":
        return default
    if isinstance(raw, bool):
        return raw
    s = str(raw).strip().lower()
    if s in ("1", "true", "yes", "on"):
        return True
    if s in ("0", "false", "no", "off"):
        return False
    return default


def _parse_cmd(raw: Any, default: list[str]) -> list[str]:
    if raw is None:
        return list(default)
    if isinstance(raw, list):
        return [str(x) for x in raw if str(x).strip()]
    s = str(raw).strip()
    if not s or s.lower() == "off":
        return []
    return shlex.split(s)


def resolve_vlm_profile(
    profile_name: str,
    *,
    env: dict[str, str] | None = None,
) -> tuple[str, str, str, bool]:
    """Resolve (base_url, model, api_key, vision_capable) from $XDG_CONFIG_HOME/local-agents/profiles.json."""
    profiles_path = xdg_config_home(env) / "local-agents" / "profiles.json"
    if not profiles_path.is_file():
        return ("", "", "", False)
    try:
        data = json.loads(profiles_path.read_text(encoding="utf-8"))
    except Exception:
        return ("", "", "", False)

    profiles = data.get("profiles") if isinstance(data, dict) else None
    if not isinstance(profiles, dict):
        return ("", "", "", False)

    wanted = (profile_name or DEFAULT_VLM_PROFILE).strip().lower()
    chosen: dict[str, Any] | None = None
    for name, spec in profiles.items():
        if not isinstance(spec, dict):
            continue
        aliases = [str(a).strip().lower() for a in (spec.get("aliases") or [])]
        if name.strip().lower() == wanted or wanted in aliases:
            chosen = spec
            break
    if chosen is None:
        return ("", "", "", False)

    url = str(chosen.get("base_url") or chosen.get("url") or "").strip().rstrip("/")
    model = str(chosen.get("model") or "").strip()
    api_key = str(chosen.get("api_key") or "").strip()
    if not api_key and chosen.get("api_key_env"):
        e = env if env is not None else os.environ
        api_key = str(e.get(str(chosen["api_key_env"]), "")).strip()
    vision = bool(chosen.get("vision", False))
    return (url, model, api_key, vision)


def load_target_auth_token(target: TargetSpec, env: dict[str, str] | None = None) -> str:
    """Load an optional target auth token from env or 0600 file at runtime (never stored in reports)."""
    e = env if env is not None else os.environ
    if target.auth_token_env:
        val = (e.get(target.auth_token_env) or "").strip()
        if val:
            return val
    if target.auth_token_file:
        path = Path(os.path.expandvars(target.auth_token_file)).expanduser()
        if path.is_file():
            return path.read_text(encoding="utf-8").strip()
    return ""


@dataclass
class NightwalkConfig:
    """Resolved runtime configuration for a nightwalk execution."""

    config_path: Path
    browser_url: str = DEFAULT_BROWSER_URL
    browser_engine: str = DEFAULT_BROWSER_ENGINE
    browser_headless: bool = True
    loopback_only: bool = True
    slow_endpoint_ms: float = DEFAULT_SLOW_ENDPOINT_MS
    link_check_timeout_sec: float = DEFAULT_LINK_CHECK_TIMEOUT_SEC
    vlm_profile: str = DEFAULT_VLM_PROFILE
    vlm_url: str = ""
    vlm_model: str = ""
    vlm_api_key: str = ""
    vlm_reasoning_effort: str = DEFAULT_VLM_REASONING_EFFORT
    vlm_timeout_sec: float = DEFAULT_VLM_TIMEOUT_SEC
    vlm_max_tokens: int = DEFAULT_VLM_MAX_TOKENS
    vlm_concurrency: int = DEFAULT_VLM_CONCURRENCY
    state_dir: Path = field(default_factory=lambda: xdg_state_home() / "nightwalk")
    report_dir: Path = field(default_factory=lambda: Path.home() / "Documents" / "reports" / "dogfood")
    panel_path: Path | None = None
    auto_file_tickets: bool = True
    ticket_priority: str = DEFAULT_TICKET_PRIORITY
    ticket_cooldown_hours: float = DEFAULT_TICKET_COOLDOWN_HOURS
    max_tickets_per_run: int = DEFAULT_MAX_TICKETS_PER_RUN
    ticket_list_cmd: list[str] = field(default_factory=lambda: ["vega-pulse", "list", "--all", "--json"])
    ticket_add_cmd: list[str] = field(default_factory=lambda: ["vega-pulse", "add"])
    artifact_retention_days: int = DEFAULT_ARTIFACT_RETENTION_DAYS
    viewports: list[ViewportSpec] = field(default_factory=default_viewports)
    targets: list[TargetSpec] = field(default_factory=list)

    @property
    def db_path(self) -> Path:
        return self.state_dir / "state.db"

    @property
    def runs_dir(self) -> Path:
        return self.state_dir / "runs"


def load_config(
    config_path: str | Path | None = None,
    *,
    env: dict[str, str] | None = None,
) -> NightwalkConfig:
    """Load merged 12-Factor config from file + environment variables."""
    e = env if env is not None else os.environ
    cfg_path = Path(config_path).expanduser() if config_path else default_config_path(e)
    raw: dict[str, Any] = {}
    if cfg_path.is_file():
        raw = json.loads(cfg_path.read_text(encoding="utf-8"))
        if not isinstance(raw, dict):
            raise ValueError(f"Config root must be a JSON object: {cfg_path}")

    browser_url = (
        (e.get("NIGHTWALK_BROWSER_URL") or "").strip()
        or (e.get("VEGA_BROWSER_URL") or "").strip()
        or str(raw.get("browser_url") or DEFAULT_BROWSER_URL).strip()
    ).rstrip("/")

    browser_engine = (
        (e.get("NIGHTWALK_BROWSER_ENGINE") or "").strip()
        or str(raw.get("browser_engine") or DEFAULT_BROWSER_ENGINE).strip()
    ).lower()

    browser_headless = _parse_bool(
        e.get("NIGHTWALK_BROWSER_HEADLESS") if "NIGHTWALK_BROWSER_HEADLESS" in e else raw.get("browser_headless"),
        True,
    )
    loopback_only = _parse_bool(
        e.get("NIGHTWALK_LOOPBACK_ONLY") if "NIGHTWALK_LOOPBACK_ONLY" in e else raw.get("loopback_only"),
        True,
    )
    slow_endpoint_ms = float(
        (e.get("NIGHTWALK_SLOW_ENDPOINT_MS") or "").strip()
        or raw.get("slow_endpoint_ms", DEFAULT_SLOW_ENDPOINT_MS)
    )
    link_check_timeout_sec = float(
        (e.get("NIGHTWALK_LINK_CHECK_TIMEOUT_SEC") or "").strip()
        or raw.get("link_check_timeout_sec", DEFAULT_LINK_CHECK_TIMEOUT_SEC)
    )

    vlm_profile = (
        (e.get("NIGHTWALK_VLM_PROFILE") or "").strip()
        or str(raw.get("vlm_profile") or DEFAULT_VLM_PROFILE).strip()
    )
    vlm_url = (e.get("NIGHTWALK_VLM_URL") or "").strip() or str(raw.get("vlm_url") or "").strip()
    vlm_model = (e.get("NIGHTWALK_VLM_MODEL") or "").strip() or str(raw.get("vlm_model") or "").strip()
    vlm_api_key = (e.get("NIGHTWALK_VLM_API_KEY") or "").strip() or str(raw.get("vlm_api_key") or "").strip()

    if not vlm_url or not vlm_model:
        prof_url, prof_model, prof_key, _ = resolve_vlm_profile(vlm_profile, env=e)
        if not vlm_url:
            vlm_url = prof_url
        if not vlm_model:
            vlm_model = prof_model
        if not vlm_api_key:
            vlm_api_key = prof_key

    vlm_reasoning_effort = (
        (e.get("NIGHTWALK_VLM_REASONING_EFFORT") or "").strip()
        or str(raw.get("vlm_reasoning_effort") or DEFAULT_VLM_REASONING_EFFORT).strip()
    )
    vlm_timeout_sec = float(
        (e.get("NIGHTWALK_VLM_TIMEOUT_SEC") or "").strip()
        or raw.get("vlm_timeout_sec", DEFAULT_VLM_TIMEOUT_SEC)
    )
    vlm_max_tokens = int(
        (e.get("NIGHTWALK_VLM_MAX_TOKENS") or "").strip()
        or raw.get("vlm_max_tokens", DEFAULT_VLM_MAX_TOKENS)
    )
    vlm_concurrency = max(
        1,
        min(
            4,
            int(
                (e.get("NIGHTWALK_VLM_CONCURRENCY") or "").strip()
                or raw.get("vlm_concurrency", DEFAULT_VLM_CONCURRENCY)
            ),
        ),
    )

    state_raw = (e.get("NIGHTWALK_STATE_DIR") or "").strip() or str(raw.get("state_dir") or "").strip()
    state_dir = Path(os.path.expandvars(state_raw)).expanduser() if state_raw else (xdg_state_home(e) / "nightwalk")

    home = Path((e.get("HOME") or str(Path.home()))).expanduser()
    report_raw = (e.get("NIGHTWALK_REPORT_DIR") or "").strip() or str(raw.get("report_dir") or "").strip()
    report_dir = (
        Path(os.path.expandvars(report_raw)).expanduser()
        if report_raw
        else (home / "Documents" / "reports" / "dogfood")
    )

    panel_raw = (e.get("NIGHTWALK_PANEL_PATH") or "").strip() or str(raw.get("panel_path") or "").strip()
    if panel_raw.lower() == "off":
        panel_path: Path | None = None
    elif panel_raw:
        panel_path = Path(os.path.expandvars(panel_raw)).expanduser()
    else:
        panels_dir = (e.get("VEGA_PANELS_DIR") or "").strip()
        base_panels = Path(panels_dir).expanduser() if panels_dir else (xdg_state_home(e) / "vega" / "panels")
        panel_path = base_panels / "12-dogfood.json"

    auto_file_tickets = _parse_bool(
        e.get("NIGHTWALK_AUTO_FILE_TICKETS")
        if "NIGHTWALK_AUTO_FILE_TICKETS" in e
        else raw.get("auto_file_tickets"),
        True,
    )
    ticket_priority = (
        (e.get("NIGHTWALK_TICKET_PRIORITY") or "").strip()
        or str(raw.get("ticket_priority") or DEFAULT_TICKET_PRIORITY).strip()
    ).upper()
    ticket_cooldown_hours = float(
        (e.get("NIGHTWALK_TICKET_COOLDOWN_HOURS") or "").strip()
        or raw.get("ticket_cooldown_hours", DEFAULT_TICKET_COOLDOWN_HOURS)
    )
    max_tickets_per_run = int(
        (e.get("NIGHTWALK_MAX_TICKETS_PER_RUN") or "").strip()
        or raw.get("max_tickets_per_run", DEFAULT_MAX_TICKETS_PER_RUN)
    )
    artifact_retention_days = int(
        (e.get("NIGHTWALK_ARTIFACT_RETENTION_DAYS") or "").strip()
        or raw.get("artifact_retention_days", DEFAULT_ARTIFACT_RETENTION_DAYS)
    )

    list_cmd_raw = (
        e.get("NIGHTWALK_TICKET_LIST_CMD")
        if "NIGHTWALK_TICKET_LIST_CMD" in e
        else raw.get("ticket_list_cmd")
    )
    add_cmd_raw = (
        e.get("NIGHTWALK_TICKET_ADD_CMD")
        if "NIGHTWALK_TICKET_ADD_CMD" in e
        else raw.get("ticket_add_cmd")
    )
    ticket_list_cmd = _parse_cmd(list_cmd_raw, ["vega-pulse", "list", "--all", "--json"])
    ticket_add_cmd = _parse_cmd(add_cmd_raw, ["vega-pulse", "add"])

    raw_viewports = raw.get("viewports")
    viewports = (
        [ViewportSpec.from_dict(v) for v in raw_viewports]
        if isinstance(raw_viewports, list) and raw_viewports
        else default_viewports()
    )

    raw_targets = raw.get("targets")
    targets = (
        [TargetSpec.from_dict(t) for t in raw_targets]
        if isinstance(raw_targets, list) and raw_targets
        else []
    )

    return NightwalkConfig(
        config_path=cfg_path,
        browser_url=browser_url,
        browser_engine=browser_engine,
        browser_headless=browser_headless,
        loopback_only=loopback_only,
        slow_endpoint_ms=slow_endpoint_ms,
        link_check_timeout_sec=link_check_timeout_sec,
        vlm_profile=vlm_profile,
        vlm_url=vlm_url.rstrip("/"),
        vlm_model=vlm_model,
        vlm_api_key=vlm_api_key,
        vlm_reasoning_effort=vlm_reasoning_effort,
        vlm_timeout_sec=vlm_timeout_sec,
        vlm_max_tokens=vlm_max_tokens,
        vlm_concurrency=vlm_concurrency,
        state_dir=state_dir,
        report_dir=report_dir,
        panel_path=panel_path,
        auto_file_tickets=auto_file_tickets,
        ticket_priority=ticket_priority,
        ticket_cooldown_hours=ticket_cooldown_hours,
        max_tickets_per_run=max_tickets_per_run,
        ticket_list_cmd=ticket_list_cmd,
        ticket_add_cmd=ticket_add_cmd,
        artifact_retention_days=artifact_retention_days,
        viewports=viewports,
        targets=targets,
    )


def write_example_config(path: Path, *, overwrite: bool = False) -> Path:
    """Write a generic 0600 starter config JSON outside source control."""
    path.parent.mkdir(parents=True, exist_ok=True)
    if path.exists() and not overwrite:
        return path
    payload = {
        "browser_url": DEFAULT_BROWSER_URL,
        "browser_engine": DEFAULT_BROWSER_ENGINE,
        "browser_headless": True,
        "loopback_only": True,
        "slow_endpoint_ms": DEFAULT_SLOW_ENDPOINT_MS,
        "vlm_profile": DEFAULT_VLM_PROFILE,
        "vlm_reasoning_effort": DEFAULT_VLM_REASONING_EFFORT,
        "auto_file_tickets": True,
        "ticket_priority": DEFAULT_TICKET_PRIORITY,
        "ticket_cooldown_hours": DEFAULT_TICKET_COOLDOWN_HOURS,
        "max_tickets_per_run": DEFAULT_MAX_TICKETS_PER_RUN,
        "viewports": [v.to_dict() for v in default_viewports()],
        "targets": [
            {
                "name": t.name,
                "base_url": t.base_url,
                "target_repo": t.target_repo,
                "description": t.description,
                "flows": [
                    {
                        "name": f.name,
                        "description": f.description,
                        "steps": [
                            {k: v for k, v in s.__dict__.items() if v not in ("", [], False, None)}
                            for s in f.steps
                        ],
                    }
                    for f in t.flows
                ],
            }
            for t in default_example_targets()
        ],
    }
    tmp = path.with_suffix(".json.tmp")
    tmp.write_text(json.dumps(payload, indent=2) + "\n", encoding="utf-8")
    os.chmod(tmp, 0o600)
    tmp.replace(path)
    return path
