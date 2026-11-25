"""Offline, deterministic unit tests for nightwalk browser, flows, pipeline, and CLI modules.

No external URLs, real browsers, real VLM servers, or real vega-pulse are used.
"""

from __future__ import annotations

import contextlib
import http.server
import io
import json
import os
import signal
import socket
import sys
import tempfile
import threading
import unittest
import urllib.parse
from pathlib import Path
from typing import Any
from unittest.mock import Mock, MagicMock, patch

from nightwalk.browser import BrowserInstanceHandle, VegaBrowserClient
from nightwalk.cli import _build_parser, main
from nightwalk.config import NightwalkConfig
from nightwalk.dedupe import StateStore
from nightwalk.flows import (
    STEP_REGISTRY,
    FlowContext,
    _slugify,
    register_step,
    run_flow,
)
from nightwalk.models import (
    ConsoleRecord,
    Defect,
    FlowRunResult,
    FlowSpec,
    FlowStep,
    LinkCheckResult,
    NetworkRecord,
    RunSummary,
    StepOutcome,
    TargetSpec,
    ViewportSpec,
    VisionAssessment,
)
from nightwalk.pipeline import (
    _probe_target_reachable,
    check_environment,
    run_dogfood,
)


# --------------------------------------------------------------------------
# Shared fixtures & helpers
# --------------------------------------------------------------------------

def _start_loopback(handler_class: type, state: dict | None = None) -> http.server.ThreadingHTTPServer:
    server = http.server.ThreadingHTTPServer(("127.0.0.1", 0), handler_class)
    server.state = state if state is not None else {}
    thread = threading.Thread(target=lambda: server.serve_forever(poll_interval=0.02), daemon=True)
    thread.start()
    return server


def _shutdown_loopback(server: http.server.ThreadingHTTPServer) -> None:
    server.shutdown()
    server.server_close()


def _free_port() -> int:
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.bind(("127.0.0.1", 0))
        return int(s.getsockname()[1])


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


class _MuxHandler(http.server.BaseHTTPRequestHandler):
    """Loopback mux serving browser-pool, target, and VLM endpoints for tests."""

    def log_message(self, *_: Any) -> None:
        return

    def _json(self, status: int, obj: Any) -> None:
        body = json.dumps(obj).encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def do_GET(self) -> None:
        server = self.server
        st = server.state
        parts = urllib.parse.urlsplit(self.path)
        path = parts.path
        if path == "/health":
            status = int(st.get("health_status", 200))
            if status != 200:
                self.send_error(status)
                return
            self._json(200, st.get("health_body", {"ok": True, "service": "browser-pool", "activeInstanceCount": 1}))
            return
        if path.endswith("/models"):
            st["vlm_auth"] = self.headers.get("Authorization") or ""
            self._json(200, {"data": []})
            return
        if path == "/api/devtools":
            st["last_devtools_query"] = parts.query
            self._json(200, st.get("devtools_body", {"console": [], "network": []}))
            return
        if path == "/api/screenshot":
            st["last_screenshot_query"] = parts.query
            body = st.get("screenshot_body", b"\x89PNG\r\n\x1a\nscreenshotbinary")
            self.send_response(200)
            self.send_header("Content-Type", "image/png")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)
            return
        if path == "/":
            st["target_headers"] = {k.lower(): v for k, v in self.headers.items()}
            status = int(st.get("target_status", 200))
            self.send_response(status)
            self.send_header("Content-Length", "2")
            self.end_headers()
            self.wfile.write(b"ok")
            return
        self.send_error(404)

    def do_POST(self) -> None:
        server = self.server
        st = server.state
        parts = urllib.parse.urlsplit(self.path)
        path = parts.path
        length = int(self.headers.get("Content-Length", "0"))
        raw = self.rfile.read(length) if length else b""
        try:
            body = json.loads(raw) if raw else {}
        except Exception:
            body = {}
        st.setdefault("posts", []).append({"path": path, "query": parts.query, "body": body})
        if path == "/api/instances":
            if body.get("browserId") == "fail-http":
                self.send_error(500, "pool exploded")
                return
            self._json(
                200,
                st.get(
                    "instance_response",
                    {
                        "state": {"cdpUrl": "http://127.0.0.1:9222", "cdpPort": 9222, "engine": "chromium"},
                        "browserId": body.get("browserId") or "bid",
                    },
                ),
            )
            return
        if path == "/api/devtools/clear":
            self._json(200, {"ok": True})
            return
        self.send_error(404)

    def do_DELETE(self) -> None:
        server = self.server
        st = server.state
        parts = urllib.parse.urlsplit(self.path)
        path = parts.path
        st.setdefault("deletes", []).append({"path": path, "query": parts.query})
        if path.startswith("/api/instances/"):
            self._json(200, {"ok": True})
            return
        self.send_error(404)


# --------------------------------------------------------------------------
# nightwalk.browser
# --------------------------------------------------------------------------

class TestVegaBrowserClient(unittest.TestCase):
    def setUp(self) -> None:
        self.server = _start_loopback(_MuxHandler)
        self.base_url = f"http://127.0.0.1:{self.server.server_port}"
        self.addCleanup(_shutdown_loopback, self.server)

    def test_init_enforces_loopback_and_strips_trailing_slash(self) -> None:
        client = VegaBrowserClient("http://127.0.0.1:8490/")
        self.assertEqual(client.base_url, "http://127.0.0.1:8490")
        with self.assertRaises(ValueError):
            VegaBrowserClient("https://example.com/internal")

    def test_health_parses_json(self) -> None:
        client = VegaBrowserClient(self.base_url)
        result = client.health()
        self.assertTrue(result["ok"])
        self.assertEqual(result["service"], "browser-pool")

    def test_health_raises_runtime_error_on_http_error(self) -> None:
        self.server.state["health_status"] = 500
        client = VegaBrowserClient(self.base_url)
        with self.assertRaises(RuntimeError):
            client.health()

    def test_spawn_instance_posts_expected_payload(self) -> None:
        client = VegaBrowserClient(self.base_url)
        handle = client.spawn_instance(
            browser_id="bid-1",
            label="Test Label",
            engine="chromium",
            headless=True,
            start_url="about:blank",
        )
        post = self.server.state["posts"][-1]
        self.assertEqual(post["path"], "/api/instances")
        self.assertEqual(
            post["body"],
            {
                "browserId": "bid-1",
                "label": "Test Label",
                "engine": "chromium",
                "reuse": False,
                "start": True,
                "url": "about:blank",
                "headless": True,
            },
        )
        self.assertEqual(handle.browser_id, "bid-1")
        self.assertEqual(handle.cdp_url, "http://127.0.0.1:9222")
        self.assertEqual(handle.cdp_port, 9222)
        self.assertEqual(handle.engine, "chromium")

    def test_spawn_instance_uses_explicit_cdp_url(self) -> None:
        self.server.state["instance_response"] = {
            "state": {"cdpUrl": "http://127.0.0.1:9999", "cdpPort": 9222, "engine": "obscura"},
            "browserId": "bid-explicit",
        }
        client = VegaBrowserClient(self.base_url)
        handle = client.spawn_instance(browser_id="bid-explicit")
        self.assertEqual(handle.cdp_url, "http://127.0.0.1:9999")
        self.assertEqual(handle.engine, "obscura")

    def test_spawn_instance_falls_back_to_cdp_port(self) -> None:
        self.server.state["instance_response"] = {
            "state": {"cdpPort": 9222, "engine": "chromium"},
            "browserId": "bid-port",
        }
        client = VegaBrowserClient(self.base_url)
        handle = client.spawn_instance(browser_id="bid-port")
        self.assertEqual(handle.cdp_url, "http://127.0.0.1:9222")
        self.assertEqual(handle.cdp_port, 9222)

    def test_spawn_instance_raises_when_no_cdp_url_and_no_port(self) -> None:
        self.server.state["instance_response"] = {"state": {}, "browserId": "bid-none"}
        client = VegaBrowserClient(self.base_url)
        with self.assertRaises(RuntimeError):
            client.spawn_instance(browser_id="bid-none")

    def test_spawn_instance_raises_on_non_loopback_cdp_url(self) -> None:
        self.server.state["instance_response"] = {
            "state": {"cdpUrl": "https://example.com/cdp", "engine": "chromium"},
            "browserId": "bid-ext",
        }
        client = VegaBrowserClient(self.base_url)
        with self.assertRaises(ValueError):
            client.spawn_instance(browser_id="bid-ext")

    def test_spawn_instance_raises_on_http_error(self) -> None:
        client = VegaBrowserClient(self.base_url)
        with self.assertRaises(RuntimeError):
            client.spawn_instance(browser_id="fail-http")

    def test_clear_devtools_posts_and_swallows_errors(self) -> None:
        client = VegaBrowserClient(self.base_url)
        client.clear_devtools("bid-1")
        post = self.server.state["posts"][-1]
        self.assertEqual(post["path"], "/api/devtools/clear")
        self.assertEqual(post["body"], {"browserId": "bid-1"})

        dead_client = VegaBrowserClient("http://127.0.0.1:1")
        dead_client.clear_devtools("bid-2")  # must not raise

    def test_get_devtools_filters_console_and_redacts(self) -> None:
        self.server.state["devtools_body"] = {
            "console": [
                "not-a-dict",
                {"level": "info", "text": "ignored info entry"},
                {
                    "level": "error",
                    "source": "console",
                    "text": "boom with secret_token_value abcdefghijkl",
                    "url": "http://127.0.0.1:8080/app.js?token=abc123def456&window=24h",
                    "line": 7,
                },
            ],
            "network": [
                "again-not-a-dict",
                {
                    "method": "GET",
                    "url": "http://127.0.0.1:8080/api/events?token=abc123def456",
                    "status": 200,
                    "ok": True,
                    "durationMs": 42.5,
                    "resourceType": "EventSource",
                    "errorText": "",
                    "canceled": False,
                },
                {
                    "method": "GET",
                    "url": "ws://127.0.0.1:8080/socket?token=abc123def456",
                    "status": None,
                    "ok": False,
                    "durationMs": 12.0,
                    "resourceType": "WebSocket",
                    "errorText": "ws error",
                    "canceled": True,
                },
            ],
        }
        client = VegaBrowserClient(self.base_url)
        console, network = client.get_devtools("bid-1", extra_secrets=("secret_token_value",))

        self.assertEqual(len(console), 1)
        rec = console[0]
        self.assertEqual(rec.level, "error")
        self.assertNotIn("secret_token_value", rec.text)
        self.assertNotIn("abc123def456", rec.text)
        self.assertIn("window=24h", rec.url)
        self.assertNotIn("abc123def456", rec.url)
        self.assertEqual(rec.line, 7)

        self.assertEqual(len(network), 2)
        self.assertTrue(network[0].streaming)
        self.assertAlmostEqual(network[0].duration_ms or 0.0, 42.5)
        self.assertEqual(network[0].resource_type, "EventSource")
        self.assertNotIn("abc123def456", network[0].url)
        self.assertTrue(network[1].streaming)  # ws: url and WebSocket resourceType
        self.assertTrue(network[1].canceled)
        self.assertEqual(network[1].error_text, "ws error")

    def test_get_devtools_returns_empty_on_server_failure(self) -> None:
        dead_client = VegaBrowserClient("http://127.0.0.1:1")
        console, network = dead_client.get_devtools("bid-dead")
        self.assertEqual(console, [])
        self.assertEqual(network, [])

    def test_capture_screenshot_returns_raw_bytes(self) -> None:
        client = VegaBrowserClient(self.base_url)
        raw = client.capture_screenshot("bid-1")
        self.assertEqual(raw, b"\x89PNG\r\n\x1a\nscreenshotbinary")
        query = self.server.state["last_screenshot_query"]
        self.assertIn("browserId=bid-1", query)

    def test_delete_instance_sends_purge_profile_flag(self) -> None:
        client = VegaBrowserClient(self.base_url)
        client.delete_instance("bid-1", purge_profile=True)
        client.delete_instance("bid-2", purge_profile=False)
        deletes = self.server.state["deletes"]
        self.assertEqual(deletes[-2]["path"], "/api/instances/bid-1")
        self.assertIn("purgeProfile=1", deletes[-2]["query"])
        self.assertEqual(deletes[-1]["path"], "/api/instances/bid-2")
        self.assertIn("purgeProfile=0", deletes[-1]["query"])

    def test_delete_instance_swallows_errors(self) -> None:
        dead_client = VegaBrowserClient("http://127.0.0.1:1")
        dead_client.delete_instance("bid-x")  # must not raise


# --------------------------------------------------------------------------
# nightwalk.flows - helpers
# --------------------------------------------------------------------------

def _flow_ctx(
    *,
    root: Path,
    cdp: Any,
    browser: Any = None,
    viewport_name: str = "desktop",
    flow_name: str = "home",
    target_name: str = "app",
    cfg: NightwalkConfig | None = None,
) -> FlowContext:
    browser = browser or Mock()
    cfg = cfg or NightwalkConfig(config_path=root / "config.json", loopback_only=False)
    target = TargetSpec(name=target_name, base_url="http://127.0.0.1:8090")
    flow = FlowSpec(name=flow_name, steps=[FlowStep(action="goto", path="/")])
    viewport = ViewportSpec(name=viewport_name, width=1280, height=800)
    return FlowContext(
        cfg=cfg,
        target=target,
        flow=flow,
        viewport=viewport,
        cdp=cdp,
        browser=browser,
        browser_id="test-bid",
        screenshots_dir=root / "shots",
    )


def _default_cfg(root: Path, **overrides: Any) -> NightwalkConfig:
    kwargs: dict[str, Any] = {
        "config_path": root / "config.json",
        "loopback_only": True,
        "vlm_concurrency": 1,
        "slow_endpoint_ms": 300.0,
        "link_check_timeout_sec": 1.0,
    }
    kwargs.update(overrides)
    return NightwalkConfig(**kwargs)


class TestSlugify(unittest.TestCase):
    def test_special_chars_and_case(self) -> None:
        self.assertEqual(_slugify("Hello World! Foo--Bar"), "hello-world-foo-bar")
        self.assertEqual(_slugify("  a__b  "), "a-b")

    def test_empty_and_special_only_falls_back(self) -> None:
        self.assertEqual(_slugify(""), "item")
        self.assertEqual(_slugify("   "), "item")
        self.assertEqual(_slugify("!!@@#$$"), "item")

    def test_truncation_48_chars(self) -> None:
        self.assertEqual(len(_slugify("a" * 200)), 48)


class TestCaptureShot(unittest.TestCase):
    def test_capture_shot_uses_cdp_and_records_vision_target(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            cdp = Mock()
            cdp.capture_screenshot.return_value = b"png"
            browser = Mock()
            browser.capture_screenshot.return_value = b"jpg"
            ctx = _flow_ctx(root=root, cdp=cdp, browser=browser)

            shot = ctx.capture_shot("hero", mark_vision=True)
            self.assertTrue(shot.is_file())
            self.assertEqual(shot.suffix, ".png")
            self.assertEqual(ctx.screenshots, [str(shot)])
            self.assertEqual(ctx.vision_targets, [(shot, "hero")])

    def test_capture_shot_falls_back_to_browser_screenshot(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            cdp = Mock()
            cdp.capture_screenshot.side_effect = RuntimeError("cdp down")
            browser = Mock()
            browser.capture_screenshot.return_value = b"jpgbytes"
            ctx = _flow_ctx(root=root, cdp=cdp, browser=browser)

            shot = ctx.capture_shot("hero")
            self.assertTrue(shot.is_file())
            self.assertEqual(shot.suffix, ".jpg")
            cdp.capture_screenshot.assert_called_once_with(fmt="png")
            browser.capture_screenshot.assert_called_once_with("test-bid")


class TestRegisterStep(unittest.TestCase):
    def test_decorator_and_direct_call_roundtrip(self) -> None:
        original = STEP_REGISTRY.get("custom-test-step")
        self.addCleanup(lambda: STEP_REGISTRY.pop("custom-test-step", None) or (
            STEP_REGISTRY.__setitem__("custom-test-step", original) if original else None
        ))

        @register_step("custom-test-step")
        def _handler(ctx, step):
            return (True, "ok", "")

        self.assertIs(STEP_REGISTRY.get("custom-test-step"), _handler)

        def _direct(ctx, step):
            return (False, "", "boom")

        result = register_step("custom-test-step", _direct)
        self.assertIs(result, _direct)
        self.assertIs(STEP_REGISTRY["custom-test-step"], _direct)


class TestBuiltinSteps(unittest.TestCase):
    def setUp(self) -> None:
        self._sleep_patch = patch("nightwalk.flows.time.sleep", lambda *a, **k: None)
        self._sleep_patch.start()
        self.addCleanup(self._sleep_patch.stop)

    def _ctx(self, root: Path, cdp: Any, browser: Any = None) -> FlowContext:
        browser = browser or Mock()
        return _flow_ctx(root=root, cdp=cdp, browser=browser)

    def test_goto_relative_path_and_explicit_url_and_loopback_guard(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            cdp = Mock()
            ctx = self._ctx(root, cdp)

            from nightwalk.flows import _step_goto

            ok, detail, _ = _step_goto(ctx, FlowStep(action="goto", path="/deep"))
            self.assertTrue(ok)
            cdp.navigate.assert_called_with(
                "http://127.0.0.1:8090/deep", timeout=max(10.0, 300 / 1000.0), settle_ms=300
            )

            ok2, _, _ = _step_goto(ctx, FlowStep(action="goto", url="http://127.0.0.1:8090/explicit"))
            self.assertTrue(ok2)
            cdp.navigate.assert_called_with(
                "http://127.0.0.1:8090/explicit", timeout=max(10.0, 300 / 1000.0), settle_ms=300
            )

            guarded = NightwalkConfig(config_path=root / "config.json", loopback_only=True)
            ctx_guarded = _flow_ctx(root=root, cdp=cdp, cfg=guarded)
            with self.assertRaises(ValueError):
                _step_goto(ctx_guarded, FlowStep(action="goto", url="https://example.com/not-local"))

    def test_wait_for_selector_found_and_timeout(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            from nightwalk.flows import _step_wait_for

            cdp = Mock()
            cdp.evaluate.return_value = {"x": 1.0, "y": 1.0, "width": 10.0, "height": 5.0}
            ctx = self._ctx(root, cdp)
            ok, detail, _ = _step_wait_for(ctx, FlowStep(action="wait_for", selector=".target"))
            self.assertTrue(ok)
            self.assertIn(".target", detail)

            cdp_slow = Mock()
            cdp_slow.evaluate.return_value = None
            ctx_slow = self._ctx(root, cdp_slow)
            ok2, _, err = _step_wait_for(ctx_slow, FlowStep(action="wait_for", selector=".gone", timeout_ms=200))
            self.assertFalse(ok2)
            self.assertIn("Timed out", err)

    def test_wait_for_expr_truthy(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            from nightwalk.flows import _step_wait_for

            cdp = Mock()
            cdp.evaluate.return_value = True
            ctx = self._ctx(root, cdp)
            ok, _, _ = _step_wait_for(ctx, FlowStep(action="wait_for", expr="window.ready"))
            self.assertTrue(ok)

    def test_click_found_and_missing(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            from nightwalk.flows import _step_click

            cdp = Mock()
            cdp.evaluate.return_value = {"x": 3.0, "y": 4.0, "left": 0.0, "top": 0.0, "width": 100.0, "height": 20.0, "text": "Go"}
            ctx = self._ctx(root, cdp)
            ok, detail, _ = _step_click(ctx, FlowStep(action="click", selector=".btn"))
            self.assertTrue(ok)
            cdp.mouse_click.assert_called_with(3.0, 4.0)
            cdp.wait_network_quiet.assert_called_once_with(quiet_ms=250, max_wait_s=3.0)
            self.assertIn(".btn", detail)

            cdp_miss = Mock()
            cdp_miss.evaluate.return_value = None
            ctx_miss = self._ctx(root, cdp_miss)
            ok2, _, err = _step_click(ctx_miss, FlowStep(action="click", selector=".gone", timeout_ms=200))
            self.assertFalse(ok2)
            self.assertIn("Element not visible", err)

    def test_click_first_delegates(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            from nightwalk.flows import _step_click_first

            cdp = Mock()
            cdp.evaluate.return_value = {"x": 5.0, "y": 6.0, "left": 0.0, "top": 0.0, "width": 10.0, "height": 10.0, "text": "x"}
            ctx = self._ctx(root, cdp)
            ok, _, _ = _step_click_first(ctx, FlowStep(action="click_first", selector=".first"))
            self.assertTrue(ok)
            cdp_miss = Mock()
            cdp_miss.evaluate.return_value = None
            ctx_miss = self._ctx(root, cdp_miss)
            ok2, _, err = _step_click_first(ctx_miss, FlowStep(action="click_first", selector=".gone", timeout_ms=200))
            self.assertFalse(ok2)

    def test_scrub_requires_visible_target_and_reports_change(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            from nightwalk.flows import _step_scrub

            state = {"reads": ["val-1", "val-2"]}

            def _eval(expr: str, **kwargs: Any) -> Any:
                if "querySelectorAll" in expr:
                    return {"x": 50.0, "y": 15.0, "left": 0.0, "top": 0.0, "width": 100.0, "height": 30.0, "text": "chart"}
                if "textContent" in expr:
                    return state["reads"].pop(0) if state["reads"] else "val-1"
                if "cursor-marker" in expr:
                    return True
                return True

            cdp = Mock()
            cdp.evaluate.side_effect = _eval
            cdp.capture_screenshot.return_value = b"png"
            ctx = self._ctx(root, cdp)
            step = FlowStep(
                action="scrub",
                selector=".chart",
                readout_selector=".readout",
                cursor_selector=".cursor-marker",
                steps=3,
                tag="mid",
                vision=False,
                expect_change=True,
            )
            ok, detail, err = _step_scrub(ctx, step)
            self.assertTrue(ok)
            self.assertIn("cursor=True", detail)
            # Mid-scrub screenshot was captured
            self.assertTrue(any("mid" in p for p in ctx.screenshots))

    def test_scrub_expect_change_failure_returns_error(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            from nightwalk.flows import _step_scrub

            cdp = Mock()

            def _eval(expr: str, **kwargs: Any) -> Any:
                if "querySelectorAll" in expr:
                    return {"x": 50.0, "y": 15.0, "left": 0.0, "top": 0.0, "width": 100.0, "height": 30.0, "text": "chart"}
                if "textContent" in expr:
                    return "same"
                if "cursor-marker" in expr:
                    return False
                return True

            cdp.evaluate.side_effect = _eval
            ctx = self._ctx(root, cdp)
            step = FlowStep(
                action="scrub",
                selector=".chart",
                readout_selector=".readout",
                cursor_selector=".cursor-marker",
                steps=2,
                expect_change=True,
            )
            ok, _, err = _step_scrub(ctx, step)
            self.assertFalse(ok)
            self.assertIn("did not update readout", err)

            cdp_miss = Mock()
            cdp_miss.evaluate.return_value = None
            ctx_miss = self._ctx(root, cdp_miss)
            ok_miss, _, err_miss = _step_scrub(ctx_miss, FlowStep(action="scrub", selector=".missing", timeout_ms=200))
            self.assertFalse(ok_miss)
            self.assertIn("Scrub target not visible", err_miss)

    def test_type_found_and_missing(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            from nightwalk.flows import _step_type

            cdp = Mock()
            cdp.evaluate.return_value = {"x": 2.0, "y": 3.0, "left": 0.0, "top": 0.0, "width": 100.0, "height": 10.0, "text": "in"}
            ctx = self._ctx(root, cdp)
            ok, detail, _ = _step_type(ctx, FlowStep(action="type", selector=".field", text="hello"))
            self.assertTrue(ok)
            cdp.insert_text.assert_called_once_with("hello")

            cdp_miss = Mock()
            cdp_miss.evaluate.return_value = None
            ctx_miss = self._ctx(root, cdp_miss)
            ok2, _, err = _step_type(ctx_miss, FlowStep(action="type", selector=".gone", timeout_ms=200))
            self.assertFalse(ok2)
            self.assertIn("Input not visible", err)

    def test_clear_input_with_and_without_selector(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            from nightwalk.flows import _step_clear_input

            cdp = Mock()
            cdp.evaluate.return_value = None
            ctx = self._ctx(root, cdp)
            ok, detail, _ = _step_clear_input(ctx, FlowStep(action="clear_input", selector=".field"))
            self.assertTrue(ok)
            self.assertIn("Cleared", detail)

            ok2, _, err = _step_clear_input(ctx, FlowStep(action="clear_input"))
            self.assertFalse(ok2)
            self.assertIn("requires 'selector'", err)

            ok3, _, _ = _step_clear_input(ctx, FlowStep(action="clear_input", selectors=[".field"]))
            self.assertTrue(ok3)

    def test_key_with_and_without_key(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            from nightwalk.flows import _step_key

            cdp = Mock()
            ctx = self._ctx(root, cdp)
            ok, detail, _ = _step_key(ctx, FlowStep(action="key", key="Enter", modifiers=["control"]))
            self.assertTrue(ok)
            cdp.dispatch_key.assert_called_once_with("Enter", modifiers=["control"])

            ok2, _, err = _step_key(ctx, FlowStep(action="key"))
            self.assertFalse(ok2)
            self.assertIn("requires 'key'", err)

    def test_assert_js_truthy_and_falsy_missing(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            from nightwalk.flows import _step_assert_js

            cdp = Mock()
            cdp.evaluate.return_value = True
            ctx = self._ctx(root, cdp)
            ok, _, _ = _step_assert_js(ctx, FlowStep(action="assert_js", expr="window.ready"))
            self.assertTrue(ok)

            cdp.evaluate.return_value = False
            ok2, _, err = _step_assert_js(ctx, FlowStep(action="assert_js", expr="window.ready"))
            self.assertFalse(ok2)
            self.assertIn("Assertion failed", err)

            ok3, _, err3 = _step_assert_js(ctx, FlowStep(action="assert_js"))
            self.assertFalse(ok3)
            self.assertIn("requires 'expr'", err3)

    def test_check_links_dedupes_broken_links(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            from nightwalk.flows import _step_check_links

            cdp = Mock()
            ctx = self._ctx(root, cdp)
            b1 = LinkCheckResult(url="http://127.0.0.1:8090/a", kind="link", status=404, ok=False, duration_ms=1.0)
            with patch("nightwalk.flows.check_same_origin_links", return_value=(2, [b1, b1])):
                ok, detail, _ = _step_check_links(ctx, FlowStep(action="check_links"))
            self.assertTrue(ok)
            self.assertEqual(ctx.links_checked, 2)
            self.assertEqual(len(ctx.broken_links), 1)
            self.assertIn("2 broken", detail)

    def test_check_layout_records_metrics(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            from nightwalk.flows import _step_check_layout

            cdp = Mock()
            ctx = self._ctx(root, cdp)
            metrics = {"horizontalOverflowPx": 8, "emojiNodes": [], "visibleTextLen": 12}
            with patch("nightwalk.flows.audit_dom_layout", return_value=metrics):
                ok, detail, _ = _step_check_layout(ctx, FlowStep(action="check_layout"))
            self.assertTrue(ok)
            self.assertEqual(ctx.layout_metrics, metrics)
            self.assertIn("overflow=8px", detail)

    def test_screenshot_step_captures_and_marks_vision(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            from nightwalk.flows import _step_screenshot

            cdp = Mock()
            cdp.capture_screenshot.return_value = b"png"
            ctx = self._ctx(root, cdp)
            ok, detail, extra = _step_screenshot(ctx, FlowStep(action="screenshot", tag="hero", vision=True))
            self.assertTrue(ok)
            self.assertEqual(extra, str(Path(extra)))
            self.assertTrue(Path(extra).is_file())
            self.assertEqual(ctx.vision_targets, [(Path(extra), "hero")])

    def test_sleep_step(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            from nightwalk.flows import _step_sleep

            cdp = Mock()
            ctx = self._ctx(root, cdp)
            ok, detail, _ = _step_sleep(ctx, FlowStep(action="sleep", ms=1))
            self.assertTrue(ok)
            self.assertIn("Settled", detail)


# --------------------------------------------------------------------------
# nightwalk.flows - run_flow
# --------------------------------------------------------------------------

class TestRunFlow(unittest.TestCase):
    def setUp(self) -> None:
        self._sleep_patch = patch("nightwalk.flows.time.sleep", lambda *a, **k: None)
        self._sleep_patch.start()
        self.addCleanup(self._sleep_patch.stop)
        self._tmp = tempfile.TemporaryDirectory()
        self.root = Path(self._tmp.name)
        self.addCleanup(self._tmp.cleanup)

    def _make_inputs(self, *, vision_enabled: bool = True) -> dict[str, Any]:
        cfg = _default_cfg(self.root, vlm_concurrency=1)
        target = TargetSpec(name="app", base_url="http://127.0.0.1:8090")
        viewport = ViewportSpec(name="fold-folded", width=374, height=844, mobile=True)
        cdp = Mock()
        cdp.snapshot_telemetry.return_value = ([], [])
        browser = Mock()
        browser.get_devtools.return_value = ([], [])
        flow = FlowSpec(name="home", steps=[FlowStep(action="goto", path="/")], vision_qa=True)
        return dict(cfg=cfg, target=target, flow=flow, viewport=viewport, cdp=cdp, browser=browser,
                    browser_id="bid-test", screenshots_dir=self.root / "shots",
                    auth_token="", vision_enabled=vision_enabled)

    def _run(self, inputs: dict[str, Any]) -> FlowRunResult:
        with patch("nightwalk.flows.inspect_screenshot", return_value=VisionAssessment(screenshot_path="", verdict="PASS")):
            return run_flow(**inputs)

    def test_viewport_skipped_step(self) -> None:
        inputs = self._make_inputs()
        inputs["flow"] = FlowSpec(
            name="home",
            steps=[
                FlowStep(action="goto", path="/", viewports=["desktop"]),
                FlowStep(action="goto", path="/home"),
            ],
            vision_qa=False,
        )
        result = self._run(inputs)
        self.assertEqual(result.steps[0].skipped, True)
        self.assertTrue(result.steps[0].ok)
        self.assertTrue(result.steps[1].ok)
        self.assertEqual(len(result.steps), 2)

    def test_unknown_action_continues_flow(self) -> None:
        inputs = self._make_inputs()
        inputs["flow"] = FlowSpec(
            name="home",
            steps=[FlowStep(action="bogus"), FlowStep(action="goto", path="/")],
            vision_qa=False,
        )
        result = self._run(inputs)
        self.assertFalse(result.steps[0].ok)
        self.assertIn("Unknown flow step action", result.steps[0].error)
        self.assertTrue(result.steps[1].ok)

    def test_optional_failing_step_continues_flow(self) -> None:
        self.addCleanup(self._restore_registry, dict(STEP_REGISTRY))

        @register_step("soft-fail")
        def _soft_fail(ctx, step):
            return (False, "", "soft boom")

        @register_step("soft-raise")
        def _soft_raise(ctx, step):
            raise RuntimeError("soft exception")

        @register_step("mark-after")
        def _mark_after(ctx, step):
            return (True, "after done", "")

        inputs = self._make_inputs()
        inputs["flow"] = FlowSpec(
            name="home",
            steps=[
                FlowStep(action="goto", path="/"),
                FlowStep(action="soft-fail", optional=True, label="optional step"),
                FlowStep(action="soft-raise", optional=True, label="optional raise"),
                FlowStep(action="mark-after", label="after step"),
            ],
            vision_qa=False,
        )
        result = self._run(inputs)
        self.assertEqual(len(result.steps), 4)
        self.assertTrue(result.steps[1].ok)
        self.assertTrue(result.steps[1].skipped)
        self.assertIn("Optional step skipped", result.steps[1].detail)
        self.assertTrue(result.steps[2].ok)
        self.assertTrue(result.steps[2].skipped)
        self.assertIn("Optional step error ignored", result.steps[2].detail)
        self.assertTrue(result.steps[3].ok)

    def test_non_goto_step_exception_records_error_and_continues(self) -> None:
        self.addCleanup(self._restore_registry, dict(STEP_REGISTRY))

        @register_step("hard-raise")
        def _hard_raise(ctx, step):
            raise RuntimeError("hard crash")

        @register_step("after-crash")
        def _after_crash(ctx, step):
            return (True, "continued", "")

        inputs = self._make_inputs()
        inputs["flow"] = FlowSpec(
            name="home",
            steps=[
                FlowStep(action="goto", path="/"),
                FlowStep(action="hard-raise", label="crasher"),
                FlowStep(action="after-crash", label="survivor"),
            ],
            vision_qa=False,
        )
        inputs["cdp"].capture_screenshot.return_value = b"png"
        result = self._run(inputs)
        self.assertEqual(len(result.steps), 3)
        self.assertFalse(result.steps[1].ok)
        self.assertIn("hard crash", result.steps[1].error)
        self.assertTrue(result.steps[1].screenshot_path)
        self.assertTrue(result.steps[2].ok)
        self.assertFalse(result.ok)

    def test_explicit_checks_skip_auto_checks_and_fallback_vision_target(self) -> None:
        inputs = self._make_inputs(vision_enabled=True)
        inputs["flow"] = FlowSpec(
            name="home",
            steps=[
                FlowStep(action="goto", path="/"),
                FlowStep(action="check_layout"),
                FlowStep(action="check_links"),
                FlowStep(action="screenshot", tag="snap", vision=False),
            ],
            check_layout=True,
            check_links=True,
            vision_qa=True,
        )
        inputs["cdp"].capture_screenshot.return_value = b"png"
        with patch("nightwalk.flows.audit_dom_layout", return_value={"horizontalOverflowPx": 0, "emojiNodes": []}) as layout_mock, \
             patch("nightwalk.flows.check_same_origin_links", return_value=(1, [])) as links_mock, \
             patch("nightwalk.flows.inspect_screenshot", return_value=VisionAssessment(screenshot_path="", verdict="PASS")) as vlm_mock:
            result = run_flow(**inputs)
        self.assertEqual(layout_mock.call_count, 1)
        self.assertEqual(links_mock.call_count, 1)
        self.assertEqual(vlm_mock.call_count, 1)
        self.assertEqual(len(result.vision), 1)

    def test_required_failing_step_breaks_remaining_steps(self) -> None:
        inputs = self._make_inputs()
        inputs["flow"] = FlowSpec(
            name="home",
            steps=[
                FlowStep(action="goto", path="/"),
                FlowStep(action="wait_for", selector=".gone", timeout_ms=200),
                FlowStep(action="screenshot", tag="late"),
            ],
            vision_qa=False,
        )
        inputs["cdp"].evaluate.return_value = None
        inputs["cdp"].capture_screenshot.return_value = b"png"
        result = self._run(inputs)
        self.assertEqual(len(result.steps), 2)
        fail = result.steps[1]
        self.assertFalse(fail.ok)
        self.assertTrue(fail.error)
        # Fail shot captured
        self.assertTrue(fail.screenshot_path)
        self.assertTrue(Path(fail.screenshot_path).is_file())
        # Defect produced
        self.assertTrue(any(d.category == "flow_error" for d in result.defects))

    def test_required_goto_raising_breaks_and_skips_auto_checks(self) -> None:
        inputs = self._make_inputs()
        inputs["flow"] = FlowSpec(
            name="home",
            steps=[FlowStep(action="goto", path="/")],
            check_layout=True,
            check_links=True,
            vision_qa=False,
        )
        inputs["cdp"].navigate.side_effect = RuntimeError("nav failed")
        inputs["cdp"].capture_screenshot.return_value = b"png"
        with patch("nightwalk.flows.audit_dom_layout") as layout_mock, \
             patch("nightwalk.flows.check_same_origin_links") as links_mock:
            result = self._run(inputs)
        self.assertEqual(len(result.steps), 1)
        self.assertFalse(result.steps[0].ok)
        layout_mock.assert_not_called()
        links_mock.assert_not_called()

    def test_automatic_final_checks_and_fallback_screenshot(self) -> None:
        inputs = self._make_inputs()
        inputs["flow"] = FlowSpec(
            name="home",
            steps=[FlowStep(action="goto", path="/")],
            check_layout=True,
            check_links=True,
            vision_qa=False,
        )
        inputs["cdp"].evaluate.return_value = None
        inputs["cdp"].capture_screenshot.return_value = b"png"
        with patch("nightwalk.flows.audit_dom_layout", return_value={"horizontalOverflowPx": 0, "emojiNodes": []}) as layout_mock, \
             patch("nightwalk.flows.check_same_origin_links", return_value=(2, [])) as links_mock:
            result = self._run(inputs)
        self.assertEqual(layout_mock.call_count, 1)
        self.assertEqual(links_mock.call_count, 1)
        self.assertEqual(result.links_checked, 2)
        self.assertEqual(result.layout_metrics, {"horizontalOverflowPx": 0, "emojiNodes": []})
        # Fallback final screenshot created
        self.assertEqual(len(result.screenshots), 1)
        self.assertTrue(result.screenshots[0].endswith("final.png") or result.screenshots[0].endswith("final.jpg"))

    def test_auth_cookie_set_when_configured(self) -> None:
        inputs = self._make_inputs()
        inputs["auth_token"] = "secret_token_value_123"
        inputs["target"] = TargetSpec(
            name="app",
            base_url="http://127.0.0.1:8090",
            auth_cookie_name="vega_token",
        )
        self._run(inputs)
        inputs["cdp"].set_cookie.assert_called_once_with(
            name="vega_token",
            value="secret_token_value_123",
            url="http://127.0.0.1:8090/",
            http_only=True,
            same_site="Lax",
        )

    def test_telemetry_merge_and_slow_endpoint_override(self) -> None:
        inputs = self._make_inputs()
        inputs["flow"] = FlowSpec(
            name="home",
            steps=[FlowStep(action="goto", path="/")],
            vision_qa=False,
        )
        inputs["target"] = TargetSpec(name="app", base_url="http://127.0.0.1:8090")
        inputs["cdp"].snapshot_telemetry.return_value = (
            [ConsoleRecord(level="error", source="console", text="boom", url="http://127.0.0.1:8090/app.js", line=1)],
            [NetworkRecord(method="GET", url="http://127.0.0.1:8090/api/slow", status=200, ok=True, duration_ms=420.0)],
        )
        inputs["browser"].get_devtools.return_value = (
            [ConsoleRecord(level="info", source="console", text="ignored")],
            [NetworkRecord(method="GET", url="http://127.0.0.1:8090/api/pool", status=200, ok=True, duration_ms=500.0)],
        )
        result = self._run(inputs)
        self.assertEqual(len(result.console_errors), 1)
        self.assertEqual(len(result.slow_endpoints), 2)

        # Override threshold via target.slow_endpoint_ms
        inputs["target"] = TargetSpec(name="app", base_url="http://127.0.0.1:8090", slow_endpoint_ms=600.0)
        result2 = self._run(inputs)
        self.assertEqual(result2.slow_endpoints, [])

    def test_single_and_multi_worker_vision_calls(self) -> None:
        for concurrency in (1, 2):
            inputs = self._make_inputs()
            inputs["cfg"] = _default_cfg(self.root, vlm_concurrency=concurrency)
            inputs["flow"] = FlowSpec(
                name="home",
                steps=[
                    FlowStep(action="screenshot", tag="a", vision=True),
                    FlowStep(action="screenshot", tag="b", vision=True),
                ],
                vision_qa=True,
            )
            inputs["cdp"].capture_screenshot.return_value = b"png"
            with patch("nightwalk.flows.inspect_screenshot") as vlm_mock:
                vlm_mock.side_effect = lambda *a, **k: VisionAssessment(screenshot_path=str(a[1]), verdict="PASS")
                result = run_flow(**inputs)
            self.assertEqual(vlm_mock.call_count, 2)
            self.assertEqual(len(result.vision), 2)

    def _restore_registry(self, snapshot: dict[str, Any]) -> None:
        for key in list(STEP_REGISTRY):
            if key not in snapshot:
                STEP_REGISTRY.pop(key, None)
        STEP_REGISTRY.update(snapshot)


# --------------------------------------------------------------------------
# nightwalk.pipeline
# --------------------------------------------------------------------------

class TestProbeTargetReachable(unittest.TestCase):
    def setUp(self) -> None:
        self.server = _start_loopback(_MuxHandler)
        self.base_url = f"http://127.0.0.1:{self.server.server_port}"
        self.addCleanup(_shutdown_loopback, self.server)

    def test_reachable_sends_cookie_and_authorization_headers(self) -> None:
        target = TargetSpec(name="app", base_url=self.base_url, auth_cookie_name="vega_token")
        with patch.dict(os.environ, {"TEST_TARGET_TOKEN": "placeholder_token_123456789"}):
            target.auth_token_env = "TEST_TARGET_TOKEN"
            ok, detail = _probe_target_reachable(target, "placeholder_token_123456789")
        self.assertTrue(ok)
        self.assertEqual(detail, "HTTP 200")
        headers = self.server.state["target_headers"]
        self.assertEqual(headers.get("cookie"), "vega_token=placeholder_token_123456789")
        self.assertEqual(headers.get("authorization"), "Bearer placeholder_token_123456789")

    def test_503_returns_false_with_http_status(self) -> None:
        self.server.state["target_status"] = 503
        target = TargetSpec(name="app", base_url=self.base_url)
        ok, detail = _probe_target_reachable(target, "")
        self.assertFalse(ok)
        self.assertIn("503", detail)

    def test_connection_failure_returns_redacted_error(self) -> None:
        target = TargetSpec(name="app", base_url=f"http://127.0.0.1:{_free_port()}")
        ok, detail = _probe_target_reachable(target, "")
        self.assertFalse(ok)
        self.assertTrue(detail)


class TestCheckEnvironment(unittest.TestCase):
    def setUp(self) -> None:
        self.server = _start_loopback(_MuxHandler)
        self.base_url = f"http://127.0.0.1:{self.server.server_port}"
        self.addCleanup(_shutdown_loopback, self.server)

    def _cfg(self, root: Path, **overrides: Any) -> NightwalkConfig:
        kwargs: dict[str, Any] = {
            "config_path": root / "config.json",
            "browser_url": self.base_url,
            "vlm_url": f"{self.base_url}/v1",
            "vlm_model": "mock-vlm",
            "vlm_api_key": "placeholder_vlm_key_123456789",
        }
        kwargs.update(overrides)
        cfg = NightwalkConfig(**kwargs)
        cfg.targets = [TargetSpec(name="app", base_url=self.base_url, auth_token_env="TEST_ENV_TOKEN")]
        return cfg

    def test_all_healthy(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            with patch.dict(os.environ, {"TEST_ENV_TOKEN": "placeholder_token_123456789"}):
                cfg = self._cfg(root)
                result = check_environment(cfg)
        self.assertTrue(result["ok"])
        self.assertTrue(result["browser_ok"])
        self.assertTrue(result["vlm_ok"])
        self.assertEqual(result["vlm_detail"], "HTTP 200 (mock-vlm)")
        self.assertEqual(result["vlm_model"], "mock-vlm")
        self.assertEqual(self.server.state["vlm_auth"], "Bearer placeholder_vlm_key_123456789")
        self.assertTrue(result["targets"][0]["reachable"])
        self.assertTrue(result["targets"][0]["auth_configured"])

    def test_browser_failure_and_down_target_flip_ok_false(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            self.server.state["health_status"] = 500
            cfg = self._cfg(root, vlm_url=f"http://127.0.0.1:{_free_port()}/v1")
            cfg.targets = [TargetSpec(name="down", base_url=f"http://127.0.0.1:{_free_port()}")]
            result = check_environment(cfg)
        self.assertFalse(result["ok"])
        self.assertFalse(result["browser_ok"])
        self.assertFalse(result["vlm_ok"])
        self.assertTrue(result["vlm_detail"])
        self.assertFalse(result["targets"][0]["reachable"])

    def test_unconfigured_vlm_reports_not_configured(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            cfg = self._cfg(root, vlm_url="", vlm_model="")
            with patch.dict(os.environ, {"TEST_ENV_TOKEN": "placeholder_token_123456789"}):
                result = check_environment(cfg)
        self.assertTrue(result["ok"])  # browser + targets healthy
        self.assertFalse(result["vlm_ok"])
        self.assertEqual(result["vlm_detail"], "not configured")


class TestRunDogfood(unittest.TestCase):
    def setUp(self) -> None:
        self.server = _start_loopback(_MuxHandler)
        self.base_url = f"http://127.0.0.1:{self.server.server_port}"
        self.addCleanup(_shutdown_loopback, self.server)

    def _cfg(self, root: Path, **overrides: Any) -> NightwalkConfig:
        pulse_state = root / "pulse.json"
        fake_pulse = root / "fake-pulse"
        _make_fake_pulse_script(fake_pulse, pulse_state)
        kwargs: dict[str, Any] = {
            "config_path": root / "config.json",
            "state_dir": root / "state",
            "report_dir": root / "reports",
            "panel_path": root / "panel.json",
            "loopback_only": True,
            "ticket_list_cmd": [str(fake_pulse), "list", "--all", "--json"],
            "ticket_add_cmd": [str(fake_pulse), "add"],
            "ticket_cooldown_hours": 72.0,
            "max_tickets_per_run": 5,
            "viewports": [
                ViewportSpec(name="mobile", width=374, height=844, mobile=True),
                ViewportSpec(name="desktop", width=1280, height=800, mobile=False),
            ],
            "targets": [
                TargetSpec(
                    name="app",
                    base_url=self.base_url,
                    flows=[
                        FlowSpec(
                            name="home",
                            steps=[FlowStep(action="goto", path="/")],
                        )
                    ],
                )
            ],
        }
        kwargs.update(overrides)
        return NightwalkConfig(**kwargs)

    def _make_result(self, target: str, flow: str, viewport: str, *, defect: Defect | None = None) -> FlowRunResult:
        return FlowRunResult(
            target=target,
            flow=flow,
            viewport=viewport,
            viewport_px="1280x800",
            ok=True,
            elapsed_ms=1.0,
            defects=[defect] if defect else [],
        )

    def test_rejects_non_loopback_target_when_loopback_only(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            cfg = self._cfg(root)
            cfg.targets = [TargetSpec(name="ext", base_url="https://example.com")]
            with patch("nightwalk.pipeline.VegaBrowserClient"), \
                 patch("nightwalk.pipeline.CDPClient"), \
                 patch("nightwalk.pipeline.run_flow"):
                with self.assertRaises(ValueError):
                    run_dogfood(cfg, dry_run=True)

    def test_unreachable_target_produces_single_critical_defect_without_browser(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            cfg = self._cfg(root)
            cfg.targets = [TargetSpec(name="down", base_url=f"http://127.0.0.1:{_free_port()}")]
            browser = MagicMock()
            with patch("nightwalk.pipeline.VegaBrowserClient", return_value=browser), \
                 patch("nightwalk.pipeline.CDPClient"), \
                 patch("nightwalk.pipeline.run_flow"):
                summary = run_dogfood(cfg, dry_run=True)
            self.assertEqual(len(summary.defects), 1)
            defect = summary.defects[0]
            self.assertEqual(defect.category, "service_down")
            self.assertEqual(defect.severity, "critical")
            browser.spawn_instance.assert_not_called()

    def test_full_orchestration_filters_isolated_instances_and_cleanup(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            cfg = self._cfg(root)
            cfg.targets = [
                TargetSpec(
                    name="app-a",
                    base_url=self.base_url,
                    flows=[FlowSpec(name="home", steps=[FlowStep(action="goto", path="/")], viewports=["mobile", "desktop"])],
                ),
                TargetSpec(
                    name="app-b",
                    base_url=self.base_url,
                    flows=[FlowSpec(name="home", steps=[FlowStep(action="goto", path="/")])],
                ),
            ]
            browser = MagicMock()
            browser.spawn_instance.side_effect = lambda **kwargs: BrowserInstanceHandle(
                browser_id=kwargs["browser_id"],
                cdp_url="http://127.0.0.1:9222",
                cdp_port=9222,
                engine="chromium",
            )
            cdp_instance = MagicMock()
            run_flow_mock = MagicMock(side_effect=lambda **kwargs: self._make_result(
                kwargs["target"].name, kwargs["flow"].name, kwargs["viewport"].name
            ))
            with patch("nightwalk.pipeline.VegaBrowserClient", return_value=browser), \
                 patch("nightwalk.pipeline.CDPClient", return_value=cdp_instance), \
                 patch("nightwalk.pipeline.run_flow", run_flow_mock):
                summary = run_dogfood(
                    cfg,
                    dry_run=True,
                    target_filter=["app-a", "app-b"],
                    viewport_filter=["mobile"],
                    flow_filter=["home"],
                )
            # Both targets run; 2 app-a viewport flows? No: app-a has 2 viewports but filtered to mobile only;
            # app-a home flow allows mobile+desktop, app-b home has no viewport filter.
            self.assertEqual(run_flow_mock.call_count, 2)
            self.assertEqual(browser.spawn_instance.call_count, 2)
            self.assertEqual(browser.delete_instance.call_count, 2)
            self.assertTrue(all(c[1].get("purge_profile") is True for c in browser.delete_instance.call_args_list))
            self.assertEqual({c[0][0] for c in browser.delete_instance.call_args_list}, {
                browser.spawn_instance.call_args_list[0][1]["browser_id"],
                browser.spawn_instance.call_args_list[1][1]["browser_id"],
            })
            self.assertEqual(cdp_instance.close.call_count, 2)
            self.assertTrue((Path(summary.artifacts_dir) / "summary.json").is_file())
            self.assertEqual(summary.flows_run, 2)
            self.assertEqual(summary.flow_results[0].target, "app-a")
            self.assertEqual(summary.flow_results[0].viewport, "mobile")
            self.assertEqual(summary.flow_results[1].target, "app-b")

    def test_flow_viewports_filter_and_target_filter(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            cfg = self._cfg(root)
            cfg.targets = [
                TargetSpec(
                    name="app",
                    base_url=self.base_url,
                    flows=[
                        FlowSpec(
                            name="home",
                            steps=[FlowStep(action="goto", path="/")],
                            viewports=["mobile"],
                        ),
                        FlowSpec(
                            name="other",
                            steps=[FlowStep(action="goto", path="/")],
                        ),
                    ],
                )
            ]
            browser = MagicMock()
            browser.spawn_instance.side_effect = lambda **kwargs: BrowserInstanceHandle(
                browser_id=kwargs["browser_id"],
                cdp_url="http://127.0.0.1:9222",
                cdp_port=9222,
                engine="chromium",
            )
            run_flow_mock = MagicMock(side_effect=lambda **kwargs: self._make_result(
                kwargs["target"].name, kwargs["flow"].name, kwargs["viewport"].name
            ))
            with patch("nightwalk.pipeline.VegaBrowserClient", return_value=browser), \
                 patch("nightwalk.pipeline.CDPClient", return_value=MagicMock()), \
                 patch("nightwalk.pipeline.run_flow", run_flow_mock):
                summary = run_dogfood(cfg, dry_run=True, viewport_filter=["desktop", "mobile"], flow_filter=["home"])
            # home flow only on mobile viewport
            self.assertEqual(run_flow_mock.call_count, 1)
            self.assertEqual(summary.flow_results[0].flow, "home")
            self.assertEqual(summary.flow_results[0].viewport, "mobile")

    def test_exception_recovery_creates_redacted_flow_error_and_reconnects(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            cfg = self._cfg(root)
            token = "placeholder_secret_value_12345"
            cfg.targets = [
                TargetSpec(
                    name="app",
                    base_url=self.base_url,
                    auth_token_file=str(root / "tokenfile"),
                    flows=[
                        FlowSpec(name="home", steps=[FlowStep(action="goto", path="/")]),
                    ],
                )
            ]
            (root / "tokenfile").write_text(token, encoding="utf-8")
            browser = MagicMock()
            browser.spawn_instance.side_effect = lambda **kwargs: BrowserInstanceHandle(
                browser_id=kwargs["browser_id"],
                cdp_url="http://127.0.0.1:9222",
                cdp_port=9222,
                engine="chromium",
            )
            cdp_instance = MagicMock()

            calls = {"n": 0}

            def _side_effect(**kwargs: Any) -> FlowRunResult:
                calls["n"] += 1
                if calls["n"] == 1:
                    raise RuntimeError(f"boom with token {token}")
                return self._make_result("app", "home", kwargs["viewport"].name)

            with patch("nightwalk.pipeline.VegaBrowserClient", return_value=browser), \
                 patch("nightwalk.pipeline.CDPClient", return_value=cdp_instance), \
                 patch("nightwalk.pipeline.run_flow", side_effect=_side_effect):
                summary = run_dogfood(cfg, dry_run=True, viewport_filter=["mobile", "desktop"])

            error_defects = [d for d in summary.defects if d.category == "flow_error"]
            self.assertEqual(len(error_defects), 1)
            self.assertNotIn(token, error_defects[0].summary)
            self.assertNotIn(token, error_defects[0].title)
            # CDP reconnect after error
            self.assertGreaterEqual(cdp_instance.connect.call_count, 2)
            self.assertEqual(summary.targets_run, 1)
            self.assertEqual(summary.flows_run, 2)

    def test_timeout_step_error_triggers_cdp_reconnect(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            cfg = self._cfg(root)
            browser = MagicMock()
            browser.spawn_instance.side_effect = lambda **kwargs: BrowserInstanceHandle(
                browser_id=kwargs["browser_id"],
                cdp_url="http://127.0.0.1:9222",
                cdp_port=9222,
                engine="chromium",
            )
            cdp_instance = MagicMock()

            def _result(**kwargs: Any) -> FlowRunResult:
                return FlowRunResult(
                    target="app",
                    flow="home",
                    viewport=kwargs["viewport"].name,
                    viewport_px="1280x800",
                    ok=True,
                    elapsed_ms=1.0,
                    steps=[StepOutcome(index=0, action="wait_for", label="w", ok=False, elapsed_ms=1.0, error="Timed out waiting for .gone")],
                )

            with patch("nightwalk.pipeline.VegaBrowserClient", return_value=browser), \
                 patch("nightwalk.pipeline.CDPClient", return_value=cdp_instance), \
                 patch("nightwalk.pipeline.run_flow", side_effect=_result):
                summary = run_dogfood(cfg, dry_run=True)
            # 2 viewports x 1 flow, each with a timed-out step: 1 initial connect + 2 reconnects, 2 timeout closes + 1 finally close
            self.assertEqual(summary.flows_run, 2)
            self.assertEqual(cdp_instance.connect.call_count, 3)
            self.assertEqual(cdp_instance.close.call_count, 3)

    def test_in_run_dedup_ticket_files_once_and_persists_run(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            cfg = self._cfg(root)
            defect = Defect(
                fingerprint="dedup_fp_test_abcd",
                target="app",
                target_repo="",
                flow="home",
                viewport="mobile (374x844)",
                category="slow_endpoint",
                severity="major",
                title="[app] Slow endpoint GET /api/x",
                summary="420ms",
            )
            browser = MagicMock()
            browser.spawn_instance.side_effect = lambda **kwargs: BrowserInstanceHandle(
                browser_id=kwargs["browser_id"],
                cdp_url="http://127.0.0.1:9222",
                cdp_port=9222,
                engine="chromium",
            )

            def _result(**kwargs: Any) -> FlowRunResult:
                return self._make_result("app", "home", kwargs["viewport"].name, defect=defect)

            with patch("nightwalk.pipeline.VegaBrowserClient", return_value=browser), \
                 patch("nightwalk.pipeline.CDPClient", return_value=MagicMock()), \
                 patch("nightwalk.pipeline.run_flow", side_effect=_result):
                summary = run_dogfood(cfg, dry_run=False)
            self.assertEqual(summary.unique_defects, 1)
            self.assertEqual(summary.total_defects, 2)
            self.assertEqual(summary.tickets_filed, 1)
            self.assertEqual(summary.ticket_actions[0].action, "filed")
            # SQLite run recorded
            store = StateStore(cfg.db_path)
            runs = store.list_runs(limit=1)
            self.assertEqual(len(runs), 1)
            self.assertEqual(runs[0]["run_id"], summary.run_id)
            # Report and panel written (not dry run)
            self.assertTrue(Path(summary.report_path).is_file())
            self.assertTrue(Path(summary.panel_path).is_file())
            self.assertTrue((Path(summary.artifacts_dir) / "summary.json").is_file())
            pulse_state = json.loads((root / "pulse.json").read_text())
            self.assertEqual(len(pulse_state), 1)

    def test_dry_run_skips_panel_and_tickets(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            cfg = self._cfg(root)
            defect = Defect(
                fingerprint="dryrun_fp_test_abcd",
                target="app",
                target_repo="",
                flow="home",
                viewport="desktop (1280x800)",
                category="console_error",
                severity="major",
                title="[app] Console error",
                summary="boom",
            )
            browser = MagicMock()
            browser.spawn_instance.side_effect = lambda **kwargs: BrowserInstanceHandle(
                browser_id=kwargs["browser_id"],
                cdp_url="http://127.0.0.1:9222",
                cdp_port=9222,
                engine="chromium",
            )

            def _result(**kwargs: Any) -> FlowRunResult:
                return self._make_result("app", "home", kwargs["viewport"].name, defect=defect)

            with patch("nightwalk.pipeline.VegaBrowserClient", return_value=browser), \
                 patch("nightwalk.pipeline.CDPClient", return_value=MagicMock()), \
                 patch("nightwalk.pipeline.run_flow", side_effect=_result):
                summary = run_dogfood(cfg, dry_run=True)
            self.assertEqual(summary.dry_run, True)
            self.assertEqual(summary.ticket_actions[0].action, "dry_run")
            self.assertEqual(summary.tickets_filed, 0)
            self.assertFalse(Path(summary.panel_path).is_file())
            self.assertTrue(Path(summary.report_path).is_file())

    def test_file_tickets_false_skips_ticket_filing(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            cfg = self._cfg(root)
            defect = Defect(
                fingerprint="no_tickets_fp_abcd",
                target="app",
                target_repo="",
                flow="home",
                viewport="desktop (1280x800)",
                category="console_error",
                severity="major",
                title="[app] Console error",
                summary="boom",
            )
            browser = MagicMock()
            browser.spawn_instance.side_effect = lambda **kwargs: BrowserInstanceHandle(
                browser_id=kwargs["browser_id"],
                cdp_url="http://127.0.0.1:9222",
                cdp_port=9222,
                engine="chromium",
            )

            def _result(**kwargs: Any) -> FlowRunResult:
                return self._make_result("app", "home", kwargs["viewport"].name, defect=defect)

            with patch("nightwalk.pipeline.VegaBrowserClient", return_value=browser), \
                 patch("nightwalk.pipeline.CDPClient", return_value=MagicMock()), \
                 patch("nightwalk.pipeline.run_flow", side_effect=_result):
                summary = run_dogfood(cfg, dry_run=False, file_tickets=False)
            self.assertFalse(summary.dry_run)
            self.assertEqual(summary.ticket_actions[0].action, "dry_run")
            self.assertEqual(summary.tickets_filed, 0)
            # Panel still written because dry_run is False
            self.assertTrue(Path(summary.panel_path).is_file())

    def test_sigterm_handler_restored_after_run(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            cfg = self._cfg(root)
            custom_handler = lambda signum, frame: None
            prev = signal.getsignal(signal.SIGTERM)
            signal.signal(signal.SIGTERM, custom_handler)
            self.addCleanup(lambda: signal.signal(signal.SIGTERM, prev))

            browser = MagicMock()
            browser.spawn_instance.side_effect = lambda **kwargs: BrowserInstanceHandle(
                browser_id=kwargs["browser_id"],
                cdp_url="http://127.0.0.1:9222",
                cdp_port=9222,
                engine="chromium",
            )
            with patch("nightwalk.pipeline.VegaBrowserClient", return_value=browser), \
                 patch("nightwalk.pipeline.CDPClient", return_value=MagicMock()), \
                 patch("nightwalk.pipeline.run_flow", side_effect=lambda **kw: self._make_result("app", "home", kw["viewport"].name)):
                run_dogfood(cfg, dry_run=True)
            self.assertIs(signal.getsignal(signal.SIGTERM), custom_handler)


# --------------------------------------------------------------------------
# nightwalk.cli
# --------------------------------------------------------------------------

def _cli_config(root: Path) -> Path:
    cfg = {
        "state_dir": str(root / "state"),
        "report_dir": str(root / "reports"),
        "panel_path": str(root / "panel.json"),
        "ticket_list_cmd": [],
        "ticket_add_cmd": [],
        "targets": [
            {
                "name": "app",
                "base_url": "http://127.0.0.1:8080",
                "flows": [{"name": "home", "steps": [{"action": "goto", "path": "/"}]}],
            }
        ],
    }
    path = root / "config.json"
    path.write_text(json.dumps(cfg), encoding="utf-8")
    return path


def _run_cli(argv: list[str]) -> tuple[int, str]:
    buf = io.StringIO()
    with contextlib.redirect_stdout(buf):
        code = main(argv)
    return code, buf.getvalue()


def _summary_for_cli(root: Path, **overrides: Any) -> RunSummary:
    kwargs: dict[str, Any] = {
        "run_id": "nw-test-0001",
        "started_at": "2026-01-01T00:00:00+00:00",
        "finished_at": "2026-01-01T00:00:05+00:00",
        "elapsed_ms": 1000.0,
        "dry_run": False,
        "engine": "chromium",
        "vision_enabled": False,
        "vision_model": "",
        "targets_run": 1,
        "flows_run": 1,
        "flows_passed": 1,
        "screenshots_captured": 1,
        "total_defects": 1,
        "unique_defects": 1,
        "tickets_filed": 0,
        "tickets_deduped": 0,
        "report_path": str(root / "reports" / "report.md"),
        "panel_path": str(root / "panel.json"),
        "artifacts_dir": str(root / "state" / "runs" / "nw-test-0001"),
    }
    kwargs.update(overrides)
    return RunSummary(**kwargs)


class TestParse(unittest.TestCase):
    def test_all_subcommands_and_repeatable_filters(self) -> None:
        p = _build_parser()
        args = p.parse_args(["init-config"])
        self.assertEqual(args.command, "init-config")
        args = p.parse_args(["check", "--json"])
        self.assertEqual(args.command, "check")
        self.assertTrue(args.json)
        args = p.parse_args(
            ["run", "--dry-run", "--no-vision", "--no-tickets", "--engine", "obscura",
             "--target", "app1", "--target", "app2", "--viewport", "mobile", "--flow", "home", "--json"]
        )
        self.assertEqual(args.command, "run")
        self.assertTrue(args.dry_run)
        self.assertTrue(args.no_vision)
        self.assertTrue(args.no_tickets)
        self.assertEqual(args.engine, "obscura")
        self.assertEqual(args.target, ["app1", "app2"])
        self.assertEqual(args.viewport, ["mobile"])
        self.assertEqual(args.flow, ["home"])
        args = p.parse_args(["status"])
        self.assertEqual(args.command, "status")
        args = p.parse_args(["history", "--limit", "5"])
        self.assertEqual(args.limit, 5)
        args = p.parse_args(["defects", "--limit", "3"])
        self.assertEqual(args.limit, 3)

    def test_engine_choices_enforced_and_subcommand_required(self) -> None:
        p = _build_parser()
        with contextlib.redirect_stderr(io.StringIO()):
            with self.assertRaises(SystemExit):
                p.parse_args(["run", "--engine", "bogus"])
            with self.assertRaises(SystemExit):
                p.parse_args([])


class TestMain(unittest.TestCase):
    def setUp(self) -> None:
        self._tmp = tempfile.TemporaryDirectory()
        self.root = Path(self._tmp.name)
        self.addCleanup(self._tmp.cleanup)

    def _config_path(self) -> Path:
        return _cli_config(self.root)

    def test_init_config_creates_0600_file(self) -> None:
        cfg_path = self.root / "config.json"
        code, out = _run_cli(["--config", str(cfg_path), "init-config"])
        self.assertEqual(code, 0)
        self.assertTrue(cfg_path.is_file())
        self.assertEqual(os.stat(cfg_path).st_mode & 0o777, 0o600)

    def test_check_text_and_json_ok_and_not_ok(self) -> None:
        cfg_path = self._config_path()
        healthy = {
            "ok": True,
            "config_path": str(cfg_path),
            "config_exists": True,
            "browser_url": "http://127.0.0.1:8490",
            "browser_ok": True,
            "vlm_model": "mock-vlm",
            "vlm_ok": True,
            "vlm_detail": "HTTP 200 (mock-vlm)",
            "targets": [
                {
                    "name": "app",
                    "base_url": "http://127.0.0.1:8080",
                    "reachable": True,
                    "detail": "HTTP 200",
                    "flows": 1,
                }
            ],
        }
        unhealthy = {**healthy, "ok": False, "browser_ok": False, "browser_detail": "boom"}
        with patch("nightwalk.cli.check_environment", return_value=healthy):
            code, out = _run_cli(["--config", str(cfg_path), "check"])
            self.assertEqual(code, 0)
            self.assertIn("Config:", out)
            self.assertIn("Browser:", out)
            self.assertIn("- app: http://127.0.0.1:8080 [OK]", out)
        with patch("nightwalk.cli.check_environment", return_value=healthy):
            code, out = _run_cli(["--config", str(cfg_path), "check", "--json"])
            self.assertEqual(code, 0)
            self.assertEqual(json.loads(out)["ok"], True)
        with patch("nightwalk.cli.check_environment", return_value=unhealthy):
            code, _ = _run_cli(["--config", str(cfg_path), "check"])
            self.assertEqual(code, 1)

    def test_run_forwards_filters_and_prints_summary(self) -> None:
        cfg_path = self._config_path()
        captured: dict[str, Any] = {}

        def _stub(cfg: Any, **kwargs: Any) -> RunSummary:
            captured["cfg"] = cfg
            captured.update(kwargs)
            summary = _summary_for_cli(self.root)
            summary.defects = [
                Defect(
                    fingerprint="fp-cli-1",
                    target="app",
                    target_repo="",
                    flow="home",
                    viewport="mobile (374x844)",
                    category="console_error",
                    severity="critical",
                    title="[app] Console error",
                    summary="boom",
                )
            ]
            summary.total_defects = 1
            summary.unique_defects = 1
            return summary

        with patch("nightwalk.cli.run_dogfood", side_effect=_stub):
            code, out = _run_cli([
                "--config", str(cfg_path), "run",
                "--dry-run", "--no-vision", "--no-tickets",
                "--engine", "obscura",
                "--target", "app-one", "--viewport", "mobile", "--flow", "home",
            ])
        self.assertEqual(code, 0)
        self.assertTrue(captured["dry_run"])
        self.assertFalse(captured["vision_enabled"])
        self.assertFalse(captured["file_tickets"])
        self.assertEqual(captured["target_filter"], ["app-one"])
        self.assertEqual(captured["viewport_filter"], ["mobile"])
        self.assertEqual(captured["flow_filter"], ["home"])
        self.assertEqual(captured["cfg"].browser_engine, "obscura")
        self.assertIn("Nightwalk nw-test-0001", out)
        self.assertIn("Report:", out)
        self.assertIn("[CRITICAL]", out)

    def test_run_json_output_is_parsable(self) -> None:
        cfg_path = self._config_path()

        def _stub(cfg: Any, **kwargs: Any) -> RunSummary:
            return _summary_for_cli(self.root)

        with patch("nightwalk.cli.run_dogfood", side_effect=_stub):
            code, out = _run_cli(["--config", str(cfg_path), "run", "--json"])
        self.assertEqual(code, 0)
        payload = json.loads(out)
        self.assertEqual(payload["run_id"], "nw-test-0001")

    def test_status_empty_and_populated_text_and_json(self) -> None:
        cfg_path = self._config_path()
        code, out = _run_cli(["--config", str(cfg_path), "status"])
        self.assertEqual(code, 0)
        self.assertIn("No nightwalk runs recorded yet.", out)
        code, out = _run_cli(["--config", str(cfg_path), "status", "--json"])
        self.assertEqual(code, 0)
        self.assertIsNone(json.loads(out))

        store = StateStore(self.root / "state" / "state.db")
        store.record_run(_summary_for_cli(self.root))

        code, out = _run_cli(["--config", str(cfg_path), "status"])
        self.assertEqual(code, 0)
        self.assertIn("Latest run nw-test-0001", out)
        self.assertIn("Report:", out)
        code, out = _run_cli(["--config", str(cfg_path), "status", "--json"])
        self.assertEqual(code, 0)
        self.assertEqual(json.loads(out)["run_id"], "nw-test-0001")

    def test_history_limit_text_and_json(self) -> None:
        cfg_path = self._config_path()
        store = StateStore(self.root / "state" / "state.db")
        for i, started in enumerate(("2026-01-01T00:00:00+00:00", "2026-01-02T00:00:00+00:00", "2026-01-03T00:00:00+00:00")):
            store.record_run(_summary_for_cli(self.root, run_id=f"nw-run-{i}", started_at=started))

        code, out = _run_cli(["--config", str(cfg_path), "history", "--limit", "2"])
        self.assertEqual(code, 0)
        self.assertIn("nw-run-2", out)
        self.assertIn("nw-run-1", out)
        self.assertNotIn("nw-run-0", out)

        code, out = _run_cli(["--config", str(cfg_path), "history", "--limit", "2", "--json"])
        self.assertEqual(code, 0)
        rows = json.loads(out)
        self.assertEqual(len(rows), 2)
        self.assertEqual(rows[0]["run_id"], "nw-run-2")

    def test_defects_limit_with_and_without_pulse_task_id(self) -> None:
        cfg_path = self._config_path()
        store = StateStore(self.root / "state" / "state.db")
        d1 = Defect(
            fingerprint="cli_fp_aaa", target="app", target_repo="", flow="home",
            viewport="mobile", category="console_error", severity="major",
            title="[app] error one", summary="s1",
        )
        d2 = Defect(
            fingerprint="cli_fp_bbb", target="app", target_repo="", flow="home",
            viewport="mobile", category="slow_endpoint", severity="critical",
            title="[app] error two", summary="s2",
        )
        store.record_defect_seen(d1)
        store.record_defect_seen(d2)
        store.mark_defect_filed("cli_fp_aaa", 42)

        code, out = _run_cli(["--config", str(cfg_path), "defects", "--limit", "5"])
        self.assertEqual(code, 0)
        self.assertIn("cli_fp_aaa", out)
        self.assertIn("#42", out)
        self.assertIn("cli_fp_bbb", out)
        self.assertIn("--", out)

        code, out = _run_cli(["--config", str(cfg_path), "defects", "--limit", "1", "--json"])
        self.assertEqual(code, 0)
        rows = json.loads(out)
        self.assertEqual(len(rows), 1)
        self.assertEqual(rows[0]["fingerprint"], "cli_fp_bbb")


if __name__ == "__main__":
    unittest.main()
