"""Unit tests for VLM vision inspection helpers and typed data models."""

from __future__ import annotations

import base64
import io
import json
import tempfile
import unittest
import urllib.request
from pathlib import Path
from unittest import mock

import nightwalk.vision as vision_module
from nightwalk.config import NightwalkConfig
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
    TicketAction,
    ViewportSpec,
    VisionAssessment,
    VisionIssue,
)
from nightwalk.vision import _encode_image_for_vlm, _strip_json_fences, inspect_screenshot

try:
    from PIL import Image
    HAS_PIL = True
except Exception:
    Image = None
    HAS_PIL = False


def _make_cfg(**overrides) -> NightwalkConfig:
    args = dict(
        config_path=Path("/tmp/fake-config.json"),
        vlm_url="http://127.0.0.1:9010/v1",
        vlm_model="test-vlm-mini",
        vlm_api_key="",
        vlm_reasoning_effort="",
        vlm_timeout_sec=5.0,
        vlm_max_tokens=64,
    )
    args.update(overrides)
    return NightwalkConfig(**args)


def _vlm_response(payload: dict) -> mock.Mock:
    body = {"choices": [{"message": {"content": json.dumps(payload)}}]}

    class _Resp:
        def read(self) -> bytes:
            return json.dumps(body).encode("utf-8")

        def __enter__(self):
            return self

        def __exit__(self, *args):
            return False

    return _Resp()


def _parse_request(request: urllib.request.Request) -> dict:
    return json.loads(request.data.decode("utf-8"))


class TestStripJsonFences(unittest.TestCase):
    def test_raw_json(self) -> None:
        self.assertEqual(_strip_json_fences('{"a": 1}'), '{"a": 1}')

    def test_json_fenced(self) -> None:
        raw = '```json\n{"a": 1}\n```'
        self.assertEqual(_strip_json_fences(raw), '{"a": 1}')

    def test_bare_fenced(self) -> None:
        raw = '```\n{"a": 1}\n```'
        self.assertEqual(_strip_json_fences(raw), '{"a": 1}')

    def test_prose_wrapping(self) -> None:
        raw = 'Here is the JSON: {"a": 1} hope this helps'
        self.assertEqual(_strip_json_fences(raw), '{"a": 1}')

    def test_empty_string(self) -> None:
        self.assertEqual(_strip_json_fences(""), "")

    def test_plain_text_no_braces(self) -> None:
        self.assertEqual(_strip_json_fences("no braces here"), "no braces here")

    def test_unclosed_and_inline_fences(self) -> None:
        self.assertEqual(_strip_json_fences('```json\n{"a": 1}'), '{"a": 1}')
        self.assertEqual(_strip_json_fences('```{"a": 2}```'), '{"a": 2}')


class TestEncodeImageForVlm(unittest.TestCase):
    def setUp(self) -> None:
        self._tmp = tempfile.TemporaryDirectory()
        self.root = Path(self._tmp.name)

    def tearDown(self) -> None:
        self._tmp.cleanup()

    def _png_bytes(self, size: tuple[int, int] = (64, 64), color=(200, 30, 30)) -> bytes:
        img = Image.new("RGB", size, color)
        buf = io.BytesIO()
        img.save(buf, format="PNG")
        return buf.getvalue()

    def _jpeg_bytes(self, size: tuple[int, int] = (64, 64)) -> bytes:
        img = Image.new("RGB", size, (30, 30, 200))
        buf = io.BytesIO()
        img.save(buf, format="JPEG")
        return buf.getvalue()

    def test_small_png_keeps_mime_and_bytes(self) -> None:
        if not HAS_PIL:
            self.skipTest("PIL unavailable")
        src = self.root / "small.png"
        raw = self._png_bytes()
        src.write_bytes(raw)
        mime, b64 = _encode_image_for_vlm(src)
        self.assertEqual(mime, "image/png")
        self.assertEqual(base64.b64decode(b64), raw)

    def test_small_jpeg_keeps_mime_and_bytes(self) -> None:
        if not HAS_PIL:
            self.skipTest("PIL unavailable")
        src = self.root / "small.jpg"
        raw = self._jpeg_bytes()
        src.write_bytes(raw)
        mime, b64 = _encode_image_for_vlm(src)
        self.assertEqual(mime, "image/jpeg")
        self.assertEqual(base64.b64decode(b64), raw)

    def test_high_res_image_is_resized_and_reencoded(self) -> None:
        if not HAS_PIL:
            self.skipTest("PIL unavailable")
        src = self.root / "big.png"
        img = Image.new("RGB", (2200, 1600), (10, 120, 60))
        buf = io.BytesIO()
        img.save(buf, format="PNG")
        src.write_bytes(buf.getvalue())
        mime, b64 = _encode_image_for_vlm(src, max_dim=1000)
        self.assertEqual(mime, "image/jpeg")
        decoded = base64.b64decode(b64)
        with Image.open(io.BytesIO(decoded)) as out:
            self.assertEqual(out.format, "JPEG")
            self.assertLessEqual(max(out.size), 1000)
            self.assertEqual(out.size[0], 1000)
            self.assertEqual(out.size[1], 727)

    def test_large_byte_small_dimension_png_reencoded(self) -> None:
        if not HAS_PIL:
            self.skipTest("PIL unavailable")
        src = self.root / "noisy.png"
        img = Image.effect_noise((400, 400), 80).convert("RGB")
        buf = io.BytesIO()
        img.save(buf, format="PNG")
        raw = buf.getvalue()
        if len(raw) <= 220_000:
            img2 = Image.effect_noise((600, 600), 80).convert("RGB")
            buf = io.BytesIO()
            img2.save(buf, format="PNG")
            raw = buf.getvalue()
        self.assertGreater(len(raw), 220_000)
        src.write_bytes(raw)
        mime, b64 = _encode_image_for_vlm(src, max_dim=1024)
        self.assertEqual(mime, "image/jpeg")
        decoded = base64.b64decode(b64)
        with Image.open(io.BytesIO(decoded)) as out:
            self.assertEqual(out.format, "JPEG")

    def test_corrupt_image_falls_back(self) -> None:
        src = self.root / "corrupt.png"
        src.write_bytes(b"this is definitely not a png")
        mime, b64 = _encode_image_for_vlm(src)
        self.assertEqual(mime, "image/png")
        self.assertEqual(base64.b64decode(b64), b"this is definitely not a png")

    def test_pil_none_falls_back(self) -> None:
        src = self.root / "x.png"
        src.write_bytes(b"raw-bytes")
        with mock.patch.object(vision_module, "Image", None):
            mime, b64 = _encode_image_for_vlm(src)
        self.assertEqual(mime, "image/png")
        self.assertEqual(base64.b64decode(b64), b"raw-bytes")


class TestInspectScreenshot(unittest.TestCase):
    def setUp(self) -> None:
        self._tmp = tempfile.TemporaryDirectory()
        self.root = Path(self._tmp.name)
        self.shot = self.root / "shot.png"
        if HAS_PIL:
            img = Image.new("RGB", (32, 32), (90, 20, 20))
            img.save(self.shot, format="PNG")
        else:
            self.shot.write_bytes(b"not-a-real-png")

    def tearDown(self) -> None:
        self._tmp.cleanup()

    def test_skip_when_vlm_not_configured(self) -> None:
        cfg = _make_cfg(vlm_url="", vlm_model="")
        result = inspect_screenshot(
            cfg, self.shot, target_name="t", flow_name="f", viewport=_viewport()
        )
        self.assertEqual(result.verdict, "SKIP")
        self.assertIn("no VLM endpoint", result.summary)

    def test_skip_when_screenshot_missing(self) -> None:
        cfg = _make_cfg()
        result = inspect_screenshot(
            cfg,
            self.root / "nope.png",
            target_name="t",
            flow_name="f",
            viewport=_viewport(),
        )
        self.assertEqual(result.verdict, "SKIP")
        self.assertIn("Screenshot file missing", result.error)

    def test_url_appends_chat_completions_once(self) -> None:
        cfg = _make_cfg(vlm_url="http://127.0.0.1:9010/v1")
        with mock.patch.object(urllib.request, "urlopen", return_value=_vlm_response({"verdict": "PASS", "score_10": 9, "summary": "ok", "issues": []})) as m:
            inspect_screenshot(cfg, self.shot, target_name="t", flow_name="f", viewport=_viewport())
        req = m.call_args[0][0]
        self.assertEqual(req.full_url, "http://127.0.0.1:9010/v1/chat/completions")

        cfg2 = _make_cfg(vlm_url="http://127.0.0.1:9010/v1/chat/completions")
        with mock.patch.object(urllib.request, "urlopen", return_value=_vlm_response({"verdict": "PASS", "score_10": 9, "summary": "ok", "issues": []})) as m2:
            inspect_screenshot(cfg2, self.shot, target_name="t", flow_name="f", viewport=_viewport())
        self.assertEqual(m2.call_args[0][0].full_url, "http://127.0.0.1:9010/v1/chat/completions")

    def test_authorization_header_only_when_key_set(self) -> None:
        cfg_no_key = _make_cfg(vlm_api_key="")
        with mock.patch.object(urllib.request, "urlopen", return_value=_vlm_response({"verdict": "PASS", "score_10": 9, "summary": "ok", "issues": []})) as m:
            inspect_screenshot(cfg_no_key, self.shot, target_name="t", flow_name="f", viewport=_viewport())
        self.assertIsNone(m.call_args[0][0].get_header("Authorization"))

        cfg_with_key = _make_cfg(vlm_api_key="test-placeholder-key-123")
        with mock.patch.object(urllib.request, "urlopen", return_value=_vlm_response({"verdict": "PASS", "score_10": 9, "summary": "ok", "issues": []})) as m:
            inspect_screenshot(cfg_with_key, self.shot, target_name="t", flow_name="f", viewport=_viewport())
        self.assertEqual(
            m.call_args[0][0].get_header("Authorization"),
            "Bearer test-placeholder-key-123",
        )

    def test_reasoning_effort_only_when_configured(self) -> None:
        cfg_unset = _make_cfg(vlm_reasoning_effort="")
        with mock.patch.object(urllib.request, "urlopen", return_value=_vlm_response({"verdict": "PASS", "score_10": 9, "summary": "ok", "issues": []})) as m:
            inspect_screenshot(cfg_unset, self.shot, target_name="t", flow_name="f", viewport=_viewport())
        payload = _parse_request(m.call_args[0][0])
        self.assertNotIn("reasoning_effort", payload)

        cfg_set = _make_cfg(vlm_reasoning_effort="low")
        with mock.patch.object(urllib.request, "urlopen", return_value=_vlm_response({"verdict": "PASS", "score_10": 9, "summary": "ok", "issues": []})) as m:
            inspect_screenshot(cfg_set, self.shot, target_name="t", flow_name="f", viewport=_viewport())
        payload = _parse_request(m.call_args[0][0])
        self.assertEqual(payload["reasoning_effort"], "low")

    def test_parses_fenced_json_and_normalizes(self) -> None:
        raw = '```json\n{"verdict":"WARN","score_10":7,"summary":"ok","issues":[{"severity":"bogus","category":"overlap","element":"header","description":"text overlaps","suggested_fix":"add margin"}]}\n```'
        body = {"choices": [{"message": {"content": raw}}]}

        class _Resp:
            def read(self):
                return json.dumps(body).encode("utf-8")

            def __enter__(self):
                return self

            def __exit__(self, *a):
                return False

        cfg = _make_cfg()
        with mock.patch.object(urllib.request, "urlopen", return_value=_Resp()):
            result = inspect_screenshot(cfg, self.shot, target_name="t", flow_name="f", viewport=_viewport())

        self.assertEqual(result.verdict, "WARN")
        self.assertEqual(result.score_10, 7.0)
        self.assertEqual(len(result.issues), 1)
        self.assertEqual(result.issues[0].severity, "minor")  # invalid sev normalized
        self.assertEqual(result.issues[0].category, "overlap")

    def test_skips_non_dict_and_incomplete_issues(self) -> None:
        payload = {
            "verdict": "PASS",
            "score_10": 9,
            "summary": "ok",
            "issues": [
                "not-a-dict",
                {"severity": "major"},
                {"severity": "major", "element": "", "description": "only desc"},
                {"severity": "major", "element": "button", "description": "real issue"},
            ],
        }
        cfg = _make_cfg()
        with mock.patch.object(urllib.request, "urlopen", return_value=_vlm_response(payload)):
            result = inspect_screenshot(cfg, self.shot, target_name="t", flow_name="f", viewport=_viewport())
        self.assertEqual(len(result.issues), 1)
        self.assertEqual(result.issues[0].element, "button")

    def test_redacts_secrets_in_summary_and_issues(self) -> None:
        payload = {
            "verdict": "PASS",
            "score_10": 8,
            "summary": "Error with token=supersecret12345 occurred",
            "issues": [
                {"severity": "major", "category": "clip", "element": "token=abcdef123", "description": "Bearer abcdef1234567890xyz clipped", "suggested_fix": "widen"}
            ],
        }
        cfg = _make_cfg()
        with mock.patch.object(urllib.request, "urlopen", return_value=_vlm_response(payload)):
            result = inspect_screenshot(cfg, self.shot, target_name="t", flow_name="f", viewport=_viewport())
        self.assertNotIn("supersecret12345", result.summary)
        self.assertIn("REDACTED", result.summary)
        self.assertNotIn("abcdef123", result.issues[0].element)
        self.assertNotIn("abcdef1234567890xyz", result.issues[0].description)

    def test_non_numeric_score_10_becomes_none(self) -> None:
        payload = {"verdict": "PASS", "score_10": "not-a-number", "summary": "ok", "issues": []}
        cfg = _make_cfg()
        with mock.patch.object(urllib.request, "urlopen", return_value=_vlm_response(payload)):
            result = inspect_screenshot(cfg, self.shot, target_name="t", flow_name="f", viewport=_viewport())
        self.assertIsNone(result.score_10)

    def test_invalid_verdict_normalized_by_issues(self) -> None:
        payload_with_critical = {"verdict": "WEIRD", "score_10": 5, "summary": "ok", "issues": [{"severity": "critical", "category": "blank", "element": "canvas", "description": "blank screen"}]}
        cfg = _make_cfg()
        with mock.patch.object(urllib.request, "urlopen", return_value=_vlm_response(payload_with_critical)):
            result = inspect_screenshot(cfg, self.shot, target_name="t", flow_name="f", viewport=_viewport())
        self.assertEqual(result.verdict, "FAIL")

        payload_only_minor = {"verdict": "WEIRD", "score_10": 5, "summary": "ok", "issues": [{"severity": "minor", "category": "clip", "element": "link", "description": "tiny clip"}]}
        with mock.patch.object(urllib.request, "urlopen", return_value=_vlm_response(payload_only_minor)):
            result = inspect_screenshot(cfg, self.shot, target_name="t", flow_name="f", viewport=_viewport())
        self.assertEqual(result.verdict, "PASS")

    def test_urlopen_exception_returns_skip_with_redacted_error(self) -> None:
        cfg = _make_cfg()
        with mock.patch.object(
            urllib.request,
            "urlopen",
            side_effect=RuntimeError("boom token=supersecret12345"),
        ):
            result = inspect_screenshot(cfg, self.shot, target_name="t", flow_name="f", viewport=_viewport())
        self.assertEqual(result.verdict, "SKIP")
        self.assertIn("VLM request failed", result.error)
        self.assertNotIn("supersecret12345", result.error)

    def test_malformed_json_and_non_dict_json_return_skip(self) -> None:
        class _BadResp:
            def read(self):
                return b"not json at all"

            def __enter__(self):
                return self

            def __exit__(self, *a):
                return False

        cfg = _make_cfg()
        with mock.patch.object(urllib.request, "urlopen", return_value=_BadResp()):
            result = inspect_screenshot(cfg, self.shot, target_name="t", flow_name="f", viewport=_viewport())
        self.assertEqual(result.verdict, "SKIP")
        self.assertIn("VLM request failed", result.error)

        body = {"choices": [{"message": {"content": "[1, 2]"}}]}

        class _ListResp:
            def read(self):
                return json.dumps(body).encode("utf-8")

            def __enter__(self):
                return self

            def __exit__(self, *a):
                return False

        with mock.patch.object(urllib.request, "urlopen", return_value=_ListResp()):
            result = inspect_screenshot(cfg, self.shot, target_name="t", flow_name="f", viewport=_viewport())
        self.assertEqual(result.verdict, "SKIP")
        self.assertIn("Unparseable VLM JSON", result.error)

    def test_empty_choices_returns_skip(self) -> None:
        class _EmptyChoicesResp:
            def read(self):
                return json.dumps({"choices": []}).encode("utf-8")

            def __enter__(self):
                return self

            def __exit__(self, *a):
                return False

        cfg = _make_cfg()
        with mock.patch.object(urllib.request, "urlopen", return_value=_EmptyChoicesResp()):
            result = inspect_screenshot(cfg, self.shot, target_name="t", flow_name="f", viewport=_viewport())
        self.assertEqual(result.verdict, "SKIP")
        self.assertIn("Unparseable VLM JSON", result.error)


def _viewport() -> ViewportSpec:
    return ViewportSpec(name="fold-folded", width=374, height=844, mobile=True)


class TestViewportSpec(unittest.TestCase):
    def test_label_and_to_dict(self) -> None:
        v = ViewportSpec(name="desktop", width=1280, height=800, mobile=False, device_scale_factor=2.0)
        self.assertEqual(v.label, "1280x800")
        self.assertEqual(
            v.to_dict(),
            {"name": "desktop", "width": 1280, "height": 800, "mobile": False, "device_scale_factor": 2.0},
        )

    def test_from_dict_defaults_mobile_inferred_and_dsf(self) -> None:
        mobile_small = ViewportSpec.from_dict({"width": 374, "height": 844})
        self.assertEqual(mobile_small.name, "374x844")
        self.assertTrue(mobile_small.mobile)
        self.assertEqual(mobile_small.device_scale_factor, 1.0)

        desktop_big = ViewportSpec.from_dict({"width": 1280, "height": 800})
        self.assertFalse(desktop_big.mobile)

        explicit = ViewportSpec.from_dict({"name": "fold-folded", "width": 374, "height": 844, "mobile": False, "device_scale_factor": 2.5})
        self.assertEqual(explicit.name, "fold-folded")
        self.assertFalse(explicit.mobile)
        self.assertEqual(explicit.device_scale_factor, 2.5)

    def test_from_dict_rejects_non_positive_dimensions(self) -> None:
        with self.assertRaises(ValueError):
            ViewportSpec.from_dict({"width": 0, "height": 844})
        with self.assertRaises(ValueError):
            ViewportSpec.from_dict({"width": 374, "height": -1})


class TestFlowStepFromDict(unittest.TestCase):
    def test_action_lowercasing_and_stripping(self) -> None:
        step = FlowStep.from_dict({"action": "  CLICK  "})
        self.assertEqual(step.action, "click")

    def test_blank_filters_and_step_clamp(self) -> None:
        step = FlowStep.from_dict({
            "action": "hover",
            "selectors": ["", "  ", "#a"],
            "modifiers": ["", "SHIFT"],
            "viewports": ["", "desktop"],
            "steps": 1,
        })
        self.assertEqual(step.selectors, ["#a"])
        self.assertEqual(step.modifiers, ["shift"])
        self.assertEqual(step.viewports, ["desktop"])
        self.assertEqual(step.steps, 2)

    def test_empty_action_raises(self) -> None:
        with self.assertRaises(ValueError):
            FlowStep.from_dict({"action": "   "})


class TestFlowSpecFromDict(unittest.TestCase):
    def test_valid_parsing(self) -> None:
        flow = FlowSpec.from_dict({
            "name": "signup",
            "description": "sign up",
            "steps": [{"action": "click", "label": "go"}],
            "viewports": ["desktop", "  "],
            "check_links": False,
        })
        self.assertEqual(flow.name, "signup")
        self.assertEqual(flow.description, "sign up")
        self.assertEqual(len(flow.steps), 1)
        self.assertEqual(flow.steps[0].action, "click")
        self.assertEqual(flow.viewports, ["desktop"])
        self.assertFalse(flow.check_links)
        self.assertTrue(flow.check_layout)
        self.assertTrue(flow.vision_qa)

    def test_empty_name_raises(self) -> None:
        with self.assertRaises(ValueError):
            FlowSpec.from_dict({"name": "  ", "steps": [{"action": "click"}]})

    def test_empty_or_non_list_steps_raise(self) -> None:
        with self.assertRaises(ValueError):
            FlowSpec.from_dict({"name": "f", "steps": []})
        with self.assertRaises(ValueError):
            FlowSpec.from_dict({"name": "f", "steps": "not-a-list"})


class TestTargetSpecFromDict(unittest.TestCase):
    def test_strips_trailing_slash_and_float_ms(self) -> None:
        target = TargetSpec.from_dict({
            "name": "local-app",
            "base_url": "http://127.0.0.1:8080/",
            "slow_endpoint_ms": "450",
            "ignore_slow_patterns": ["", " /health"],
            "flows": [],
        })
        self.assertEqual(target.base_url, "http://127.0.0.1:8080")
        self.assertEqual(target.slow_endpoint_ms, 450.0)
        self.assertEqual(target.ignore_slow_patterns, [" /health"])

    def test_none_slow_endpoint_and_blank_filtered(self) -> None:
        target = TargetSpec.from_dict({
            "name": "local-app",
            "base_url": "http://127.0.0.1:8080",
            "slow_endpoint_ms": None,
            "ignore_console_patterns": ["", "  ", "favicon"],
            "ignore_network_patterns": ["  ", "/api/telemetry"],
        })
        self.assertIsNone(target.slow_endpoint_ms)
        self.assertEqual(target.ignore_console_patterns, ["favicon"])
        self.assertEqual(target.ignore_network_patterns, ["/api/telemetry"])

    def test_missing_name_or_base_url_raises(self) -> None:
        with self.assertRaises(ValueError):
            TargetSpec.from_dict({"name": "", "base_url": "http://127.0.0.1:8080"})
        with self.assertRaises(ValueError):
            TargetSpec.from_dict({"name": "x", "base_url": "  "})


class TestToDict(unittest.TestCase):
    def test_network_record(self) -> None:
        r = NetworkRecord(method="GET", url="http://127.0.0.1/a", status=200, ok=True, duration_ms=12.3)
        self.assertEqual(r.to_dict()["duration_ms"], 12.3)

    def test_console_record(self) -> None:
        r = ConsoleRecord(level="error", source="js", text="boom", url="http://127.0.0.1/a", line=42)
        self.assertEqual(
            r.to_dict(),
            {"level": "error", "source": "js", "text": "boom", "url": "http://127.0.0.1/a", "line": 42},
        )

    def test_link_check_result_rounds_duration(self) -> None:
        r = LinkCheckResult(url="http://127.0.0.1/a", kind="link", status=200, ok=True, duration_ms=12.34, error="")
        self.assertEqual(r.to_dict()["duration_ms"], 12.3)

    def test_vision_issue(self) -> None:
        i = VisionIssue(severity="major", category="clip", element="btn", description="clipped", suggested_fix="widen")
        self.assertEqual(
            i.to_dict(),
            {"severity": "major", "category": "clip", "element": "btn", "description": "clipped", "suggested_fix": "widen"},
        )

    def test_vision_assessment_rounds_elapsed_and_nests_issues(self) -> None:
        v = VisionAssessment(
            screenshot_path="/tmp/shot.png",
            verdict="WARN",
            score_10=7.0,
            elapsed_ms=123.456,
            model="test-vlm",
            summary="meh",
            issues=[VisionIssue(severity="minor", category="clip", element="a", description="b")],
            error="",
        )
        d = v.to_dict()
        self.assertEqual(d["elapsed_ms"], 123.5)
        self.assertEqual(d["score_10"], 7.0)
        self.assertEqual(len(d["issues"]), 1)
        self.assertEqual(d["issues"][0]["element"], "a")

    def test_step_outcome_rounds_elapsed(self) -> None:
        s = StepOutcome(index=0, action="click", label="go", ok=True, elapsed_ms=10.04)
        self.assertEqual(s.to_dict()["elapsed_ms"], 10.0)

    def test_defect_copies_lists(self) -> None:
        d = Defect(
            fingerprint="fp",
            target="t",
            target_repo="r",
            flow="f",
            viewport="v",
            category="layout_defect",
            severity="major",
            title="t",
            summary="s",
            screenshots=["a.png"],
            repro_steps=["step1"],
        )
        d2 = d.to_dict()
        d.screenshots.append("b.png")
        d.repro_steps.append("step2")
        self.assertEqual(d2["screenshots"], ["a.png"])
        self.assertEqual(d2["repro_steps"], ["step1"])

    def test_flow_run_result_nests_children(self) -> None:
        fr = FlowRunResult(
            target="t",
            flow="f",
            viewport="v",
            viewport_px="374x844",
            ok=True,
            elapsed_ms=100.04,
            steps=[StepOutcome(index=0, action="click", label="go", ok=True, elapsed_ms=10.0)],
            console_errors=[ConsoleRecord(level="error", source="js", text="boom")],
            failed_requests=[NetworkRecord(method="GET", url="http://127.0.0.1/a", status=500, ok=False, duration_ms=55.0)],
            broken_links=[LinkCheckResult(url="http://127.0.0.1/a", kind="link", status=404, ok=False, duration_ms=5.0)],
            links_checked=2,
            vision=[VisionAssessment(screenshot_path="/tmp/s.png", verdict="PASS", score_10=9.0, elapsed_ms=10.01)],
            defects=[
                Defect(fingerprint="fp", target="t", target_repo="r", flow="f", viewport="v", category="layout_defect", severity="major", title="t", summary="s")
            ],
        )
        d = fr.to_dict()
        self.assertEqual(d["elapsed_ms"], 100.0)
        self.assertEqual(len(d["steps"]), 1)
        self.assertEqual(len(d["console_errors"]), 1)
        self.assertEqual(len(d["failed_requests"]), 1)
        self.assertEqual(len(d["broken_links"]), 1)
        self.assertEqual(d["links_checked"], 2)
        self.assertEqual(len(d["vision"]), 1)
        self.assertEqual(len(d["defects"]), 1)

    def test_ticket_action(self) -> None:
        ta = TicketAction(fingerprint="fp", action="filed", title="t", task_id=7, reason="new")
        self.assertEqual(
            ta.to_dict(),
            {"fingerprint": "fp", "action": "filed", "title": "t", "task_id": 7, "reason": "new"},
        )

    def test_run_summary_to_dict_nests_children(self) -> None:
        summary = RunSummary(
            run_id="run_x",
            started_at="2026-06-01T00:00:00+00:00",
            finished_at="2026-06-01T00:01:00+00:00",
            elapsed_ms=123.456,
            dry_run=True,
            engine="chromium",
            vision_enabled=False,
            vision_model="",
            targets_run=1,
            flows_run=2,
            flows_passed=2,
            screenshots_captured=4,
            total_defects=2,
            unique_defects=1,
            tickets_filed=1,
            tickets_deduped=0,
            report_path="/tmp/r.md",
            panel_path="/tmp/p.json",
            artifacts_dir="/tmp/a",
            flow_results=[
                FlowRunResult(target="t", flow="f", viewport="v", viewport_px="374x844", ok=True, elapsed_ms=100.0)
            ],
            defects=[
                Defect(fingerprint="fp", target="t", target_repo="r", flow="f", viewport="v", category="layout_defect", severity="major", title="t", summary="s")
            ],
            ticket_actions=[TicketAction(fingerprint="fp", action="filed", title="t", task_id=3, reason="new")],
        )
        d = summary.to_dict()
        self.assertEqual(d["elapsed_ms"], 123.5)
        self.assertEqual(d["run_id"], "run_x")
        self.assertEqual(len(d["flow_results"]), 1)
        self.assertEqual(len(d["defects"]), 1)
        self.assertEqual(len(d["ticket_actions"]), 1)
        self.assertEqual(d["ticket_actions"][0]["task_id"], 3)


if __name__ == "__main__":
    unittest.main()
