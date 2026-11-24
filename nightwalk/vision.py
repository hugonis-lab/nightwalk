"""Multimodal Vision QA inspection via any local OpenAI-compatible VLM endpoint."""

from __future__ import annotations

import base64
import io
import json
import time
import urllib.request
from pathlib import Path
from typing import Any

from .config import NightwalkConfig
from .models import ViewportSpec, VisionAssessment, VisionIssue
from .redact import redact_text

try:
    from PIL import Image
except Exception:  # pragma: no cover
    Image = None  # type: ignore[assignment]


def _strip_json_fences(raw: str) -> str:
    s = (raw or "").strip()
    if s.startswith("```"):
        s = s.split("\n", 1)[1] if "\n" in s else s[3:]
        if "```" in s:
            s = s.rsplit("```", 1)[0]
    start = s.find("{")
    end = s.rfind("}")
    if start >= 0 and end > start:
        return s[start : end + 1]
    return s.strip()


def _encode_image_for_vlm(path: Path, max_dim: int = 1024) -> tuple[str, str]:
    """Return (mime_type, base64_data); downscale high-res frames in-memory by pixel dimension."""
    raw = path.read_bytes()
    ext = path.suffix.lower()
    mime = "image/jpeg" if ext in (".jpg", ".jpeg") else "image/png"
    if Image is None:
        return (mime, base64.b64encode(raw).decode("ascii"))
    try:
        with Image.open(io.BytesIO(raw)) as img:
            w, h = img.size
            needs_resize = max(w, h) > max_dim
            if not needs_resize and len(raw) <= 220_000:
                return (mime, base64.b64encode(raw).decode("ascii"))
            if needs_resize:
                scale = max_dim / float(max(w, h))
                img = img.resize((max(1, int(w * scale)), max(1, int(h * scale))), Image.Resampling.LANCZOS)
            buf = io.BytesIO()
            img.convert("RGB").save(buf, format="JPEG", quality=84, optimize=True)
            return ("image/jpeg", base64.b64encode(buf.getvalue()).decode("ascii"))
    except Exception:
        return (mime, base64.b64encode(raw).decode("ascii"))


def inspect_screenshot(
    cfg: NightwalkConfig,
    screenshot_path: Path,
    *,
    target_name: str,
    flow_name: str,
    viewport: ViewportSpec,
    telemetry_context: dict[str, Any] | None = None,
) -> VisionAssessment:
    """Send a captured screenshot and grounded DOM telemetry to the configured VLM for visual QA."""
    if not cfg.vlm_url or not cfg.vlm_model:
        return VisionAssessment(
            screenshot_path=str(screenshot_path),
            verdict="SKIP",
            summary="Vision QA skipped (no VLM endpoint configured).",
        )
    if not screenshot_path.is_file():
        return VisionAssessment(
            screenshot_path=str(screenshot_path),
            verdict="SKIP",
            error=f"Screenshot file missing: {screenshot_path}",
        )

    mime, b64 = _encode_image_for_vlm(screenshot_path)
    ctx_json = json.dumps(telemetry_context or {}, ensure_ascii=True)
    prompt = (
        "You are an automated Customer-Zero UI/UX Vision QA inspector auditing a live web application screenshot.\n"
        f"App: {target_name}\n"
        f"Flow: {flow_name}\n"
        f"Viewport: {viewport.name} ({viewport.width}x{viewport.height}, mobile={viewport.mobile})\n"
        f"Grounded DOM/network telemetry: {ctx_json}\n\n"
        "Inspect ONLY what is actually visible in the screenshot. Do NOT invent invisible defects.\n"
        "Do NOT flag normal responsive design choices as defects:\n"
        "- Intentional CSS text-overflow ellipsis ('...' or '…') on narrow mobile viewports is EXPECTED, not clipping.\n"
        "- Monochrome geometric or typographic UI glyphs (dots, arrows, chevrons, diamonds, four-point stars) are NOT emojis.\n"
        "- Only flag genuine colorful pictographic emojis (faces, hands, rockets, fire, checkmarks) as emoji defects.\n\n"
        "Flag ONLY genuine customer-facing visual regressions:\n"
        "- overlapping or colliding text/controls that block reading or tapping\n"
        "- un-ellipsized hard clipping where glyphs are sliced mid-character or controls run off-screen\n"
        "- blank/stuck loading canvas, error stack trace, or broken/missing SVG chart or broken image\n"
        "- severely unreadable text contrast or broken layout collapse\n\n"
        "Use severity strictly:\n"
        "- critical: broken/blank screen, unusable overlapping controls, unreadable core UI\n"
        "- major: obvious un-ellipsized clipping, broken chart/widget, misaligned layout breaking usability, pictographic emoji in chrome\n"
        "- minor: small spacing or stylistic polish nit (use verdict='PASS' when only minor nits exist)\n\n"
        "Return ONLY valid raw JSON (no markdown fences) matching this exact schema:\n"
        '{\n'
        '  "verdict": "PASS" | "WARN" | "FAIL",\n'
        '  "score_10": 1-10,\n'
        '  "summary": "one concise sentence describing visual quality",\n'
        '  "issues": [\n'
        '    {"severity": "critical"|"major"|"minor", "category": "overlap"|"clip"|"contrast"|"blank"|"broken_layout"|"emoji"|"unreadable", "element": "specific visible UI element", "description": "concrete observed defect", "suggested_fix": "short CSS/layout fix"}\n'
        '  ]\n'
        '}'
    )

    payload: dict[str, Any] = {
        "model": cfg.vlm_model,
        "temperature": 1.0,
        "top_p": 0.95,
        "max_tokens": cfg.vlm_max_tokens,
        "messages": [
            {
                "role": "user",
                "content": [
                    {"type": "text", "text": prompt},
                    {"type": "image_url", "image_url": {"url": f"data:{mime};base64,{b64}"}},
                ],
            }
        ],
    }
    if cfg.vlm_reasoning_effort:
        payload["reasoning_effort"] = cfg.vlm_reasoning_effort

    url = cfg.vlm_url.rstrip("/")
    if not url.endswith("/chat/completions"):
        url = f"{url}/chat/completions"

    headers = {"Content-Type": "application/json", "Accept": "application/json"}
    if cfg.vlm_api_key:
        headers["Authorization"] = f"Bearer {cfg.vlm_api_key}"

    req = urllib.request.Request(
        url,
        data=json.dumps(payload).encode("utf-8"),
        headers=headers,
        method="POST",
    )
    t0 = time.perf_counter()
    try:
        with urllib.request.urlopen(req, timeout=cfg.vlm_timeout_sec) as resp:
            body = json.loads(resp.read().decode("utf-8"))
        elapsed_ms = (time.perf_counter() - t0) * 1000.0
    except Exception as exc:
        elapsed_ms = (time.perf_counter() - t0) * 1000.0
        return VisionAssessment(
            screenshot_path=str(screenshot_path),
            verdict="SKIP",
            elapsed_ms=elapsed_ms,
            model=cfg.vlm_model,
            error=redact_text(f"VLM request failed: {exc}")[:300],
        )

    choices = body.get("choices") or []
    raw_content = ""
    if choices and isinstance(choices[0], dict):
        msg = choices[0].get("message") or {}
        raw_content = str(msg.get("content") or "")

    try:
        parsed = json.loads(_strip_json_fences(raw_content))
        if not isinstance(parsed, dict):
            raise ValueError("VLM response is not a JSON object")
    except Exception as exc:
        return VisionAssessment(
            screenshot_path=str(screenshot_path),
            verdict="SKIP",
            elapsed_ms=elapsed_ms,
            model=cfg.vlm_model,
            error=f"Unparseable VLM JSON ({exc}): {redact_text(raw_content[:200])}",
        )

    issues: list[VisionIssue] = []
    for item in parsed.get("issues") or []:
        if not isinstance(item, dict):
            continue
        sev = str(item.get("severity") or "minor").strip().lower()
        if sev not in ("critical", "major", "minor"):
            sev = "minor"
        cat = str(item.get("category") or "broken_layout").strip().lower()
        elem = redact_text(str(item.get("element") or "").strip())[:120]
        desc = redact_text(str(item.get("description") or "").strip())[:400]
        fix = redact_text(str(item.get("suggested_fix") or "").strip())[:240]
        if elem and desc:
            issues.append(
                VisionIssue(
                    severity=sev,
                    category=cat,
                    element=elem,
                    description=desc,
                    suggested_fix=fix,
                )
            )

    verdict = str(parsed.get("verdict") or "PASS").strip().upper()
    if verdict not in ("PASS", "WARN", "FAIL"):
        verdict = "FAIL" if any(i.severity in ("critical", "major") for i in issues) else "PASS"

    score_raw = parsed.get("score_10")
    try:
        score = float(score_raw) if score_raw is not None else None
    except (TypeError, ValueError):
        score = None

    return VisionAssessment(
        screenshot_path=str(screenshot_path),
        verdict=verdict,
        score_10=score,
        elapsed_ms=elapsed_ms,
        model=cfg.vlm_model,
        summary=redact_text(str(parsed.get("summary") or "").strip())[:400],
        issues=issues,
    )
