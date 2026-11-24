"""Deterministic checks: telemetry filtering, link probing, DOM layout/emoji audit, and defect fingerprinting."""

from __future__ import annotations

import hashlib
import re
import time
import urllib.error
import urllib.parse
import urllib.request
from typing import Any

from .cdp import CDPClient
from .models import (
    ConsoleRecord,
    Defect,
    LinkCheckResult,
    NetworkRecord,
    TargetSpec,
    ViewportSpec,
    VisionAssessment,
)
from .redact import is_loopback_url, is_same_origin, redact_text, redact_url

_UUID_RE = re.compile(r"\b[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}\b")
_HEX_RE = re.compile(r"\b[0-9a-fA-F]{12,}\b")
_NUM_RE = re.compile(r"\b\d+(?:\.\d+)?(?:ms|s|px|%|KB|MB|GB)?\b")
_WS_RE = re.compile(r"\s+")

_EXTRACT_LINKS_JS = """
(() => {
  const links = new Set();
  for (const a of document.querySelectorAll('a[href]')) {
    const raw = (a.getAttribute('href') || '').trim();
    if (!raw || raw.startsWith('#') || raw.startsWith('javascript:') || raw.startsWith('mailto:') || raw.startsWith('tel:') || raw.startsWith('data:')) continue;
    try {
      const u = new URL(raw, location.href);
      u.hash = '';
      links.add(u.href);
    } catch {}
  }
  const images = [];
  const brokenDomImages = [];
  const seenImg = new Set();
  for (const img of document.querySelectorAll('img[src]')) {
    const raw = (img.getAttribute('src') || '').trim();
    if (!raw || raw.startsWith('data:') || raw.startsWith('blob:')) continue;
    try {
      const u = new URL(raw, location.href);
      if (!seenImg.has(u.href)) {
        seenImg.add(u.href);
        images.push(u.href);
      }
      const style = window.getComputedStyle(img);
      const visible = style.display !== 'none' && style.visibility !== 'hidden' && img.getClientRects().length > 0;
      if (visible && img.complete && img.naturalWidth === 0) {
        brokenDomImages.push(u.href);
      }
    } catch {}
  }
  return {
    origin: location.origin,
    href: location.href,
    links: Array.from(links),
    images,
    brokenDomImages
  };
})()
"""

# Deterministic DOM layout, silent text clip, and zero-emoji UI chrome audit.
_LAYOUT_AUDIT_JS = """
(() => {
  const docEl = document.documentElement;
  const body = document.body;
  const vw = window.innerWidth || docEl.clientWidth || 0;
  const vh = window.innerHeight || docEl.clientHeight || 0;
  const scrollWidth = Math.max(docEl.scrollWidth || 0, body ? body.scrollWidth || 0 : 0);
  const horizontalOverflowPx = Math.max(0, Math.round(scrollWidth - vw));

  const bodyText = ((body && body.innerText) || '').trim();
  const textLen = bodyText.length;

  // Detect clipped visible text nodes lacking ellipsis/scroll
  const clipped = [];
  const emojiRe = /[\\u{1F300}-\\u{1FAFF}\\u{2600}-\\u{27BF}]/u;
  const emojis = [];
  const all = document.querySelectorAll('h1,h2,h3,h4,button,a,span,p,label,div,td,th');
  for (let i = 0; i < all.length && i < 1500; i++) {
    const el = all[i];
    if (!el || el.closest('[hidden], .hidden, [aria-hidden="true"]')) continue;
    const style = window.getComputedStyle(el);
    if (style.display === 'none' || style.visibility === 'hidden' || parseFloat(style.opacity || '1') === 0) continue;
    const rect = el.getBoundingClientRect();
    if (rect.width < 2 || rect.height < 2) continue;

    // Check direct text for decorative emojis in UI chrome (skip code/pre/article user content)
    if (!el.closest('pre, code, article, .chat-stream, .file-viewer-body, textarea')) {
      for (const node of el.childNodes) {
        if (node.nodeType === 3 && node.nodeValue && emojiRe.test(node.nodeValue)) {
          const sample = node.nodeValue.trim().slice(0, 60);
          if (sample && emojis.length < 10) {
            emojis.push({ tag: el.tagName.toLowerCase(), id: el.id || '', sample });
          }
        }
      }
    }

    // Check horizontal silent clip (overflow hidden without text-overflow ellipsis)
    const ox = style.overflowX;
    if ((ox === 'hidden' || ox === 'clip') && style.textOverflow !== 'ellipsis') {
      const diff = el.scrollWidth - el.clientWidth;
      if (diff > 10 && el.clientWidth > 20 && el.children.length === 0) {
        const txt = (el.textContent || '').trim();
        if (txt.length > 4 && clipped.length < 10) {
          clipped.push({
            tag: el.tagName.toLowerCase(),
            id: el.id || '',
            cls: typeof el.className === 'string' ? el.className.slice(0, 50) : '',
            overflowPx: Math.round(diff),
            text: txt.slice(0, 60)
          });
        }
      }
    }
  }

  return {
    viewportWidth: vw,
    viewportHeight: vh,
    scrollWidth,
    horizontalOverflowPx,
    visibleTextLen: textLen,
    clippedNodes: clipped,
    emojiNodes: emojis
  };
})()
"""


def normalize_for_fingerprint(text: str) -> str:
    """Strip volatile numbers, UUIDs, hex hashes, and whitespace for stable deduplication."""
    s = redact_text(str(text or "")).lower().strip()
    s = _UUID_RE.sub("<uuid>", s)
    s = _HEX_RE.sub("<hex>", s)
    s = _NUM_RE.sub("<n>", s)
    s = _WS_RE.sub(" ", s)
    return s[:180]


def normalize_endpoint_key(url: str) -> str:
    """Normalize a URL to scheme-agnostic path + sorted query keys for stable endpoint grouping."""
    clean = redact_url(url)
    try:
        parts = urllib.parse.urlsplit(clean)
    except Exception:
        return normalize_for_fingerprint(clean)
    path = _UUID_RE.sub("<id>", parts.path or "/")
    path = re.sub(r"/\d+(?=/|$)", "/<n>", path)
    keys = sorted({k for k, _ in urllib.parse.parse_qsl(parts.query, keep_blank_values=True)})
    if keys:
        return f"{path}?{'&'.join(keys)}"
    return path


def compute_fingerprint(target: str, category: str, key: str) -> str:
    raw = f"{target.strip().lower()}|{category.strip().lower()}|{normalize_for_fingerprint(key)}"
    return hashlib.sha256(raw.encode("utf-8")).hexdigest()[:12]


def _matches_any(patterns: list[str], value: str) -> bool:
    for pat in patterns:
        try:
            if re.search(pat, value, re.IGNORECASE):
                return True
        except re.error:
            if pat.lower() in value.lower():
                return True
    return False


def merge_console_errors(
    direct: list[ConsoleRecord],
    pool: list[ConsoleRecord],
    ignore_patterns: list[str] | None = None,
) -> list[ConsoleRecord]:
    """Combine and deduplicate console errors from direct CDP and browser pool telemetry."""
    ignores = ignore_patterns or []
    seen: set[str] = set()
    out: list[ConsoleRecord] = []
    for rec in (*direct, *pool):
        if rec.level.lower() != "error":
            continue
        if _matches_any(ignores, rec.text) or (rec.url and _matches_any(ignores, rec.url)):
            continue
        sig = f"{rec.source}|{normalize_for_fingerprint(rec.text)}|{normalize_endpoint_key(rec.url)}"
        if sig in seen:
            continue
        seen.add(sig)
        out.append(rec)
    return out


def analyze_network(
    direct: list[NetworkRecord],
    pool: list[NetworkRecord],
    *,
    slow_threshold_ms: float = 300.0,
    ignore_slow_patterns: list[str] | None = None,
    ignore_network_patterns: list[str] | None = None,
) -> tuple[list[NetworkRecord], list[NetworkRecord]]:
    """Return (failed_requests, slow_endpoints) deduplicated across telemetry sources."""
    ignore_slow = ignore_slow_patterns or []
    ignore_net = ignore_network_patterns or []

    # Direct CDP telemetry has full loadingFinished duration + streaming MIME detection;
    # supplement with pool telemetry for any requests not seen directly.
    all_records = list(direct)
    direct_keys = {(r.method, r.url, r.status) for r in direct}
    for r in pool:
        if (r.method, r.url, r.status) not in direct_keys:
            all_records.append(r)

    failed: list[NetworkRecord] = []
    slow: list[NetworkRecord] = []
    seen_failed: set[str] = set()
    slow_by_endpoint: dict[str, NetworkRecord] = {}

    for rec in all_records:
        url = rec.url or ""
        if not url or url.startswith(("data:", "blob:", "about:", "chrome-extension:")):
            continue
        if _matches_any(ignore_net, url):
            continue

        is_failed = (rec.ok is False and not rec.canceled) or (rec.status is not None and rec.status >= 400)
        if is_failed:
            fkey = f"{rec.method}|{normalize_endpoint_key(url)}|{rec.status}|{rec.error_text or ''}"
            if fkey not in seen_failed:
                seen_failed.add(fkey)
                failed.append(rec)

        if (
            rec.duration_ms is not None
            and rec.duration_ms > slow_threshold_ms
            and not rec.streaming
            and not rec.canceled
            and not _matches_any(ignore_slow, url)
        ):
            ep = f"{rec.method} {normalize_endpoint_key(url)}"
            prev = slow_by_endpoint.get(ep)
            if prev is None or (prev.duration_ms or 0.0) < rec.duration_ms:
                slow_by_endpoint[ep] = rec

    slow = sorted(slow_by_endpoint.values(), key=lambda r: -(r.duration_ms or 0.0))
    return (failed, slow)


def check_same_origin_links(
    cdp: CDPClient,
    target: TargetSpec,
    *,
    auth_token: str = "",
    max_links: int = 30,
    timeout_sec: float = 5.0,
    loopback_only: bool = True,
) -> tuple[int, list[LinkCheckResult]]:
    """Extract same-origin <a href> and <img src> from DOM and verify via strictly read-only GET."""
    extracted = cdp.evaluate(_EXTRACT_LINKS_JS, timeout=8.0) or {}
    raw_links = [str(u) for u in (extracted.get("links") or [])]
    raw_images = [str(u) for u in (extracted.get("images") or [])]
    broken_dom_imgs = {str(u) for u in (extracted.get("brokenDomImages") or [])}

    candidates: list[tuple[str, str]] = []
    seen: set[str] = set()
    for kind, items in (("link", raw_links), ("image", raw_images)):
        for url in items:
            if url in seen:
                continue
            if not is_same_origin(target.base_url, url):
                continue
            if loopback_only and not is_loopback_url(url):
                continue
            seen.add(url)
            candidates.append((kind, url))
            if len(candidates) >= max_links:
                break
        if len(candidates) >= max_links:
            break

    headers: dict[str, str] = {"Accept": "*/*"}
    if auth_token:
        if target.auth_cookie_name:
            headers["Cookie"] = f"{target.auth_cookie_name}={urllib.parse.quote(auth_token)}"
        headers["Authorization"] = f"{target.auth_header_prefix}{auth_token}"

    broken: list[LinkCheckResult] = []
    checked = 0
    for kind, url in candidates:
        checked += 1
        redacted = redact_url(url)
        t0 = time.perf_counter()
        req = urllib.request.Request(url, headers=headers, method="GET")
        try:
            with urllib.request.urlopen(req, timeout=timeout_sec) as resp:
                status = int(resp.status)
                # Read only a small prefix to verify body streams cleanly without pulling giant files.
                resp.read(1024)
            dur_ms = (time.perf_counter() - t0) * 1000.0
            if status >= 400:
                broken.append(LinkCheckResult(url=redacted, kind=kind, status=status, ok=False, duration_ms=dur_ms))
        except urllib.error.HTTPError as exc:
            dur_ms = (time.perf_counter() - t0) * 1000.0
            broken.append(
                LinkCheckResult(
                    url=redacted,
                    kind=kind,
                    status=int(exc.code),
                    ok=False,
                    duration_ms=dur_ms,
                    error=f"HTTP {exc.code}",
                )
            )
        except Exception as exc:
            dur_ms = (time.perf_counter() - t0) * 1000.0
            broken.append(
                LinkCheckResult(
                    url=redacted,
                    kind=kind,
                    status=None,
                    ok=False,
                    duration_ms=dur_ms,
                    error=redact_text(str(exc)[:200]),
                )
            )

    broken_urls = {b.url for b in broken}
    for dom_img in broken_dom_imgs:
        r_img = redact_url(dom_img)
        if r_img not in broken_urls:
            broken.append(
                LinkCheckResult(
                    url=r_img,
                    kind="image",
                    status=None,
                    ok=False,
                    duration_ms=0.0,
                    error="Rendered <img> has naturalWidth=0",
                )
            )

    return (checked, broken)


def audit_dom_layout(cdp: CDPClient) -> dict[str, Any]:
    """Run deterministic viewport overflow, silent clip, and zero-emoji DOM invariants."""
    res = cdp.evaluate(_LAYOUT_AUDIT_JS, timeout=8.0)
    return res if isinstance(res, dict) else {}


def build_defects_from_flow(
    *,
    target: TargetSpec,
    flow_name: str,
    viewport: ViewportSpec,
    step_errors: list[str],
    console_errors: list[ConsoleRecord],
    failed_requests: list[NetworkRecord],
    slow_endpoints: list[NetworkRecord],
    broken_links: list[LinkCheckResult],
    layout_metrics: dict[str, Any],
    vision_assessments: list[VisionAssessment],
    screenshots: list[str],
    slow_threshold_ms: float,
    repro_steps: list[str],
) -> list[Defect]:
    """Synthesize deduplicatable, evidence-backed Defects from deterministic + Vision telemetry."""
    defects: list[Defect] = []
    vp_label = f"{viewport.name} ({viewport.label})"

    # 1. Interactive flow step failures (grouped across viewports by target+flow+error)
    for err in step_errors:
        fp = compute_fingerprint(target.name, "flow_error", f"{flow_name}|{err}")
        defects.append(
            Defect(
                fingerprint=fp,
                target=target.name,
                target_repo=target.target_repo,
                flow=flow_name,
                viewport=vp_label,
                category="flow_error",
                severity="major",
                title=f"[{target.name}] Flow '{flow_name}' failed: {err[:90]}",
                summary=err,
                evidence={"step_error": err},
                screenshots=list(screenshots),
                repro_steps=list(repro_steps),
            )
        )

    # 2. Console errors / uncaught JS exceptions
    for c in console_errors:
        fp = compute_fingerprint(target.name, "console_error", f"{c.source}|{c.text}|{normalize_endpoint_key(c.url)}")
        snippet = c.text[:90].replace("\n", " ")
        defects.append(
            Defect(
                fingerprint=fp,
                target=target.name,
                target_repo=target.target_repo,
                flow=flow_name,
                viewport=vp_label,
                category="console_error",
                severity="major",
                title=f"[{target.name}] Console error in {flow_name}: {snippet}",
                summary=f"{c.source}: {c.text}" + (f" ({c.url}:{c.line})" if c.url else ""),
                evidence=c.to_dict(),
                screenshots=list(screenshots),
                repro_steps=list(repro_steps),
            )
        )

    # 3. Failed network requests
    for r in failed_requests:
        ep = normalize_endpoint_key(r.url)
        fp = compute_fingerprint(target.name, "network_error", f"{r.method}|{ep}|{r.status or r.error_text}")
        status_str = f"HTTP {r.status}" if r.status else (r.error_text or "failed")
        defects.append(
            Defect(
                fingerprint=fp,
                target=target.name,
                target_repo=target.target_repo,
                flow=flow_name,
                viewport=vp_label,
                category="network_error",
                severity="major",
                title=f"[{target.name}] Failed request {r.method} {ep} ({status_str})",
                summary=f"{r.method} {r.url} returned {status_str} during {flow_name} on {vp_label}.",
                evidence=r.to_dict(),
                screenshots=list(screenshots),
                repro_steps=list(repro_steps),
            )
        )

    # 4. Slow endpoints (> slow_threshold_ms, default 300ms)
    for r in slow_endpoints:
        ep = normalize_endpoint_key(r.url)
        fp = compute_fingerprint(target.name, "slow_endpoint", f"{r.method}|{ep}")
        dur = round(r.duration_ms or 0.0, 1)
        defects.append(
            Defect(
                fingerprint=fp,
                target=target.name,
                target_repo=target.target_repo,
                flow=flow_name,
                viewport=vp_label,
                category="slow_endpoint",
                severity="major",
                title=f"[{target.name}] Slow endpoint {r.method} {ep} ({dur}ms > {int(slow_threshold_ms)}ms)",
                summary=(
                    f"{r.method} {r.url} took {dur}ms (budget {int(slow_threshold_ms)}ms, HTTP {r.status}) "
                    f"during {flow_name} on {vp_label}."
                ),
                evidence={**r.to_dict(), "threshold_ms": slow_threshold_ms},
                screenshots=list(screenshots),
                repro_steps=list(repro_steps),
            )
        )

    # 5. Broken same-origin links & images
    for link in broken_links:
        ep = normalize_endpoint_key(link.url)
        fp = compute_fingerprint(target.name, "broken_link", f"{link.kind}|{ep}")
        detail = f"HTTP {link.status}" if link.status else (link.error or "unreachable")
        defects.append(
            Defect(
                fingerprint=fp,
                target=target.name,
                target_repo=target.target_repo,
                flow=flow_name,
                viewport=vp_label,
                category="broken_link",
                severity="major",
                title=f"[{target.name}] Broken {link.kind} {ep} ({detail})",
                summary=f"Read-only probe of {link.kind} {link.url} failed ({detail}) in {flow_name}.",
                evidence=link.to_dict(),
                screenshots=list(screenshots),
                repro_steps=list(repro_steps),
            )
        )

    # 6. Layout invariants (horizontal overflow > 4px, blank page, or UI chrome emojis)
    overflow_px = int(layout_metrics.get("horizontalOverflowPx") or 0)
    if overflow_px > 4:
        fp = compute_fingerprint(target.name, "layout_overflow", f"{flow_name}|{viewport.name}")
        defects.append(
            Defect(
                fingerprint=fp,
                target=target.name,
                target_repo=target.target_repo,
                flow=flow_name,
                viewport=vp_label,
                category="layout_defect",
                severity="major",
                title=f"[{target.name}] Horizontal overflow (+{overflow_px}px) in {flow_name} on {viewport.name}",
                summary=(
                    f"Page scrollWidth ({layout_metrics.get('scrollWidth')}px) exceeds viewport width "
                    f"({layout_metrics.get('viewportWidth')}px) by {overflow_px}px on {vp_label}."
                ),
                evidence=layout_metrics,
                screenshots=list(screenshots),
                repro_steps=list(repro_steps),
            )
        )

    emoji_nodes = layout_metrics.get("emojiNodes") or []
    if emoji_nodes:
        fp = compute_fingerprint(target.name, "ui_emoji", f"{flow_name}|{emoji_nodes[0].get('id') or emoji_nodes[0].get('tag')}")
        defects.append(
            Defect(
                fingerprint=fp,
                target=target.name,
                target_repo=target.target_repo,
                flow=flow_name,
                viewport=vp_label,
                category="layout_defect",
                severity="major",
                title=f"[{target.name}] Rendered emoji glyph in UI chrome during {flow_name}",
                summary=f"Found {len(emoji_nodes)} UI chrome node(s) containing decorative emoji glyphs.",
                evidence={"emoji_nodes": emoji_nodes},
                screenshots=list(screenshots),
                repro_steps=list(repro_steps),
            )
        )

    # 7. Multimodal Vision QA high-confidence visual regressions (FAIL verdict or critical severity)
    for va in vision_assessments:
        if va.verdict not in ("FAIL", "WARN"):
            continue
        for issue in va.issues:
            if va.verdict == "WARN" and issue.severity != "critical":
                continue
            if issue.severity not in ("critical", "major"):
                continue
            if not issue.element or not issue.description:
                continue
            fp = compute_fingerprint(
                target.name,
                "vision_defect",
                f"{flow_name}|{viewport.name}|{issue.category}|{issue.element}",
            )
            defects.append(
                Defect(
                    fingerprint=fp,
                    target=target.name,
                    target_repo=target.target_repo,
                    flow=flow_name,
                    viewport=vp_label,
                    category="vision_defect",
                    severity=issue.severity,
                    title=f"[{target.name}] Visual {issue.category} in {issue.element} ({viewport.name})",
                    summary=(
                        f"Vision QA ({va.model or 'VLM'}, score {va.score_10}/10) flagged {issue.severity} "
                        f"{issue.category} on '{issue.element}': {issue.description}"
                        + (f" Suggested fix: {issue.suggested_fix}" if issue.suggested_fix else "")
                    ),
                    evidence={
                        "vision_verdict": va.verdict,
                        "vision_score_10": va.score_10,
                        "vision_model": va.model,
                        "issue": issue.to_dict(),
                    },
                    screenshots=[va.screenshot_path] if va.screenshot_path else list(screenshots),
                    repro_steps=list(repro_steps),
                )
            )

    return defects
