"""Client for managing isolated browser sessions via the loopback vega-browser pool API."""

from __future__ import annotations

import json
import time
import urllib.error
import urllib.parse
import urllib.request
from dataclasses import dataclass
from typing import Any

from .models import ConsoleRecord, NetworkRecord
from .redact import ensure_loopback_url, redact_text, redact_url


@dataclass
class BrowserInstanceHandle:
    """Allocated isolated browser instance in the local browser pool."""

    browser_id: str
    cdp_url: str
    cdp_port: int | None
    engine: str


class VegaBrowserClient:
    """HTTP client for the loopback vega-browser pool daemon (e.g. 127.0.0.1:8490)."""

    def __init__(self, base_url: str = "http://127.0.0.1:8490", *, timeout: float = 20.0) -> None:
        self.base_url = ensure_loopback_url(base_url.rstrip("/"), context="browser pool URL")
        self.timeout = timeout

    def _request_json(
        self,
        method: str,
        path: str,
        body: dict[str, Any] | None = None,
        timeout: float | None = None,
    ) -> dict[str, Any]:
        url = f"{self.base_url}{path}"
        data = json.dumps(body).encode("utf-8") if body is not None else None
        headers = {"Accept": "application/json"}
        if data is not None:
            headers["Content-Type"] = "application/json"
        req = urllib.request.Request(url, data=data, headers=headers, method=method)
        try:
            with urllib.request.urlopen(req, timeout=timeout or self.timeout) as resp:
                raw = resp.read().decode("utf-8")
                return json.loads(raw) if raw else {}
        except urllib.error.HTTPError as exc:
            err_body = exc.read().decode("utf-8", errors="replace")[:400]
            raise RuntimeError(f"Browser pool {method} {path} returned HTTP {exc.code}: {err_body}") from exc

    def health(self) -> dict[str, Any]:
        return self._request_json("GET", "/health", timeout=5.0)

    def spawn_instance(
        self,
        *,
        browser_id: str | None = None,
        label: str = "Nightwalk QA",
        engine: str = "chromium",
        headless: bool = True,
        start_url: str = "about:blank",
    ) -> BrowserInstanceHandle:
        """Create and start an isolated browser instance with its own CDP port & profile."""
        bid = browser_id or f"nightwalk-{int(time.time())}"
        payload: dict[str, Any] = {
            "browserId": bid,
            "label": label,
            "engine": engine,
            "reuse": False,
            "start": True,
            "url": start_url,
            "headless": bool(headless),
        }
        resp = self._request_json("POST", "/api/instances", body=payload, timeout=30.0)
        state = resp.get("state") or resp.get("instance") or {}
        cdp_url = str(state.get("cdpUrl") or "").strip()
        cdp_port = state.get("cdpPort")
        if not cdp_url and cdp_port:
            cdp_url = f"http://127.0.0.1:{int(cdp_port)}"
        if not cdp_url:
            raise RuntimeError(f"Browser pool instance {bid!r} started without cdpUrl: {resp}")
        return BrowserInstanceHandle(
            browser_id=str(resp.get("browserId") or bid),
            cdp_url=ensure_loopback_url(cdp_url, context="instance cdpUrl"),
            cdp_port=int(cdp_port) if cdp_port is not None else None,
            engine=str(state.get("engine") or engine),
        )

    def clear_devtools(self, browser_id: str) -> None:
        try:
            self._request_json("POST", "/api/devtools/clear", body={"browserId": browser_id}, timeout=5.0)
        except Exception:
            pass

    def get_devtools(
        self,
        browser_id: str,
        *,
        limit: int = 250,
        extra_secrets: tuple[str, ...] = (),
    ) -> tuple[list[ConsoleRecord], list[NetworkRecord]]:
        """Fetch captured console and network telemetry from vega-browser's ring buffers."""
        q = urllib.parse.urlencode({"browserId": browser_id, "kind": "all", "limit": str(limit)})
        try:
            data = self._request_json("GET", f"/api/devtools?{q}", timeout=5.0)
        except Exception:
            return ([], [])

        console: list[ConsoleRecord] = []
        for entry in data.get("console") or []:
            if not isinstance(entry, dict):
                continue
            level = str(entry.get("level") or "").lower()
            if level != "error":
                continue
            console.append(
                ConsoleRecord(
                    level="error",
                    source=str(entry.get("source") or "console"),
                    text=redact_text(str(entry.get("text") or ""), extra_secrets),
                    url=redact_url(str(entry.get("url") or "")),
                    line=entry.get("line"),
                )
            )

        network: list[NetworkRecord] = []
        for entry in data.get("network") or []:
            if not isinstance(entry, dict):
                continue
            url = redact_url(str(entry.get("url") or ""))
            rtype = str(entry.get("resourceType") or "")
            dur = entry.get("durationMs")
            network.append(
                NetworkRecord(
                    method=str(entry.get("method") or "GET"),
                    url=url,
                    status=entry.get("status"),
                    ok=entry.get("ok"),
                    duration_ms=float(dur) if dur is not None else None,
                    resource_type=rtype,
                    error_text=redact_text(str(entry.get("errorText") or ""), extra_secrets) or None,
                    canceled=bool(entry.get("canceled", False)),
                    streaming=rtype.lower() in ("eventsource", "websocket") or url.startswith(("ws:", "wss:")),
                )
            )
        return (console, network)

    def capture_screenshot(self, browser_id: str) -> bytes:
        """Fallback JPEG screenshot via vega-browser HTTP API."""
        q = urllib.parse.urlencode({"browserId": browser_id})
        req = urllib.request.Request(f"{self.base_url}/api/screenshot?{q}", method="GET")
        with urllib.request.urlopen(req, timeout=10.0) as resp:
            return resp.read()

    def delete_instance(self, browser_id: str, *, purge_profile: bool = True) -> None:
        """Stop and remove an isolated browser instance and purge its ephemeral profile."""
        q = urllib.parse.urlencode({"purgeProfile": "1" if purge_profile else "0"})
        try:
            self._request_json("DELETE", f"/api/instances/{urllib.parse.quote(browser_id)}?{q}", timeout=15.0)
        except Exception:
            pass
