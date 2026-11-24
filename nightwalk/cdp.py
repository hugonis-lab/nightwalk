"""Pure Python 3.11+ stdlib RFC 6455 loopback WebSocket & Chrome DevTools Protocol client."""

from __future__ import annotations

import base64
import hashlib
import json
import os
import queue
import socket
import struct
import threading
import time
import urllib.parse
import urllib.request
from typing import Any

from .models import ConsoleRecord, NetworkRecord
from .redact import ensure_loopback_url, redact_text, redact_url

_WS_GUID = "258EAFA5-E914-47DA-95CA-C5AB0DC85B11"

_KEY_SPECS: dict[str, tuple[str, int, str]] = {
    "Enter": ("Enter", 13, "\r"),
    "Tab": ("Tab", 9, "\t"),
    "Escape": ("Escape", 27, ""),
    "Backspace": ("Backspace", 8, ""),
    "Delete": ("Delete", 46, ""),
    "Space": ("Space", 32, " "),
    "ArrowUp": ("ArrowUp", 38, ""),
    "ArrowDown": ("ArrowDown", 40, ""),
    "ArrowLeft": ("ArrowLeft", 37, ""),
    "ArrowRight": ("ArrowRight", 39, ""),
    "Home": ("Home", 36, ""),
    "End": ("End", 35, ""),
    "PageUp": ("PageUp", 33, ""),
    "PageDown": ("PageDown", 34, ""),
}

_MODIFIER_FLAGS: dict[str, int] = {
    "alt": 1,
    "control": 2,
    "ctrl": 2,
    "meta": 4,
    "cmd": 4,
    "shift": 8,
}

_STREAMING_TYPES = frozenset({"eventsource", "websocket"})


class LoopbackWebSocket:
    """Minimal, RFC 6455 compliant client WebSocket restricted strictly to loopback URLs."""

    def __init__(self, ws_url: str, timeout: float = 10.0) -> None:
        ensure_loopback_url(ws_url, context="CDP WebSocket URL")
        self.ws_url = ws_url
        self.timeout = timeout
        self._sock: socket.socket | None = None
        self._buf = bytearray()
        self._send_lock = threading.Lock()
        self._closed = False

    def connect(self) -> None:
        parts = urllib.parse.urlsplit(self.ws_url)
        host = parts.hostname or "127.0.0.1"
        port = parts.port or (443 if parts.scheme == "wss" else 80)
        path = parts.path or "/"
        if parts.query:
            path = f"{path}?{parts.query}"

        sock = socket.create_connection((host, port), timeout=self.timeout)
        sock.settimeout(self.timeout)
        self._sock = sock

        key = base64.b64encode(os.urandom(16)).decode("ascii")
        expected_accept = base64.b64encode(
            hashlib.sha1((key + _WS_GUID).encode("ascii")).digest()
        ).decode("ascii")

        req = (
            f"GET {path} HTTP/1.1\r\n"
            f"Host: {host}:{port}\r\n"
            "Upgrade: websocket\r\n"
            "Connection: Upgrade\r\n"
            f"Sec-WebSocket-Key: {key}\r\n"
            "Sec-WebSocket-Version: 13\r\n"
            "\r\n"
        )
        sock.sendall(req.encode("ascii"))

        header_end = -1
        while header_end < 0:
            chunk = sock.recv(4096)
            if not chunk:
                raise ConnectionError("WebSocket handshake closed before HTTP headers completed")
            self._buf.extend(chunk)
            header_end = self._buf.find(b"\r\n\r\n")
            if len(self._buf) > 65536:
                raise ConnectionError("WebSocket handshake response headers too large")

        raw_headers = bytes(self._buf[:header_end]).decode("iso-8859-1", errors="replace")
        del self._buf[: header_end + 4]

        lines = raw_headers.split("\r\n")
        if not lines or "101" not in lines[0]:
            raise ConnectionError(f"WebSocket handshake failed: {lines[0] if lines else 'empty'}")

        hdrs: dict[str, str] = {}
        for line in lines[1:]:
            if ":" in line:
                k, v = line.split(":", 1)
                hdrs[k.strip().lower()] = v.strip()
        if hdrs.get("sec-websocket-accept") != expected_accept:
            raise ConnectionError("WebSocket handshake Sec-WebSocket-Accept mismatch")

        # After handshake, allow short recv timeouts so reader loops can check shutdown cleanly.
        sock.settimeout(0.25)

    def _recv_exact(self, n: int) -> bytes:
        assert self._sock is not None
        while len(self._buf) < n:
            if self._closed:
                raise ConnectionError("WebSocket closed")
            try:
                chunk = self._sock.recv(max(4096, n - len(self._buf)))
            except socket.timeout:
                continue
            if not chunk:
                raise ConnectionError("WebSocket EOF")
            self._buf.extend(chunk)
        out = bytes(self._buf[:n])
        del self._buf[:n]
        return out

    def _send_frame(self, opcode: int, payload: bytes) -> None:
        if self._closed or self._sock is None:
            raise ConnectionError("WebSocket is not connected")
        mask = os.urandom(4)
        length = len(payload)
        header = bytearray([0x80 | (opcode & 0x0F)])
        if length < 126:
            header.append(0x80 | length)
        elif length < 65536:
            header.append(0x80 | 126)
            header.extend(struct.pack("!H", length))
        else:
            header.append(0x80 | 127)
            header.extend(struct.pack("!Q", length))
        header.extend(mask)

        masked = bytes(b ^ mask[i & 3] for i, b in enumerate(payload))
        with self._send_lock:
            self._sock.sendall(bytes(header) + masked)

    def send_text(self, text: str) -> None:
        self._send_frame(0x1, text.encode("utf-8"))

    def recv_text(self) -> str:
        """Read next complete text message (handles fragmentation and PING control frames)."""
        fragments: list[bytes] = []
        collecting = False
        while True:
            hdr = self._recv_exact(2)
            b0, b1 = hdr[0], hdr[1]
            fin = bool(b0 & 0x80)
            opcode = b0 & 0x0F
            masked = bool(b1 & 0x80)
            length = b1 & 0x7F

            if length == 126:
                length = struct.unpack("!H", self._recv_exact(2))[0]
            elif length == 127:
                length = struct.unpack("!Q", self._recv_exact(8))[0]

            mask_key = self._recv_exact(4) if masked else b""
            payload = self._recv_exact(length) if length else b""
            if masked:
                payload = bytes(b ^ mask_key[i & 3] for i, b in enumerate(payload))

            if opcode == 0x8:  # CLOSE
                self.close()
                raise ConnectionError("WebSocket closed by remote peer")
            if opcode == 0x9:  # PING -> reply PONG
                try:
                    self._send_frame(0xA, payload)
                except Exception:
                    pass
                continue
            if opcode == 0xA:  # PONG
                continue

            if opcode == 0x1:  # TEXT
                fragments = [payload]
                collecting = True
            elif opcode == 0x0 and collecting:  # CONTINUATION
                fragments.append(payload)
            else:
                # Ignore binary/unexpected frames
                continue

            if fin and collecting:
                return b"".join(fragments).decode("utf-8", errors="replace")

    def close(self) -> None:
        if self._closed:
            return
        self._closed = True
        sock = self._sock
        self._sock = None
        if sock is not None:
            try:
                sock.shutdown(socket.SHUT_RDWR)
            except Exception:
                pass
            try:
                sock.close()
            except Exception:
                pass


class CDPClient:
    """Synchronous-ergonomics Chrome DevTools Protocol client over a loopback WebSocket."""

    def __init__(self, cdp_http_url: str, *, extra_secrets: tuple[str, ...] = ()) -> None:
        self.cdp_http_url = ensure_loopback_url(cdp_http_url.rstrip("/"), context="CDP HTTP URL")
        self.extra_secrets = extra_secrets
        self._ws: LoopbackWebSocket | None = None
        self._reader: threading.Thread | None = None
        self._cmd_id = 0
        self._id_lock = threading.Lock()
        self._pending: dict[int, queue.Queue[dict[str, Any]]] = {}
        self._session_id: str | None = None
        self._connected = False

        # Telemetry state (guarded by _tel_lock)
        self._tel_lock = threading.Lock()
        self._pending_reqs: dict[str, dict[str, Any]] = {}
        self._network: list[NetworkRecord] = []
        self._console: list[ConsoleRecord] = []
        self._load_event = threading.Event()
        self._last_network_activity = time.monotonic()

    @property
    def connected(self) -> bool:
        return self._connected and self._ws is not None

    def connect(self, timeout: float = 10.0) -> None:
        """Discover active page target and connect CDP WebSocket + telemetry domains."""
        ws_url, needs_attach, target_id = self._discover_ws(timeout=timeout)
        ws = LoopbackWebSocket(ws_url, timeout=timeout)
        ws.connect()
        self._ws = ws
        self._connected = True
        self._reader = threading.Thread(target=self._reader_loop, name="nightwalk-cdp-reader", daemon=True)
        self._reader.start()

        if needs_attach:
            if not target_id:
                res = self.call("Target.getTargets", {})
                pages = [t for t in (res.get("targetInfos") or []) if t.get("type") == "page"]
                if pages:
                    target_id = pages[-1]["targetId"]
                else:
                    created = self.call("Target.createTarget", {"url": "about:blank"})
                    target_id = created["targetId"]
            attached = self.call("Target.attachToTarget", {"targetId": target_id, "flatten": True})
            self._session_id = str(attached["sessionId"])

        for domain in ("Page.enable", "Runtime.enable", "Network.enable", "Log.enable"):
            try:
                self.call(domain, {}, timeout=5.0)
            except Exception:
                pass

    def _discover_ws(self, timeout: float = 10.0) -> tuple[str, bool, str | None]:
        # Prefer direct page WebSocket from /json/list (works on Chromium and ObscuraCDPMux)
        try:
            with urllib.request.urlopen(f"{self.cdp_http_url}/json/list", timeout=timeout) as resp:
                targets = json.loads(resp.read().decode("utf-8"))
            if isinstance(targets, list):
                pages = [t for t in targets if isinstance(t, dict) and t.get("type") == "page" and t.get("webSocketDebuggerUrl")]
                if pages:
                    # Prefer a non-extension, non-devtools page
                    chosen = next(
                        (
                            p
                            for p in reversed(pages)
                            if not str(p.get("url") or "").startswith(("chrome-extension:", "devtools:"))
                        ),
                        pages[-1],
                    )
                    return (str(chosen["webSocketDebuggerUrl"]), False, str(chosen.get("id") or ""))
        except Exception:
            pass

        with urllib.request.urlopen(f"{self.cdp_http_url}/json/version", timeout=timeout) as resp:
            ver = json.loads(resp.read().decode("utf-8"))
        return (str(ver["webSocketDebuggerUrl"]), True, None)

    def close(self) -> None:
        self._connected = False
        if self._ws is not None:
            self._ws.close()
            self._ws = None
        if self._reader is not None and self._reader.is_alive():
            self._reader.join(timeout=1.0)
        self._reader = None

    def _reader_loop(self) -> None:
        assert self._ws is not None
        try:
            while self._connected and self._ws is not None:
                raw = self._ws.recv_text()
                try:
                    msg = json.loads(raw)
                except Exception:
                    continue
                if "id" in msg and msg["id"] is not None:
                    cid = int(msg["id"])
                    with self._id_lock:
                        q = self._pending.get(cid)
                    if q is not None:
                        q.put(msg)
                else:
                    self._handle_event(msg)
        except Exception:
            self._connected = False
            with self._id_lock:
                for q in list(self._pending.values()):
                    q.put({"error": {"message": "CDP connection closed"}})

    def _handle_event(self, msg: dict[str, Any]) -> None:
        sid = msg.get("sessionId")
        if self._session_id and sid and sid != self._session_id:
            return
        method = str(msg.get("method") or "")
        params = msg.get("params") or {}

        if method == "Page.loadEventFired":
            self._load_event.set()
            return

        if method == "Runtime.consoleAPICalled":
            api_type = str(params.get("type") or "log").lower()
            level = {"error": "error", "assert": "error", "warning": "warn"}.get(api_type, "log")
            if level != "error":
                return
            parts: list[str] = []
            for arg in params.get("args") or []:
                if not isinstance(arg, dict):
                    continue
                if "value" in arg:
                    parts.append(str(arg.get("value")))
                elif arg.get("description"):
                    parts.append(str(arg["description"]))
            frames = (params.get("stackTrace") or {}).get("callFrames") or []
            top = frames[0] if frames else {}
            rec = ConsoleRecord(
                level="error",
                source="console",
                text=redact_text(" ".join(parts)[:1200] or "(empty console error)", self.extra_secrets),
                url=redact_url(str(top.get("url") or "")),
                line=int(top["lineNumber"]) if top.get("lineNumber") is not None else None,
            )
            with self._tel_lock:
                self._console.append(rec)
            return

        if method == "Runtime.exceptionThrown":
            details = params.get("exceptionDetails") or {}
            exc = details.get("exception") if isinstance(details.get("exception"), dict) else {}
            raw_text = str(exc.get("description") or exc.get("value") or details.get("text") or "Uncaught exception")
            frames = (details.get("stackTrace") or {}).get("callFrames") or []
            top = frames[0] if frames else {}
            rec = ConsoleRecord(
                level="error",
                source="exception",
                text=redact_text(raw_text[:1200], self.extra_secrets),
                url=redact_url(str(top.get("url") or details.get("url") or "")),
                line=int(top["lineNumber"]) if top.get("lineNumber") is not None else None,
            )
            with self._tel_lock:
                self._console.append(rec)
            return

        if method == "Log.entryAdded":
            entry = params.get("entry") or {}
            level = str(entry.get("level") or "info").lower()
            if level != "error":
                return
            rec = ConsoleRecord(
                level="error",
                source=str(entry.get("source") or "browser"),
                text=redact_text(str(entry.get("text") or "")[:1200], self.extra_secrets),
                url=redact_url(str(entry.get("url") or "")),
                line=int(entry["lineNumber"]) if entry.get("lineNumber") is not None else None,
            )
            with self._tel_lock:
                self._console.append(rec)
            return

        if method == "Network.requestWillBeSent":
            rid = str(params.get("requestId") or "")
            req = params.get("request") or {}
            if not rid:
                return
            rtype = str(params.get("type") or "")
            url = redact_url(str(req.get("url") or ""))
            # Preserve original timing on redirect chains if already tracked
            with self._tel_lock:
                self._last_network_activity = time.monotonic()
                self._pending_reqs[rid] = {
                    "method": str(req.get("method") or "GET"),
                    "url": url,
                    "resource_type": rtype,
                    "start_mono": time.monotonic(),
                    "status": None,
                    "mime_type": "",
                    "streaming": rtype.lower() in _STREAMING_TYPES or url.startswith(("ws:", "wss:")),
                }
            return

        if method == "Network.responseReceived":
            rid = str(params.get("requestId") or "")
            resp = params.get("response") or {}
            if not rid:
                return
            status = int(resp.get("status") or 0)
            mime = str(resp.get("mimeType") or "")
            rtype = str(params.get("type") or "")
            now = time.monotonic()
            with self._tel_lock:
                self._last_network_activity = now
                pending = self._pending_reqs.get(rid)
                if pending is None:
                    pending = {
                        "method": "GET",
                        "url": redact_url(str(resp.get("url") or "")),
                        "resource_type": rtype,
                        "start_mono": now,
                    }
                    self._pending_reqs[rid] = pending
                pending["status"] = status
                pending["mime_type"] = mime
                if rtype:
                    pending["resource_type"] = rtype
                if "text/event-stream" in mime.lower() or rtype.lower() in _STREAMING_TYPES:
                    pending["streaming"] = True
                pending["response_ms"] = round((now - float(pending["start_mono"])) * 1000.0, 1)
            return

        if method == "Network.loadingFinished":
            rid = str(params.get("requestId") or "")
            if not rid:
                return
            now = time.monotonic()
            with self._tel_lock:
                self._last_network_activity = now
                pending = self._pending_reqs.pop(rid, None)
                if pending is None:
                    return
                duration_ms = round((now - float(pending["start_mono"])) * 1000.0, 1)
                status = pending.get("status")
                ok = (200 <= status < 400) if isinstance(status, int) and status > 0 else True
                self._network.append(
                    NetworkRecord(
                        method=str(pending.get("method") or "GET"),
                        url=str(pending.get("url") or ""),
                        status=status,
                        ok=ok,
                        duration_ms=duration_ms,
                        resource_type=str(pending.get("resource_type") or ""),
                        mime_type=str(pending.get("mime_type") or ""),
                        streaming=bool(pending.get("streaming", False)),
                    )
                )
            return

        if method == "Network.loadingFailed":
            rid = str(params.get("requestId") or "")
            if not rid:
                return
            now = time.monotonic()
            err_text = redact_text(str(params.get("errorText") or "loading failed"), self.extra_secrets)
            canceled = bool(params.get("canceled"))
            with self._tel_lock:
                self._last_network_activity = now
                pending = self._pending_reqs.pop(rid, None)
                if pending is None:
                    return
                duration_ms = round((now - float(pending["start_mono"])) * 1000.0, 1)
                self._network.append(
                    NetworkRecord(
                        method=str(pending.get("method") or "GET"),
                        url=str(pending.get("url") or ""),
                        status=pending.get("status"),
                        ok=False,
                        duration_ms=duration_ms,
                        resource_type=str(pending.get("resource_type") or ""),
                        mime_type=str(pending.get("mime_type") or ""),
                        error_text=err_text,
                        canceled=canceled,
                        streaming=bool(pending.get("streaming", False)),
                    )
                )

    def call(self, method: str, params: dict[str, Any] | None = None, timeout: float = 10.0) -> dict[str, Any]:
        if not self._connected or self._ws is None:
            raise RuntimeError("CDP client is not connected")
        with self._id_lock:
            self._cmd_id += 1
            cid = self._cmd_id
            q: queue.Queue[dict[str, Any]] = queue.Queue(maxsize=1)
            self._pending[cid] = q
        payload: dict[str, Any] = {"id": cid, "method": method, "params": params or {}}
        if self._session_id:
            payload["sessionId"] = self._session_id
        try:
            self._ws.send_text(json.dumps(payload))
            resp = q.get(timeout=timeout)
        except queue.Empty as exc:
            raise TimeoutError(f"CDP {method} timed out after {timeout:.1f}s") from exc
        finally:
            with self._id_lock:
                self._pending.pop(cid, None)
        if "error" in resp:
            raise RuntimeError(f"CDP {method} error: {resp['error']}")
        return resp.get("result") or {}

    def clear_telemetry(self) -> None:
        with self._tel_lock:
            self._pending_reqs.clear()
            self._network.clear()
            self._console.clear()

    def snapshot_telemetry(self) -> tuple[list[ConsoleRecord], list[NetworkRecord]]:
        """Return captured console errors and network records (including completed responseReceived)."""
        with self._tel_lock:
            console = list(self._console)
            network = list(self._network)
            # Include any pending requests that already received an HTTP response (e.g. cached/slow/streaming)
            for p in self._pending_reqs.values():
                if p.get("status") is not None:
                    status = int(p["status"])
                    network.append(
                        NetworkRecord(
                            method=str(p.get("method") or "GET"),
                            url=str(p.get("url") or ""),
                            status=status,
                            ok=200 <= status < 400,
                            duration_ms=p.get("response_ms"),
                            resource_type=str(p.get("resource_type") or ""),
                            mime_type=str(p.get("mime_type") or ""),
                            streaming=bool(p.get("streaming", False)),
                        )
                    )
        return (console, network)

    def set_viewport(self, width: int, height: int, *, mobile: bool = False, device_scale_factor: float = 1.0) -> None:
        self.call(
            "Emulation.setDeviceMetricsOverride",
            {
                "width": int(width),
                "height": int(height),
                "deviceScaleFactor": float(device_scale_factor),
                "mobile": bool(mobile),
            },
        )
        try:
            self.call("Emulation.setTouchEmulationEnabled", {"enabled": bool(mobile), "maxTouchPoints": 5 if mobile else 1})
        except Exception:
            pass

    def set_cookie(
        self,
        *,
        name: str,
        value: str,
        url: str,
        http_only: bool = True,
        same_site: str = "Lax",
    ) -> None:
        self.call(
            "Network.setCookie",
            {
                "name": name,
                "value": value,
                "url": url,
                "httpOnly": http_only,
                "sameSite": same_site,
            },
        )

    def navigate(self, url: str, *, timeout: float = 15.0, settle_ms: int = 450) -> None:
        self._load_event.clear()
        res = self.call("Page.navigate", {"url": url}, timeout=timeout)
        if res.get("errorText"):
            raise RuntimeError(f"Page.navigate failed: {res['errorText']}")
        self._load_event.wait(timeout=min(timeout, 10.0))
        self.wait_network_quiet(quiet_ms=max(250, settle_ms), max_wait_s=min(timeout, 6.0))

    def wait_network_quiet(self, *, quiet_ms: int = 350, max_wait_s: float = 5.0) -> None:
        deadline = time.monotonic() + max_wait_s
        quiet_s = quiet_ms / 1000.0
        while time.monotonic() < deadline:
            with self._tel_lock:
                since = time.monotonic() - self._last_network_activity
            if since >= quiet_s:
                return
            time.sleep(0.05)

    def evaluate(self, expression: str, *, await_promise: bool = False, timeout: float = 10.0) -> Any:
        res = self.call(
            "Runtime.evaluate",
            {
                "expression": expression,
                "returnByValue": True,
                "awaitPromise": bool(await_promise),
            },
            timeout=timeout,
        )
        if res.get("exceptionDetails"):
            exc = res["exceptionDetails"]
            msg = (exc.get("exception") or {}).get("description") or exc.get("text") or "JS evaluation error"
            raise RuntimeError(redact_text(str(msg), self.extra_secrets))
        return (res.get("result") or {}).get("value")

    def capture_screenshot(self, *, fmt: str = "png", quality: int = 85) -> bytes:
        params: dict[str, Any] = {"format": fmt}
        if fmt == "jpeg":
            params["quality"] = quality
        res = self.call("Page.captureScreenshot", params, timeout=15.0)
        b64 = res.get("data")
        if not isinstance(b64, str) or not b64:
            raise RuntimeError("CDP Page.captureScreenshot returned empty data")
        return base64.b64decode(b64)

    def mouse_move(self, x: float, y: float, *, buttons: int = 0) -> None:
        self.call(
            "Input.dispatchMouseEvent",
            {"type": "mouseMoved", "x": float(x), "y": float(y), "buttons": int(buttons)},
        )

    def mouse_click(self, x: float, y: float, *, button: str = "left") -> None:
        self.mouse_move(x, y)
        self.call(
            "Input.dispatchMouseEvent",
            {"type": "mousePressed", "x": float(x), "y": float(y), "button": button, "clickCount": 1},
        )
        self.call(
            "Input.dispatchMouseEvent",
            {"type": "mouseReleased", "x": float(x), "y": float(y), "button": button, "clickCount": 1},
        )

    def mouse_down(self, x: float, y: float, *, button: str = "left") -> None:
        self.call(
            "Input.dispatchMouseEvent",
            {"type": "mousePressed", "x": float(x), "y": float(y), "button": button, "clickCount": 1, "buttons": 1},
        )

    def mouse_up(self, x: float, y: float, *, button: str = "left") -> None:
        self.call(
            "Input.dispatchMouseEvent",
            {"type": "mouseReleased", "x": float(x), "y": float(y), "button": button, "clickCount": 1, "buttons": 0},
        )

    def dispatch_key(self, key: str, modifiers: list[str] | None = None) -> None:
        mods = 0
        for m in modifiers or []:
            mods |= _MODIFIER_FLAGS.get(m.strip().lower(), 0)
        if key in _KEY_SPECS:
            code, vk, txt = _KEY_SPECS[key]
            key_name = " " if key == "Space" else key
        else:
            code = f"Key{key.upper()}" if len(key) == 1 and key.isalpha() else key
            vk = ord(key.upper()) if len(key) == 1 else 0
            txt = key if len(key) == 1 and mods == 0 else ""
            key_name = key

        down: dict[str, Any] = {
            "type": "keyDown",
            "key": key_name,
            "code": code,
            "windowsVirtualKeyCode": vk,
            "nativeVirtualKeyCode": vk,
            "modifiers": mods,
        }
        if txt:
            down["text"] = txt
            down["unmodifiedText"] = txt
        self.call("Input.dispatchKeyEvent", down)
        self.call(
            "Input.dispatchKeyEvent",
            {
                "type": "keyUp",
                "key": key_name,
                "code": code,
                "windowsVirtualKeyCode": vk,
                "nativeVirtualKeyCode": vk,
                "modifiers": mods,
            },
        )

    def insert_text(self, text: str) -> None:
        if text:
            self.call("Input.insertText", {"text": text})
