"""Unit tests for pure-stdlib RFC 6455 loopback WebSocket, telemetry analysis, and Vision QA."""

from __future__ import annotations

import base64
import hashlib
import http.server
import json
import socket
import struct
import tempfile
import threading
import unittest
from pathlib import Path

from nightwalk.cdp import LoopbackWebSocket
from nightwalk.checks import (
    analyze_network,
    build_defects_from_flow,
    compute_fingerprint,
    merge_console_errors,
    normalize_endpoint_key,
)
from nightwalk.config import NightwalkConfig
from nightwalk.models import (
    ConsoleRecord,
    LinkCheckResult,
    NetworkRecord,
    TargetSpec,
    ViewportSpec,
    VisionAssessment,
    VisionIssue,
)
from nightwalk.vision import inspect_screenshot

_WS_GUID = "258EAFA5-E914-47DA-95CA-C5AB0DC85B11"


def _ws_pack_server_text(text: str) -> bytes:
    payload = text.encode("utf-8")
    out = bytearray([0x81])
    n = len(payload)
    if n < 126:
        out.append(n)
    elif n < 65536:
        out.append(126)
        out.extend(struct.pack("!H", n))
    else:
        out.append(127)
        out.extend(struct.pack("!Q", n))
    out.extend(payload)
    return bytes(out)


def _ws_read_client_frame(conn: socket.socket) -> tuple[int, bytes]:
    hdr = conn.recv(2)
    opcode = hdr[0] & 0x0F
    masked = bool(hdr[1] & 0x80)
    length = hdr[1] & 0x7F
    if length == 126:
        length = struct.unpack("!H", conn.recv(2))[0]
    elif length == 127:
        length = struct.unpack("!Q", conn.recv(8))[0]
    mask = conn.recv(4) if masked else b""
    buf = bytearray()
    while len(buf) < length:
        chunk = conn.recv(length - len(buf))
        if not chunk:
            break
        buf.extend(chunk)
    data = bytes(buf)
    if masked:
        data = bytes(b ^ mask[i & 3] for i, b in enumerate(data))
    return (opcode, data)


class TestLoopbackWebSocket(unittest.TestCase):
    def test_handshake_ping_and_echo(self) -> None:
        srv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        srv.bind(("127.0.0.1", 0))
        port = srv.getsockname()[1]
        srv.listen(1)

        received: list[str] = []

        def _worker() -> None:
            conn, _ = srv.accept()
            try:
                raw = b""
                while b"\r\n\r\n" not in raw:
                    raw += conn.recv(1024)
                key = ""
                for line in raw.decode().split("\r\n"):
                    if line.lower().startswith("sec-websocket-key:"):
                        key = line.split(":", 1)[1].strip()
                accept = base64.b64encode(hashlib.sha1((key + _WS_GUID).encode()).digest()).decode()
                conn.sendall(
                    (
                        "HTTP/1.1 101 Switching Protocols\r\n"
                        "Upgrade: websocket\r\n"
                        "Connection: Upgrade\r\n"
                        f"Sec-WebSocket-Accept: {accept}\r\n\r\n"
                    ).encode()
                )
                _, data = _ws_read_client_frame(conn)
                received.append(data.decode())
                # Send a PING first, then a large text frame (>126 bytes)
                conn.sendall(bytes([0x89, 2]) + b"hi")
                op_pong, pong_payload = _ws_read_client_frame(conn)
                assert op_pong == 0xA and pong_payload == b"hi"
                conn.sendall(_ws_pack_server_text("reply:" + ("x" * 300)))
            finally:
                conn.close()
                srv.close()

        t = threading.Thread(target=_worker, daemon=True)
        t.start()

        ws = LoopbackWebSocket(f"ws://127.0.0.1:{port}/devtools/page/1", timeout=5.0)
        ws.connect()
        ws.send_text('{"id":1,"method":"Page.enable"}')
        reply = ws.recv_text()
        ws.close()
        t.join(timeout=3.0)

        self.assertEqual(received, ['{"id":1,"method":"Page.enable"}'])
        self.assertEqual(reply, "reply:" + ("x" * 300))


class TestChecksAndVision(unittest.TestCase):
    def test_network_analysis_detects_slow_and_ignores_streams(self) -> None:
        direct = [
            NetworkRecord(method="GET", url="http://127.0.0.1:8480/api/o11y/series?window=24h", status=200, ok=True, duration_ms=420.5, resource_type="Fetch"),
            NetworkRecord(method="GET", url="http://127.0.0.1:8480/api/events", status=200, ok=True, duration_ms=5000.0, resource_type="EventSource", streaming=True),
            NetworkRecord(method="GET", url="http://127.0.0.1:8480/api/broken", status=500, ok=False, duration_ms=80.0, resource_type="Fetch"),
            NetworkRecord(method="GET", url="http://127.0.0.1:8480/api/canceled", status=None, ok=False, duration_ms=10.0, canceled=True),
        ]
        failed, slow = analyze_network(direct, [], slow_threshold_ms=300.0)
        self.assertEqual(len(failed), 1)
        self.assertEqual(failed[0].status, 500)
        self.assertEqual(len(slow), 1)
        self.assertIn("/api/o11y/series", slow[0].url)

    def test_fingerprint_stability_across_dynamic_values(self) -> None:
        fp1 = compute_fingerprint("app", "console_error", "TypeError at 123ms for 123e4567-e89b-12d3-a456-426614174000")
        fp2 = compute_fingerprint("app", "console_error", "TypeError at 987ms for 999e4567-e89b-12d3-a456-426614174999")
        self.assertEqual(fp1, fp2)
        self.assertEqual(
            normalize_endpoint_key("http://127.0.0.1:8480/api/items/42?b=2&a=1"),
            "/api/items/<n>?a&b",
        )

    def test_merge_console_and_build_defects(self) -> None:
        c1 = ConsoleRecord(level="error", source="console", text="Failed to fetch /api/x", url="http://127.0.0.1:8480/app.js", line=12)
        c2 = ConsoleRecord(level="error", source="console", text="Failed to fetch /api/x", url="http://127.0.0.1:8480/app.js", line=12)
        merged = merge_console_errors([c1], [c2])
        self.assertEqual(len(merged), 1)

        target = TargetSpec(name="demo", base_url="http://127.0.0.1:8080", target_repo="demo")
        vp = ViewportSpec(name="fold-folded", width=374, height=844, mobile=True)
        va = VisionAssessment(
            screenshot_path="/tmp/shot.png",
            verdict="FAIL",
            score_10=5.0,
            model="test-vlm",
            issues=[
                VisionIssue(severity="major", category="overlap", element="topbar", description="Pill overlaps title"),
                VisionIssue(severity="minor", category="contrast", element="footer", description="Slight nit"),
            ],
        )
        defects = build_defects_from_flow(
            target=target,
            flow_name="main",
            viewport=vp,
            step_errors=[],
            console_errors=merged,
            failed_requests=[],
            slow_endpoints=[],
            broken_links=[LinkCheckResult(url="http://127.0.0.1:8080/missing", kind="link", status=404, ok=False, duration_ms=12.0)],
            layout_metrics={"horizontalOverflowPx": 24, "scrollWidth": 398, "viewportWidth": 374, "emojiNodes": []},
            vision_assessments=[va],
            screenshots=["/tmp/shot.png"],
            slow_threshold_ms=300.0,
            repro_steps=["1. Open home"],
        )
        cats = {d.category for d in defects}
        self.assertEqual(cats, {"console_error", "broken_link", "layout_defect", "vision_defect"})
        # Minor vision nit must not become a defect
        self.assertEqual(sum(1 for d in defects if d.category == "vision_defect"), 1)

    def test_vision_qa_parses_mock_openai_response(self) -> None:
        class _Handler(http.server.BaseHTTPRequestHandler):
            def do_POST(self) -> None:
                length = int(self.headers.get("Content-Length", "0"))
                _ = self.rfile.read(length)
                body = json.dumps(
                    {
                        "choices": [
                            {
                                "message": {
                                    "content": json.dumps(
                                        {
                                            "verdict": "PASS",
                                            "score_10": 9,
                                            "summary": "Clean layout across viewport.",
                                            "issues": [],
                                        }
                                    )
                                }
                            }
                        ]
                    }
                ).encode()
                self.send_response(200)
                self.send_header("Content-Type", "application/json")
                self.send_header("Content-Length", str(len(body)))
                self.end_headers()
                self.wfile.write(body)

            def log_message(self, format: str, *args: object) -> None:
                return

        server = http.server.HTTPServer(("127.0.0.1", 0), _Handler)
        t = threading.Thread(target=server.serve_forever, daemon=True)
        t.start()
        try:
            with tempfile.TemporaryDirectory() as td:
                shot = Path(td) / "shot.png"
                shot.write_bytes(b"\x89PNG\r\n\x1a\nfakebytes")
                cfg = NightwalkConfig(
                    config_path=Path(td) / "config.json",
                    vlm_url=f"http://127.0.0.1:{server.server_port}/v1",
                    vlm_model="mock-vision",
                )
                va = inspect_screenshot(
                    cfg,
                    shot,
                    target_name="demo",
                    flow_name="home",
                    viewport=ViewportSpec(name="desktop", width=1280, height=800),
                )
                self.assertEqual(va.verdict, "PASS")
                self.assertEqual(va.score_10, 9.0)
                self.assertEqual(va.issues, [])
        finally:
            server.shutdown()
            server.server_close()


if __name__ == "__main__":
    unittest.main()
