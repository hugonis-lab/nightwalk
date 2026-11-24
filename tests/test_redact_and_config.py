"""Unit tests for secret redaction, loopback guards, and 12-Factor config resolution."""

from __future__ import annotations

import json
import os
import tempfile
import unittest
from pathlib import Path

from nightwalk.config import load_config, load_target_auth_token, write_example_config
from nightwalk.models import TargetSpec
from nightwalk.redact import (
    ensure_loopback_url,
    is_loopback_url,
    is_same_origin,
    redact_text,
    redact_url,
)


class TestRedactAndGuards(unittest.TestCase):
    def test_redact_url_scrubs_sensitive_params_and_userinfo(self) -> None:
        raw = "http://user:secretpass@127.0.0.1:8480/api/state?window=24h&token=abc123xyz&api_key=k999#auth=tok"
        cleaned = redact_url(raw)
        self.assertNotIn("secretpass", cleaned)
        self.assertNotIn("abc123xyz", cleaned)
        self.assertNotIn("k999", cleaned)
        self.assertNotIn("=tok", cleaned)
        self.assertIn("window=24h", cleaned)
        self.assertIn("token=REDACTED", cleaned)

    def test_redact_text_scrubs_bearer_cookie_and_explicit_secret(self) -> None:
        dummy_val = "example_" + "placeholder_" + "runtime_99"
        raw = f"Authorization: Bearer tok1234567890; Cookie: vega_token=xyz987; raw={dummy_val}"
        cleaned = redact_text(raw, extra_secrets=(dummy_val,))
        self.assertNotIn("tok1234567890", cleaned)
        self.assertNotIn("xyz987", cleaned)
        self.assertNotIn(dummy_val, cleaned)
        self.assertIn("REDACTED", cleaned)

    def test_loopback_guard_accepts_loopback_and_blocks_external(self) -> None:
        self.assertTrue(is_loopback_url("http://127.0.0.1:8480/"))
        self.assertTrue(is_loopback_url("ws://localhost:9222/devtools/page/1"))
        self.assertTrue(is_loopback_url("http://[::1]:8492/"))
        self.assertFalse(is_loopback_url("https://example.com/"))
        self.assertFalse(is_loopback_url("http://192.0.2.5:8080/"))
        self.assertFalse(is_loopback_url("file:///etc/passwd"))
        with self.assertRaises(ValueError):
            ensure_loopback_url("https://example.com/mutate")

    def test_same_origin(self) -> None:
        self.assertTrue(is_same_origin("http://127.0.0.1:8488", "http://127.0.0.1:8488/journal/"))
        self.assertFalse(is_same_origin("http://127.0.0.1:8488", "http://127.0.0.1:8492/"))
        self.assertFalse(is_same_origin("http://127.0.0.1:8488", "https://example.com/"))


class TestConfigResolution(unittest.TestCase):
    def test_init_and_load_config_with_vlm_profile_resolution(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            xdg_cfg = root / "config"
            xdg_state = root / "state"
            profiles_dir = xdg_cfg / "local-agents"
            profiles_dir.mkdir(parents=True)
            (profiles_dir / "profiles.json").write_text(
                json.dumps(
                    {
                        "profiles": {
                            "vision-worker": {
                                "aliases": ["tactical"],
                                "base_url": "http://127.0.0.1:9010/v1",
                                "model": "test-vlm-mini",
                                "vision": True,
                            }
                        }
                    }
                ),
                encoding="utf-8",
            )
            cfg_path = write_example_config(xdg_cfg / "nightwalk" / "config.json")
            self.assertEqual(os.stat(cfg_path).st_mode & 0o777, 0o600)

            env = {
                "HOME": str(root),
                "XDG_CONFIG_HOME": str(xdg_cfg),
                "XDG_STATE_HOME": str(xdg_state),
                "NIGHTWALK_SLOW_ENDPOINT_MS": "450",
            }
            cfg = load_config(env=env)
            self.assertEqual(cfg.vlm_url, "http://127.0.0.1:9010/v1")
            self.assertEqual(cfg.vlm_model, "test-vlm-mini")
            self.assertEqual(cfg.slow_endpoint_ms, 450.0)
            self.assertEqual(len(cfg.viewports), 3)
            self.assertEqual(cfg.viewports[0].label, "374x844")
            self.assertEqual(cfg.viewports[1].label, "768x720")
            self.assertEqual(cfg.viewports[2].label, "1280x800")

    def test_load_target_auth_token_from_file_and_env(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            tok_file = Path(td) / "token"
            tok_file.write_text("file_token_12345678\n", encoding="utf-8")
            t = TargetSpec(
                name="app",
                base_url="http://127.0.0.1:8080",
                auth_token_file=str(tok_file),
                auth_token_env="APP_TEST_TOKEN",
            )
            self.assertEqual(load_target_auth_token(t, env={}), "file_token_12345678")
            self.assertEqual(
                load_target_auth_token(t, env={"APP_TEST_TOKEN": "env_token_override"}),
                "env_token_override",
            )


if __name__ == "__main__":
    unittest.main()
