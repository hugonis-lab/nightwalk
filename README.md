# Nightwalk

Nightly customer-zero interactive dogfooding runner for local web applications and PWAs. Nightwalk drives real browser flows over Chrome DevTools Protocol across folded mobile, unfolded foldable, and desktop viewports. It collects network latency, console errors, and link health, runs multimodal Vision QA on screenshots, and files deduplicated bug tickets.

Built with Python 3.11+ standard library only (zero pip dependencies) and strict 12-Factor separation between portable code and machine-local config.

## Quick Start & CLI Usage

```bash
chmod +x bin/nightwalk
ln -sf "$PWD/bin/nightwalk" "$HOME/.local/bin/nightwalk"

nightwalk init-config
nightwalk check
nightwalk run --dry-run --json
nightwalk run
nightwalk status
nightwalk history --limit 10
nightwalk defects --limit 20
```

## What It Does

- **Isolated browser pool execution (`vega-browser` + stdlib CDP)**:
  - Spawns one ephemeral browser instance per run via `POST /api/instances` and purges its profile on teardown.
  - Drives real CDP interactions (`Emulation.setDeviceMetricsOverride`, clicks, typing, keyboard shortcuts, and continuous chart scrubbing) over a loopback RFC 6455 WebSocket.
- **Deterministic telemetry & layout checks**:
  - Captures console errors and uncaught JS exceptions from both direct CDP events and the browser pool DevTools ring buffer.
  - Flags failed HTTP requests (`>= 400` or non-canceled load errors) and slow endpoints over `300ms`, excluding WebSocket and SSE streams.
  - Probes same-origin `<a href>` and `<img src>` assets with strictly read-only HTTP `GET` requests.
  - Audits horizontal overflow (`scrollWidth > clientWidth + 4px`), broken images (`naturalWidth === 0`), and decorative emoji glyphs in UI chrome.
- **Multimodal Vision QA**:
  - Sends captured PNG screenshots and grounded DOM telemetry to any local OpenAI-compatible vision `/v1/chat/completions` endpoint.
  - Promotes only concrete `critical` or `major` visual regressions with localized element citations into tickets; logs minor nits in the report.
- **Two-layer deduplicated bug ticket filing**:
  - Computes normalized defect fingerprints (`[dogfood:<hash>]`) so identical defects across viewports or nights collapse into one ticket.
  - Deduplicates against both live open backlog tickets (`vega-pulse list --all --json`) and a `0600` SQLite WAL cooldown ledger.
  - Enforces a per-run filing cap and collapses unreachable services into one critical ticket instead of cascading errors.
- **Reports and calm status panel**:
  - Atomically writes nightly Markdown reports (`$NIGHTWALK_REPORT_DIR/YYYY-MM-DD-nightwalk.md`) and a `panel.schema.json`-compatible read-first status card.

## Safety & Read-Only Invariants

- Strictly read-only: flows navigate, filter, scrub charts, and probe same-origin links via `GET` without mutating services or submitting forms.
- Loopback-only guard (`NIGHTWALK_LOOPBACK_ONLY=1`) refuses navigation, CDP sockets, and link probes targeting non-loopback hosts.
- Secret redaction strips tokens, bearer headers, and sensitive query parameters from telemetry, reports, SQLite state, and filed tickets.
- Auth tokens load at runtime from `0600` files or environment variables and inject via HttpOnly CDP cookies.

## Configuration

Settings resolve in priority order: CLI flags, environment variables in [`.env.example`](.env.example), `$XDG_CONFIG_HOME/nightwalk/config.json`, and portable defaults. See [`examples/config.example.json`](examples/config.example.json) for a full declarative target and flow template.

| Variable | Purpose | Default |
| --- | --- | --- |
| `NIGHTWALK_BROWSER_URL` | Loopback browser-pool HTTP API URL | `http://127.0.0.1:8490` |
| `NIGHTWALK_BROWSER_ENGINE` | Browser engine (`chromium` or `obscura`) | `chromium` |
| `NIGHTWALK_BROWSER_HEADLESS` | Request headless isolated instance (`1` or `0`) | `1` |
| `NIGHTWALK_CONFIG` | Path to machine-local targets & flows JSON | `$XDG_CONFIG_HOME/nightwalk/config.json` |
| `NIGHTWALK_VLM_PROFILE` | Vision profile in `local-agents/profiles.json` | `tactical` |
| `NIGHTWALK_VLM_URL` | Direct OpenAI-compatible `/v1` base URL override | unset |
| `NIGHTWALK_VLM_MODEL` | Vision model ID override | unset |
| `NIGHTWALK_SLOW_ENDPOINT_MS` | Slow endpoint threshold in milliseconds | `300` |
| `NIGHTWALK_STATE_DIR` | SQLite ledger and screenshot artifact directory | `$XDG_STATE_HOME/nightwalk` |
| `NIGHTWALK_REPORT_DIR` | Nightly Markdown report directory | `$HOME/Documents/reports/dogfood` |
| `NIGHTWALK_PANEL_PATH` | Status panel JSON path (`off` disables) | `$XDG_STATE_HOME/vega/panels/12-dogfood.json` |
| `NIGHTWALK_TICKET_PRIORITY` | Priority for auto-filed bug tickets | `P2` |
| `NIGHTWALK_TICKET_COOLDOWN_HOURS` | Deduplication cooldown after filing | `72` |
| `NIGHTWALK_MAX_TICKETS_PER_RUN` | Maximum tickets filed in a single run | `8` |

## Nightly Systemd User Timer (02:30 America/Chicago)

Install the bundled generic systemd user units:

```bash
mkdir -p "$HOME/.config/systemd/user"
cp systemd/nightwalk.{service,timer} "$HOME/.config/systemd/user/"
systemctl --user daemon-reload
systemctl --user enable --now nightwalk.timer
systemctl --user list-timers nightwalk.timer
```

## Extending With Custom Flow Steps

Register additional read-only step handlers in Python via `nightwalk.flows.register_step(action_name, handler_fn)`.

## Tests

```bash
python3 -m unittest discover -s tests -v
```

## License

MIT — see [LICENSE](LICENSE).
