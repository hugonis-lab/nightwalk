"""Secret redaction and loopback-only safety guardrails."""

from __future__ import annotations

import ipaddress
import re
import urllib.parse

LOOPBACK_HOSTS = frozenset({"127.0.0.1", "localhost", "::1"})

SENSITIVE_PARAM_EXACT = frozenset(
    {
        "token",
        "key",
        "apikey",
        "api_key",
        "secret",
        "password",
        "passwd",
        "pwd",
        "auth",
        "authorization",
        "access_token",
        "refresh_token",
        "id_token",
        "session",
        "session_id",
        "sid",
        "sig",
        "signature",
        "jwt",
        "bearer",
        "credential",
        "credentials",
        "cookie",
        "code",
    }
)

SENSITIVE_PARAM_SUFFIXES = (
    "_token",
    "_key",
    "_secret",
    "_password",
    "_passwd",
    "_auth",
    "_sig",
    "_signature",
    "_jwt",
)

_SENSITIVE_QUERY_RE = re.compile(
    r"([?&#](?:[A-Za-z0-9._-]*(?:token|key|secret|pass(?:wd|word)?|auth|jwt|sig(?:nature)?|bearer|session|cookie)[A-Za-z0-9._-]*)=)([^&#\s\"'<>]+)",
    re.IGNORECASE,
)
_BEARER_RE = re.compile(r"(Bearer\s+)[A-Za-z0-9._~+/=-]{8,}", re.IGNORECASE)
_COOKIE_TOKEN_RE = re.compile(r"((?:vega_token|session|auth|token)\s*=\s*)([^;\s\"']+)", re.IGNORECASE)


def is_sensitive_param(name: str) -> bool:
    low = name.strip().lower()
    if low in SENSITIVE_PARAM_EXACT:
        return True
    return any(low.endswith(sfx) for sfx in SENSITIVE_PARAM_SUFFIXES)


def _redact_kv(raw: str) -> str:
    if not raw or "=" not in raw:
        return raw
    pairs = urllib.parse.parse_qsl(raw, keep_blank_values=True)
    if not pairs:
        return raw
    cleaned = [(k, "REDACTED" if is_sensitive_param(k) else v) for k, v in pairs]
    return urllib.parse.urlencode(cleaned, safe=":/")


def redact_url(url: str) -> str:
    """Scrub sensitive query params, fragment params, and userinfo from a URL."""
    if not url:
        return ""
    try:
        parts = urllib.parse.urlsplit(str(url))
    except Exception:
        return redact_text(str(url))

    netloc = parts.netloc
    if "@" in netloc:
        userinfo, hostport = netloc.rsplit("@", 1)
        if ":" in userinfo:
            user, _ = userinfo.split(":", 1)
            netloc = f"{user}:REDACTED@{hostport}"
        else:
            netloc = f"REDACTED@{hostport}"

    query = _redact_kv(parts.query)
    fragment = _redact_kv(parts.fragment) if "=" in parts.fragment else parts.fragment
    return urllib.parse.urlunsplit((parts.scheme, netloc, parts.path, query, fragment))


def redact_text(text: str, extra_secrets: tuple[str, ...] = ()) -> str:
    """Scrub sensitive query tokens, bearer headers, cookie tokens, and explicit secrets."""
    if not text:
        return ""
    out = str(text)
    for secret in extra_secrets:
        if secret and len(secret) >= 8:
            out = out.replace(secret, "REDACTED")
    out = _SENSITIVE_QUERY_RE.sub(r"\1REDACTED", out)
    out = _BEARER_RE.sub(r"\1REDACTED", out)
    out = _COOKIE_TOKEN_RE.sub(r"\1REDACTED", out)
    return out


def is_loopback_host(hostname: str) -> bool:
    """Return True iff hostname is strictly loopback (127.0.0.0/8, ::1, localhost)."""
    host = (hostname or "").strip().lower().strip("[]")
    if not host:
        return False
    if host in LOOPBACK_HOSTS:
        return True
    try:
        ip = ipaddress.ip_address(host)
        return ip.is_loopback
    except ValueError:
        return False


def is_loopback_url(url: str) -> bool:
    """Return True iff url uses http/https/ws/wss on a strictly loopback host."""
    try:
        parts = urllib.parse.urlsplit(url)
    except Exception:
        return False
    if parts.scheme.lower() not in ("http", "https", "ws", "wss"):
        return False
    return is_loopback_host(parts.hostname or "")


def ensure_loopback_url(url: str, *, context: str = "target URL") -> str:
    """Raise ValueError unless url points strictly to a loopback host."""
    if not is_loopback_url(url):
        raise ValueError(
            f"Refusing non-loopback {context} {redact_url(url)!r}; loopback_only safety guard is enabled"
        )
    return url


def is_same_origin(base_url: str, candidate_url: str) -> bool:
    """Return True iff candidate_url shares exact scheme, host, and effective port with base_url."""
    try:
        b = urllib.parse.urlsplit(base_url)
        c = urllib.parse.urlsplit(candidate_url)
    except Exception:
        return False
    b_scheme = b.scheme.lower()
    c_scheme = c.scheme.lower()
    if b_scheme != c_scheme or b_scheme not in ("http", "https"):
        return False
    b_port = b.port or (443 if b_scheme == "https" else 80)
    c_port = c.port or (443 if c_scheme == "https" else 80)
    return (b.hostname or "").lower() == (c.hostname or "").lower() and b_port == c_port
