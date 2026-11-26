"""Sensitive header, URL, body, and wire-text redaction with deterministic SHA-256 fingerprints."""

from __future__ import annotations

import hashlib
import re
import urllib.parse
from typing import Any, Dict, Mapping, Sequence, Tuple

SENSITIVE_HEADER_NAMES = frozenset(
    {
        "authorization",
        "api-key",
        "x-api-key",
        "x-openai-api-key",
        "x-goog-api-key",
        "x-auth-token",
        "cookie",
        "set-cookie",
        "proxy-authorization",
    }
)

_SENSITIVE_HEADER_SUBSTRINGS = (
    "auth",
    "api-key",
    "apikey",
    "token",
    "secret",
    "cookie",
    "password",
    "passwd",
    "credential",
)

RECOGNIZED_AUTH_SCHEMES = frozenset(
    {
        "bearer",
        "basic",
        "digest",
        "token",
        "apikey",
        "aws4-hmac-sha256",
        "hoba",
        "mutual",
        "negotiate",
        "oauth",
        "scram-sha-1",
        "scram-sha-256",
        "vapid",
    }
)

SAFE_EXPORT_QUERY_KEYS = frozenset(
    {
        "api-version",
        "version",
        "alt",
        "stream",
    }
)

_SENSITIVE_BODY_KEY_RE = re.compile(
    r"(?i)(?:^|[_\-\.])("
    r"api[_\-]?key|secret|password|passwd|auth|authorization|cookie|"
    r"credential|credentials|bearer|private[_\-]?key|client[_\-]?secret|"
    r"access[_\-]?token|refresh[_\-]?token|id[_\-]?token|session[_\-]?token|auth[_\-]?token"
    r")$"
)

# Common credential / API-key value shapes scrubbed from exported text and wire excerpts.
_SECRET_VALUE_PATTERNS = (
    re.compile(r"\b(?:sk|rk|pk)-(?:proj-|ant-|live-|test-)?[A-Za-z0-9_\-]{12,}\b"),
    re.compile(r"\b(?:ghp|gho|ghu|ghs|ghr)_[A-Za-z0-9]{16,}\b"),
    re.compile(r"\bAIza[0-9A-Za-z_\-]{20,}\b"),
    re.compile(r"\bxox[baprs]-[0-9A-Za-z\-]{10,}\b"),
    re.compile(r"\bAKIA[0-9A-Z]{16}\b"),
    re.compile(r"\beyJ[A-Za-z0-9_\-]{10,}\.[A-Za-z0-9_\-]{10,}\.[A-Za-z0-9_\-]{10,}\b"),
    re.compile(r"(?i)\b(Bearer|Basic)\s+[A-Za-z0-9._~+/=\-]{8,}"),
    re.compile(
        r"(?i)\b(api[_\-]?key|access[_\-]?token|auth[_\-]?token|secret|password|passwd)"
        r"(\s*[:=]\s*[\"']?)([^\s\"',;}{&]{4,})"
    ),
)

SAFE_REPRO_PROTOCOL_KEYS = frozenset(
    {
        "model",
        "stream",
        "max_tokens",
        "max_completion_tokens",
        "max_output_tokens",
        "max_new_tokens",
        "temperature",
        "top_p",
        "top_k",
        "seed",
        "ignore_eos",
        "stop",
        "stop_token_ids",
        "stop_regex",
        "stream_options",
        "sampling_params",
        "options",
        "extra_request_body",
        "tool_choice",
        "parallel_tool_calls",
        "reasoning",
        "think",
    }
)


def fingerprint8(value: str) -> str:
    """Return the first 8 hex characters of SHA-256(value) for equality checks."""
    return hashlib.sha256(value.encode("utf-8", errors="surrogateescape")).hexdigest()[:8]


def is_sensitive_header(name: str) -> bool:
    low = name.strip().lower()
    if low in SENSITIVE_HEADER_NAMES:
        return True
    return any(sub in low for sub in _SENSITIVE_HEADER_SUBSTRINGS)


def redact_header_value(name: str, value: str) -> str:
    """Mask sensitive header values, preserving only recognized auth scheme prefixes."""
    low = name.strip().lower()
    if not is_sensitive_header(low):
        return value
    digest = fingerprint8(value)
    if low in ("authorization", "proxy-authorization"):
        parts = value.strip().split(None, 1)
        if len(parts) == 2 and parts[0].lower() in RECOGNIZED_AUTH_SCHEMES:
            return f"{parts[0]} $REDACTED_sha256:{digest}"
    return f"$REDACTED_sha256:{digest}"


def redact_headers(headers: Mapping[str, str] | Sequence[Tuple[str, str]]) -> Dict[str, str]:
    """Return lowercase-keyed header dict with sensitive values redacted."""
    items = headers.items() if isinstance(headers, Mapping) else headers
    out: Dict[str, str] = {}
    for k, v in items:
        low = k.strip().lower()
        if not low:
            continue
        out[low] = redact_header_value(low, v)
    return out


def extract_header_secret_values(headers: Mapping[str, str], *, min_length: int = 6) -> list[str]:
    """Return sensitive header and token values for scrubbing reflections."""
    secrets_out: list[str] = []
    for k, v in headers.items():
        if not is_sensitive_header(k) or not isinstance(v, str):
            continue
        raw = v.strip()
        if len(raw) >= min_length:
            secrets_out.append(raw)
        parts = raw.split(None, 1)
        if len(parts) == 2 and parts[0].lower() in RECOGNIZED_AUTH_SCHEMES and len(parts[1].strip()) >= min_length:
            secrets_out.append(parts[1].strip())
    return sorted(set(secrets_out), key=len, reverse=True)


def extract_query_secret_values(query: str) -> list[str]:
    """Return non-allowlisted query values that can be echoed by a target."""
    return [value for name, value in urllib.parse.parse_qsl(query)
            if len(value) >= 6 and name.lower() not in SAFE_EXPORT_QUERY_KEYS]


def scrub_known_secrets(text: str, known_secrets: Sequence[str] = ()) -> str:
    """Scrub exact known outgoing secret strings plus standard secret patterns from text."""
    if not text:
        return text
    out = text
    for sec in sorted(set(s for s in known_secrets if isinstance(s, str) and len(s) >= 6), key=len, reverse=True):
        if sec in out:
            out = out.replace(sec, f"$REDACTED_sha256:{fingerprint8(sec)}")
    return redact_secret_text(out)


def redact_secret_text(text: str) -> str:
    """Scrub recognized credential patterns from free-form text or wire excerpts."""
    if not text:
        return text
    out = text
    for idx, pat in enumerate(_SECRET_VALUE_PATTERNS):
        if idx == 6:
            out = pat.sub(lambda m: f"{m.group(1)} $REDACTED_sha256:{fingerprint8(m.group(0))}", out)
        elif idx == 7:
            out = pat.sub(
                lambda m: f"{m.group(1)}{m.group(2)}$REDACTED_sha256:{fingerprint8(m.group(3))}",
                out,
            )
        else:
            out = pat.sub(lambda m: f"$REDACTED_sha256:{fingerprint8(m.group(0))}", out)
    return out


def has_control_chars(text: str) -> bool:
    return any(ord(ch) < 32 or ord(ch) == 127 for ch in text)


def sanitize_url_for_error(url: str) -> str:
    """Return scheme://host[:port]/path with credentials, query, and fragment stripped."""
    if not isinstance(url, str) or not url or has_control_chars(url):
        return "<invalid-url>"
    try:
        parsed = urllib.parse.urlsplit(url)
    except ValueError:
        return "<invalid-url>"
    if parsed.scheme not in ("http", "https") or not parsed.hostname:
        return "<invalid-url>"
    host = parsed.hostname
    if ":" in host and not host.startswith("["):
        host = f"[{host}]"
    try:
        port = parsed.port
    except ValueError:
        return "<invalid-url>"
    netloc = f"{host}:{port}" if port is not None else host
    path = redact_secret_text(parsed.path or "/")
    suffix = "?<redacted>" if parsed.query else ""
    return f"{parsed.scheme}://{netloc}{path}{suffix}"


def sanitize_url_for_export(url: str) -> str:
    """Validate HTTP(S) URL, strip userinfo/fragment, and redact non-allowlisted query params."""
    if not isinstance(url, str) or not url or has_control_chars(url):
        raise ValueError("Invalid or unsafe URL")
    parsed = urllib.parse.urlsplit(url)
    if parsed.scheme not in ("http", "https") or not parsed.hostname:
        raise ValueError("URL must use http:// or https:// with a valid hostname")
    host = parsed.hostname
    if ":" in host and not host.startswith("["):
        host = f"[{host}]"
    port = parsed.port  # raises ValueError if invalid
    netloc = f"{host}:{port}" if port is not None else host
    path = redact_secret_text(parsed.path or "/")

    if parsed.query:
        pairs = urllib.parse.parse_qsl(parsed.query, keep_blank_values=True)
        safe_pairs = []
        for k, v in pairs:
            if k.lower() in SAFE_EXPORT_QUERY_KEYS and not _looks_like_secret(v):
                safe_pairs.append((k, v))
            else:
                safe_pairs.append((k, f"REDACTED_sha256:{fingerprint8(v)}"))
        query = urllib.parse.urlencode(safe_pairs, safe=":")
    else:
        query = ""

    return urllib.parse.urlunsplit((parsed.scheme, netloc, path, query, ""))


def _looks_like_secret(val: str) -> bool:
    return redact_secret_text(val) != val


def _collect_sensitive_values(obj: Any, out: list[str]) -> None:
    if isinstance(obj, dict):
        for k, v in obj.items():
            if _SENSITIVE_BODY_KEY_RE.search(str(k)) and isinstance(v, str) and len(v) >= 6:
                out.append(v)
            else:
                _collect_sensitive_values(v, out)
    elif isinstance(obj, list):
        for item in obj:
            _collect_sensitive_values(item, out)


def sanitize_body_for_export(obj: Any, *, key_name: str = "") -> Any:
    """Recursively redact sensitive fields, known secret values, and credential-shaped strings."""
    known_secrets: list[str] = []
    _collect_sensitive_values(obj, known_secrets)
    # Longest first to avoid partial overlap
    known_secrets = sorted(set(known_secrets), key=len, reverse=True)

    def _scrub_str(text: str) -> str:
        s = redact_secret_text(text)
        for sec in known_secrets:
            if sec in s:
                s = s.replace(sec, f"$REDACTED_sha256:{fingerprint8(sec)}")
        return s

    def _walk(node: Any) -> Any:
        if isinstance(node, dict):
            out: Dict[str, Any] = {}
            for k, v in node.items():
                k_str = str(k)
                if _SENSITIVE_BODY_KEY_RE.search(k_str):
                    out[k_str] = f"$REDACTED_sha256:{fingerprint8(str(v))}"
                else:
                    out[k_str] = _walk(v)
            return out
        if isinstance(node, list):
            return [_walk(item) for item in node]
        if isinstance(node, str):
            return _scrub_str(node)
        return node

    return _walk(obj)


SAFE_SCALAR_PROTOCOL_KEYS = frozenset(
    {
        "model",
        "stream",
        "max_tokens",
        "max_completion_tokens",
        "max_output_tokens",
        "max_new_tokens",
        "temperature",
        "top_p",
        "top_k",
        "seed",
        "ignore_eos",
        "parallel_tool_calls",
        "think",
    }
)

SAFE_NESTED_PROTOCOL_KEYS = {
    "sampling_params": frozenset({"max_new_tokens", "max_tokens", "ignore_eos", "temperature", "top_p", "top_k", "seed"}),
    "options": frozenset({"num_predict", "ignore_eos", "temperature", "top_p", "top_k", "seed"}),
    "extra_request_body": frozenset({"max_output_tokens", "max_completion_tokens", "max_tokens", "max_new_tokens", "ignore_eos", "temperature", "seed"}),
    "stream_options": frozenset({"include_usage"}),
}


def _is_safe_primitive(key: str, val: Any) -> bool:
    if key == "model":
        return isinstance(val, str) and len(val) <= 128 and not _looks_like_secret(val)
    if key in ("stream", "ignore_eos", "parallel_tool_calls", "think", "include_usage"):
        return isinstance(val, bool)
    if isinstance(val, bool):
        return False
    return isinstance(val, (int, float))


def extract_safe_repro_body(body: Mapping[str, Any]) -> Tuple[Dict[str, Any], bool]:
    """Keep ONLY strictly validated protocol primitives; flag omitted=True for any arbitrary keys/strings."""
    safe: Dict[str, Any] = {}
    omitted = False
    for k, v in body.items():
        if k in SAFE_SCALAR_PROTOCOL_KEYS and _is_safe_primitive(k, v):
            safe[k] = redact_secret_text(v) if isinstance(v, str) else v
        elif k in SAFE_NESTED_PROTOCOL_KEYS and isinstance(v, dict):
            allowed = SAFE_NESTED_PROTOCOL_KEYS[k]
            sub_safe: Dict[str, Any] = {}
            for sk, sv in v.items():
                if sk in allowed and _is_safe_primitive(sk, sv):
                    sub_safe[sk] = sv
                else:
                    omitted = True
            if sub_safe:
                safe[k] = sub_safe
        else:
            omitted = True
    return safe, omitted
