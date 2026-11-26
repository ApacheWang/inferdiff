"""Sensitive header, URL, body, and wire-text redaction with deterministic SHA-256 fingerprints."""

from __future__ import annotations

import hashlib
import json
import re
import urllib.parse
from typing import Any, Callable, Dict, Mapping, Sequence, Tuple

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

_REPORT_URL_RE = re.compile(r"https?://[^\s<>\"'\\]+", re.IGNORECASE)
_REPORT_HEADER_NAMES = "|".join(re.escape(name) for name in sorted(SENSITIVE_HEADER_NAMES))
_REPORT_X_HEADER_NAMES = "|".join(re.escape(part) for part in _SENSITIVE_HEADER_SUBSTRINGS)
_REPORT_HEADER_NAME = rf"(?:{_REPORT_HEADER_NAMES}|x-[\w-]*(?:{_REPORT_X_HEADER_NAMES})[\w-]*)"
_REPORT_HEADER_RE = re.compile(
    rf"(?i)(?<![\w-])({_REPORT_HEADER_NAME}[ \t]*[:=][ \t]*)[^\r\n]+"
)
_REPORT_QUOTED_HEADER_RE = re.compile(
    rf"(?i)([\"'])(?P<name>{_REPORT_HEADER_NAME})\1[ \t]*:[ \t]*"
    r"(\"(?:\\.|[^\"\\])*\"|'(?:\\.|[^'\\])*')"
)
_REDACTED_QUERY_RE = re.compile(r"REDACTED_sha256:[a-f0-9]{8}\Z")
_REDACTED_HEADER_RE = re.compile(r"(?:[\w-]+ )?\$REDACTED_sha256:[a-f0-9]{8}\Z")
_GEMINI_QUERY_KEY_RE = re.compile(
    r"(?i)((?:[?&]|&amp;|\\u0026|\\u003f)(?:key|x-goog-api-key)=)([^&#\s\"'\\<>]+)"
)
_GEMINI_HEADER_KEY_RE = re.compile(
    r"(?i)(?<![\w-])((?P<quote>[\"']?)x-goog-api-key(?P=quote)[ \t]*[:=][ \t]*)"
    r"(\"(?:\\.|[^\"\\])*\"|'(?:\\.|[^'\\])*'|[^\s\"'&,;}{<>]+)"
)
_PATH_CREDENTIAL_NAMES = {"key", "token", "sig", "signature", "bearer"}
_JSON_STRING_RE = re.compile(r'"(?:\\[^\r\n]|[^"\\\r\n])*"')

_CHAT_FINISH_REASONS = frozenset({"stop", "length", "tool_calls", "content_filter", "function_call"})
# https://aistudio.google.com/api-reference/generate-content#Resource:Candidate
_GEMINI_FINISH_REASONS = frozenset({
    "FINISH_REASON_UNSPECIFIED", "STOP", "MAX_TOKENS", "SAFETY", "RECITATION", "LANGUAGE", "OTHER",
    "BLOCKLIST", "PROHIBITED_CONTENT", "SPII", "MALFORMED_FUNCTION_CALL", "IMAGE_SAFETY",
    "IMAGE_PROHIBITED_CONTENT", "IMAGE_OTHER", "NO_IMAGE", "IMAGE_RECITATION", "UNEXPECTED_TOOL_CALL",
    "TOO_MANY_TOOL_CALLS", "MISSING_THOUGHT_SIGNATURE", "MALFORMED_RESPONSE", "ESCALATION",
    "PUP_LIMITED_DISABLED", "CONTINUATION",
})
_ANTHROPIC_STOP_REASONS = frozenset({
    "end_turn", "max_tokens", "stop_sequence", "tool_use", "pause_turn", "refusal", "model_context_window_exceeded",
})
_RESPONSES_STATUSES = frozenset({"completed", "incomplete", "failed", "in_progress", "cancelled", "queued"})
_RESPONSES_INCOMPLETE_REASONS = frozenset({"max_output_tokens", "content_filter"})
_SSE_EVENTS = {
    "anthropic-messages": frozenset({
        "message_start", "message_delta", "message_stop", "content_block_start", "content_block_delta",
        "content_block_stop", "ping", "error",
    }),
    "openai-responses": frozenset({
        "response.created", "response.in_progress", "response.completed", "response.incomplete", "response.failed",
        "response.output_text.delta", "response.refusal.delta", "response.reasoning_summary_text.delta",
        "response.reasoning_text.delta", "response.output_item.added", "response.output_item.done",
        "response.function_call_arguments.delta", "response.function_call_arguments.done", "error",
    }),
    "ollama-ndjson": frozenset({"ollama.done"}),
}
_FINISH_REASONS = {
    "gemini-sse": _GEMINI_FINISH_REASONS,
    "anthropic-messages": _ANTHROPIC_STOP_REASONS,
    "openai-chat": _CHAT_FINISH_REASONS,
    "openai-responses": _RESPONSES_INCOMPLETE_REASONS,
    "sglang-native": _CHAT_FINISH_REASONS,
    "ollama-ndjson": _CHAT_FINISH_REASONS,
}
_WIRE_ENUMS = {
    "gemini-sse": {("candidates", None, "finishReason"): _GEMINI_FINISH_REASONS},
    "anthropic-messages": {
        ("type",): _SSE_EVENTS["anthropic-messages"],
        ("delta", "stop_reason"): _ANTHROPIC_STOP_REASONS,
        ("message", "stop_reason"): _ANTHROPIC_STOP_REASONS,
        ("delta", "type"): frozenset({"text_delta", "thinking_delta", "signature_delta", "input_json_delta"}),
        ("content_block", "type"): frozenset({"text", "thinking", "tool_use", "server_tool_use"}),
    },
    "openai-chat": {("choices", None, "finish_reason"): _CHAT_FINISH_REASONS},
    "openai-responses": {
        ("type",): _SSE_EVENTS["openai-responses"],
        ("response", "status"): _RESPONSES_STATUSES,
        ("response", "incomplete_details", "reason"): _RESPONSES_INCOMPLETE_REASONS,
        ("response", "output", None, "type"): frozenset({"function_call"}),
        ("item", "type"): frozenset({"function_call"}),
    },
    "ollama-ndjson": {("done_reason",): _CHAT_FINISH_REASONS},
    "sglang-native": {
        ("meta_info", "finish_reason"): _CHAT_FINISH_REASONS,
        ("meta_info", "finish_reason", "type"): _CHAT_FINISH_REASONS,
    },
}
_WIRE_KEYS = {
    "anthropic-messages": {("delta", "stop_sequence"), ("content_block", "input")},
    "openai-chat": {("choices", None, "delta", "tool_calls"), ("choices", None, "stop_reason")},
    "ollama-ndjson": {("done",), ("message", "tool_calls")},
    "sglang-native": {("meta_info", "finish_reason", "matched")},
}


def is_protocol_event(dialect: str, value: str) -> bool:
    return value in _SSE_EVENTS.get(dialect, ())


def is_protocol_enum(dialect: str, field: str, value: object) -> bool:
    """Identify public protocol values in a normalized control field."""
    if not isinstance(value, str):
        return False
    if field == "terminal_status":
        return value in (_RESPONSES_STATUSES if dialect == "openai-responses" else {"completed", "incomplete"})
    if field in {"finish_reason", "stop_reason"}:
        return value in _FINISH_REASONS.get(dialect, ())
    return False

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
    try:
        encoded = value.encode("utf-8", errors="surrogateescape")
    except UnicodeEncodeError:
        encoded = value.encode("utf-8", errors="surrogatepass")
    return hashlib.sha256(encoded).hexdigest()[:8]


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
        if _REDACTED_HEADER_RE.fullmatch(raw):
            continue
        if len(raw) >= min_length:
            secrets_out.append(raw)
        parts = raw.split(None, 1)
        if len(parts) == 2 and parts[0].lower() in RECOGNIZED_AUTH_SCHEMES and len(parts[1].strip()) >= min_length:
            secrets_out.append(parts[1].strip())
        if k.lower() in {"cookie", "set-cookie"}:
            cookies = raw.split(";") if k.lower() == "cookie" else [raw.split(";", 1)[0]]
            for cookie in cookies:
                _, _, value = cookie.partition("=")
                value = value.strip().strip('"')
                if len(value) >= min_length:
                    secrets_out.append(value)
    return sorted(set(secrets_out), key=len, reverse=True)


def extract_query_secret_values(query: str) -> list[str]:
    """Return non-allowlisted query values that can be echoed by a target."""
    return [value for name, value in urllib.parse.parse_qsl(query)
            if len(value) >= 6 and name.lower() not in SAFE_EXPORT_QUERY_KEYS]


def extract_url_secret_values(url: str) -> list[str]:
    """Collect URL credentials that might be reflected outside the URL itself."""
    try:
        parts = urllib.parse.urlsplit(url)
    except ValueError:
        return []
    bare_query = [part for part in parts.query.split("&") if part and "=" not in part]
    _, path_secrets = _sanitize_url_path(parts.path)
    secrets = [urllib.parse.unquote(value) for value in (parts.username, parts.password, parts.fragment, *bare_query)
               if value]
    for field in parts.query.split("&"):
        raw_name, equals, raw_value = field.partition("=")
        if not equals or urllib.parse.unquote_plus(raw_name).lower() in SAFE_EXPORT_QUERY_KEYS:
            continue
        value = urllib.parse.unquote_plus(raw_value)
        if value and not _REDACTED_QUERY_RE.fullmatch(value):
            secrets.append(value)
            if raw_value != value:
                secrets.append(raw_value)
    return secrets + path_secrets


def _is_report_credential(key: str) -> bool:
    name = key.lower()
    return (name in SENSITIVE_HEADER_NAMES or name == "token" or bool(_SENSITIVE_BODY_KEY_RE.search(name))
            or (name.startswith("x-") and is_sensitive_header(name)))


def _sanitize_url_path(path: str) -> tuple[str, list[str]]:
    segments = []
    secrets = []
    secret_next = False
    for encoded in path.split("/"):
        part = urllib.parse.unquote(encoded)
        name, sep, value = part.partition("=") if "=" in part else part.partition("/")
        credential = name.lower() in _PATH_CREDENTIAL_NAMES or _is_report_credential(name)
        secret = part if secret_next else value if credential and sep else ""
        if secret and not _REDACTED_QUERY_RE.fullmatch(secret):
            secrets.append(secret)
            prefix = name + sep if not secret_next else ""
            cleaned = f"{prefix}REDACTED_sha256:{fingerprint8(secret)}"
        else:
            cleaned = redact_secret_text(part)
        segments.append(encoded if cleaned == part else urllib.parse.quote(cleaned, safe=":@$=", errors="replace"))
        secret_next = (not secret and credential and not sep) or (secret_next and not part)
    return "/".join(segments), secrets


def sanitize_url_path(path: str) -> str:
    """Redact recognizable credentials in an endpoint path."""
    return _sanitize_url_path(path)[0]


def _secret_variants(known_secrets: Sequence[str], min_length: int) -> dict[str, str]:
    variants = {}
    for secret in sorted({s for s in known_secrets if isinstance(s, str) and len(s) >= min_length}):
        for variant in (
            secret, urllib.parse.quote(secret, safe="", errors="replace"), urllib.parse.quote(secret, errors="replace"),
            urllib.parse.quote_plus(secret, errors="replace"), json.dumps(secret, ensure_ascii=True)[1:-1],
        ):
            variants.setdefault(variant, secret)
    return variants


def _secret_pattern(variants: Mapping[str, str]) -> re.Pattern[str]:
    alternatives = []
    for value in sorted(variants, key=lambda value: (-len(value), value)):
        literal = re.escape(value)
        if len(value) < 4 and value.isalnum():
            literal = rf"(?<!\w){literal}(?!\w)"
        alternatives.append(literal)
    return re.compile("|".join(alternatives))


def scrub_report_text(text: str, known_secrets: Sequence[str] = ()) -> str:
    """Redact credentials and their common encodings in user-visible report fields."""
    if not text:
        return text

    variants = _secret_variants(known_secrets, 1)
    if variants:
        pattern = _secret_pattern(variants)
        text = pattern.sub("[redacted]", text)
        # Proxies may percent-encode characters that urllib.quote leaves unescaped.
        decoded = urllib.parse.unquote(text)
        if decoded != text:
            clean_decoded = pattern.sub("[redacted]", decoded)
            if clean_decoded != decoded:
                text = clean_decoded

    def clean_url(match: re.Match[str]) -> str:
        try:
            return sanitize_url_for_export(match.group())
        except ValueError:
            return "[redacted URL]"

    def clean_quoted_header(match: re.Match[str]) -> str:
        value = match.group(3)
        return match.group()[:-len(value)] + f"{value[0]}[redacted]{value[0]}"

    text = _REPORT_URL_RE.sub(clean_url, text)
    text = _REPORT_QUOTED_HEADER_RE.sub(clean_quoted_header, text)
    return redact_secret_text(_REPORT_HEADER_RE.sub(r"\1[redacted]", text))


def scrub_report_data(value: Any, known_secrets: Sequence[str] = ()) -> Any:
    """Scrub JSON report values and dynamic keys before encoding the document."""
    # Short credentials can coincide with fixed schema keys such as 'id'.
    key_secrets = [secret for secret in known_secrets if len(secret) >= 6]

    def scrub(item: Any) -> Any:
        if isinstance(item, dict):
            clean = {}
            for key, child in item.items():
                key = str(key)
                if _is_report_credential(key):
                    if not isinstance(child, str) or not _REDACTED_HEADER_RE.fullmatch(child):
                        child = "[redacted]"
                clean[scrub_report_text(key, key_secrets)] = scrub(child)
            return clean
        if isinstance(item, (list, tuple)):
            return [scrub(child) for child in item]
        return scrub_report_text(item, known_secrets) if isinstance(item, str) else item

    return scrub(value)


def scrub_known_secrets(text: str, known_secrets: Sequence[str] = (), *, min_length: int = 6) -> str:
    """Scrub exact known outgoing secret strings plus standard secret patterns from text."""
    if not text:
        return text
    scrub = _known_secret_scrubber(known_secrets, min_length)
    return scrub(text)


def _known_secret_scrubber(known_secrets: Sequence[str], min_length: int) -> Callable[[str], str]:
    variants = _secret_variants(known_secrets, min_length)
    if not variants:
        return redact_secret_text
    pattern = _secret_pattern(variants)

    def scrub(value: str) -> str:
        return redact_secret_text(pattern.sub(
            lambda match: f"$REDACTED_sha256:{fingerprint8(variants[match.group()])}", value,
        ))

    return scrub


class _JSONMembers(list):
    """Object pairs in lexical order, including repeated keys."""


def scrub_protocol_payload(text: str, dialect: str, known_secrets: Sequence[str]) -> str:
    """Scrub JSON strings while preserving public enums in their actual wire fields."""
    if text == "[DONE]" and dialect not in {"anthropic-messages", "gemini-sse", "ollama-ndjson"}:
        return text
    scrub = _known_secret_scrubber(known_secrets, 1)
    try:
        # Walk decoded paths and replace original string spans to retain wire whitespace and framing.
        payload = json.loads(text, object_pairs_hook=_JSONMembers)
        wire_enums = _WIRE_ENUMS.get(dialect, {})
        control_paths = (*wire_enums, *_WIRE_KEYS.get(dialect, ()))
        control_keys = {path[:size] for path in control_paths for size in range(1, len(path) + 1)}
        literals = iter(_JSON_STRING_RE.finditer(text))
        pieces: list[str] = []
        end = 0

        def redact_literal(value: str, *, preserve: bool, credential: str | None = None) -> None:
            nonlocal end
            literal = next(literals)
            if preserve:
                return
            if credential and value and value != "[redacted]" and not _REDACTED_HEADER_RE.fullmatch(value):
                safe = redact_header_value(credential, value) if is_sensitive_header(credential) else "[redacted]"
            else:
                safe = scrub(value)
            if safe != value:
                pieces.extend((text[end:literal.start()], json.dumps(safe, ensure_ascii=True)))
                end = literal.end()

        def walk(node: Any, path: tuple[str | None, ...]) -> None:
            if isinstance(node, _JSONMembers):
                for key, value in node:
                    member_path = (*path, key)
                    redact_literal(key, preserve=member_path in control_keys)
                    walk(value, member_path)
            elif isinstance(node, list):
                for item in node:
                    walk(item, (*path, None))
            elif isinstance(node, str):
                name = path[-1] if path else None
                credential = name if name and _is_report_credential(name) else None
                redact_literal(node, preserve=node in wire_enums.get(path, ()), credential=credential)

        walk(payload, ())
    except (ValueError, RecursionError):
        # A broken envelope may still contain complete JSON string literals.
        def scrub_literal(match: re.Match[str]) -> str:
            literal = match[0]
            try:
                value = json.loads(literal)
            except ValueError:
                return literal
            safe = scrub(value)
            return json.dumps(safe, ensure_ascii=True) if safe != value else literal

        return scrub(_JSON_STRING_RE.sub(scrub_literal, text))
    return "".join((*pieces, text[end:]))


def redact_secret_text(text: str) -> str:
    """Scrub recognized credential patterns from free-form text or wire excerpts."""
    if not text:
        return text
    def redact_query_key(match: re.Match[str]) -> str:
        prefix, value = match.groups()
        if value == "[redacted]" or _REDACTED_QUERY_RE.fullmatch(value.removeprefix("$")):
            return match.group()
        return prefix + f"REDACTED_sha256:{fingerprint8(value)}"

    def redact_google_header(match: re.Match[str]) -> str:
        prefix, _, value = match.groups()
        quote = value[0] if value[0] in "\"'" else ""
        secret = value[1:-1] if quote else value
        if not secret or secret == "[redacted]" or _REDACTED_HEADER_RE.fullmatch(secret):
            return match.group()
        return f"{prefix}{quote}$REDACTED_sha256:{fingerprint8(secret)}{quote}"

    out = _GEMINI_QUERY_KEY_RE.sub(redact_query_key, text)
    out = _GEMINI_HEADER_KEY_RE.sub(redact_google_header, out)
    for idx, pat in enumerate(_SECRET_VALUE_PATTERNS):
        if idx == 6:
            out = pat.sub(lambda m: f"{m.group(1)} $REDACTED_sha256:{fingerprint8(m.group(0))}", out)
        elif idx == 7:
            out = pat.sub(
                lambda m: m.group() if m.group(3) == "[redacted]" or _REDACTED_HEADER_RE.fullmatch(m.group(3))
                else f"{m.group(1)}{m.group(2)}$REDACTED_sha256:{fingerprint8(m.group(3))}",
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
    path = sanitize_url_path(parsed.path or "/")
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
    path = sanitize_url_path(parsed.path or "/")

    if parsed.query:
        # A query component without '=' may itself be a credential, with no public parameter name.
        query_fields = [part if "=" in part else f"redacted={part}" for part in parsed.query.split("&") if part]
        pairs = urllib.parse.parse_qsl("&".join(query_fields), keep_blank_values=True)
        safe_pairs = []
        for k, v in pairs:
            if _REDACTED_QUERY_RE.fullmatch(v) or (k.lower() in SAFE_EXPORT_QUERY_KEYS and not _looks_like_secret(v)):
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


def extract_body_secret_values(body: Any) -> list[str]:
    """Collect sensitive credential values from a structured request body."""
    values: list[str] = []
    _collect_sensitive_values(body, values)
    return values


def sanitize_body_for_export(obj: Any, *, key_name: str = "") -> Any:
    """Recursively redact sensitive fields, known secret values, and credential-shaped strings."""
    # Longest first to avoid partial overlap
    known_secrets = sorted(set(extract_body_secret_values(obj)), key=len, reverse=True)

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
