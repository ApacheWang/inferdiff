"""Field names and redaction shared by the storage probes and trace export."""

from __future__ import annotations

import re
from urllib.parse import SplitResult, parse_qsl, urlsplit, urlunsplit

from .redact import has_control_chars, redact_secret_text

PROBE_SOURCES = ("lmcache_mp", "mooncake", "proc_io")
PROBE_URL_FIELDS = frozenset({"endpoint", "master_endpoint", "client_endpoint", "master_url", "client_url"})
_VERSION = re.compile(
    r"v?[0-9]{1,5}\.[0-9]{1,5}\.[0-9]{1,5}"
    r"(?:(?:\.post|\.dev|rc|a|b)[0-9]{1,5})?(?: \(git: [0-9a-f]{3,12}\))?"
)
_FAILURE_REASONS = frozenset({"l1_oom", "not_found", "serde_failure", "unknown"})
MOONCAKE_CLIENT_COUNTERS = frozenset(
    f"mooncake_{plane}_{direction}_{unit}{suffix}"
    for plane, units in {
        "te": ("bytes", "requests", "failures", "timeouts"),
        "transfer": ("bytes", "operation_count", "operation_bytes"),
        "ssd": ("bytes", "ops"),
        "offload": ("bytes", "ops", "requests"),
    }.items()
    for direction in ("read", "write")
    for unit in units
    for suffix in ("", "_total")
) | frozenset({"mooncake_ssd_total_bytes_total", "mooncake_ssd_total_ops_total"})
MOONCAKE_STORAGE_READ_COUNTERS = frozenset(
    name for name in MOONCAKE_CLIENT_COUNTERS if name.startswith(("mooncake_ssd_read_", "mooncake_offload_read_"))
)
NUMBER = (int, float)
METRIC_MAP = {None: NUMBER}
PREFILL_FIELDS = {
    "status": str,
    "delta_rchar_bytes": int, "delta_read_bytes": int, "delta_syscr": int,
    "delta_write_bytes_net": int, "avg_syscall_read_kb": NUMBER,
}
FULL_FIELDS = {"delta_read_bytes_total": int, "delta_rchar_bytes_total": int, "delta_write_bytes_net": int}
SOURCE_FIELDS = {
    "lmcache_mp": {
        "endpoint": str, "status": str, "first_seen_at_eof": bool,
        "delta_l2_prefetch_failures": METRIC_MAP,
        **{key: NUMBER for key in (
            "delta_lookup_prompt_tokens", "delta_hit_l1_tokens", "delta_hit_l2_tokens",
            "delta_hit_l1_keys", "delta_hit_l2_keys", "delta_l2_load_completed",
            "delta_l1_read_failures", "delta_event_bus_dropped", "event_bus_dropped",
        )},
    },
    "mooncake": {
        "master_endpoint": str, "client_endpoint": str, "master_url": str, "client_url": str,
        "master_status": str, "client_status": str, "master_ready": bool, "client_version": str,
        "delta_quota_rejects": NUMBER, "delta_evict_bytes": NUMBER, "client_deltas": METRIC_MAP,
    },
    "proc_io": {
        "pid": int, "comm": str, "status": str, "prefill_window": PREFILL_FIELDS, "full_window": FULL_FIELDS,
    },
}
PROBE_FIELDS = {
    **{key: value for fields in SOURCE_FIELDS.values() for key, value in fields.items()},
    **SOURCE_FIELDS,
    "probe_version": str, "concurrency_isolated": bool, "sources": list,
}
PROBE_STATUSES = frozenset({
    "ok", "incomplete", "unavailable", "unavailable_push_or_cold", "degraded_503",
    "skipped_permission", "skipped_unavailable", "process_changed",
    "ttft_not_observed", "ttft_unavailable", "probe_error",
})


def probe_url(value: str) -> str | None:
    """Keep only the HTTP(S) origin and path of an imported or live probe URL."""
    if has_control_chars(value):
        return None
    try:
        parsed = urlsplit(value)
        host, port = parsed.hostname, parsed.port
    except ValueError:
        return None
    if parsed.scheme not in ("http", "https") or not host or port == 0:
        return None
    netloc = f"[{host}]" if ":" in host else host
    if port is not None:
        netloc += f":{port}"
    return urlunsplit((parsed.scheme, netloc, redact_secret_text(parsed.path or "/"), "", ""))


def probe_query_secrets(*urls: SplitResult | None) -> set[str]:
    """Treat probe query components as sensitive, including short and encoded values."""
    values = set()
    for url in urls:
        if url is not None:
            for key, value in parse_qsl(url.query, keep_blank_values=True):
                values.update((key, value))
            for term in url.query.split("&"):
                key, _, value = term.partition("=")
                values.update((key, value))
    values.discard("")
    return values


def safe_client_version(value: object, secrets: set[str]) -> str | None:
    if (isinstance(value, str) and len(value) <= 64 and _VERSION.fullmatch(value)
            and _not_sensitive(value, secrets)):
        return value
    return None


def safe_failure_reason(value: str, secrets: set[str]) -> str:
    return value if value in _FAILURE_REASONS and _not_sensitive(value, secrets) else "unknown"


def _not_sensitive(value: str, secrets: set[str]) -> bool:
    return redact_secret_text(value) == value and not any(secret in value for secret in secrets)
