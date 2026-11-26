"""Independent Mooncake Store master and client telemetry planes."""

from __future__ import annotations

from collections import defaultdict
from typing import Any
from urllib.parse import SplitResult

from .._probe_data import MOONCAKE_CLIENT_COUNTERS, probe_query_secrets, probe_url, safe_client_version
from .._urls import validate_url
from ..schema import strict_json_loads
from ._http import get_text, validate_timeout
from .prom import Number, Scrape, parse_scrape, scrape_clock_ms, series_deltas, sum_deltas

_MASTER_COUNTERS = {
    "mooncake_tenant_quota_reject_total": "delta_quota_rejects",
    "mooncake_tenant_evict_bytes_total": "delta_evict_bytes",
}


def _object(text: str) -> dict[str, Any]:
    try:
        value = strict_json_loads(text)
    except (ValueError, RecursionError):
        return {}
    return value if isinstance(value, dict) else {}


def _master_ready(status: int | None, text: str) -> bool:
    if status != 200:
        return False
    obj = _object(text)
    for key in ("service_ready", "ready"):
        if isinstance(obj.get(key), bool):
            return obj[key]
    if "role" in obj or "ha_state" in obj:
        return False  # HA process health is distinct from metadata serving readiness.
    return obj.get("status") == "ok" or text.strip().lower() == "ok"


class MooncakeStoreProbe:
    name = "mooncake"

    def __init__(
        self, master_url: str | None = None, client_url: str | None = None, timeout: float = 2.0,
    ) -> None:
        validate_timeout(timeout)
        self._master = validate_url(master_url) if master_url is not None else None
        self._client = validate_url(client_url) if client_url is not None else None
        self._query_secrets = probe_query_secrets(self._master, self._client)
        self._timeout = timeout
        self._pre_master = Scrape()
        self._pre_client = Scrape()
        self._pre_client_code: int | None = None

    def describe_topology(self) -> dict[str, Any]:
        return {
            f"{plane}_endpoint": probe_url(url.geturl())
            for plane, url in (("master", self._master), ("client", self._client)) if url is not None
        }

    def _metrics(self, url: SplitResult) -> tuple[int | None, Scrape]:
        started = scrape_clock_ms()
        code, text = get_text(url._replace(path="/metrics"), self._timeout)
        return code, parse_scrape(text, started)

    def sample_pre(self) -> None:
        if self._master is not None:
            _, self._pre_master = self._metrics(self._master)
        if self._client is not None:
            self._pre_client_code, self._pre_client = self._metrics(self._client)

    def sample_ttft(self) -> None:
        pass

    def sample_eof(self) -> dict[str, Any]:
        result = self.describe_topology()
        if self._master is not None:
            _, after = self._metrics(self._master)
            deltas, incomplete, _ = series_deltas(self._pre_master, after, _MASTER_COUNTERS.__contains__)
            if self._pre_master.series and after.series:
                result["master_status"] = "incomplete" if incomplete else "ok"
            else:
                result["master_status"] = "unavailable"
            for name, key in _MASTER_COUNTERS.items():
                total = sum_deltas(delta for metric, _, delta in deltas if metric == name)
                if total is not None:
                    result[key] = total
            status, text = get_text(self._master._replace(path="/health"), self._timeout, max_bytes=8192)
            result["master_ready"] = _master_ready(status, text)

        if self._client is not None:
            status, after = self._metrics(self._client)
            deltas, incomplete, _ = series_deltas(
                self._pre_client, after, MOONCAKE_CLIENT_COUNTERS.__contains__, require_counter_type=True,
            )
            if 503 in (self._pre_client_code, status):
                result["client_status"] = "degraded_503"
            elif self._pre_client.series and after.series:
                result["client_status"] = "incomplete" if incomplete else "ok"
            else:
                result["client_status"] = "unavailable"
            counters: dict[str, list[Number]] = defaultdict(list)
            for name, _, delta in deltas:
                if not any(secret in name for secret in self._query_secrets):
                    counters[name].append(delta)
            if counters:
                result["client_deltas"] = {
                    name: total for name, values in counters.items() if (total := sum_deltas(values)) is not None
                }
            _, text = get_text(self._client._replace(path="/version"), self._timeout, max_bytes=8192)
            version = safe_client_version(_object(text).get("display_version"), self._query_secrets)
            if version is not None:
                result["client_version"] = version
        return result
