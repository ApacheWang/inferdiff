"""LMCache MP lookup, load, and failure counters from its Prometheus endpoint."""

from __future__ import annotations

from collections import defaultdict
from typing import Any

from .._probe_data import probe_query_secrets, probe_url, safe_failure_reason
from .._urls import validate_url
from ._http import get_text, validate_timeout
from .prom import Labels, Number, Scrape, parse_scrape, scrape_clock_ms, series_deltas, sum_deltas

# Prefer the contract's canonical family when exporters expose multiple aliases.
_COUNTERS = {
    "lookup_prompt_tokens": ("lookup_prompt_tokens", "lookup_prompt"),
    "hit_l1_tokens": ("hit_l1_tokens", "lookup_hit_l1_tokens", "lookup_hit_l1"),
    "hit_l2_tokens": ("hit_l2_tokens", "lookup_hit_l2_tokens", "lookup_hit_l2"),
    "hit_l1_keys": ("hit_l1_keys", "lookup_hit_l1_keys"),
    "hit_l2_keys": ("hit_l2_keys", "lookup_hit_l2_keys"),
    "l2_load_completed": ("l2_load_completed", "l2_load_completed_requests"),
    "l2_prefetch_failures": ("l2_prefetch_failures", "l2_prefetch_failure", "l2_prefetch_failure_chunks"),
    "l1_read_failures": ("l1_read_failures", "l1_read_failure", "l1_read_failure_chunks"),
    "event_bus_dropped": ("event_bus_dropped", "event_bus_dropped_events"),
}


def _canonical(name: str) -> str:
    return name.replace(":", "_").removeprefix("lmcache_mp_").removeprefix("lmcache_").removesuffix("_total")


class LmcacheMpProbe:
    name = "lmcache_mp"

    def __init__(self, endpoint: str, timeout: float = 2.0) -> None:
        parsed = validate_url(endpoint)
        validate_timeout(timeout)
        self._url = parsed._replace(path="/metrics") if parsed.path in ("", "/") else parsed
        self._endpoint = probe_url(self._url.geturl())
        self._query_secrets = probe_query_secrets(self._url)
        self._timeout = timeout
        self._pre = Scrape()

    def describe_topology(self) -> dict[str, Any]:
        return {"endpoint": self._endpoint}

    def _scrape(self) -> Scrape:
        started = scrape_clock_ms()
        _, text = get_text(self._url, self._timeout)
        return parse_scrape(text, started)

    def sample_pre(self) -> None:
        self._pre = self._scrape()

    def sample_ttft(self) -> None:
        pass

    def sample_eof(self) -> dict[str, Any]:
        after = self._scrape()
        result = self.describe_topology()
        if not self._pre.series or not after.series:
            return {**result, "status": "unavailable_push_or_cold"}
        names: dict[str, set[str]] = defaultdict(set)
        for name, _ in self._pre.series | after.series:
            names[_canonical(name)].add(name)
        selected: dict[str, str] = {}
        for metric, aliases in _COUNTERS.items():
            matches = next((names[alias] for alias in aliases if alias in names), ())
            if matches:
                name = min(matches, key=lambda n: (not n.endswith("_total"), not n.startswith("lmcache"), n))
                selected[name] = metric
        deltas, incomplete, first_seen = series_deltas(self._pre, after, selected.__contains__)
        result["status"] = "incomplete" if incomplete else "ok"
        if any(selected[name] in ("l1_read_failures", "l2_prefetch_failures") for name in first_seen):
            result["first_seen_at_eof"] = True
        by_metric: dict[str, list[tuple[Labels, Number]]] = defaultdict(list)
        for name, labels, delta in deltas:
            by_metric[selected[name]].append((labels, delta))
        for metric, values in by_metric.items():
            if metric == "l2_prefetch_failures":
                reasons: dict[str, list[Number]] = defaultdict(list)
                for labels, delta in values:
                    reason = dict(labels).get("reason") or "unknown"
                    reasons[safe_failure_reason(reason, self._query_secrets)].append(delta)
                result["delta_l2_prefetch_failures"] = {
                    reason: total for reason, values in reasons.items() if (total := sum_deltas(values)) is not None
                }
            else:
                total = sum_deltas(delta for _, delta in values)
                if total is not None:
                    result[f"delta_{metric}"] = total
                    if metric == "event_bus_dropped":
                        result["event_bus_dropped"] = total
        return result
