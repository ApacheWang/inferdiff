"""Bounded, stdlib-only Prometheus text exposition for proxy and watch."""

from __future__ import annotations

import math
import os
import uuid
from bisect import bisect_left
from collections import Counter
from itertools import accumulate
from pathlib import Path
from typing import TYPE_CHECKING, Sequence

if TYPE_CHECKING:
    from .detectors import Finding


PROMETHEUS_CONTENT_TYPE = "text/plain; version=0.0.4; charset=utf-8"
METRICS_PATH = "/_inferdiff/metrics"

_DIALECT_NAMES = {
    "openai-chat": "openai-chat",
    "openai-responses": "openai-responses",
    "anthropic-messages": "anthropic",
    "gemini-sse": "gemini",
}
_DIALECTS = (*_DIALECT_NAMES.values(), "other")
_UPSTREAMS = ("primary", "fallback")
_DETECTORS = ("D1", "D2", "D3", "D4")
_SEVERITIES = ("P0", "P1")
_TTFT_BOUNDS = (50, 100, 250, 500, 1000, 2500, 5000)


def _metadata(name: str, kind: str, help_text: str) -> list[str]:
    return [f"# HELP {name} {help_text}", f"# TYPE {name} {kind}"]


class ProxyMetrics:
    """Proxy counters and buckets, accessed under the proxy server's lock."""

    def __init__(self) -> None:
        self.requests: Counter[tuple[str, str]] = Counter()
        self.streaming_requests: Counter[str] = Counter()
        self.findings: Counter[tuple[str, str]] = Counter()
        self.active_streams = 0
        self._ttft_buckets = [0] * (len(_TTFT_BOUNDS) + 1)
        self._ttft_sum = 0.0

    def record_request(
        self, dialect: str, upstream: str, streaming: bool, findings: Sequence[Finding], ttft_ms: float | None,
    ) -> None:
        dialect = _DIALECT_NAMES.get(dialect, "other")
        upstream = "fallback" if upstream == "fallback" else "primary"
        self.requests[dialect, upstream] += 1
        if streaming:
            self.streaming_requests[dialect] += 1
        for finding in findings:
            if finding.detector_id in _DETECTORS and finding.severity in _SEVERITIES:
                self.findings[finding.detector_id, finding.severity] += 1
        if ttft_ms is not None and math.isfinite(ttft_ms) and ttft_ms >= 0:
            self._ttft_buckets[bisect_left(_TTFT_BOUNDS, ttft_ms)] += 1
            self._ttft_sum += ttft_ms

    def render(self, *, failovers_total: int) -> bytes:
        name = "inferdiff_proxy_requests_total"
        lines = _metadata(name, "counter", "Completed proxy requests by protocol dialect and final upstream.")
        lines.extend(
            f'{name}{{dialect="{dialect}",upstream="{upstream}"}} {self.requests[dialect, upstream]}'
            for dialect in _DIALECTS for upstream in _UPSTREAMS
        )

        name = "inferdiff_proxy_streaming_requests_total"
        lines.extend(_metadata(name, "counter", "Completed streaming proxy requests by protocol dialect."))
        lines.extend(f'{name}{{dialect="{dialect}"}} {self.streaming_requests[dialect]}' for dialect in _DIALECTS)

        name = "inferdiff_proxy_findings_total"
        lines.extend(_metadata(name, "counter", "Stream audit findings by detector and severity."))
        lines.extend(
            f'{name}{{detector="{detector}",severity="{severity}"}} {self.findings[detector, severity]}'
            for detector in _DETECTORS for severity in _SEVERITIES
        )

        name = "inferdiff_proxy_failovers_total"
        lines.extend(_metadata(name, "counter", "Requests retried on the fallback upstream."))
        lines.append(f"{name} {failovers_total}")

        name = "inferdiff_proxy_ttft_ms"
        lines.extend(_metadata(name, "histogram", "Effective time to first token in milliseconds."))
        cumulative = list(accumulate(self._ttft_buckets))
        lines.extend(
            f'{name}_bucket{{le="{bound}"}} {count}'
            for bound, count in zip((*_TTFT_BOUNDS, "+Inf"), cumulative)
        )
        lines.extend([f"{name}_sum {self._ttft_sum}", f"{name}_count {cumulative[-1]}"])

        name = "inferdiff_proxy_active_streams"
        lines.extend(_metadata(name, "gauge", "Streaming responses currently being relayed."))
        lines.append(f"{name} {self.active_streams}")
        return ("\n".join(lines) + "\n").encode("utf-8")


def render_watch_metrics(
    *, up: bool, grade_score: int, probes_passed: int, probes_total: int, p0_breaches: int,
    ttft_ms: float | None, last_check_timestamp_seconds: float,
) -> bytes:
    gauges = (
        ("up", "Whether the latest watch cycle was healthy (1) or unhealthy (0).", int(up)),
        ("grade_score", "Latest canary grade as a score from 0 to 100 (F=0, C=70, B=80, A=90, A+=100).", grade_score),
        ("probes_passed", "Probes that passed in the latest watch cycle.", probes_passed),
        ("probes_total", "Probes selected for the watch cycle.", probes_total),
        ("p0_breaches", "P0 breaches reported in the latest watch cycle.", p0_breaches),
        ("ttft_ms", "Median effective time to first token in the latest cycle in milliseconds (NaN if unavailable).",
         ttft_ms if ttft_ms is not None and math.isfinite(ttft_ms) else "NaN"),
        ("last_check_timestamp_seconds", "Unix timestamp of the latest completed watch cycle (0 before any cycle).",
         last_check_timestamp_seconds),
    )
    lines = []
    for suffix, help_text, value in gauges:
        name = f"inferdiff_watch_{suffix}"
        lines.extend(_metadata(name, "gauge", help_text))
        lines.append(f"{name} {value}")
    return ("\n".join(lines) + "\n").encode("utf-8")


def write_prometheus_textfile(path: str | Path, data: bytes) -> None:
    """Replace a textfile using a closed, same-directory file outside the collector glob."""
    destination = Path(path)
    destination.parent.mkdir(parents=True, exist_ok=True)
    temporary = destination.with_name(f".inferdiff-{uuid.uuid4().hex}.tmp")
    stream = temporary.open("xb")
    try:
        with stream:
            stream.write(data)
            stream.flush()
            os.fsync(stream.fileno())
        os.replace(temporary, destination)
    finally:
        temporary.unlink(missing_ok=True)
