"""Minimal Prometheus text parsing and monotonic counter arithmetic."""

from __future__ import annotations

import re
from collections.abc import Callable, Iterable
from dataclasses import dataclass, field
from decimal import Decimal, InvalidOperation
from time import time_ns

from ..schema import is_finite_number

Number = int | float
Labels = tuple[tuple[str, str], ...]
Series = tuple[str, Labels]
Samples = dict[Series, Number]

_LABEL = r'[a-zA-Z_][a-zA-Z_0-9]*\s*=\s*"(?:[^"\\]|\\["\\n])*"'
_LABELS = rf'{_LABEL}(?:\s*,\s*{_LABEL})*(?:\s*,)?'
_NUMBER = r'[+-]?(?:[0-9]+(?:\.[0-9]*)?|\.[0-9]+)(?:[eE][+-]?[0-9]+)?'
_SAMPLE_RE = re.compile(
    rf'([a-zA-Z_:][a-zA-Z_0-9:]*)(?:\{{\s*(?:({_LABELS})\s*)?\}})?'
    rf'\s+({_NUMBER}|[+-]?Inf|NaN)(?:\s+([+-]?[0-9]+))?\s*'
)
_LABEL_RE = re.compile(r'([a-zA-Z_][a-zA-Z_0-9]*)\s*=\s*"((?:[^"\\]|\\["\\n])*)"')
_ESCAPE_RE = re.compile(r'\\(["\\n])')
_MAX_LINE_CHARS = 16384


@dataclass
class Scrape:
    samples: Samples = field(default_factory=dict)
    timestamps: dict[Series, int] = field(default_factory=dict)
    invalid: set[Series] = field(default_factory=set)
    types: dict[str, str] = field(default_factory=dict)
    started_ms: int = 0
    received_ms: int = 0
    oversized_line: bool = False

    @property
    def series(self) -> set[Series]:
        return self.samples.keys() | self.invalid

    def metric_type(self, name: str) -> str | None:
        exact = self.types.get(name)
        family = self.types.get(name.removesuffix("_total"))
        if exact is not None and family is not None and exact != family:
            return "invalid"
        return exact or family


def scrape_clock_ms() -> int:
    return time_ns() // 1_000_000


def parse_scrape(text: str, started_ms: int = 0) -> Scrape:
    """Parse samples and retain metadata required to validate a counter interval."""
    scrape = Scrape(started_ms=started_ms, received_ms=scrape_clock_ms())
    for line in text.split("\n"):
        if len(line) > _MAX_LINE_CHARS:
            scrape.oversized_line = True
            continue
        if line.lstrip().startswith("#"):
            fields = line.split()
            if len(fields) == 4 and fields[:2] == ["#", "TYPE"]:
                name, kind = fields[2:]
                if name in scrape.types:
                    kind = "invalid"
                scrape.types[name] = kind
            continue
        match = _SAMPLE_RE.fullmatch(line.strip())
        if not match:
            continue
        name, raw_labels, token, timestamp = match.groups()
        labels = tuple(sorted(
            (key, _ESCAPE_RE.sub(lambda m: "\n" if m[1] == "n" else m[1], raw))
            for key, raw in _LABEL_RE.findall(raw_labels or "")
        ))
        key = name, labels
        if key in scrape.invalid or key in scrape.samples or len({label for label, _ in labels}) != len(labels):
            scrape.invalid.add(key)
            scrape.samples.pop(key, None)
            scrape.timestamps.pop(key, None)
            continue
        try:
            number = Decimal(token)
            # Keep large and scientific-notation integer counters exact.
            value = float(number)
            if not is_finite_number(value):
                raise ValueError
            if number == number.to_integral_value():
                value = int(number)
            stamp = int(timestamp) if timestamp is not None else None
        except (ValueError, InvalidOperation, OverflowError):
            scrape.invalid.add(key)
            continue
        scrape.samples[key] = value
        if stamp is not None:
            scrape.timestamps[key] = stamp
    return scrape


def parse_prometheus(text: str) -> Samples:
    """Return finite, nonduplicate samples by metric name and sorted labels."""
    return parse_scrape(text).samples


def counter_delta(before: Number | None, after: Number | None) -> Number | None:
    """Return a delta only when both samples belong to a comparable monotonic interval."""
    if not is_finite_number(before) or not is_finite_number(after) or not 0 <= before <= after:
        return None
    return after - before


def _epoch_changed(before: Scrape, after: Scrape, keys: set[Series]) -> bool:
    return any(
        key in before.invalid or key in after.invalid
        or before.samples.get(key) != after.samples.get(key) or _stale(before, after, key)
        for key in keys
    )


def _stale(before: Scrape, after: Scrape, key: Series) -> bool:
    first, last = before.timestamps.get(key), after.timestamps.get(key)
    if first is None or last is None:
        return first != last
    # Explicit timestamps should describe the scrapes, with a small allowance for clock skew.
    skew_ms = 5000
    return (
        first >= last
        or not before.started_ms - skew_ms <= first <= before.received_ms + skew_ms
        or not after.started_ms - skew_ms <= last <= after.received_ms + skew_ms
    )


def series_deltas(
    before: Scrape, after: Scrape, select: Callable[[str], bool], *, require_counter_type: bool = False,
) -> tuple[list[tuple[str, Labels, Number]], bool, set[str]]:
    """Return valid counter deltas, incomplete coverage, and newly visible metric names."""
    if before.oversized_line or after.oversized_line:
        return [], True, set()
    deltas = []
    incomplete = False
    first_seen = set()
    before_series, after_series = before.series, after.series
    all_series = before_series | after_series
    process_epochs = {key for key in all_series if key[0].endswith("process_start_time_seconds")}
    restarted = _epoch_changed(before, after, process_epochs)
    for key in sorted(all_series):
        name, labels = key
        if not select(name):
            continue
        before_type, after_type = before.metric_type(name), after.metric_type(name)
        if require_counter_type and before_type is None and after_type is None and not name.endswith("_total"):
            continue
        if before_type != after_type or before_type not in (None, "counter"):
            incomplete = True
            continue
        if key in after_series and key not in before_series:
            first_seen.add(name)
        created = (name.removesuffix("_total") + "_created", labels)
        if restarted or _epoch_changed(before, after, {created}) or _stale(before, after, key):
            incomplete = True
            continue
        delta = counter_delta(before.samples.get(key), after.samples.get(key))
        if delta is None:
            incomplete = True
        else:
            deltas.append((name, labels, delta))
    return deltas, incomplete, first_seen


def sum_deltas(deltas: Iterable[Number]) -> Number | None:
    """Return a finite total, preserving the difference between zero and absent evidence."""
    total: Number | None = None
    try:
        for delta in deltas:
            total = (total or 0) + delta
    except OverflowError:
        return None
    return total if is_finite_number(total) else None
