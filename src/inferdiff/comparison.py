"""Compare the observed streaming contracts of two live canary targets."""

from __future__ import annotations

import html
import unicodedata
from dataclasses import asdict, dataclass
from statistics import median
from typing import Any, Callable, Optional, Sequence

from . import __version__
from .canary import DoctorReport, ProbeResult
from .exporter import _c, _supports_color
from .redact import is_protocol_enum, sanitize_url_for_export, scrub_report_text
from .schema import (
    EXIT_OK,
    EXIT_SEMANTIC_REGRESSION,
    EXIT_SILENT_PROTOCOL_BREACH,
    EXIT_USAGE_OR_IO_ERROR,
    TraceDocument,
    is_finite_number,
    scan_think_tags,
    strict_json_loads,
)
from .waterfall import (
    COLOR_STALL,
    STALL_GAP_MS,
    _esc,
    _frame_category,
    _frame_color,
    _wrap_html_document,
)

MIN_LATENCY_DELTA_MS = 20.0
_STATUSES = {"PASS": "32", "WARN": "33", "FAIL": "31", "SKIP": "36", "ERROR": "31"}


@dataclass(frozen=True)
class ComparisonTarget:
    label: str
    target_url: str
    model: str
    dialect: str
    observed_models: list[str]
    system_fingerprints: list[str]


@dataclass(frozen=True)
class ToolContract:
    name: str
    json_valid: bool
    arguments_streamed: bool
    arguments_done: bool
    arguments_mismatch: bool
    identity_conflict: bool


DivergenceValue = str | bool | list[str] | list[ToolContract] | None


@dataclass(frozen=True)
class StreamContract:
    sample: str
    dialect: str
    requested_model: str
    models: list[str]
    system_fingerprints: list[str]
    ttft_ms: Optional[float]
    total_ms: Optional[float]
    finish_reason: Optional[str]
    terminal_status: Optional[str]
    eof_clean: bool
    tool_calls: list[ToolContract]
    thinking_stream: str
    timeline: list[tuple[float, float, str]]

    def to_dict(self) -> dict[str, Any]:
        return {name: getattr(self, name) for name in (
            "sample", "dialect", "requested_model", "models", "system_fingerprints", "ttft_ms", "total_ms",
            "finish_reason", "terminal_status", "eof_clean", "thinking_stream",
        )} | {"tool_calls": [asdict(tool) for tool in self.tool_calls]}


@dataclass(frozen=True)
class CheckSide:
    status: str
    summary: str
    samples: dict[str, StreamContract]

    def to_dict(self) -> dict[str, Any]:
        return {"status": self.status, "summary": self.summary,
                "samples": [sample.to_dict() for sample in self.samples.values()]}


@dataclass(frozen=True)
class Divergence:
    probe_id: str
    field: str
    sample: Optional[str]
    a: DivergenceValue
    b: DivergenceValue


@dataclass(frozen=True)
class CheckComparison:
    probe_id: str
    code: str
    a: CheckSide
    b: CheckSide
    divergences: list[Divergence]

    def to_dict(self) -> dict[str, Any]:
        return {"probe_id": self.probe_id, "code": self.code, "a": self.a.to_dict(), "b": self.b.to_dict(),
                "divergences": [asdict(item) for item in self.divergences]}


@dataclass(frozen=True)
class ComparisonTiming:
    a_ttft_ms: Optional[float]
    b_ttft_ms: Optional[float]
    ttft_ratio: Optional[float]
    a_total_ms: Optional[float]
    b_total_ms: Optional[float]
    total_latency_ratio: Optional[float]
    ttft_pairs: int
    total_pairs: int


@dataclass(frozen=True)
class ComparisonReport:
    a: ComparisonTarget
    b: ComparisonTarget
    checks: list[CheckComparison]
    timing: ComparisonTiming
    model_mismatch: bool
    contract_drift: bool
    latency_regression: bool
    verdict: str
    exit_code: int

    @property
    def divergences(self) -> list[Divergence]:
        return [item for check in self.checks for item in check.divergences]

    def to_dict(self) -> dict[str, Any]:
        return {
            "version": __version__, "verdict": self.verdict, "exit_code": self.exit_code,
            "a": asdict(self.a), "b": asdict(self.b), "checks": [check.to_dict() for check in self.checks],
            "timing": asdict(self.timing), "divergences": [asdict(item) for item in self.divergences],
            "model_mismatch": self.model_mismatch, "contract_drift": self.contract_drift,
            "latency_regression": self.latency_regression,
        }


def _sanitize_display(known_secrets: Sequence[str]) -> Callable[[str], str]:
    def clean(value: str) -> str:
        value = scrub_report_text(value, known_secrets)
        value = "".join(" " if unicodedata.category(ch) in {"Cc", "Cf", "Cs", "Zl", "Zp"} else ch for ch in value)
        return value.strip()[:240]

    return clean


def _number(value: Any) -> Optional[float]:
    return float(value) if is_finite_number(value) and value >= 0 else None


def _wire_identity(doc: TraceDocument, clean: Callable[[str], str]) -> tuple[list[str], list[str]]:
    models: set[str] = set()
    fingerprints: set[str] = set()
    for frame in doc.frames:
        if frame.parse_error:
            continue
        wire = frame.raw_wire
        if wire.lstrip().startswith("{"):
            payload = wire
        else:
            lines = wire.replace("\r\n", "\n").replace("\r", "\n").split("\n")
            payload = "\n".join(line[5:].removeprefix(" ") for line in lines if line.startswith("data:"))
        if not payload.lstrip().startswith("{"):
            continue
        try:
            obj = strict_json_loads(payload)
        except (ValueError, RecursionError):
            continue
        for part in (obj, obj.get("message"), obj.get("response")):
            if not isinstance(part, dict):
                continue
            model, fingerprint = part.get("model"), part.get("system_fingerprint")
            if isinstance(model, str) and model:
                models.add(clean(model))
            if isinstance(fingerprint, str) and fingerprint:
                fingerprints.add(clean(fingerprint))
    return sorted(models - {""}), sorted(fingerprints - {""})


def _stream_contract(doc: TraceDocument, name: str, fallback_model: str, clean: Callable[[str], str]) -> StreamContract:
    summary = doc.summary.assembled
    timing = doc.summary.timing
    model = (doc.header.request.get("effective_params") or {}).get("model")
    models, fingerprints = _wire_identity(doc, clean)
    tools = [ToolContract(
        name=clean(tool.get("name") or ""),
        json_valid=tool.get("json_valid") is True,
        arguments_streamed=tool.get("saw_args_delta") is True,
        arguments_done=tool.get("saw_args_done_event") is True,
        arguments_mismatch=tool.get("args_mismatch") is True,
        identity_conflict=tool.get("identity_conflict") is True,
    ) for tool in summary.get("tool_calls") or []]
    dedicated = any(frame.norm.get("reasoning_delta") for frame in doc.frames)
    _, thinking_text, unclosed = scan_think_tags("".join(frame.norm.get("text_delta") or "" for frame in doc.frames))
    if unclosed or summary.get("has_unclosed_think"):
        thinking = "unclosed_inline"
    elif thinking_text or (summary.get("reasoning_text") and not dedicated):
        thinking = "dedicated_and_inline" if dedicated else "inline"
    else:
        thinking = "dedicated" if dedicated else "none"

    timeline: list[tuple[float, float, str]] = []
    stride = max(1, (len(doc.frames) + 17) // 18)
    for index in range(0, len(doc.frames), stride):
        first, last = doc.frames[index], doc.frames[min(index + stride, len(doc.frames)) - 1]
        start, end = _number(first.t_rel_ms - first.dt_ms), _number(last.t_rel_ms)
        if end is not None:
            timeline.append((min(start or 0.0, end), end, _frame_category(last)))

    def protocol_value(field: str) -> str | None:
        value = summary.get(field)
        if not isinstance(value, str) or value == "unknown":
            return None
        return value if is_protocol_enum(doc.header.dialect, field, value) else clean(value)

    return StreamContract(
        clean(name), clean(doc.header.dialect), clean(model) if isinstance(model, str) else fallback_model,
        models, fingerprints, _number(timing.get("ttft_effective_ms")), _number(timing.get("total_ms")),
        protocol_value("finish_reason"), protocol_value("terminal_status"),
        doc.summary.eof_clean, tools, thinking, timeline,
    )


def _check_side(result: Optional[ProbeResult], model: str, clean: Callable[[str], str]) -> CheckSide:
    if result is None:
        return CheckSide("SKIP", "Check was unavailable for this target.", {})
    samples: dict[str, StreamContract] = {}
    for doc in result.traces:
        name = base = doc.header.label or "stream"
        suffix = 2
        while name in samples:
            name = f"{base} #{suffix}"
            suffix += 1
        samples[name] = _stream_contract(doc, name, model, clean)
    status = result.status if result.status in _STATUSES else "ERROR"
    return CheckSide(status, clean(result.summary), samples)


def _compare_streams(probe_id: str, a: StreamContract, b: StreamContract) -> tuple[list[Divergence], bool, bool]:
    fields = ["finish_reason", "terminal_status", "eof_clean", "tool_calls", "thinking_stream"]
    protocol = [Divergence(probe_id, field, a.sample, getattr(a, field), getattr(b, field))
                for field in fields if getattr(a, field) != getattr(b, field)]
    model_changed = a.models != b.models
    fingerprint_changed = a.system_fingerprints != b.system_fingerprints
    model_drift = bool(a.models and b.models and model_changed)
    fingerprint_drift = bool(a.system_fingerprints and b.system_fingerprints and fingerprint_changed)
    a_renamed = bool(a.models and any(model != a.requested_model for model in a.models))
    b_renamed = bool(b.models and any(model != b.requested_model for model in b.models))
    identity: list[Divergence] = []
    if model_changed:
        identity.append(Divergence(probe_id, "model", a.sample, a.models, b.models))
    if fingerprint_changed:
        identity.append(Divergence(probe_id, "system_fingerprint", a.sample, a.system_fingerprints, b.system_fingerprints))
    if a.models and b.models and a_renamed != b_renamed:
        identity.append(Divergence(probe_id, "model_rewrite", a.sample, a_renamed, b_renamed))
    same_request = a.requested_model == b.requested_model
    appears_swapped = not same_request and (
        (a_renamed and b.requested_model in a.models) or (b_renamed and a.requested_model in b.models)
    )
    suspect = (same_request and (model_drift or fingerprint_drift)) or appears_swapped
    return identity + protocol, suspect, bool(protocol)


def _pairs(a: CheckSide, b: CheckSide) -> list[tuple[StreamContract, StreamContract]]:
    return [(stream, b.samples[name]) for name, stream in a.samples.items() if name in b.samples]


def _timing(checks: list[CheckComparison]) -> ComparisonTiming:
    pairs = [pair for check in checks for pair in _pairs(check.a, check.b)]
    ttft = [(a.ttft_ms, b.ttft_ms) for a, b in pairs if a.ttft_ms is not None and b.ttft_ms is not None]
    totals = [(a.total_ms, b.total_ms) for a, b in pairs if a.total_ms is not None and b.total_ms is not None]
    a_ttft, b_ttft = (_number(median(side)) for side in zip(*ttft)) if ttft else (None, None)
    a_total, b_total = (_number(sum(side)) for side in zip(*totals)) if totals else (None, None)
    return ComparisonTiming(a_ttft, b_ttft, _ratio(a_ttft, b_ttft), a_total, b_total,
                            _ratio(a_total, b_total), len(ttft), len(totals))


def _ratio(a: Optional[float], b: Optional[float]) -> Optional[float]:
    # A zero baseline has no relative ratio. A zero candidate still has a ratio of zero.
    if a is None or a <= 0.0 or b is None:
        return None
    return _number(b / a)


def _regressed(a: Optional[float], b: Optional[float], percent: float) -> bool:
    ratio = _ratio(a, b)
    return (ratio is not None and a is not None and b is not None
            and b - a >= MIN_LATENCY_DELTA_MS and ratio >= 1 + percent / 100)


def _target(report: DoctorReport, label: str, sides: list[CheckSide], clean: Callable[[str], str]) -> ComparisonTarget:
    samples = [sample for side in sides for sample in side.samples.values()]
    try:
        target_url = sanitize_url_for_export(report.target_url) if report.target_url else ""
    except ValueError:
        target_url = ""
    return ComparisonTarget(
        clean(label), clean(target_url), clean(report.model), clean(report.dialect),
        sorted({model for sample in samples for model in sample.models}),
        sorted({fingerprint for sample in samples for fingerprint in sample.system_fingerprints}),
    )


def compare_reports(
    a_report: DoctorReport, b_report: DoctorReport, *, a_label: str = "A", b_label: str = "B",
    known_secrets: Sequence[str] = (), ignore_timing: bool = False, ttft_regress_pct: float = 50.0,
) -> ComparisonReport:
    """Compare like-for-like canary requests using response metadata and normalized contracts."""
    if _number(ttft_regress_pct) is None:
        raise ValueError("Latency regression percentage must be finite and nonnegative.")
    clean = _sanitize_display(known_secrets)
    a_results = {result.probe_id: result for result in a_report.results}
    b_results = {result.probe_id: result for result in b_report.results}
    checks: list[CheckComparison] = []
    model_mismatch = contract_drift = False
    for probe_id in dict.fromkeys((*a_results, *b_results)):
        report_id = clean(probe_id)
        a_result, b_result = a_results.get(probe_id), b_results.get(probe_id)
        a, b = _check_side(a_result, clean(a_report.model), clean), _check_side(b_result, clean(b_report.model), clean)
        divergences: list[Divergence] = []
        if a.status != b.status:
            divergences.append(Divergence(report_id, "status", None, a.status, b.status))
            contract_drift = True
        for name in dict.fromkeys((*a.samples, *b.samples)):
            if (name in a.samples) != (name in b.samples):
                divergences.append(Divergence(report_id, "sample_availability", clean(name),
                                              name in a.samples, name in b.samples))
                contract_drift = True
        for a_stream, b_stream in _pairs(a, b):
            diff, suspect, contract_changed = _compare_streams(report_id, a_stream, b_stream)
            divergences.extend(diff)
            model_mismatch |= suspect
            contract_drift |= contract_changed
        result = a_results[probe_id] if a_result is not None else b_results[probe_id]
        checks.append(CheckComparison(report_id, clean(result.code), a, b, divergences))

    timing = _timing(checks)
    latency_regression = not ignore_timing and any(
        _regressed(a, b, ttft_regress_pct) for a, b in (
            (timing.a_ttft_ms, timing.b_ttft_ms), (timing.a_total_ms, timing.b_total_ms),
        )
    )
    if model_mismatch:
        verdict = "SUSPECTED_MODEL_MISMATCH"
    elif contract_drift:
        verdict = "CONTRACT_DRIFT"
    elif latency_regression:
        verdict = "LATENCY_REGRESSION"
    else:
        verdict = "IDENTICAL_CONTRACT"

    statuses = {side.status for check in checks for side in (check.a, check.b)}
    codes = {a_report.exit_code, b_report.exit_code}
    if "FAIL" in statuses or EXIT_SILENT_PROTOCOL_BREACH in codes:
        exit_code = EXIT_SILENT_PROTOCOL_BREACH
    elif "ERROR" in statuses or EXIT_USAGE_OR_IO_ERROR in codes:
        exit_code = EXIT_USAGE_OR_IO_ERROR
    elif verdict != "IDENTICAL_CONTRACT" or EXIT_SEMANTIC_REGRESSION in codes:
        exit_code = EXIT_SEMANTIC_REGRESSION
    else:
        exit_code = EXIT_OK
    return ComparisonReport(
        _target(a_report, a_label, [check.a for check in checks], clean),
        _target(b_report, b_label, [check.b for check in checks], clean),
        checks, timing, model_mismatch, contract_drift, latency_regression, verdict, exit_code,
    )


_FIELD_LABELS = {
    "status": "Check status", "model": "Reported model", "system_fingerprint": "System fingerprint",
    "model_rewrite": "Reported model differs from requested model", "finish_reason": "Finish reason",
    "terminal_status": "Terminal status", "eof_clean": "Clean stream termination", "tool_calls": "Tool calls",
    "thinking_stream": "Thinking stream", "sample_availability": "Stream observed",
}


def _describe(value: Any) -> str:
    if value is None:
        return "—"
    if isinstance(value, bool):
        return "yes" if value else "no"
    if isinstance(value, list):
        return (", ".join(_describe(item) for item in value) or "none")[:240]
    if isinstance(value, ToolContract):
        details = ["valid JSON" if value.json_valid else "incomplete or invalid JSON"]
        if value.arguments_streamed:
            details.append("streamed arguments")
        if value.arguments_done:
            details.append("arguments-done event")
        if value.arguments_mismatch:
            details.append("argument mismatch")
        if value.identity_conflict:
            details.append("identity conflict")
        return f"{value.name or 'unnamed'} ({', '.join(details)})"
    return str(value)


def _metric_rows(report: ComparisonReport) -> list[tuple[str, str, str, str]]:
    def milliseconds(value: Optional[float]) -> str:
        return f"{value:.1f} ms" if value is not None else "—"

    def ratio(value: Optional[float]) -> str:
        return f"{value:.2f}×" if value is not None else "—"

    timing = report.timing
    return [
        ("Requested model", report.a.model, report.b.model, "—"),
        ("Reported model", _describe(report.a.observed_models), _describe(report.b.observed_models), "—"),
        ("System fingerprint", _describe(report.a.system_fingerprints), _describe(report.b.system_fingerprints), "—"),
        ("Median TTFT", milliseconds(timing.a_ttft_ms), milliseconds(timing.b_ttft_ms), ratio(timing.ttft_ratio)),
        ("Total stream latency", milliseconds(timing.a_total_ms), milliseconds(timing.b_total_ms),
         ratio(timing.total_latency_ratio)),
    ]


def _divergence_label(item: Divergence) -> str:
    sample = f" ({item.sample})" if item.sample and item.sample != f"doctor-{item.probe_id}" else ""
    return f"{item.probe_id} {_FIELD_LABELS[item.field]}{sample}"


def _target_labels(report: ComparisonReport) -> tuple[str, str]:
    a_label = f"A · {report.a.label}" if report.a.label and report.a.label != "A" else "A"
    b_label = f"B · {report.b.label}" if report.b.label and report.b.label != "B" else "B"
    return a_label, b_label


def render_comparison_terminal(report: ComparisonReport, *, no_color: bool = False) -> str:
    """Render the canary matrix and divergence summary for terminals and CI logs."""
    color = _supports_color(no_color)
    a_label, b_label = _target_labels(report)
    lines = [
        _c(f"inferdiff compare | {report.verdict} | Exit {report.exit_code}", "1", color),
        f"{a_label}  {report.a.target_url}", f"{b_label}  {report.b.target_url}", "",
        f"{'Check':<38}  {'A':<6}  {'B':<6}",
    ]
    for check in report.checks:
        statuses = [_c(f"{side.status:<6}", _STATUSES[side.status], color) for side in (check.a, check.b)]
        lines.append(f"{f'{check.probe_id} {check.code}':<38}  {statuses[0]}  {statuses[1]}")
    for metric, a, b, ratio in _metric_rows(report):
        suffix = f"  (B/A {ratio})" if ratio != "—" else ""
        lines.append(f"{metric:<22} {a} | {b}{suffix}")
    if report.divergences:
        lines.append("")
        for item in report.divergences:
            lines.append(f"{_divergence_label(item)}  {_describe(item.a)} → {_describe(item.b)}")
    return "\n".join(line.rstrip() for line in lines) + "\n"


_MD_ESCAPE = str.maketrans({char: f"&#{ord(char)};" for char in "|\\`[]!*_~"})


def _md_cell(value: str) -> str:
    return html.escape(value, quote=False).translate(_MD_ESCAPE)


def _md_row(*cells: str) -> str:
    return "| " + " | ".join(_md_cell(cell) for cell in cells) + " |"


def render_comparison_markdown(report: ComparisonReport) -> str:
    """Render Markdown tables that can be pasted into an issue or forum post."""
    labels = _target_labels(report)
    lines = [
        "## inferdiff comparison", "", f"**Verdict** `{report.verdict}` · exit {report.exit_code}", "",
        _md_row("Check", *labels), "| --- | --- | --- |",
    ]
    lines.extend(_md_row(f"{check.probe_id} {check.code}", check.a.status, check.b.status) for check in report.checks)
    lines.extend(("", _md_row("Metric", *labels, "B/A"), "| --- | --- | --- | --- |"))
    lines.extend(_md_row(*row) for row in _metric_rows(report))
    if report.divergences:
        lines.extend(("", _md_row("Divergence", *labels), "| --- | --- | --- |"))
        lines.extend(_md_row(_divergence_label(item), _describe(item.a), _describe(item.b))
                     for item in report.divergences)
    return "\n".join(lines) + "\n"


def _waterfall_lane(sample: Optional[StreamContract], scale: float) -> str:
    if sample is None or not sample.timeline:
        return "<p>Stream timing unavailable</p>"
    width = 500
    segments = [f'<rect x="0" y="5" width="{width}" height="14" rx="3" fill="#1e293b"/>']
    for start, end, category in sample.timeline:
        x_start, x_end = width * (start / scale), min(width - 2, width * (end / scale))
        if end - start > STALL_GAP_MS:
            segments.append(f'<line x1="{x_start:.1f}" y1="12" x2="{x_end:.1f}" y2="12" '
                            f'stroke="{COLOR_STALL}" stroke-dasharray="4 3"/>')
            x_start = x_end
        segment_width = max(2.0, x_end - x_start)
        segments.append(f'<rect x="{min(x_start, x_end):.1f}" y="7" width="{segment_width:.1f}" height="10" '
                        f'fill="{_frame_color(category)}"><title>{category}, {end:.1f} ms</title></rect>')
    segments.append(f'<text x="1" y="33" fill="#94a3b8" font-size="11">0 ms</text>'
                    f'<text x="{width}" y="33" text-anchor="end" fill="#94a3b8" font-size="11">{scale:.1f} ms</text>')
    return (f'<svg viewBox="0 0 {width} 36" role="img" aria-label="Stream timing">'
            f'{"".join(segments)}</svg>')


def _html_table(headers: Sequence[str], rows: Sequence[Sequence[str]]) -> str:
    headings = "".join(f"<th scope=\"col\">{_esc(cell)}</th>" for cell in headers)
    contents = "".join("<tr>" + "".join(f"<td>{_esc(cell)}</td>" for cell in row) + "</tr>" for row in rows)
    return f"<table><thead><tr>{headings}</tr></thead><tbody>{contents}</tbody></table>"


def render_comparison_html(report: ComparisonReport) -> str:
    """Render an offline dark report with paired waterfalls on shared time scales."""
    a_label, b_label = _target_labels(report)
    table = _html_table(("Check", a_label, b_label), [
        (f"{check.probe_id} {check.code}", f"{check.a.status} · {check.a.summary}", f"{check.b.status} · {check.b.summary}")
        for check in report.checks
    ])
    rows = []
    for check in report.checks:
        for key in dict.fromkeys((*check.a.samples, *check.b.samples)):
            a, b = check.a.samples.get(key), check.b.samples.get(key)
            samples = [sample for sample in (a, b) if sample is not None]
            scale = max(1.0, *(max(sample.total_ms or 0.0, sample.timeline[-1][1] if sample.timeline else 0.0)
                               for sample in samples))
            rows.append(f'<h3>{_esc(samples[0].sample)}</h3><div class="split">'
                        f'<div><strong>{_esc(a_label)}</strong>{_waterfall_lane(a, scale)}</div>'
                        f'<div><strong>{_esc(b_label)}</strong>{_waterfall_lane(b, scale)}</div></div>')
    legend_items = [(name, _frame_color(phase)) for name, phase in (
        ("Handshake", "HANDSHAKE"), ("Thinking", "REASONING"), ("Text", "CONTENT"), ("Tool", "TOOL"),
        ("Terminal", "TERMINAL"), ("Error", "ERROR"),
    )] + [("Gap >250 ms", COLOR_STALL)]
    legend = '<div class="legend">' + "".join(
        f'<span><i class="dot" style="background:{color}"></i>{_esc(name)}</span>' for name, color in legend_items
    ) + "</div>"
    body = (
        f'<header class="hero"><h1>inferdiff comparison</h1><p><strong>{report.verdict}</strong> · exit {report.exit_code}</p>'
        f'<p>{_esc(a_label)} · {_esc(report.a.target_url)}<br>{_esc(b_label)} · {_esc(report.b.target_url)}</p></header>'
        f'<section class="sec"><h2>Canary checks</h2>{table}</section>'
        f'<section class="sec"><h2>Identity and latency</h2>'
        f'{_html_table(("Metric", a_label, b_label, "B/A"), _metric_rows(report))}</section>'
    )
    if report.divergences:
        summary = _html_table(("Contract evidence", a_label, b_label), [
            (_divergence_label(item), _describe(item.a), _describe(item.b)) for item in report.divergences
        ])
        body += f'<section class="sec"><h2>Divergences</h2>{summary}</section>'
    waterfalls = "".join(rows) or "<p>Stream timing unavailable</p>"
    body += f'<section class="sec"><h2>Side-by-side Waterfall</h2>{legend}{waterfalls}</section>'
    return _wrap_html_document("inferdiff comparison", body)
