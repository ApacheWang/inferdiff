"""Re-run current detectors against saved trace bundles."""

from __future__ import annotations

from collections import defaultdict
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Iterable, Sequence

from . import __version__
from .detectors import D1, Finding, audit_trace, detect_d5, detect_d8_pair
from .exporter import _strip_controls_and_newlines
from .redact import scrub_report_text
from .schema import EXIT_OK, EXIT_SEMANTIC_REGRESSION, EXIT_SILENT_PROTOCOL_BREACH, TraceDocument, is_strict_int, load_trace

_TRACE_SUFFIX = ".trace.jsonl"


@dataclass(frozen=True)
class ReplayTrace:
    path: Path
    name: str
    doc: TraceDocument
    findings: list[Finding]
    pair_findings: list[Finding] | None = None

    def to_dict(self) -> dict[str, Any]:
        return {
            "trace": self.name,
            "dialect": self.doc.header.dialect,
            "findings": [finding.to_dict() for finding in self.findings],
            "pair_findings": [finding.to_dict() for finding in self.pair_findings] if self.pair_findings is not None else None,
        }


@dataclass(frozen=True)
class ReplayBreach:
    trace: str
    finding: Finding
    previous_severity: str | None = None
    current_severity: str | None = None

    def to_dict(self) -> dict[str, Any]:
        payload = {"trace": self.trace, **self.finding.to_dict()}
        if self.previous_severity is not None:
            payload["previous_severity"] = self.previous_severity
        if self.current_severity is not None:
            payload["current_severity"] = self.current_severity
        return payload


@dataclass
class ReplayRegression:
    new: list[ReplayBreach] = field(default_factory=list)
    fixed: list[ReplayBreach] = field(default_factory=list)
    unchanged: list[ReplayBreach] = field(default_factory=list)

    def sections(self) -> tuple[tuple[str, list[ReplayBreach]], ...]:
        return (("NEW_BREACHES", self.new), ("FIXED_BREACHES", self.fixed), ("UNCHANGED", self.unchanged))

    def to_dict(self) -> dict[str, list[dict[str, Any]]]:
        return {label: [breach.to_dict() for breach in breaches] for label, breaches in self.sections()}


@dataclass(frozen=True)
class ReplayReport:
    traces: list[ReplayTrace]
    baseline_traces: list[ReplayTrace]
    regression: ReplayRegression | None
    exit_code: int

    @property
    def input_paths(self) -> list[Path]:
        return [trace.path for trace in self.traces + self.baseline_traces]

    def to_dict(self) -> dict[str, Any]:
        result = {
            "version": __version__,
            "exit_code": self.exit_code,
            "traces": [trace.to_dict() for trace in self.traces],
        }
        if self.regression is not None:
            result["baseline_traces"] = [trace.to_dict() for trace in self.baseline_traces]
            result["regression"] = self.regression.to_dict()
        return result


def _trace_paths(path: Path, *, directory_only: bool = False) -> dict[str, Path]:
    if path.is_dir():
        traces = {file.relative_to(path).as_posix(): file for file in path.rglob(f"*{_TRACE_SUFFIX}")
                  if file.name.endswith(_TRACE_SUFFIX) and file.is_file()}
        return dict(sorted(traces.items()))
    if not directory_only and path.is_file() and path.name.endswith(_TRACE_SUFFIX):
        return {path.name: path}
    if directory_only:
        raise ValueError("--baseline must be a directory of .trace.jsonl files.")
    raise ValueError("Replay input must be a .trace.jsonl file or a directory of traces.")


def _findings_by_subject(findings: Iterable[Finding]) -> dict[tuple[str, str, int], list[Finding]]:
    grouped: dict[tuple[str, str, int], list[Finding]] = defaultdict(list)
    for finding in findings:
        # D1 can emit one finding for each malformed call. Tool index survives chunking changes.
        index = finding.evidence.get("tool_index") if finding.detector_id == D1 else None
        grouped[finding.detector_id, finding.code, index if is_strict_int(index) else -1].append(finding)
    return grouped


def _compare_trace_findings(
    regression: ReplayRegression, name: str, before: Iterable[Finding], after: Iterable[Finding],
) -> None:
    old_groups, new_groups = _findings_by_subject(before), _findings_by_subject(after)
    for subject in sorted(old_groups.keys() | new_groups.keys()):
        old, new = old_groups.get(subject, []), new_groups.get(subject, [])
        remaining = []
        for finding in new:
            match_index = next((i for i, prior in enumerate(old) if prior.severity == finding.severity), None)
            if match_index is None:
                remaining.append(finding)
            else:
                old.pop(match_index)
                regression.unchanged.append(ReplayBreach(name, finding))

        old.sort(key=lambda finding: finding.severity)
        remaining.sort(key=lambda finding: finding.severity)
        for prior, finding in zip(old, remaining):
            if finding.severity < prior.severity:
                regression.new.append(ReplayBreach(name, finding, previous_severity=prior.severity))
            else:
                regression.fixed.append(ReplayBreach(name, prior, current_severity=finding.severity))
        regression.new.extend(ReplayBreach(name, finding) for finding in remaining[len(old):])
        regression.fixed.extend(ReplayBreach(name, finding) for finding in old[len(remaining):])


def run_replay(path: str | Path, *, baseline: str | Path | None = None, strict: bool = False) -> ReplayReport:
    """Audit saved traces and optionally compare matching relative filenames."""
    paths = _trace_paths(Path(path))
    baseline_paths = _trace_paths(Path(baseline), directory_only=True) if baseline is not None else {}
    if not paths and not baseline_paths:
        raise ValueError("No .trace.jsonl files found for replay.")

    baseline_traces = {}
    for name, file in baseline_paths.items():
        doc = load_trace(file)
        baseline_traces[name] = ReplayTrace(file, name, doc, audit_trace(doc))
    traces = {}
    for name, file in paths.items():
        doc = load_trace(file)
        prior = baseline_traces.get(name)
        pair_findings = detect_d5(prior.doc, doc) + detect_d8_pair(prior.doc, doc) if prior else None
        traces[name] = ReplayTrace(file, name, doc, audit_trace(doc), pair_findings)

    regression = None
    if baseline is None:
        gate_findings = (finding for trace in traces.values() for finding in trace.findings)
    else:
        regression = ReplayRegression()
        for name in sorted(baseline_traces.keys() | traces.keys()):
            prior, current = baseline_traces.get(name), traces.get(name)
            _compare_trace_findings(regression, name, prior.findings if prior else [], current.findings if current else [])
            if current and current.pair_findings:
                regression.new.extend(ReplayBreach(name, finding) for finding in current.pair_findings)
        gate_findings = (breach.finding for breach in regression.new)

    severities = {finding.severity for finding in gate_findings}
    exit_code = EXIT_OK
    if "P0" in severities:
        exit_code = EXIT_SILENT_PROTOCOL_BREACH
    elif strict and "P1" in severities:
        exit_code = EXIT_SEMANTIC_REGRESSION
    return ReplayReport(list(traces.values()), list(baseline_traces.values()), regression, exit_code)


def _finding_label(finding: Finding) -> str:
    return f"{finding.detector_id} {finding.severity} {finding.code}"


def render_replay_terminal(report: ReplayReport, *, known_secrets: Sequence[str] = ()) -> str:
    """Render a bundle summary for the terminal."""
    lines = [f"inferdiff replay  |  traces={len(report.traces)}  exit={report.exit_code}"]
    if report.regression is None:
        for trace in report.traces:
            lines.append(f"  {trace.name}  |  {len(trace.findings)} findings")
            lines.extend(f"    {_finding_label(finding)}  {finding.message}" for finding in trace.findings)
    else:
        for section, breaches in report.regression.sections():
            lines.append(f"  {section}  {len(breaches)}")
            lines.extend(
                f"    {breach.trace}  {_finding_label(breach.finding)}  {breach.finding.message}"
                for breach in breaches
            )
    return "\n".join(_strip_controls_and_newlines(scrub_report_text(line, known_secrets)) for line in lines) + "\n"
