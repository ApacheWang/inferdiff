"""Serialize canary and detector results as SARIF 2.1.0 or JUnit XML."""

from __future__ import annotations

import json
import xml.etree.ElementTree as ET
from collections import defaultdict
from dataclasses import dataclass
from typing import Iterable, Sequence
from urllib.parse import quote, unquote, urlsplit

from . import __version__
from .canary import DoctorReport
from .comparison import ComparisonReport
from .detectors import DETECTOR_NAMES, D5, VALID_AUDIT_DETECTORS, Finding
from .differ import DiffReport
from .redact import sanitize_url_path, scrub_report_text
from .replay import ReplayReport
from .schema import EXIT_SEMANTIC_REGRESSION, EXIT_USAGE_OR_IO_ERROR, TraceDocument, is_finite_number

_SARIF_SCHEMA = "https://json.schemastore.org/sarif-2.1.0.json"
_SARIF_ENDPOINT_BASE = "INFERDIFF_ENDPOINTS"
_SARIF_TRACE_BASE = "INFERDIFF_TRACES"
_SARIF_LEVELS = {"FAIL": "error", "WARN": "warning"}
_JUNIT_TAGS = {"FAIL": "failure", "SKIP": "skipped", "ERROR": "error"}
_STATUS_RANK = {status: rank for rank, status in enumerate(("PASS", "SKIP", "WARN", "FAIL", "ERROR"))}


@dataclass(frozen=True)
class _ReportCase:
    rule_id: str | None
    code: str
    scope: str
    endpoint: str = ""
    outcomes: tuple[tuple[str, str], ...] = ()
    duration_seconds: float = 0.0
    executed: bool = True
    trace_path: str = ""

    @property
    def status(self) -> str:
        return max((status for status, _ in self.outcomes), key=_STATUS_RANK.__getitem__, default="PASS")


def canary_cases(report: DoctorReport) -> list[_ReportCase]:
    """Keep the outcome and runtime of each selected check."""
    cases = []
    for result in report.results:
        endpoint = _trace_endpoint(result.traces[0]) if result.traces else ""
        cases.append(_ReportCase(
            result.probe_id, result.code, "canary", endpoint or report.chat_url or report.target_url,
            ((result.status, result.summary),), _seconds(result.duration_ms),
        ))
    return cases


def _trace_endpoint(doc: TraceDocument) -> str:
    return doc.header.request.get("url") or ""


def _detector_cases(
    detector_ids: Iterable[str], findings: Sequence[Finding], endpoint: str, scope: str, *, trace_path: str = "",
) -> list[_ReportCase]:
    outcomes: dict[str, list[tuple[str, str]]] = defaultdict(list)
    for finding in findings:
        status = "FAIL" if finding.severity == "P0" else "WARN"
        outcomes[finding.detector_id].append((status, finding.message))
    return [_ReportCase(rule_id, DETECTOR_NAMES[rule_id], scope, endpoint, tuple(outcomes[rule_id]), trace_path=trace_path)
            for rule_id in sorted(detector_ids)]


def audit_cases(
    doc: TraceDocument, findings: Sequence[Finding], *, only: Iterable[str] | None = None,
) -> list[_ReportCase]:
    """Represent enabled single-trace detectors, including those with no findings."""
    return _detector_cases(VALID_AUDIT_DETECTORS if only is None else only, findings, _trace_endpoint(doc), "audit")


def replay_cases(report: ReplayReport) -> list[_ReportCase]:
    """Export every executed detector and the findings that can drive the replay gate."""
    regressions: dict[str, list[Finding]] = defaultdict(list)
    if report.regression is not None:
        for breach in report.regression.new:
            regressions[breach.trace].append(breach.finding)
    cases = []
    for trace in report.traces:
        scope = f"replay.{trace.name}"
        has_pair = trace.pair_findings is not None
        detectors = DETECTOR_NAMES if has_pair else VALID_AUDIT_DETECTORS
        findings = trace.findings if report.regression is None else regressions[trace.name]
        trace_cases = _detector_cases(detectors, findings, "", scope, trace_path=trace.name)
        if not has_pair:
            trace_cases.append(_ReportCase(D5, DETECTOR_NAMES[D5], scope, executed=False,
                                           outcomes=(("SKIP", "D5 requires a matching baseline trace."),)))
        cases.extend(sorted(trace_cases, key=lambda case: case.rule_id or ""))
    if report.exit_code == EXIT_SEMANTIC_REGRESSION:
        cases.append(_ReportCase(None, "Replay verdict", "replay", outcomes=(("FAIL", "Strict replay detected a P1 breach."),)))
    return cases


def diff_cases(after: TraceDocument, report: DiffReport, *, ignore_timing: bool = False) -> list[_ReportCase]:
    """Represent target and pair findings that can drive the diff exit code."""
    endpoint = _trace_endpoint(after)
    cases = _detector_cases(VALID_AUDIT_DETECTORS if ignore_timing else DETECTOR_NAMES,
                            [*report.after_findings, *report.pair_findings], endpoint, "diff")
    if ignore_timing:
        cases.append(_ReportCase(D5, DETECTOR_NAMES[D5], "diff", endpoint,
                                 (("SKIP", "Timing checks disabled."),), executed=False))
        cases.sort(key=lambda case: case.rule_id or "")
    if report.exit_code and not any(case.status == "FAIL" for case in cases):
        reasons = []
        if not report.semantic_equal:
            reasons.append("Semantic output changed.")
        if report.ttft_regressed:
            reasons.append("Time to first token regressed.")
        message = " ".join(["Diff reached the configured failure threshold.", *reasons])
        cases.append(_ReportCase(None, "Diff verdict", "diff", outcomes=(("FAIL", message),)))
    return cases


def comparison_cases(report: ComparisonReport) -> list[_ReportCase]:
    """Keep each target's check outcome and any additional failing comparison verdict."""
    cases = []
    for check in report.checks:
        for label, side in (("A", check.a), ("B", check.b)):
            duration = sum(_seconds(sample.total_ms) for sample in side.samples.values())
            cases.append(_ReportCase(check.probe_id, check.code, f"compare.{label}",
                                     outcomes=((side.status, side.summary),), duration_seconds=duration))
    if report.exit_code and not any(case.status in ("FAIL", "ERROR") for case in cases):
        status = "ERROR" if report.exit_code == EXIT_USAGE_OR_IO_ERROR else "FAIL"
        cases.append(_ReportCase(None, "Comparison verdict", "compare", outcomes=((status, report.verdict),)))
    return cases


def _clean_text(value: str, known_secrets: Sequence[str]) -> str:
    value = scrub_report_text(value, known_secrets)
    # XML 1.0 excludes most ASCII controls, surrogates, and the terminal BMP noncharacters.
    return "".join(ch if ch in "\t\n\r" or 0x20 <= ord(ch) <= 0xD7FF
                   or 0xE000 <= ord(ch) <= 0xFFFD or ord(ch) >= 0x10000 else " " for ch in value)


def _endpoint_uri(endpoint: str, rule_id: str, known_secrets: Sequence[str]) -> str:
    """Build a synthetic artifact path with neither URL authority nor query data."""
    try:
        parsed = urlsplit(endpoint)
        path = parsed.path if parsed.scheme in ("http", "https") and parsed.hostname else ""
    except ValueError:
        path = ""
    return _artifact_uri(path, rule_id, known_secrets, prefix="inferdiff-endpoints")


def _artifact_uri(path: str, rule_id: str, known_secrets: Sequence[str], *, prefix: str) -> str:
    segments = [prefix]
    for part in _clean_text(sanitize_url_path(path), known_secrets).split("/"):
        value = _clean_text(unquote(part), known_secrets)
        if value in ("", ".", ".."):
            continue
        if "/" in value or "\\" in value:
            value = "redacted"
        segments.append(quote(value, safe=""))
    segments.append(rule_id)
    return "/".join(segments)


def render_sarif(cases: Sequence[_ReportCase], *, known_secrets: Sequence[str] = ()) -> str:
    """Render executed rules and a result for each failed check or warning."""
    rules, results = [], []
    rule_indices: dict[str, int] = {}
    uri_bases = {_SARIF_ENDPOINT_BASE: {"uri": "file:///", "description": {"text": "Root for synthetic endpoint paths."}}}
    for case in cases:
        rule_id = case.rule_id
        if not case.executed or rule_id is None:
            continue
        if rule_id not in rule_indices:
            rule_indices[rule_id] = len(rules)
            name = _clean_text(case.code, known_secrets)
            rules.append({"id": rule_id, "name": name, "shortDescription": {"text": name.replace("_", " ")}})
        for status, message in case.outcomes:
            if status not in _SARIF_LEVELS:
                continue
            if case.trace_path:
                uri = _artifact_uri(case.trace_path, rule_id, known_secrets, prefix="inferdiff-traces")
                base = _SARIF_TRACE_BASE
                uri_bases[base] = {"uri": "file:///", "description": {"text": "Root for synthetic trace paths."}}
            else:
                uri = _endpoint_uri(case.endpoint, rule_id, known_secrets)
                base = _SARIF_ENDPOINT_BASE
            results.append({
                "ruleId": rule_id,
                "ruleIndex": rule_indices[rule_id],
                "level": _SARIF_LEVELS[status],
                "message": {"text": _clean_text(message, known_secrets) or rule_id},
                "locations": [{
                    "physicalLocation": {"artifactLocation": {"uri": uri, "uriBaseId": base}},
                    "logicalLocations": [{"name": rule_id, "fullyQualifiedName": uri}],
                }],
            })
    return json.dumps({
        "$schema": _SARIF_SCHEMA,
        "version": "2.1.0",
        "runs": [{
            "tool": {"driver": {"name": "inferdiff", "version": __version__, "rules": rules}},
            "originalUriBaseIds": uri_bases,
            "results": results,
        }],
    }, ensure_ascii=True, indent=2, allow_nan=False) + "\n"


def _seconds(milliseconds: float | None) -> float:
    return milliseconds / 1000.0 if is_finite_number(milliseconds) and milliseconds > 0 else 0.0


def render_junit(cases: Sequence[_ReportCase], *, known_secrets: Sequence[str] = ()) -> str:
    """Render one XML testcase for each check, detector, or failing aggregate verdict."""
    root = ET.Element("testsuites")
    suite = ET.SubElement(root, "testsuite", name="inferdiff", tests=str(len(cases)))
    counts = dict.fromkeys(_JUNIT_TAGS, 0)
    total_seconds = 0.0
    for case in cases:
        seconds = case.duration_seconds
        total_seconds += seconds
        name = f"{case.rule_id} {case.code}" if case.rule_id else case.code
        testcase = ET.SubElement(suite, "testcase", classname=_clean_text(f"inferdiff.{case.scope}", known_secrets),
                                 name=_clean_text(name, known_secrets), time=f"{seconds:.6f}")
        status = case.status
        if status == "PASS":
            continue
        notes = [_clean_text(message, known_secrets) for _, message in case.outcomes]
        message = "\n".join(note for note in notes if note)
        if status == "WARN":
            ET.SubElement(testcase, "system-out").text = f"WARN: {message}"
        else:
            counts[status] += 1
            element = ET.SubElement(testcase, _JUNIT_TAGS[status], message=message or status)
            if status != "SKIP":
                element.text = message
    suite.attrib.update(failures=str(counts["FAIL"]), skipped=str(counts["SKIP"]),
                        errors=str(counts["ERROR"]), time=f"{total_seconds:.6f}")
    ET.indent(root)
    return ET.tostring(root, encoding="unicode", xml_declaration=True) + "\n"
