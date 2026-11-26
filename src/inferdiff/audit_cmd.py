"""Read offline captures and prepare private audit reports for the CLI."""

from __future__ import annotations

import io
import re
import sys
from pathlib import Path
from urllib.parse import unquote

from ._sse_contract import contract_report, inspect_capture, inspect_recording
from .detectors import DETECTOR_NAMES, VALID_AUDIT_DETECTORS, Finding, audit_trace
from .exporter import MAX_ISSUE_LINES, sanitize_trace_for_json_export
from .exporters import _ReportCase
from .redact import is_protocol_enum, scrub_report_data
from .schema import (
    EXIT_OK, EXIT_SEMANTIC_REGRESSION, EXIT_SILENT_PROTOCOL_BREACH, TraceDocument,
    empty_usage, is_finite_number, is_strict_int, parse_trace, strict_json_loads,
)

AUDIT_RULES = VALID_AUDIT_DETECTORS | {"C9", "C10"}
_WIRE_RULES = {"D1", "D2", "D3", "D4"}
_DIALECT_RULES = {"anthropic-messages": "C9", "gemini-sse": "C10"}
_TRACE_MESSAGES = {
    "D1": "The recorded stream reported success with an incomplete or inconsistent tool call.",
    "D2": "The recorded stream consumed budget or reported success without visible output.",
    "D3": "The recorded stream produced fewer tokens than the requested fixed budget.",
    "D4": "The recorded stream ended without a clean terminal state.",
    "D6": "Storage measurements suggest a page-cache warm-up effect.",
    "D7": "A storage lookup hit did not result in successful prefetch delivery.",
    "D8": "Storage reads were fragmented or slower than recomputing the prefix.",
}
_PRIVATE_METADATA = re.compile(r"(?i)\b(?:sk-|bearer\b|x-(?:goog-)?api-key\b)|[?&]key=|(?<!\w)[a-z]:[\\/]|\\\\")


def select_audit_rules(raw: str | None) -> set[str] | None:
    if raw is None:
        return None
    selected = {token.strip().upper() for token in raw.split(",") if token.strip()}
    if not selected or selected - AUDIT_RULES:
        allowed = ", ".join(sorted(AUDIT_RULES))
        raise ValueError(f"Invalid --only selection. Use {allowed}. D5 requires a trace pair.")
    return selected


def read_capture(source: str) -> bytes:
    try:
        if source != "-":
            return Path(source).read_bytes()
        if hasattr(sys.stdin, "buffer"):
            return sys.stdin.buffer.read()
        return sys.stdin.read().encode("utf-8", errors="surrogatepass")
    except (OSError, ValueError):
        raise ValueError("Could not read the audit input.") from None


def _is_trace(raw: bytes) -> bool:
    if not raw.lstrip().startswith(b"{"):
        return False
    for line in io.BytesIO(raw):
        line = line.lstrip()
        if not line:
            continue
        if not line.startswith(b"{"):
            break
        try:
            record = strict_json_loads(line.decode("utf-8"))
        except (ValueError, RecursionError):
            continue
        if isinstance(record, dict):
            record_type = record.get("type")
            return (record_type == "header" or "schema_version" in record
                    or (record_type == "frame" and "raw_wire" in record)
                    or (record_type == "summary" and "assembled" in record))
        break
    return False


def _recorded_finding(finding: Finding, total_frames: int) -> dict:
    rule = finding.detector_id
    seq = finding.frame_seq
    return {"code": rule, "detector_id": rule, "severity": finding.severity,
            "frame_seq": seq if is_strict_int(seq) and 0 <= seq < total_frames else None,
            "message": _TRACE_MESSAGES[rule]}


def audit_capture(
    raw: bytes, *, dialect: str, expect_usage: bool, strict: bool, only: set[str] | None,
) -> tuple[dict, TraceDocument | None, list[Finding]]:
    raw = raw.removeprefix(b"\xef\xbb\xbf")
    doc = None
    recorded = []
    if _is_trace(raw):
        try:
            doc = parse_trace(io.StringIO(raw.decode("utf-8")), source="Audit trace")
            dialect, findings = inspect_recording(doc, dialect=dialect, expect_usage=expect_usage)
            trace_rules = VALID_AUDIT_DETECTORS if only is None else only & VALID_AUDIT_DETECTORS
            trace_rules -= {"D4"}  # The shared checks include wire validity and recorded EOF evidence.
            if dialect != doc.header.dialect:
                trace_rules -= _WIRE_RULES
            if trace_rules:
                recorded = audit_trace(doc, only=trace_rules)
        except (TypeError, OverflowError, RecursionError, UnicodeError):
            raise ValueError("Invalid data in the recorded trace.") from None

        # Preserve transport, budget and storage evidence recorded alongside the wire.
        seen = {(item["detector_id"], item["severity"]) for item in findings}
        findings.extend(_recorded_finding(finding, len(doc.frames)) for finding in recorded
                        if (finding.detector_id, finding.severity) not in seen)
    else:
        dialect, findings = inspect_capture(raw, dialect=dialect, expect_usage=expect_usage)

    if only is not None:
        findings = [finding for finding in findings if finding["detector_id"] in only]
        recorded = [finding for finding in recorded if finding.detector_id in only]
    findings.sort(key=lambda item: (item["severity"], item["detector_id"]))
    report = contract_report(dialect, findings)
    report["exit_code"] = (EXIT_SILENT_PROTOCOL_BREACH if report["p0_count"] else
                           EXIT_SEMANTIC_REGRESSION if strict and report["warning_count"] else EXIT_OK)
    return report, doc, recorded


def _safe_probe_data(value: object, known_secrets: list[str]) -> object:
    def hide_private(item: object) -> object:
        if isinstance(item, dict):
            return {key: hide_private(child) for key, child in item.items()}
        if isinstance(item, list):
            return [hide_private(child) for child in item]
        if isinstance(item, str) and _PRIVATE_METADATA.search(unquote(item)):
            return "[redacted]"
        return item

    return hide_private(scrub_report_data(value, known_secrets))


def trace_report_metadata(doc: TraceDocument, known_secrets: list[str]) -> dict:
    """Retain structured recording context without exporting arbitrary trace strings."""
    exported = sanitize_trace_for_json_export(doc)
    metadata = doc.header.response_meta
    asm = doc.summary.assembled
    timing = {key: doc.summary.timing.get(key) for key in ("t_headers_ms", "ttff_ms", "ttft_effective_ms", "total_ms")}
    effective = doc.header.request.get("effective_params") or {}
    parameters = {key: effective.get(key) for key in ("max_budget_tokens", "temperature", "seed")}
    if any(isinstance(value, float) and not is_finite_number(value) for value in parameters.values()):
        raise ValueError("Audit trace has a non-finite request parameter.")
    parameters = {key: value if is_finite_number(value) else None for key, value in parameters.items()}
    finish = asm.get("finish_reason")
    usage = asm.get("reported_usage") or {}
    header = {
        "type": "header", "schema_version": doc.header.schema_version, "dialect": doc.header.dialect,
        "request": {"effective_params": parameters}, "response_meta": {"status_code": metadata["status_code"]},
        "backend_probe": _safe_probe_data(exported["header"]["backend_probe"], known_secrets),
    }
    summary = {
        "type": "summary", "eof_clean": doc.summary.eof_clean, "total_frames": doc.summary.total_frames,
        "timing": timing, "assembled": {
            "content_utf8_bytes": asm.get("content_utf8_bytes"),
            "observed_delta_frames": asm.get("observed_delta_frames"),
            "finish_reason": finish if is_protocol_enum(doc.header.dialect, "finish_reason", finish) else "unknown",
            "reported_usage": {key: usage[key] for key in (*empty_usage(), "total_tokens")
                               if is_strict_int(usage.get(key)) and usage[key] >= 0},
        },
    }
    if "backend_probe" in exported["summary"]:
        summary["backend_probe"] = _safe_probe_data(exported["summary"]["backend_probe"], known_secrets)
    return {"header": header, "summary": summary}


def _finding_line(finding: dict) -> str:
    seq = finding["frame_seq"]
    location = f" at frame #{seq}" if seq is not None else ""
    return f"[{finding['severity']}] {finding['code']}{location} {finding['message']}"


def render_audit_report(report: dict, *, github_issue: bool) -> str:
    heading = "### inferdiff offline audit" if github_issue else "inferdiff offline audit"
    verdict = (f"Grade {report['grade']} ({report['dialect']}) | "
               f"{report['p0_count']} P0 | {report['warning_count']} P1 | exit {report['exit_code']}")
    lines = [heading, verdict]
    findings = report["findings"]
    if github_issue:
        lines.append("")
        available = MAX_ISSUE_LINES - len(lines)
        if len(findings) > available:
            remaining = len(findings) - available + 1
            lines.extend(f"- {_finding_line(item)}" for item in findings[:available - 1])
            lines.append(f"- {remaining} more findings. See the full audit report.")
        else:
            lines.extend(f"- {_finding_line(item)}" for item in findings)
    else:
        lines.extend(f"  {_finding_line(item)}" for item in findings)
    return "\n".join(lines) + "\n"


def stream_audit_cases(report: dict, *, recorded: bool, only: set[str] | None) -> list[_ReportCase]:
    rules = (VALID_AUDIT_DETECTORS if recorded else _WIRE_RULES) | {
        rule for dialect, rule in _DIALECT_RULES.items() if report["dialect"] == dialect
    }
    if only is not None:
        rules &= only
    outcomes: dict[str, list[tuple[str, str]]] = {rule: [] for rule in rules}
    for finding in report["findings"]:
        status = "FAIL" if finding["severity"] == "P0" else "WARN"
        outcomes.setdefault(finding["detector_id"], []).append((status, _finding_line(finding)))
    cases = [_ReportCase(rule, DETECTOR_NAMES.get(rule, rule) if recorded else rule, "audit",
                         outcomes=tuple(notes), trace_path="capture") for rule, notes in sorted(outcomes.items())]
    if report["exit_code"] == EXIT_SEMANTIC_REGRESSION:
        cases.append(_ReportCase(None, "Audit verdict", "audit", outcomes=(("FAIL", "Strict audit detected a warning."),)))
    return cases
