"""Stdlib assertion helpers for captured SSE and live inference endpoints."""

from __future__ import annotations

from http.client import HTTPException

from ._sse_contract import contract_report, inspect_sse
from .canary import PROBE_CATALOG, DoctorReport, run_doctor
from .detectors import DETECTOR_NAMES
from .recorder import RecorderError
from .schema import EXIT_OK, EXIT_USAGE_OR_IO_ERROR, is_strict_int

__all__ = ["InferdiffAssertionError", "assert_sse_honest", "assert_endpoint_honest"]

_GRADES = ("F", "C", "B", "A", "A+")
_DIAGNOSTIC_TOKENS = (
    set(PROBE_CATALOG) | set(DETECTOR_NAMES) | set(DETECTOR_NAMES.values())
    | {code for code, _, _ in PROBE_CATALOG.values()}
    | {"DOCTOR_ERROR", "FAIL", "WARN", "SKIP", "ERROR", "P0", "P1", "P2"}
)


class InferdiffAssertionError(AssertionError):
    """An assertion failure with a redacted report and structured findings."""

    def __init__(self, report: dict, *, min_grade: str | None = None) -> None:
        self.report = report
        self.findings = report["findings"]
        grade = report.get("grade")
        summary = f"Grade {grade if grade in _GRADES else 'unknown'}"
        if min_grade in _GRADES:
            summary += f" (minimum {min_grade})"

        diagnostics = {}
        for finding in self.findings:
            fields = [finding.get(key) for key in ("probe_id", "code", "status", "severity")]
            detail = " ".join(field for field in fields if isinstance(field, str) and field in _DIAGNOSTIC_TOKENS)
            if not detail or detail in diagnostics:
                continue
            seq = finding.get("frame_seq")
            last_seq = finding.get("last_frame_seq")
            if is_strict_int(seq) and seq >= 0:
                diagnostics[detail] = f"{detail} at frame seq {seq}"
            elif is_strict_int(last_seq) and last_seq >= 0:
                diagnostics[detail] = f"{detail} (last frame seq {last_seq})"
            else:
                diagnostics[detail] = detail
        if diagnostics:
            summary += ". " + ", ".join(diagnostics.values())
        super().__init__(summary)


def assert_sse_honest(
    sse_text: str,
    *,
    dialect: str = "auto",
    allow_warnings: bool = False,
    expect_usage: bool = False,
) -> dict:
    """Audit captured SSE offline and return a redacted contract report.

    Set ``expect_usage=True`` if the original request asked for usage. Missing
    requested usage is a P1 warning. P0 breaches always fail the assertion.
    """
    resolved_dialect, findings = inspect_sse(sse_text, dialect=dialect, expect_usage=expect_usage)
    report = contract_report(resolved_dialect, findings)
    if report["p0_count"] or (report["warning_count"] and not allow_warnings):
        raise InferdiffAssertionError(report)
    return report


def _doctor_assertion_report(report: DoctorReport) -> dict:
    # Only doctor-generated codes, enums, and numeric evidence reach this report.
    # Raw summaries, model IDs, endpoints, and trace paths can contain reflections.
    results = []
    findings = []
    for result in report.results:
        probe = {
            "probe_id": result.probe_id,
            "code": result.code,
            "severity": result.severity,
            "status": result.status,
        }
        trace_findings = [
            {"detector_id": finding.detector_id, "code": finding.code,
             "severity": finding.severity, "frame_seq": finding.frame_seq}
            for finding in result.findings
        ]
        results.append({
            **probe,
            "duration_ms": round(result.duration_ms, 1),
            "total_frames": result.total_frames,
            "findings": trace_findings,
        })
        if result.status != "PASS":
            frame_seq = next((finding.frame_seq for finding in result.findings
                              if finding.severity == result.severity and finding.frame_seq is not None), None)
            last_frame_seq = next((trace.frames[-1].seq for trace in reversed(result.traces) if trace.frames), None)
            findings.append({**probe, "frame_seq": frame_seq, "last_frame_seq": last_frame_seq})
    return {
        "dialect": report.dialect,
        "profile": report.profile,
        "grade": report.grade,
        "exit_code": report.exit_code,
        "p0_count": report.p0_count,
        "warning_count": report.warning_count,
        "error_count": report.error_count,
        "results": results,
        "findings": findings,
    }


def assert_endpoint_honest(
    base_url: str,
    *,
    model: str | None = None,
    api_key: str | None = None,
    profile: str = "quick",
    protocol: str = "openai",
    min_grade: str = "A",
    allow_warnings: bool = False,
    timeout: float = 30.0,
) -> dict:
    """Run live doctor probes and require the minimum grade and a clean exit.

    Returns a redacted scorecard. ``allow_warnings`` allows P1 warnings when
    the resulting grade meets ``min_grade``. Probe evidence is held in memory.
    """
    if min_grade not in _GRADES:
        raise ValueError("min_grade must be one of A+, A, B, C, or F.")
    try:
        doctor = run_doctor(
            base_url=base_url, model=model, api_key=api_key, profile=profile,
            protocol=protocol, timeout=timeout, save_dir=None, strict=not allow_warnings,
        )
    except (RecorderError, OSError, ValueError, HTTPException):
        # Setup and transport exceptions can carry arbitrary provider text or URLs.
        doctor = None

    if doctor is None:
        raise InferdiffAssertionError({
            "grade": "F", "exit_code": EXIT_USAGE_OR_IO_ERROR, "p0_count": 0,
            "warning_count": 0, "error_count": 1, "results": [],
            "findings": [{"code": "DOCTOR_ERROR", "status": "ERROR", "frame_seq": None}],
        })

    report = _doctor_assertion_report(doctor)
    below_minimum = _GRADES.index(doctor.grade) < _GRADES.index(min_grade)
    if doctor.exit_code != EXIT_OK or doctor.p0_count or below_minimum:
        raise InferdiffAssertionError(report, min_grade=min_grade if below_minimum else None)
    return report
