"""inferdiff: Wire-level canary doctor, regression diff, silent-failure forensics, and HTML waterfall."""

from __future__ import annotations

__version__ = "0.2.0.dev0"

from .canary import DoctorReport, ProbeResult, run_doctor
from .detectors import Finding, audit_trace, detect_d1, detect_d2, detect_d3, detect_d4, detect_d5
from .differ import DiffReport, DivergencePoint, diff_traces
from .exporter import render_audit_terminal, render_ci_summary, render_diff_terminal, render_github_issue
from .recorder import RecorderError, record_stream
from .schema import (
    EXIT_OK,
    EXIT_SEMANTIC_REGRESSION,
    EXIT_SILENT_PROTOCOL_BREACH,
    EXIT_USAGE_OR_IO_ERROR,
    SCHEMA_VERSION,
    TraceDocument,
    TraceFrame,
    TraceHeader,
    TraceSchemaError,
    TraceSummary,
    load_trace,
    write_trace,
)
from .waterfall import render_audit_html, render_diff_html, render_doctor_html

__all__ = [
    "__version__",
    "SCHEMA_VERSION",
    "EXIT_OK",
    "EXIT_USAGE_OR_IO_ERROR",
    "EXIT_SILENT_PROTOCOL_BREACH",
    "EXIT_SEMANTIC_REGRESSION",
    "DoctorReport",
    "ProbeResult",
    "run_doctor",
    "Finding",
    "DiffReport",
    "DivergencePoint",
    "TraceDocument",
    "TraceFrame",
    "TraceHeader",
    "TraceSummary",
    "TraceSchemaError",
    "RecorderError",
    "record_stream",
    "load_trace",
    "write_trace",
    "audit_trace",
    "diff_traces",
    "detect_d1",
    "detect_d2",
    "detect_d3",
    "detect_d4",
    "detect_d5",
    "render_audit_terminal",
    "render_diff_terminal",
    "render_github_issue",
    "render_ci_summary",
    "render_audit_html",
    "render_diff_html",
    "render_doctor_html",
]
