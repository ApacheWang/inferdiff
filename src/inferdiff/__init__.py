"""inferdiff: wire-level regression diff and silent-failure forensics for LLM serving."""

__version__ = "0.1.0"

from .detectors import Finding, audit_trace
from .differ import DiffReport, diff_traces
from .exporter import render_github_issue
from .recorder import record_stream
from .schema import (
    EXIT_OK,
    EXIT_SEMANTIC_REGRESSION,
    EXIT_SILENT_PROTOCOL_BREACH,
    EXIT_USAGE_OR_IO_ERROR,
    SCHEMA_VERSION,
    TraceDocument,
    load_trace,
    write_trace,
)

__all__ = [
    "__version__",
    "SCHEMA_VERSION",
    "EXIT_OK",
    "EXIT_USAGE_OR_IO_ERROR",
    "EXIT_SILENT_PROTOCOL_BREACH",
    "EXIT_SEMANTIC_REGRESSION",
    "TraceDocument",
    "Finding",
    "DiffReport",
    "record_stream",
    "load_trace",
    "write_trace",
    "audit_trace",
    "diff_traces",
    "render_github_issue",
]
