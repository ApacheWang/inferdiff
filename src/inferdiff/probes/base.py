"""v0.2 extension protocol for optional non-intrusive backend KV/storage probes.

Implements the three-point snapshot contract (T_pre -> T_ttft -> T_eof):
  - describe_topology() -> written to header.backend_probe
  - sample_pre()        -> baseline before request dispatch (HTTP /metrics + /proc/pid/io)
  - sample_ttft()       -> schedule a local snapshot at the first effective payload frame
  - sample_eof()        -> post-EOF snapshot & delta payload for summary.backend_probe
"""

from __future__ import annotations

from typing import Any, Dict, Optional, Protocol


class BackendProbe(Protocol):
    """Interface for v0.2 backend telemetry probes (LMCache / Mooncake / Linux proc_io)."""

    name: str

    def describe_topology(self) -> Optional[Dict[str, Any]]:
        """Return static probe topology & version metadata for header.backend_probe."""
        ...

    def sample_pre(self) -> None:
        """T_pre: capture baseline counters immediately before request dispatch."""
        ...

    def sample_ttft(self) -> None:
        """T_ttft: schedule a local snapshot after the first effective frame is recorded."""
        ...

    def sample_eof(self) -> Optional[Dict[str, Any]]:
        """T_eof: capture post-stream counters and return delta dict for summary.backend_probe."""
        ...


class NullProbe:
    """Default v0.1 no-op probe (keeps header.backend_probe = null and zero runtime overhead)."""

    name = "null"

    def describe_topology(self) -> Optional[Dict[str, Any]]:
        return None

    def sample_pre(self) -> None:
        return None

    def sample_ttft(self) -> None:
        return None

    def sample_eof(self) -> Optional[Dict[str, Any]]:
        return None
