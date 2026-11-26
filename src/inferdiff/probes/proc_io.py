"""Linux process-wide I/O counters sampled at the three stream boundaries."""

from __future__ import annotations

from pathlib import Path
from time import monotonic
from typing import Any

from ..redact import redact_secret_text
from ._task import ProbeTask

_COUNTERS = frozenset({"rchar", "syscr", "read_bytes", "write_bytes", "cancelled_write_bytes"})
_SAMPLE_BUDGET = 0.05
_Identity = tuple[str, int | str]
_Snapshot = tuple[str | None, dict[str, int], _Identity | None, str | None]


def _window(before: dict[str, int], after: dict[str, int]) -> dict[str, int]:
    return {key: value - before[key] for key, value in after.items() if key in before and value >= before[key]}


class LinuxProcIoProbe:
    name = "proc_io"

    def __init__(self, pid: int, proc_root: str = "/proc") -> None:
        if type(pid) is not int or pid <= 0:
            raise ValueError("Probe PID must be a positive integer.")
        self.pid = pid
        self._proc_dir = Path(proc_root) / str(pid)
        self._pre: _Snapshot = ("skipped_unavailable", {}, None, None)
        self._ttft_task: ProbeTask[_Snapshot] | None = None
        self._ttft_deadline = 0.0

    def describe_topology(self) -> dict[str, Any]:
        return {"pid": self.pid}

    def _read_io(self) -> tuple[str | None, dict[str, int]]:
        try:
            content = (self._proc_dir / "io").read_text(encoding="ascii")
        except PermissionError:
            return "skipped_permission", {}
        except (OSError, UnicodeError):
            return "skipped_unavailable", {}
        counters = {}
        for line in content.splitlines():
            key, _, raw = line.partition(":")
            if key not in _COUNTERS:
                continue
            try:
                value = int(raw)
            except ValueError:
                continue
            if 0 <= value < 2**64:
                counters[key] = value
        return (None if counters else "skipped_unavailable"), counters

    def _identity(self) -> tuple[_Identity, str | None]:
        try:
            stat = (self._proc_dir / "stat").read_text(encoding="utf-8", errors="replace")
        except FileNotFoundError:
            comm = (self._proc_dir / "comm").read_text(encoding="utf-8", errors="replace").rstrip("\n")
            if not comm:
                raise ValueError("Missing process identity")
            return ("comm", comm), comm
        # comm can contain spaces and ')' characters. The numeric fields follow the last ')'.
        prefix, close, rest = stat.rpartition(")")
        pid, open_paren, comm = prefix.partition("(")
        if not close or not open_paren or int(pid) != self.pid:
            raise ValueError("Invalid process identity")
        start = int(rest.split()[19])  # Field 22, with the state (field 3) at index 0.
        return ("start_time", start), comm

    def _snapshot(self) -> _Snapshot:
        try:
            identity, comm = self._identity()
            status, counters = self._read_io()
            if self._identity()[0] != identity:
                return "process_changed", {}, None, None
            return status, counters, identity, comm
        except PermissionError:
            return "skipped_permission", {}, None, None
        except (OSError, ValueError, IndexError):
            return "skipped_unavailable", {}, None, None

    def _bounded_snapshot(self) -> _Snapshot:
        deadline = monotonic() + _SAMPLE_BUDGET
        task = ProbeTask(self._snapshot, "inferdiff-proc-snapshot")
        return task.wait_until(deadline) or ("skipped_unavailable", {}, None, None)

    def sample_pre(self) -> None:
        self._ttft_task = None
        self._pre = self._bounded_snapshot()

    def sample_ttft(self) -> None:
        self._ttft_deadline = monotonic() + _SAMPLE_BUDGET
        self._ttft_task = ProbeTask(self._snapshot, "inferdiff-proc-ttft")

    def sample_eof(self, *, cutoff: float | None = None) -> dict[str, Any]:
        if cutoff is None:
            cutoff = monotonic()
        pre_status, pre, identity, comm = self._pre
        ttft_status = "ttft_not_observed"
        ttft: dict[str, int] = {}
        if self._ttft_task is not None:
            sample = self._ttft_task.result_at(min(cutoff, self._ttft_deadline))
            ttft_status, ttft, ttft_identity, _ = sample or ("ttft_unavailable", {}, None, None)
            if identity is not None and ttft_identity is not None and identity != ttft_identity:
                ttft_status = "process_changed"
        eof_status, eof, eof_identity, _ = self._bounded_snapshot()
        if identity is not None and eof_identity is not None and identity != eof_identity:
            eof_status = "process_changed"
        changed = "process_changed" in (pre_status, ttft_status, eof_status)
        status = "process_changed" if changed else pre_status or eof_status or ttft_status or "ok"
        prefill = _window(pre, ttft) if not (changed or pre_status or ttft_status) else {}
        full = _window(pre, eof) if not (changed or pre_status or eof_status) else {}
        prefill_window: dict[str, int | float | str] = {
            result: prefill[key] for key, result in (
                ("rchar", "delta_rchar_bytes"), ("read_bytes", "delta_read_bytes"), ("syscr", "delta_syscr"),
            ) if key in prefill
        }
        if ttft_status or pre_status or changed:
            prefill_window["status"] = "process_changed" if changed else ttft_status or pre_status
        if "rchar" in prefill and prefill.get("syscr", 0) > 0:
            prefill_window["avg_syscall_read_kb"] = prefill["rchar"] / (1024 * prefill["syscr"])
        full_window = {
            result: full[key] for key, result in (
                ("read_bytes", "delta_read_bytes_total"), ("rchar", "delta_rchar_bytes_total"),
            ) if key in full
        }
        if "write_bytes" in prefill and "cancelled_write_bytes" in prefill:
            prefill_window["delta_write_bytes_net"] = prefill["write_bytes"] - prefill["cancelled_write_bytes"]
        if "write_bytes" in full and "cancelled_write_bytes" in full:
            # Cancellations can exceed the writes attributed to this process in the window.
            full_window["delta_write_bytes_net"] = full["write_bytes"] - full["cancelled_write_bytes"]
        result = {
            **self.describe_topology(),
            "status": status,
            "prefill_window": prefill_window,
            "full_window": full_window,
        }
        if comm:
            result["comm"] = redact_secret_text(comm)[:64]
        return result
