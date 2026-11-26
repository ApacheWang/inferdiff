"""Compose the selected telemetry sources into the v0.2 trace contract."""

from __future__ import annotations

from time import monotonic
from typing import Any

from ._task import TTFT_HOOK_BUDGET, ProbeTask, run_ttft_hook
from .base import BackendProbe
from .lmcache import LmcacheMpProbe
from .mooncake import MooncakeStoreProbe
from .proc_io import LinuxProcIoProbe

class CompositeBackendProbe:
    """Combine sources, with isolation asserted only by a caller that established it."""

    name = "composite"

    def __init__(
        self,
        lmcache_mp: LmcacheMpProbe | None = None,
        mooncake: MooncakeStoreProbe | None = None,
        proc_io: LinuxProcIoProbe | None = None,
        *,
        concurrency_isolated: bool = False,
    ) -> None:
        self._proc_io = proc_io
        self._http: tuple[BackendProbe, ...] = tuple(p for p in (lmcache_mp, mooncake) if p is not None)
        self._sources: tuple[BackendProbe, ...] = self._http + ((proc_io,) if proc_io is not None else ())
        self._metadata = {"probe_version": "0.2.0", "concurrency_isolated": concurrency_isolated}
        self._failed: set[str] = set()
        self._ttft_task: ProbeTask[bool] | None = None
        self._ttft_deadline = 0.0

    def describe_topology(self) -> dict[str, Any]:
        result = {**self._metadata, "sources": [probe.name for probe in self._sources]}
        for probe in self._sources:
            try:
                result[probe.name] = probe.describe_topology() or {}
            except Exception:
                result[probe.name] = {"status": "probe_error"}
        return result

    def sample_pre(self) -> None:
        # Keep the local baseline closest to request dispatch.
        self._failed.clear()
        self._ttft_task = None
        for probe in self._sources:
            try:
                probe.sample_pre()
            except Exception:
                self._failed.add(probe.name)

    def sample_ttft(self) -> None:
        probe = self._proc_io
        if probe is not None and probe.name not in self._failed:
            try:
                hook = probe.sample_ttft
                if getattr(hook, "__func__", None) is LinuxProcIoProbe.sample_ttft:
                    hook()
                else:
                    self._ttft_deadline = monotonic() + TTFT_HOOK_BUDGET
                    self._ttft_task = ProbeTask(lambda: run_ttft_hook(hook), "inferdiff-proc-ttft-hook")
            except Exception:
                self._failed.add(probe.name)

    def sample_eof(self, *, cutoff: float | None = None) -> dict[str, Any]:
        result: dict[str, Any] = dict(self._metadata)
        # Close the local window before any post-stream HTTP scrapes.
        local = (self._proc_io,) if self._proc_io is not None else ()
        for probe in local + self._http:
            try:
                ttft_ok: bool | None = True
                if probe is self._proc_io and self._ttft_task is not None:
                    ttft_ok = self._ttft_task.wait_until(self._ttft_deadline)
                if ttft_ok is None:
                    result[probe.name] = {"status": "ttft_unavailable"}
                elif not ttft_ok or probe.name in self._failed:
                    result[probe.name] = {"status": "probe_error"}
                else:
                    hook = probe.sample_eof
                    if getattr(hook, "__func__", None) is LinuxProcIoProbe.sample_eof:
                        result[probe.name] = hook(cutoff=cutoff)
                    else:
                        result[probe.name] = hook() or {}
            except Exception:
                result[probe.name] = {"status": "probe_error"}
        return result
