"""Bound optional blocking I/O, including operations without socket timeouts."""

from __future__ import annotations

from collections.abc import Callable
from threading import BoundedSemaphore, Event, Thread
from time import monotonic
from typing import Generic, TypeVar

T = TypeVar("T")
TTFT_HOOK_BUDGET = 0.05
_WORKER_SLOTS = BoundedSemaphore(16)


class ProbeTask(Generic[T]):
    """Run a probe operation without allowing it to keep the recorder alive."""

    def __init__(self, operation: Callable[[], T], name: str) -> None:
        self._result: T | None = None
        self._finished_at = float("inf")
        self._done = Event()

        def run() -> None:
            try:
                self._result = operation()
            except Exception:
                pass  # The caller supplies its own unavailable status.
            finally:
                self._finished_at = monotonic()
                self._done.set()
                _WORKER_SLOTS.release()

        # DNS and procfs reads cannot always be cancelled. Bound stranded workers.
        if _WORKER_SLOTS.acquire(blocking=False):
            try:
                Thread(target=run, name=name, daemon=True).start()
                return
            except RuntimeError:
                _WORKER_SLOTS.release()
        self._done.set()

    def result_at(self, cutoff: float) -> T | None:
        return self._result if self._done.is_set() and self._finished_at <= cutoff else None

    def wait_until(self, deadline: float) -> T | None:
        self._done.wait(max(0.0, deadline - monotonic()))
        return self.result_at(deadline)


def run_ttft_hook(hook: Callable[[], None]) -> bool:
    """Distinguish a failed hook from a hook still running past its deadline."""
    try:
        hook()
    except Exception:
        return False
    return True
