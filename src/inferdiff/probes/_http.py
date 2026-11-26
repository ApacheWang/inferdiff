"""Read-only HTTP transport shared by the optional backend scrapers."""

from __future__ import annotations

import http.client
import socket
import threading
from contextlib import closing
from time import monotonic
from urllib.parse import SplitResult

from ..schema import is_finite_number
from ._task import ProbeTask

_MAX_METRICS_BYTES = 4 * 1024 * 1024


def validate_timeout(timeout: float) -> None:
    if not is_finite_number(timeout) or not 0 < timeout <= threading.TIMEOUT_MAX:
        raise ValueError("Probe timeout must be a positive finite number.")


def get_text(
    url: SplitResult, timeout: float, *, max_bytes: int = _MAX_METRICS_BYTES,
) -> tuple[int | None, str]:
    """GET only the configured target, without redirect, request credentials, or proxy handling."""
    deadline = monotonic() + timeout
    try:
        if url.scheme not in ("http", "https") or not url.hostname or url.port == 0:
            return None, ""
        port = url.port or (443 if url.scheme == "https" else 80)
    except ValueError:
        return None, ""
    cls = http.client.HTTPSConnection if url.scheme == "https" else http.client.HTTPConnection
    target = url.path or "/"
    if url.query:
        target += "?" + url.query
    active_socket = None

    def remaining() -> float:
        budget = deadline - monotonic()
        if budget <= 0:
            raise TimeoutError
        return budget

    def scrape() -> tuple[int, str]:
        nonlocal active_socket
        # Passing an explicit port prevents http.client from splitting an IPv6 hextet.
        with closing(cls(url.hostname, port, timeout=remaining())) as conn:
            conn.connect()
            sock = active_socket = conn.sock
            sock.settimeout(remaining())
            conn.request("GET", target)
            sock.settimeout(remaining())
            with conn.getresponse() as response:
                if response.status != 200:
                    return response.status, ""
                if response.length is not None and response.length > max_bytes:
                    return response.status, ""
                body = bytearray()
                while len(body) <= max_bytes and not response.isclosed():
                    sock.settimeout(remaining())
                    chunk = response.read1(min(8192, max_bytes + 1 - len(body)))
                    if not chunk:
                        break
                    body.extend(chunk)
                if len(body) > max_bytes or response.length not in (0, None):
                    return response.status, ""
                return response.status, body.decode("utf-8")

    result = ProbeTask(scrape, "inferdiff-probe-http").wait_until(deadline)
    if result is not None:
        return result
    # Interrupt an active socket even if individual header or chunk reads made progress.
    sock = active_socket
    if sock is not None:
        try:
            sock.shutdown(socket.SHUT_RDWR)
        except OSError:
            pass
    return None, ""
