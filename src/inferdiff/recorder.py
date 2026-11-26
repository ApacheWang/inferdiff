"""Monotonic-clock HTTP streaming recorder with strict RFC 9112 framing, SSE/NDJSON framers, and per-frame flush."""

from __future__ import annotations

import dataclasses
import datetime
import http.client
import json
import math
import re
import secrets
import socket
import ssl
import time
import urllib.parse
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Dict, Iterator, List, Mapping, Optional, Tuple, Union

from .dialects import detect_dialect, normalize_payload
from .probes.base import BackendProbe
from .redact import (
    extract_header_secret_values,
    has_control_chars,
    redact_headers,
    sanitize_url_for_error,
    sanitize_url_for_export,
    scrub_known_secrets,
)
from .schema import (
    TraceDocument,
    TraceFrame,
    TraceHeader,
    assemble_summary,
    body_sha256,
    canonical_json_bytes,
    canonical_json_line,
    empty_usage,
    extract_effective_params,
    frame_has_effective_payload,
    has_lone_surrogate,
    strict_json_loads,
)

# RFC 9110 HTTP field-name token characters
_HEADER_NAME_RE = re.compile(r"^[!#$%&'*+\-.^_`|~0-9A-Za-z]+$")
_MANAGED_HEADERS = frozenset({"content-length", "transfer-encoding", "host"})
_MAX_CHUNK_LINE_BYTES = 16384
_MAX_TRAILER_BYTES = 65536


class RecorderError(RuntimeError):
    """Raised on network connection refusal, invalid URL/headers, or non-200 HTTP error."""


def validate_url(url: str) -> urllib.parse.SplitResult:
    """Validate an HTTP(S) target URL before connection (rejects control chars & embedded credentials)."""
    if not isinstance(url, str) or not url or has_control_chars(url):
        raise RecorderError("Invalid URL: empty or contains control characters.")
    try:
        parsed = urllib.parse.urlsplit(url)
    except ValueError as exc:
        raise RecorderError(f"Invalid URL syntax: {exc}") from exc
    if parsed.scheme not in ("http", "https") or not parsed.hostname:
        raise RecorderError(f"Unsupported or invalid URL scheme/host: {sanitize_url_for_error(url)}")
    if parsed.username or parsed.password:
        raise RecorderError("URL must not contain embedded credentials; use --header instead.")
    try:
        _ = parsed.port
    except ValueError as exc:
        raise RecorderError(f"Invalid URL port: {exc}") from exc
    return parsed


def validate_and_merge_headers(
    base: Mapping[str, str],
    extra: Optional[Mapping[str, str]] = None,
) -> Dict[str, str]:
    """Validate RFC 9110 header names/values, merge case-insensitively, and reject framing overrides."""
    merged: Dict[str, Tuple[str, str]] = {}
    for k, v in base.items():
        merged[k.lower()] = (k, v)

    if extra:
        for raw_k, raw_v in extra.items():
            if not isinstance(raw_k, str) or not isinstance(raw_v, str):
                raise RecorderError("HTTP headers must be string key/value pairs.")
            k = raw_k.strip()
            v = raw_v.strip()
            if not k or not _HEADER_NAME_RE.match(k):
                raise RecorderError(f"Invalid HTTP header name: {k!r}")
            if has_control_chars(v):
                raise RecorderError(f"Invalid control characters in HTTP header value for {k!r}.")
            low = k.lower()
            if low in _MANAGED_HEADERS:
                raise RecorderError(f"Header {k!r} is managed internally by inferdiff and cannot be overridden.")
            merged[low] = (k, v)

    return {orig_k: val for orig_k, val in merged.values()}


def _decode_safe(data: bytes) -> Tuple[str, bool]:
    """Decode UTF-8 bytes cleanly; fall back to surrogateescape on invalid byte sequences."""
    try:
        return data.decode("utf-8"), False
    except UnicodeDecodeError:
        return data.decode("utf-8", errors="surrogateescape"), True


@dataclass
class WireChunk:
    """One framed raw wire record (either an SSE block or an NDJSON line)."""

    t_mono_ns: int
    sse_event: Optional[str]
    payload_text: str
    raw_wire: str
    is_incomplete: bool = False
    invalid_utf8: bool = False
    framing_error: Optional[str] = None


class SSEFramer:
    """Incremental WHATWG SSE byte framer resilient to split UTF-8, mixed CRLF/LF/CR, and sticky packets."""

    def __init__(self) -> None:
        self._bom_checked = False
        self._bom_buf = bytearray()
        self._line_buf = bytearray()
        self._pending_cr = False
        self._discard_next_lf = False
        self._block_raw = bytearray()
        self._event_name: Optional[str] = None
        self._data_suffixes: List[bytes] = []
        self._has_data = False
        self._has_meaningful_field = False
        self._pending_dispatch: Optional[Tuple[int, Optional[str], List[bytes], bytearray]] = None

    def feed(self, chunk: bytes, t_mono_ns: int) -> List[WireChunk]:
        if not chunk:
            return []
        events: List[WireChunk] = []
        data = chunk

        if not self._bom_checked:
            self._bom_buf.extend(data)
            if len(self._bom_buf) < 3:
                if b"\xef\xbb\xbf".startswith(bytes(self._bom_buf)):
                    return events
                data = bytes(self._bom_buf)
                self._bom_buf.clear()
                self._bom_checked = True
            else:
                if self._bom_buf[:3] == b"\xef\xbb\xbf":
                    del self._bom_buf[:3]
                data = bytes(self._bom_buf)
                self._bom_buf.clear()
                self._bom_checked = True

        i = 0
        n = len(data)
        while i < n:
            b = data[i]
            if self._pending_cr:
                self._pending_cr = False
                if b == 0x0A:
                    if self._pending_dispatch is not None:
                        ts, ev, sufs, raw = self._pending_dispatch
                        raw.append(0x0A)
                        self._pending_dispatch = None
                        events.append(self._emit(ts, ev, sufs, raw, incomplete=False))
                    elif self._discard_next_lf:
                        self._discard_next_lf = False
                    else:
                        self._block_raw.append(0x0A)
                    i += 1
                    continue
                self._discard_next_lf = False
                if self._pending_dispatch is not None:
                    ts, ev, sufs, raw = self._pending_dispatch
                    self._pending_dispatch = None
                    events.append(self._emit(ts, ev, sufs, raw, incomplete=False))

            if b == 0x0D:  # CR
                line = bytes(self._line_buf)
                self._line_buf.clear()
                self._pending_cr = True
                if not line:
                    self._block_raw.append(0x0D)
                    if self._has_data:
                        self._pending_dispatch = (t_mono_ns, self._event_name, self._data_suffixes, self._block_raw)
                        self._block_raw = bytearray()
                        self._event_name = None
                        self._data_suffixes = []
                        self._has_data = False
                        self._has_meaningful_field = False
                    else:
                        # Discard paired LF of this non-data/comment-only CRLF blank line
                        self._discard_next_lf = True
                        self._reset_block()
                else:
                    self._block_raw.extend(line)
                    self._block_raw.append(0x0D)
                    self._handle_line(line)
                i += 1
            elif b == 0x0A:  # LF
                line = bytes(self._line_buf)
                self._line_buf.clear()
                if not line:
                    self._block_raw.append(0x0A)
                    if self._has_data:
                        events.append(self._emit(t_mono_ns, self._event_name, self._data_suffixes, self._block_raw, incomplete=False))
                    self._reset_block()
                else:
                    self._block_raw.extend(line)
                    self._block_raw.append(0x0A)
                    self._handle_line(line)
                i += 1
            else:
                self._line_buf.append(b)
                i += 1
        return events

    def finish(self, t_end_ns: int) -> List[WireChunk]:
        events: List[WireChunk] = []
        if not self._bom_checked and self._bom_buf:
            leftover = bytes(self._bom_buf)
            self._bom_buf.clear()
            self._bom_checked = True
            events.extend(self.feed(leftover, t_end_ns))
        if self._pending_dispatch is not None:
            ts, ev, sufs, raw = self._pending_dispatch
            self._pending_dispatch = None
            self._pending_cr = False
            events.append(self._emit(ts, ev, sufs, raw, incomplete=False))
        if self._line_buf:
            line = bytes(self._line_buf)
            self._line_buf.clear()
            self._block_raw.extend(line)
            self._handle_line(line)
        # Preserve both unterminated data: blocks AND unterminated event:/field tails as incomplete evidence
        if self._has_data or self._has_meaningful_field:
            events.append(self._emit(t_end_ns, self._event_name, self._data_suffixes, self._block_raw, incomplete=True))
        self._reset_block()
        self._pending_cr = False
        self._discard_next_lf = False
        return events

    def _reset_block(self) -> None:
        self._block_raw = bytearray()
        self._event_name = None
        self._data_suffixes = []
        self._has_data = False
        self._has_meaningful_field = False

    def _handle_line(self, line: bytes) -> None:
        if not line or line.startswith(b":"):
            return
        self._has_meaningful_field = True
        colon = line.find(b":")
        if colon == -1:
            field, suffix = line, b""
        else:
            field, suffix = line[:colon], line[colon + 1 :]
        if field == b"data":
            self._has_data = True
            self._data_suffixes.append(suffix)
        elif field == b"event":
            val = suffix[1:] if suffix.startswith(b" ") else suffix
            dec, _ = _decode_safe(val)
            self._event_name = dec if dec != "" else None

    @staticmethod
    def _emit(
        t_mono_ns: int,
        event: Optional[str],
        suffixes: List[bytes],
        raw_blk: bytearray,
        *,
        incomplete: bool,
    ) -> WireChunk:
        stripped_lines = [s[1:] if s.startswith(b" ") else s for s in suffixes]
        payload_text, bad_p = _decode_safe(b"\n".join(stripped_lines))
        raw_wire, bad_r = _decode_safe(bytes(raw_blk))
        return WireChunk(
            t_mono_ns=t_mono_ns,
            sse_event=event,
            payload_text=payload_text,
            raw_wire=raw_wire,
            is_incomplete=incomplete,
            invalid_utf8=bad_p or bad_r,
        )


class NDJSONFramer:
    """Strict incremental line-delimited JSON byte framer for Ollama /api/chat and /api/generate."""

    def __init__(self) -> None:
        self._buf = bytearray()

    def feed(self, chunk: bytes, t_mono_ns: int) -> List[WireChunk]:
        if not chunk:
            return []
        self._buf.extend(chunk)
        out: List[WireChunk] = []
        while True:
            nl = self._buf.find(b"\n")
            if nl == -1:
                break
            raw_line = bytes(self._buf[: nl + 1])
            del self._buf[: nl + 1]
            # Consume exact single LF or CRLF delimiter; reject embedded bare CR (e.g. \r\r\n)
            if raw_line.endswith(b"\r\n"):
                content = raw_line[:-2]
            else:
                content = raw_line[:-1]
            if not content.strip():
                if b"\r" in content:
                    raw_wire, bad_r = _decode_safe(raw_line)
                    out.append(
                        WireChunk(
                            t_mono_ns=t_mono_ns,
                            sse_event=None,
                            payload_text="",
                            raw_wire=raw_wire,
                            is_incomplete=False,
                            invalid_utf8=bad_r,
                            framing_error="invalid_ndjson_cr",
                        )
                    )
                continue
            has_bare_cr = b"\r" in content
            payload_text, bad_p = _decode_safe(content)
            raw_wire, bad_r = _decode_safe(raw_line)
            out.append(
                WireChunk(
                    t_mono_ns=t_mono_ns,
                    sse_event=None,
                    payload_text=payload_text,
                    raw_wire=raw_wire,
                    is_incomplete=False,
                    invalid_utf8=bad_p or bad_r,
                    framing_error="invalid_ndjson_cr" if has_bare_cr else None,
                )
            )
        return out

    def finish(self, t_end_ns: int) -> List[WireChunk]:
        if not self._buf:
            return []
        raw_line = bytes(self._buf)
        self._buf.clear()
        if not raw_line.strip():
            return []
        has_bare_cr = b"\r" in raw_line
        payload_text, bad_p = _decode_safe(raw_line)
        raw_wire, bad_r = _decode_safe(raw_line)
        if has_bare_cr:
            return [
                WireChunk(
                    t_mono_ns=t_end_ns,
                    sse_event=None,
                    payload_text=payload_text,
                    raw_wire=raw_wire,
                    is_incomplete=False,
                    invalid_utf8=bad_p or bad_r,
                    framing_error="invalid_ndjson_cr",
                )
            ]
        # Compatibility choice: accept a valid final JSON object without trailing LF (some Ollama proxies)
        is_inc = False
        try:
            obj = strict_json_loads(payload_text)
            if not isinstance(obj, dict):
                is_inc = True
        except Exception:
            is_inc = True
        return [
            WireChunk(
                t_mono_ns=t_end_ns,
                sse_event=None,
                payload_text=payload_text,
                raw_wire=raw_wire,
                is_incomplete=is_inc,
                invalid_utf8=bad_p or bad_r,
            )
        ]


def _parse_content_length_headers(resp: http.client.HTTPResponse) -> Tuple[Optional[int], bool]:
    """Normalize Content-Length headers per RFC 9112. Returns (expected_len, framing_valid)."""
    raw_headers = resp.headers.get_all("Content-Length") or []
    if not raw_headers:
        return None, True
    values: List[int] = []
    for hdr in raw_headers:
        for part in hdr.split(","):
            tok = part.strip()
            # Reject non-digits or absurdly long integers before int() conversion
            if not tok or not tok.isdigit() or len(tok) > 20:
                return None, False
            try:
                values.append(int(tok))
            except ValueError:
                return None, False
    if not values:
        return None, False
    if len(set(values)) > 1:
        return None, False
    return values[0], True


def _iter_chunked_body_strict(fp: Any, read_size: int = 8192) -> Iterator[Tuple[bytes, bool]]:
    """Strict RFC 9112 §7.1 incremental chunked decoder reading via read1().

    Yields (confirmed_body_bytes, True) incrementally, and yields a final sentinel (b"", clean_eof)
    where clean_eof is True ONLY when 0-chunk AND terminating CRLF after trailers are explicitly observed.
    Never passes HTTP chunk delimiters to the application framer and never raises uncaught LineTooLong.
    """
    buf = bytearray()
    state = "CHUNK_SIZE"
    chunk_rem = 0
    trailer_bytes = 0

    def _fill() -> bool:
        try:
            data = fp.read1(read_size) if hasattr(fp, "read1") else fp.read(read_size)
        except (socket.timeout, TimeoutError, OSError, http.client.HTTPException):
            return False
        if not data:
            return False
        buf.extend(data)
        return True

    while True:
        if state == "CHUNK_SIZE":
            idx = buf.find(b"\r\n")
            if idx == -1:
                if len(buf) > _MAX_CHUNK_LINE_BYTES:
                    yield b"", False
                    return
                if not _fill():
                    yield b"", False
                    return
                continue
            size_line = bytes(buf[:idx])
            del buf[: idx + 2]
            semi = size_line.find(b";")
            size_part = (size_line[:semi] if semi != -1 else size_line).strip()
            if not size_part or any(c not in b"0123456789abcdefABCDEF" for c in size_part):
                yield b"", False
                return
            chunk_size = int(size_part, 16)
            if chunk_size == 0:
                state = "TRAILER"
            else:
                chunk_rem = chunk_size
                state = "CHUNK_DATA"

        elif state == "CHUNK_DATA":
            if not buf:
                if not _fill():
                    yield b"", False
                    return
            take = min(chunk_rem, len(buf))
            if take > 0:
                out = bytes(buf[:take])
                del buf[:take]
                chunk_rem -= take
                yield out, True
            if chunk_rem == 0:
                state = "CHUNK_CRLF"

        elif state == "CHUNK_CRLF":
            while len(buf) < 2:
                if not _fill():
                    yield b"", False
                    return
            if buf[:2] != b"\r\n":
                yield b"", False
                return
            del buf[:2]
            state = "CHUNK_SIZE"

        elif state == "TRAILER":
            idx = buf.find(b"\r\n")
            if idx == -1:
                if trailer_bytes + len(buf) > _MAX_TRAILER_BYTES:
                    yield b"", False
                    return
                if not _fill():
                    # Missing terminating CRLF after 0\r\n (or truncated trailer)
                    yield b"", False
                    return
                continue
            trailer_line = bytes(buf[:idx])
            del buf[: idx + 2]
            trailer_bytes += len(trailer_line) + 2
            if trailer_bytes > _MAX_TRAILER_BYTES:
                yield b"", False
                return
            if len(trailer_line) == 0:
                # Explicitly observed final empty CRLF terminating chunked body!
                yield b"", True
                return


def build_frame_from_chunk(
    chunk: WireChunk,
    *,
    seq: int,
    dialect: str,
    prev_rel_ms: float,
    t0_ns: int,
    sglang_prev_text: str,
) -> Tuple[TraceFrame, str]:
    """Convert one framed WireChunk into a TraceFrame + updated sglang cumulative text."""
    t_rel_ms = round(max(0, chunk.t_mono_ns - t0_ns) / 1_000_000.0, 3)
    dt_ms = round(max(0.0, t_rel_ms - prev_rel_ms), 3) if seq > 0 else t_rel_ms

    empty_norm = dataclasses.asdict(normalize_payload("openai-chat", {}, sse_event=None))
    empty_norm["phase"] = "UNKNOWN"
    empty_norm["usage"] = empty_usage()

    if chunk.framing_error:
        return (
            TraceFrame(
                seq=seq,
                t_rel_ms=t_rel_ms,
                dt_ms=dt_ms,
                sse_event=chunk.sse_event,
                raw_wire=chunk.raw_wire,
                is_done_sentinel=False,
                parse_error=chunk.framing_error,
                norm=empty_norm,
            ),
            sglang_prev_text,
        )

    if chunk.is_incomplete:
        return (
            TraceFrame(
                seq=seq,
                t_rel_ms=t_rel_ms,
                dt_ms=dt_ms,
                sse_event=chunk.sse_event,
                raw_wire=chunk.raw_wire,
                is_done_sentinel=False,
                parse_error="incomplete_event",
                norm=empty_norm,
            ),
            sglang_prev_text,
        )

    if chunk.invalid_utf8:
        return (
            TraceFrame(
                seq=seq,
                t_rel_ms=t_rel_ms,
                dt_ms=dt_ms,
                sse_event=chunk.sse_event,
                raw_wire=chunk.raw_wire,
                is_done_sentinel=False,
                parse_error="invalid_utf8",
                norm=empty_norm,
            ),
            sglang_prev_text,
        )

    if dialect != "ollama-ndjson" and chunk.payload_text == "[DONE]":
        done_norm = dict(empty_norm)
        done_norm["phase"] = "TERMINAL"
        done_norm["closed_events"] = ["[DONE]"]
        done_norm["is_done_sentinel"] = True
        return (
            TraceFrame(
                seq=seq,
                t_rel_ms=t_rel_ms,
                dt_ms=dt_ms,
                sse_event=chunk.sse_event,
                raw_wire=chunk.raw_wire,
                is_done_sentinel=True,
                parse_error=None,
                norm=done_norm,
            ),
            sglang_prev_text,
        )

    try:
        payload_obj = strict_json_loads(chunk.payload_text)
    except (json.JSONDecodeError, ValueError, RecursionError) as exc:
        msg = exc.msg if isinstance(exc, json.JSONDecodeError) else str(exc)
        return (
            TraceFrame(
                seq=seq,
                t_rel_ms=t_rel_ms,
                dt_ms=dt_ms,
                sse_event=chunk.sse_event,
                raw_wire=chunk.raw_wire,
                is_done_sentinel=False,
                parse_error=f"invalid_json: {msg}",
                norm=empty_norm,
            ),
            sglang_prev_text,
        )

    if not isinstance(payload_obj, dict):
        return (
            TraceFrame(
                seq=seq,
                t_rel_ms=t_rel_ms,
                dt_ms=dt_ms,
                sse_event=chunk.sse_event,
                raw_wire=chunk.raw_wire,
                is_done_sentinel=False,
                parse_error="json_not_object",
                norm=empty_norm,
            ),
            sglang_prev_text,
        )

    if has_lone_surrogate(payload_obj):
        return (
            TraceFrame(
                seq=seq,
                t_rel_ms=t_rel_ms,
                dt_ms=dt_ms,
                sse_event=chunk.sse_event,
                raw_wire=chunk.raw_wire,
                is_done_sentinel=False,
                parse_error="invalid_unicode_surrogate",
                norm=empty_norm,
            ),
            sglang_prev_text,
        )

    try:
        norm_obj = normalize_payload(
            dialect,
            payload_obj,
            sse_event=chunk.sse_event,
            prev_text=sglang_prev_text,
        )
    except (ValueError, TypeError, OverflowError, RecursionError) as exc:
        return (
            TraceFrame(
                seq=seq,
                t_rel_ms=t_rel_ms,
                dt_ms=dt_ms,
                sse_event=chunk.sse_event,
                raw_wire=chunk.raw_wire,
                is_done_sentinel=False,
                parse_error=f"normalize_error: {type(exc).__name__}",
                norm=empty_norm,
            ),
            sglang_prev_text,
        )
    new_prev = sglang_prev_text
    if dialect == "sglang-native" and isinstance(payload_obj.get("text"), str) and payload_obj["text"] != "":
        new_prev = payload_obj["text"]

    norm_dict = dataclasses.asdict(norm_obj)
    return (
        TraceFrame(
            seq=seq,
            t_rel_ms=t_rel_ms,
            dt_ms=dt_ms,
            sse_event=chunk.sse_event,
            raw_wire=chunk.raw_wire,
            is_done_sentinel=norm_obj.is_done_sentinel,
            parse_error=norm_obj.protocol_error,
            norm=norm_dict,
        ),
        new_prev,
    )


def record_stream(
    *,
    url: str,
    request_body: Dict[str, Any],
    out_path: Optional[Union[str, Path]] = None,
    headers: Optional[Mapping[str, str]] = None,
    dialect: str = "auto",
    label: str = "",
    timeout: float = 120.0,
    probe: Optional[BackendProbe] = None,
) -> TraceDocument:
    """Send one streaming POST via stdlib http.client and record per-frame flushed .trace.jsonl."""
    parsed = validate_url(url)
    if not (isinstance(timeout, (int, float)) and not isinstance(timeout, bool) and math.isfinite(timeout) and timeout > 0):
        raise RecorderError("Timeout must be a positive finite number.")

    if not isinstance(request_body, dict):
        raise RecorderError("Request body must be a JSON object.")

    body = dict(request_body)
    if "stream" not in body:
        body["stream"] = True
    elif body["stream"] is not True:
        raise RecorderError("Request body must have stream=true for streaming capture.")

    body_bytes = canonical_json_bytes(body)
    req_path = parsed.path or "/"
    if parsed.query:
        req_path = f"{req_path}?{parsed.query}"

    default_headers: Dict[str, str] = {
        "Content-Type": "application/json",
        "Accept": "text/event-stream, application/x-ndjson",
        "Accept-Encoding": "identity",
    }
    send_headers = validate_and_merge_headers(default_headers, headers)

    conn: http.client.HTTPConnection
    if parsed.scheme == "https":
        conn = http.client.HTTPSConnection(
            parsed.hostname,
            parsed.port or 443,
            timeout=timeout,
            context=ssl.create_default_context(),
        )
    else:
        conn = http.client.HTTPConnection(
            parsed.hostname,
            parsed.port or 80,
            timeout=timeout,
        )

    now_utc = datetime.datetime.now(datetime.timezone.utc)
    trace_id = f"tr_{now_utc.strftime('%Y%m%dT%H%M%SZ')}_{secrets.token_hex(3)}"
    recorded_at = now_utc.strftime("%Y-%m-%dT%H:%M:%S.%f")[:-3] + "Z"

    probe_topology = probe.describe_topology() if probe is not None else None
    if probe is not None:
        probe.sample_pre()

    try:
        conn.connect()
        t0_ns = time.monotonic_ns()
        conn.request("POST", req_path, body=body_bytes, headers=send_headers)
        resp = conn.getresponse()
        t_headers_ns = time.monotonic_ns()
    except (OSError, http.client.HTTPException) as exc:
        conn.close()
        raise RecorderError(
            f"HTTP connection/request failed for {sanitize_url_for_error(url)} ({type(exc).__name__})"
        ) from exc

    status_code = resp.status
    content_type = resp.getheader("Content-Type") or ""
    resolved_dialect = detect_dialect(parsed.path, content_type) if dialect == "auto" else dialect
    t_headers_ms = round((t_headers_ns - t0_ns) / 1_000_000.0, 3)

    # Streaming capture strictly requires HTTP 200; never expose raw query or response body in errors
    if status_code != 200:
        conn.close()
        raise RecorderError(
            f"HTTP {status_code} from {sanitize_url_for_error(url)} (expected HTTP 200 for streaming capture)"
        )

    redacted_req_headers = redact_headers(send_headers)
    outgoing_secrets = extract_header_secret_values(send_headers)
    # Also capture any non-allowlisted query param values as secrets to scrub if reflected
    if parsed.query:
        for qk, qv in urllib.parse.parse_qsl(parsed.query, keep_blank_values=True):
            if len(qv) >= 6 and qk.lower() not in ("api-version", "version", "alt", "stream"):
                outgoing_secrets.append(qv)
        outgoing_secrets = sorted(set(outgoing_secrets), key=len, reverse=True)

    safe_stored_url = sanitize_url_for_export(url)
    header = TraceHeader(
        trace_id=trace_id,
        label=label,
        recorded_at_utc=recorded_at,
        dialect=resolved_dialect,
        request={
            "method": "POST",
            "url": safe_stored_url,
            "headers_redacted": redacted_req_headers,
            "body_sha256": body_sha256(body),
            "body": body,
            "effective_params": extract_effective_params(body, resolved_dialect),
        },
        response_meta={
            "status_code": status_code,
            "content_type": content_type,
            "t_headers_ms": t_headers_ms,
        },
        backend_probe=probe_topology,
    )

    framer: Union[SSEFramer, NDJSONFramer] = (
        NDJSONFramer() if resolved_dialect == "ollama-ndjson" else SSEFramer()
    )

    expected_len: Optional[int] = None
    cl_valid = True

    fh = None
    frames: List[TraceFrame] = []
    prev_rel_ms = 0.0
    sglang_prev = ""
    bytes_read = 0
    socket_eof_clean = True
    probe_ttft_sampled = False
    summary = None
    interrupted_exc: Optional[BaseException] = None

    def _emit_chunk(wc: WireChunk) -> None:
        nonlocal prev_rel_ms, sglang_prev, probe_ttft_sampled
        # Scrub any reflected outgoing credential (e.g. echoed API key) BEFORE normalization or persistence
        if outgoing_secrets:
            wc = WireChunk(
                t_mono_ns=wc.t_mono_ns,
                sse_event=scrub_known_secrets(wc.sse_event, outgoing_secrets) if wc.sse_event else None,
                payload_text=scrub_known_secrets(wc.payload_text, outgoing_secrets),
                raw_wire=scrub_known_secrets(wc.raw_wire, outgoing_secrets),
                is_incomplete=wc.is_incomplete,
                invalid_utf8=wc.invalid_utf8,
                framing_error=wc.framing_error,
            )
        tf, sglang_prev = build_frame_from_chunk(
            wc,
            seq=len(frames),
            dialect=resolved_dialect,
            prev_rel_ms=prev_rel_ms,
            t0_ns=t0_ns,
            sglang_prev_text=sglang_prev,
        )
        if probe is not None and not probe_ttft_sampled and frame_has_effective_payload(tf.norm):
            probe.sample_ttft()
            probe_ttft_sampled = True
        prev_rel_ms = tf.t_rel_ms
        frames.append(tf)
        if fh is not None:
            fh.write(canonical_json_line(tf.to_dict()) + "\n")
            fh.flush()

    try:
        if not resp.chunked:
            expected_len, cl_valid = _parse_content_length_headers(resp)
            socket_eof_clean = cl_valid
        if out_path is not None:
            out_p = Path(out_path)
            out_p.parent.mkdir(parents=True, exist_ok=True)
            fh = out_p.open("w", encoding="utf-8", newline="\n")
            fh.write(canonical_json_line(header.to_dict()) + "\n")
            fh.flush()

        try:
            if resp.chunked:
                for body_chunk, ok in _iter_chunked_body_strict(resp.fp, 8192):
                    if not body_chunk:
                        if not ok:
                            socket_eof_clean = False
                        break
                    t_now = time.monotonic_ns()
                    bytes_read += len(body_chunk)
                    for wc in framer.feed(body_chunk, t_now):
                        _emit_chunk(wc)
            else:
                while True:
                    to_read = 8192
                    if expected_len is not None:
                        rem = expected_len - bytes_read
                        if rem <= 0:
                            break
                        to_read = min(8192, rem)
                    try:
                        raw = resp.fp.read1(to_read) if hasattr(resp.fp, "read1") else resp.read1(to_read)
                    except (http.client.HTTPException, socket.timeout, TimeoutError, OSError):
                        socket_eof_clean = False
                        break
                    if not raw:
                        break
                    t_now = time.monotonic_ns()
                    bytes_read += len(raw)
                    for wc in framer.feed(raw, t_now):
                        _emit_chunk(wc)

                if expected_len is not None and bytes_read != expected_len:
                    socket_eof_clean = False
        except BaseException as exc:
            socket_eof_clean = False
            interrupted_exc = exc

        # Always finalize trailing partial frames and summary so flushed evidence is never stranded
        t_end_ns = time.monotonic_ns()
        for wc in framer.finish(t_end_ns):
            _emit_chunk(wc)

        probe_summary = probe.sample_eof() if probe is not None else None
        total_ms = round((t_end_ns - t0_ns) / 1_000_000.0, 3)
        summary = assemble_summary(
            header,
            frames,
            total_ms=total_ms,
            socket_eof_clean=socket_eof_clean,
            backend_probe_summary=probe_summary,
        )
        if fh is not None:
            fh.write(canonical_json_line(summary.to_dict()) + "\n")
            fh.flush()
    finally:
        if fh is not None:
            fh.close()
        try:
            resp.close()
        except Exception:
            pass
        conn.close()

    if interrupted_exc is not None:
        raise interrupted_exc

    assert summary is not None
    return TraceDocument(header=header, frames=frames, summary=summary)
