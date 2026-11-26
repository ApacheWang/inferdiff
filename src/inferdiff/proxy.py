"""A local HTTP reverse proxy with an in-memory audit of streamed responses."""

from __future__ import annotations

import datetime
import http.client
import http.server
import ipaddress
import json
import math
import re
import statistics
import sys
import threading
import time
import uuid
import zlib
from collections import deque
from pathlib import Path
from urllib.parse import SplitResult, unquote, unquote_plus, urlsplit

from ._urls import RecorderError, validate_url
from .detectors import Finding, audit_trace
from .dialects import detect_dialect
from .exporter import _md_code_span
from .recorder import (
    NDJSONFramer,
    SSEFramer,
    WireChunk,
    _iter_chunked_body_strict,
    _scrub_normalized_data,
    _scrub_wire_chunk,
    build_frame_from_chunk,
)
from .redact import (
    extract_body_secret_values,
    extract_header_secret_values,
    extract_url_secret_values,
    is_protocol_enum,
    is_protocol_event,
    sanitize_url_path,
    scrub_report_data,
    scrub_report_text,
)
from .schema import (
    TraceDocument,
    TraceFrame,
    TraceHeader,
    assemble_summary,
    extract_effective_params,
    safe_utf8_len,
    strict_json_loads,
    write_trace,
)

_HOP_HEADERS = {
    "connection", "keep-alive", "proxy-connection", "proxy-authenticate", "proxy-authorization",
    "te", "trailer", "transfer-encoding", "upgrade",
}
_STREAM_TYPES = {"text/event-stream", "application/x-ndjson", "application/ndjson"}
_SSE_PREFIXES = (b"data:", b"event:", b"id:", b"retry:", b":")
_DETECTORS = {"D1", "D2", "D3", "D4"}
_FINDING_DESCRIPTIONS = {
    "D1": "The stream reported success with an incomplete or inconsistent tool call.",
    "D2": "The stream returned empty visible output despite signs of generation.",
    "D3": "The stream produced fewer tokens than the fixed generation budget.",
    "D4": "The stream ended without a clean protocol or transport termination.",
}
_RECENT_EVENT_LIMIT = 100
_FRAME_LIMIT = 200
_FINDINGS_PER_DETECTOR = 25
_DASHBOARD_CSP = "default-src 'none'; style-src 'unsafe-inline'; script-src 'unsafe-inline'; connect-src 'self'"
_UI_ROOT = "/_inferdiff"
_UI_PAGES = {_UI_ROOT, _UI_ROOT + "/"}
_UI_STATUS = _UI_ROOT + "/status"
_UI_CLEAR = _UI_ROOT + "/clear"
_UI_EVENT_PREFIX = _UI_ROOT + "/event/"
_UI_ROUTES = _UI_PAGES | {_UI_STATUS, _UI_CLEAR}
_READ_SIZE = 8192
_URL_QUERY = re.compile(r"((?:https?://|(?<![\w/:])/)[^\s<>\"'\\?#]+)\?[^\s<>\"'\\#]+", re.IGNORECASE)
_PATH_SUFFIX = re.compile(r"[?#]|%(?:25)*(?:3f|23)", re.IGNORECASE)


def _end_to_end(headers):
    connection_fields = {
        name.strip().lower()
        for value in headers.get_all("Connection", [])
        for name in value.split(",")
    }
    return [(name, value) for name, value in headers.items()
            if name.lower() not in _HOP_HEADERS | connection_fields | {"content-length"}]


def _framing(headers) -> tuple[bool, int | None]:
    codings = [part.strip().lower() for value in headers.get_all("Transfer-Encoding", [])
               for part in value.split(",")]
    lengths = [part.strip() for value in headers.get_all("Content-Length", []) for part in value.split(",")]
    if codings:
        if codings != ["chunked"] or lengths:
            raise ValueError("Unsupported HTTP transfer framing.")
        return True, None
    if not lengths:
        return False, None
    if any(not length.isascii() or not length.isdecimal() or len(length) > 20 for length in lengths):
        raise ValueError("Invalid HTTP Content-Length.")
    length = int(lengths[0])
    if any(int(value) != length for value in lengths):
        raise ValueError("Conflicting HTTP Content-Length values.")
    return False, length


def _body_chunks(fp, *, chunked: bool, length: int | None):
    if chunked:
        yield from _iter_chunked_body_strict(fp, _READ_SIZE)
        return
    remaining = length
    while remaining != 0:
        size = _READ_SIZE if remaining is None else min(remaining, _READ_SIZE)
        try:
            data = fp.read1(size)
        except (OSError, http.client.HTTPException):
            yield b"", False
            return
        if not data:
            break
        if remaining is not None:
            remaining -= len(data)
        yield data, True
    yield b"", remaining in (None, 0)


def _encode_chunk(data: bytes) -> bytes:
    return f"{len(data):X}\r\n".encode("ascii") + data + b"\r\n"


def _header_secrets(headers) -> list[str]:
    return [secret for name, value in headers.items()
            for secret in extract_header_secret_values({name: value}, min_length=1)]


def _query_secrets(query: str) -> list[str]:
    secrets = []
    for field in query.split("&"):
        name, sep, value = field.partition("=")
        raw = value if sep else name
        if raw:
            secrets.extend((raw, unquote_plus(raw)))
    return secrets


def _display(text: str, secrets: list[str]) -> str:
    clean = scrub_report_text(text, secrets)
    return "".join(char if char.isprintable() else ascii(char)[1:-1] for char in clean)


def _display_path(path: str, secrets: list[str]) -> str:
    path = sanitize_url_path(path)
    decoded = unquote(path)
    if decoded != path:
        scrubbed = scrub_report_text(decoded, secrets)
        if scrubbed != decoded:
            path = scrubbed
    # Encoded URL delimiters can disguise credential-bearing queries or fragments.
    return _display(_PATH_SUFFIX.split(path, maxsplit=1)[0], secrets)


def _scrub_capture_text(text: str, secrets: list[str]) -> str:
    return scrub_report_text(_URL_QUERY.sub(r"\1", text), secrets)


def _request_metadata(raw: bytearray) -> dict:
    try:
        body = strict_json_loads(raw)
    except (ValueError, RecursionError):
        return {}
    return body if isinstance(body, dict) else {}


class _UpstreamResponse(http.client.HTTPResponse):
    def _read_status(self):
        status_line = super()._read_status()
        # http.client normally skips only 100 Continue before the final response.
        while 100 <= status_line[1] < 200 and status_line[1] != 101:
            http.client.parse_headers(self.fp)
            status_line = super()._read_status()
        return status_line


class _Capture:
    """Collect framed stream evidence after each successful downstream write."""

    def __init__(self, path: str, content_type: str, encoding: str, chunked: bool) -> None:
        self.media_type = content_type.partition(";")[0].strip().lower()
        self.dialect = detect_dialect(path, content_type)
        self.framer = None
        self.wire: list[WireChunk] = []
        self.streaming = self.media_type in _STREAM_TYPES
        self.sniff = chunked and not self.streaming
        self.prefix = bytearray()
        self.decoder = None
        self.gzip = encoding in {"gzip", "x-gzip"}
        self.available = True
        self.decoding_clean = True
        if self.streaming or self.sniff:
            if self.gzip:
                self.decoder = zlib.decompressobj(16 + zlib.MAX_WBITS)
            elif encoding == "deflate":
                self.decoder = zlib.decompressobj()
            elif encoding not in {"", "identity"}:
                self.available = False
        if self.streaming and self.available:
            if self.media_type == "text/event-stream":
                self.framer = SSEFramer()
            else:
                self.dialect = "ollama-ndjson"
                self.framer = NDJSONFramer()

    def feed(self, data: bytes, now: int) -> None:
        if not self.available or not (self.streaming or self.sniff) or not self.decoding_clean:
            return
        if self.decoder is not None:
            try:
                data = self._decode(data)
            except zlib.error:
                self.decoding_clean = False
                return
        if self.sniff and self.framer is None:
            self.prefix.extend(data)
            candidate = bytes(self.prefix).removeprefix(b"\xef\xbb\xbf").lstrip()
            if candidate.startswith(_SSE_PREFIXES):
                self.streaming = True
                self.framer = SSEFramer()
                data = bytes(self.prefix)
            elif len(self.prefix) < _READ_SIZE and (
                any(prefix.startswith(candidate) for prefix in _SSE_PREFIXES)
                or b"\xef\xbb\xbf".startswith(candidate)
            ):
                return
            self.sniff = False
            self.prefix.clear()
        if self.framer is not None:
            self.wire.extend(self.framer.feed(data, now))

    def _decode(self, data: bytes) -> bytes:
        if not self.gzip:
            return self.decoder.decompress(data)
        pieces = []
        while data:
            if self.decoder.eof:
                self.decoder = zlib.decompressobj(16 + zlib.MAX_WBITS)
            pieces.append(self.decoder.decompress(data))
            data = self.decoder.unused_data
        return b"".join(pieces)

    def document(self, header: TraceHeader, secrets: list[str], *, start: int, end: int, clean: bool) -> TraceDocument:
        assert self.framer is not None
        self.wire.extend(self.framer.finish(end))
        frames: list[TraceFrame] = []
        prev_ms, prev_text = 0.0, ""

        def scrub(text: str) -> str:
            return _scrub_capture_text(text, secrets)

        for chunk in self.wire:
            frame, prev_text = build_frame_from_chunk(
                _scrub_wire_chunk(chunk, self.dialect, secrets, scrub_text=scrub), seq=len(frames), dialect=self.dialect,
                prev_rel_ms=prev_ms, t0_ns=start, sglang_prev_text=prev_text,
            )
            if frame.parse_error:
                code, sep, detail = frame.parse_error.partition(": ")
                frame.parse_error = code + sep + scrub_report_text(detail, secrets)
            frame.norm = _scrub_normalized_data(frame.norm, self.dialect, secrets)
            frames.append(frame)
            prev_ms = frame.t_rel_ms
        clean = clean and self.decoding_clean and (self.decoder is None or self.decoder.eof)
        summary = assemble_summary(header, frames, total_ms=_elapsed(start, end), socket_eof_clean=clean)
        summary.assembled = _scrub_normalized_data(summary.assembled, self.dialect, secrets)
        summary.assembled["content_utf8_bytes"] = safe_utf8_len(summary.assembled["content_text"])
        return TraceDocument(header, frames, summary)


def _elapsed(start: int, end: int) -> float:
    return round((end - start) / 1_000_000, 3)


def _frame_metadata(frame: TraceFrame, dialect: str) -> dict:
    norm = frame.norm
    event = frame.sse_event
    if frame.is_done_sentinel:
        event = "[DONE]"
    elif not event or not is_protocol_event(dialect, event):
        event = norm.get("phase", "UNKNOWN")
    reason = norm.get("finish_reason")
    return {
        "seq": frame.seq, "t_rel_ms": frame.t_rel_ms, "dt_ms": frame.dt_ms, "event": event,
        "finish_reason": reason if is_protocol_enum(dialect, "finish_reason", reason) else None,
        "terminal": norm.get("phase") == "TERMINAL", "parse_error": bool(frame.parse_error),
        "content_bytes": safe_utf8_len(norm.get("text_delta") or ""),
        "tool_call_count": len(norm.get("tool_deltas") or []),
    }


def _dashboard_findings(findings: list[Finding]) -> list[dict]:
    # Detector messages/evidence can include provider-supplied names and parse excerpts.
    retained = []
    counts: dict[str, int] = {}
    for finding in findings:
        detector = finding.detector_id
        count = counts.get(detector, 0)
        if count < _FINDINGS_PER_DETECTOR:
            retained.append({
                "detector_id": detector, "code": finding.code, "severity": finding.severity,
                "message": _FINDING_DESCRIPTIONS[detector], "frame_seq": finding.frame_seq,
            })
            counts[detector] = count + 1
    return retained


def _issue_markdown(event: dict) -> str:
    request = _md_code_span(f"{event['method']} {event['path']}")
    ttft = event["ttft_ms"]
    ttft_note = "Unavailable" if ttft is None else f"{ttft:g} ms"
    lines = [
        "## inferdiff proxy incident", "", "### Request and stream", "",
        f"- Request: {request}",
        f"- HTTP status: {event['status']}",
        f"- Dialect: {event['dialect'] or 'Unknown'}",
        f"- Finish: {event['finish_reason'] or event['terminal_status'] or 'Unknown'}",
        f"- TTFT: {ttft_note}",
        f"- Total time: {event['total_ms']:g} ms",
        f"- Frames: {event['frame_count']}", "", "### Findings", "",
    ]
    for finding in event["findings"]:
        seq = finding["frame_seq"]
        frame = f" at frame {seq}" if seq is not None else ""
        lines.append(f"- **{finding['severity']} {finding['detector_id']}** `{finding['code']}`{frame}. "
                     f"{finding['message']}")
    if not event["findings"]:
        lines.append("No D1–D4 findings.")
    elif event["findings_count"] > len(event["findings"]):
        lines.append(f"\n{event['findings_count'] - len(event['findings'])} additional findings omitted.")
    return "\n".join(lines) + "\n"


def _json_bytes(data: dict) -> bytes:
    return json.dumps(data, allow_nan=False).encode("utf-8")


class ProxyServer(http.server.ThreadingHTTPServer):
    def __init__(
        self, address: tuple[str, int], upstream: SplitResult, *, save_dir: Path | None,
        only_breaches: bool, timeout: float, max_requests: int, no_color: bool, no_ui: bool = False,
    ) -> None:
        self.upstream = upstream
        self.save_dir = save_dir
        self.only_breaches = only_breaches
        self.socket_timeout = timeout
        self.max_requests = max_requests
        self.no_color = no_color
        self.ui_enabled = not no_ui
        self.lock = threading.Lock()
        self.requests_total = 0
        self.streaming_requests = 0
        self.p0_breaches = 0
        self.p1_warnings = 0
        self.active = 0
        self.recent_events: deque[dict] = deque(maxlen=_RECENT_EVENT_LIMIT)
        super().__init__(address, _ProxyHandler)

    def handle_error(self, request, client_address) -> None:
        # socketserver's default traceback can include upstream URLs or credentials.
        self.log("[PROXY ERROR] Request handler failed")

    def log(self, line: str) -> None:
        try:
            print(line, flush=True)
        except (OSError, UnicodeError, ValueError):
            pass

    def begin(self) -> bool:
        with self.lock:
            if self.max_requests and self.requests_total >= self.max_requests:
                return False
            self.requests_total += 1
            self.active += 1
            return True

    def complete(self, event: dict, streaming: bool, findings: list[Finding], line: str) -> None:
        with self.lock:
            self.log(line)
            if self.ui_enabled:
                event["p0_breaches"] = sum(f.severity == "P0" for f in findings)
                event["p1_warnings"] = sum(f.severity == "P1" for f in findings)
                self.recent_events.appendleft(event)
                self.streaming_requests += streaming
                self.p0_breaches += event["p0_breaches"]
                self.p1_warnings += event["p1_warnings"]
            self.active -= 1
            stop = self.requests_total == self.max_requests and self.active == 0
        if stop:
            self.shutdown()

    def status(self) -> bytes:
        with self.lock:
            events = [{key: value for key, value in event.items() if key not in {"frames", "findings"}}
                      for event in self.recent_events]
            ttfts = [event["ttft_ms"] for event in events if event["ttft_ms"] is not None]
            snapshot = {
                "requests_total": self.requests_total,
                "streaming_requests": self.streaming_requests,
                "p0_breaches": self.p0_breaches,
                "p1_warnings": self.p1_warnings,
                "median_ttft_ms": round(statistics.median(ttfts), 3) if ttfts else None,
                "recent_events": events,
            }
        return _json_bytes(snapshot)

    def event(self, event_id: str) -> dict | None:
        with self.lock:
            return next((event for event in self.recent_events if event["id"] == event_id), None)

    def clear_events(self) -> None:
        with self.lock:
            self.recent_events.clear()


class _ProxyHandler(http.server.BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"
    server: ProxyServer

    def setup(self) -> None:
        self.request.settimeout(self.server.socket_timeout)
        super().setup()

    def log_message(self, format, *args) -> None:
        # Even parse-time errors in BaseHTTPRequestHandler can include a raw target.
        pass

    def __getattr__(self, name):
        if name.startswith("do_"):
            return self._forward
        raise AttributeError(name)

    def _local_response(self, status: int, data: bytes = b"", *, content_type: str = "application/json") -> None:
        self.close_connection = True
        self.send_response_only(status)
        if status != 204:
            self.send_header("Content-Type", f"{content_type}; charset=utf-8")
            self.send_header("Content-Length", str(len(data)))
        self.send_header("Cache-Control", "no-store")
        self.send_header("X-Content-Type-Options", "nosniff")
        if content_type == "text/html":
            self.send_header("Content-Security-Policy", _DASHBOARD_CSP)
            self.send_header("X-Frame-Options", "DENY")
        self.send_header("Connection", "close")
        self.end_headers()
        if data and self.command != "HEAD":
            self.wfile.write(data)

    def _clear_origin_allowed(self) -> bool:
        origins = self.headers.get_all("Origin", [])
        if not origins:
            return True
        hosts = self.headers.get_all("Host", [])
        if len(origins) != 1 or len(hosts) != 1:
            return False
        origin, host = origins[0].lower(), hosts[0].lower()
        try:
            parsed = urlsplit(origin)
            hostname = parsed.hostname or ""
            loopback = hostname == "localhost" or ipaddress.ip_address(hostname).is_loopback
            name = f"[{hostname}]" if ":" in hostname else hostname
            port = parsed.port
        except ValueError:
            return False
        authority = f"{name}:{port}" if port is not None else name
        host_matches = host == authority or (port in {None, 80} and host in {name, f"{name}:80"})
        return loopback and host_matches and "%" not in hostname and origin == f"http://{authority}"

    def _serve_local(self, path: str) -> None:
        if self.server.ui_enabled:
            if self.command == "GET":
                if path in _UI_PAGES:
                    from .proxy_ui import DASHBOARD_HTML

                    self._local_response(200, DASHBOARD_HTML, content_type="text/html")
                    return
                if path == _UI_STATUS:
                    self._local_response(200, self.server.status())
                    return
                if path.startswith(_UI_EVENT_PREFIX):
                    event = self.server.event(path.removeprefix(_UI_EVENT_PREFIX))
                    if event is not None:
                        self._local_response(200, _json_bytes({**event, "issue_markdown": _issue_markdown(event)}))
                        return
            if self.command == "POST" and path == _UI_CLEAR:
                if self._clear_origin_allowed():
                    self.server.clear_events()
                    self._local_response(204)
                else:
                    self._local_response(403, b'{"error":"Forbidden origin"}')
                return
        self._local_response(404, b'{"error":"Not found"}')

    def _forward(self) -> None:
        # BaseHTTPRequestHandler normalizes leading // for redirects. We send origin-form
        # targets to a fixed upstream, so retain the original path from the request line.
        target = self.requestline.split()[1]
        path, query_sep, query = target.partition("?")
        if path in _UI_ROUTES or path.startswith(_UI_EVENT_PREFIX):
            self._serve_local(path)
            return
        star = self.command == "OPTIONS" and target == "*"
        if not (star or path.startswith("/")) or "#" in target or self.command == "CONNECT":
            self.send_error(400, "Expected an origin-form request target")
            return
        if not self.server.begin():
            self.send_error(503, "Proxy request limit reached")
            return

        upstream = self.server.upstream
        upstream_path = "*" if star else upstream.path.rstrip("/") + path
        upstream_query = "&".join(part for part in (upstream.query, query) if part)
        outgoing_target = upstream_path
        if not star and (upstream_query or query_sep):
            outgoing_target += "?" + upstream_query
        endpoint_path = "/" if star else upstream_path
        endpoint = f"{upstream.scheme}://{upstream.netloc}{endpoint_path}"
        secrets = _header_secrets(self.headers) + _query_secrets(upstream_query) + extract_url_secret_values(endpoint)
        start = time.monotonic_ns()
        capture = None
        header_time = start
        status = 502
        clean = False
        raw_body = bytearray()
        response_started = False
        conn_class = http.client.HTTPSConnection if upstream.scheme == "https" else http.client.HTTPConnection
        conn = conn_class(upstream.hostname, upstream.port, timeout=self.server.socket_timeout)
        conn.response_class = _UpstreamResponse
        try:
            try:
                request_chunked, request_length = _framing(self.headers)
            except ValueError:
                status = 400
                self.send_error(status, "Invalid request body framing")
                return
            if not self._send_request(conn, outgoing_target, request_chunked, request_length, raw_body):
                status = 400
                self.send_error(status, "Incomplete request body")
                return
            with conn.getresponse() as response:
                header_time = time.monotonic_ns()
                if response.status == 101:
                    self.send_error(status, "Upstream protocol upgrades are unsupported")
                    return
                response_chunked, response_length = _framing(response.headers)
                secrets.extend(_header_secrets(response.headers))
                for name in ("Location", "Content-Location"):
                    for value in response.headers.get_all(name, []):
                        secrets.extend(extract_url_secret_values(value))
                        secrets.extend(_query_secrets(value.partition("?")[2].partition("#")[0]))
                status = response.status
                has_body = self.command != "HEAD" and not (100 <= status < 200 or status in (204, 304))
                if has_body:
                    capture = _Capture(upstream_path, response.getheader("Content-Type", ""),
                                       response.getheader("Content-Encoding", "").strip().lower(), response_chunked)
                downstream_chunked = has_body and response_length is None and self.request_version == "HTTP/1.1"
                response_started = True
                self._send_headers(response, response_length, downstream_chunked, has_body)
                if has_body:
                    clean = self._relay_body(response, response_chunked, response_length, downstream_chunked, capture)
                else:
                    clean = True
        except (OSError, http.client.HTTPException, ValueError):
            if not response_started:
                status = 502
                self.send_error(status, "Upstream request failed")
        finally:
            conn.close()
            if not clean:
                self.close_connection = True
            self._complete(capture, endpoint, path, status, start, header_time, clean, secrets, raw_body)

    def _send_request(self, conn, target, chunked, length, raw_body) -> bool:
        upstream = self.server.upstream
        conn.putrequest(self.command, target, skip_host=True, skip_accept_encoding=True)
        conn.putheader("Host", upstream.netloc)
        for name, value in _end_to_end(self.headers):
            if name.lower() != "host":
                conn.putheader(name, value)
        if chunked:
            conn.putheader("Transfer-Encoding", "chunked")
            # The chunk parser can read ahead. End the downstream connection after this request.
            self.close_connection = True
        elif length is not None:
            conn.putheader("Content-Length", str(length))
        conn.endheaders()
        for data, clean in _body_chunks(self.rfile, chunked=chunked, length=length or 0):
            if data:
                raw_body.extend(data)
                conn.send(_encode_chunk(data) if chunked else data)
            elif clean and chunked:
                conn.send(_encode_chunk(b""))
        return clean

    def _send_headers(self, response, length, chunked, has_body) -> None:
        self.send_response_only(response.status, response.reason)
        for name, value in _end_to_end(response.headers):
            self.send_header(name, value)
        if chunked:
            self.send_header("Transfer-Encoding", "chunked")
        elif length is not None and (has_body or self.command == "HEAD" or response.status == 304):
            self.send_header("Content-Length", str(length))
        elif has_body:
            self.close_connection = True
        if self.close_connection:
            self.send_header("Connection", "close")
        self.end_headers()
        self.wfile.flush()

    def _relay_body(self, response, chunked, length, downstream_chunked, capture: _Capture) -> bool:
        for data, clean in _body_chunks(response.fp, chunked=chunked, length=length):
            if not data:
                if clean and downstream_chunked:
                    self.wfile.write(_encode_chunk(b""))
                    self.wfile.flush()
                return clean
            now = time.monotonic_ns()
            try:
                self.wfile.write(_encode_chunk(data) if downstream_chunked else data)
                self.wfile.flush()
            finally:
                # Retain the last bytes read if the client disconnected during the write.
                capture.feed(data, now)
        return False

    def _complete(self, capture, endpoint, path, status, start, header_time, clean, secrets, raw_body) -> None:
        end = time.monotonic_ns()
        event = {"method": "[redacted]", "path": "[redacted]", "status": status, "ttft_ms": None,
                 "total_ms": _elapsed(start, end), "findings_count": 0}
        findings = []
        streaming = capture is not None and capture.streaming
        if self.server.ui_enabled:
            event.update(id=f"proxy_{uuid.uuid4().hex}", streaming=streaming, frame_count=0, finish_reason=None,
                         terminal_status=None, dialect=capture.dialect if streaming else None, frames=[], findings=[])
        try:
            body = _request_metadata(raw_body)
            secrets.extend(extract_body_secret_values(body))
            safe_path = _display_path(path, secrets)
            method = _display(self.command, secrets)
            event.update(method=method, path=safe_path)
            line = f"[HTTP {status}] {method} {safe_path}"
            if streaming and capture.framer is not None:
                trace_id = event.get("id") or f"proxy_{uuid.uuid4().hex}"
                header = TraceHeader(
                    trace_id, "proxy", datetime.datetime.now(datetime.timezone.utc).isoformat(), capture.dialect,
                    {"method": method, "url": _display(endpoint, secrets), "effective_params": scrub_report_data(
                        extract_effective_params(body, capture.dialect), secrets,
                    )},
                    {"status_code": status, "content_type": capture.media_type, "t_headers_ms": _elapsed(start, header_time)},
                )
                doc = capture.document(header, secrets, start=start, end=end, clean=clean)
                findings = audit_trace(doc, only=_DETECTORS)
                event["ttft_ms"] = doc.summary.timing["ttft_effective_ms"]
                event["findings_count"] = len(findings)
                line = self._summary_line(event, findings, len(doc.frames))
                should_save = not self.server.only_breaches or any(f.severity in {"P0", "P1"} for f in findings)
                if self.server.save_dir is not None and should_save:
                    try:
                        write_trace(self.server.save_dir / f"{trace_id}.trace.jsonl", doc)
                    except (OSError, ValueError):
                        line += " [TRACE SAVE FAILED]"
                if self.server.ui_enabled:
                    frames = doc.frames
                    if len(frames) > _FRAME_LIMIT:
                        half = _FRAME_LIMIT // 2
                        frames = frames[:half] + frames[-half:]
                    assembled = doc.summary.assembled
                    event.update(frame_count=len(doc.frames), findings=_dashboard_findings(findings),
                                 frames=[_frame_metadata(frame, capture.dialect) for frame in frames])
                    for field in ("finish_reason", "terminal_status"):
                        value = assembled.get(field)
                        if is_protocol_enum(capture.dialect, field, value):
                            event[field] = value
            elif streaming:
                line = f"[CAPTURE UNAVAILABLE] {method} {safe_path}"
        except (ValueError, TypeError, OverflowError, RecursionError):
            line = "[CAPTURE ERROR] Could not audit request safely"
        finally:
            self.server.complete(event, streaming, findings, line)

    def _summary_line(self, event: dict, findings: list[Finding], frames: int) -> str:
        subject = f"{event['method']} {event['path']}"
        if findings:
            finding = findings[0]
            kind = "BREACH" if finding.severity == "P0" else "WARNING"
            tag = f"{finding.severity} {kind} {finding.detector_id}"
            detail = finding.code.lower().replace("_", " ")
            line = f"{subject} -> {detail}"
        else:
            ttft = event["ttft_ms"]
            if event["status"] == 200:
                tag = f"PASS {ttft:.0f}ms TTFT" if ttft is not None else "PASS"
            else:
                tag = f"HTTP {event['status']}"
            line = f"{subject} ({frames} frames)"
        if not self.server.no_color and sys.stdout.isatty():
            color = "31" if findings and findings[0].severity == "P0" else "33" if findings else "32"
            tag = f"\x1b[{color}m{tag}\x1b[0m"
        return f"[{tag}] {line}"


def create_proxy_server(
    upstream: str, *, host: str = "127.0.0.1", port: int = 8787, save_dir: str | Path | None = None,
    only_breaches: bool = False, timeout: float = 120, max_requests: int = 0, no_color: bool = False,
    no_ui: bool = False,
) -> ProxyServer:
    """Bind a proxy to an address. The caller owns the serving loop and cleanup."""
    target = validate_url(upstream)
    if target.fragment or any(char.isspace() for char in upstream):
        raise RecorderError("Upstream URL must contain no whitespace or fragment.")
    if not 0 <= port <= 65535:
        raise RecorderError("Proxy port must be between 0 and 65535.")
    if not math.isfinite(timeout) or timeout <= 0:
        raise RecorderError("Proxy timeout must be finite and positive.")
    if max_requests < 0:
        raise RecorderError("Proxy request limit must be nonnegative.")
    directory = Path(save_dir) if save_dir else None
    if directory is not None:
        try:
            directory.mkdir(parents=True, exist_ok=True)
        except OSError:
            raise RecorderError("Could not create proxy trace directory.") from None
    try:
        return ProxyServer((host, port), target, save_dir=directory, only_breaches=only_breaches,
                           timeout=timeout, max_requests=max_requests, no_color=no_color, no_ui=no_ui)
    except OSError:
        raise RecorderError("Could not bind proxy listener.") from None
