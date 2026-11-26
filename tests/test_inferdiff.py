"""Comprehensive unit, protocol, security, and socket torture tests for inferdiff v0.1.0."""

from __future__ import annotations

import http.server
import io
import json
import socket
import socketserver
import tempfile
import threading
import time
import unittest
from contextlib import redirect_stderr, redirect_stdout
from pathlib import Path
from typing import Any, Callable, Dict, List, Optional

from inferdiff.cli import main as cli_main
from inferdiff.detectors import D1, D2, D3, D4, D5, audit_trace
from inferdiff.differ import diff_traces
from inferdiff.exporter import (
    MAX_ISSUE_LINES,
    render_diff_terminal,
    render_github_issue,
)
from inferdiff.recorder import (
    NDJSONFramer,
    RecorderError,
    SSEFramer,
    WireChunk,
    build_frame_from_chunk,
    record_stream,
)
from inferdiff.redact import fingerprint8, redact_headers
from inferdiff.schema import (
    EXIT_OK,
    EXIT_SEMANTIC_REGRESSION,
    EXIT_SILENT_PROTOCOL_BREACH,
    EXIT_USAGE_OR_IO_ERROR,
    TraceDocument,
    TraceHeader,
    TraceSchemaError,
    assemble_summary,
    body_sha256,
    extract_effective_params,
    load_trace,
    scan_think_tags,
    write_trace,
)


class _ReusableThreadingServer(socketserver.ThreadingMixIn, http.server.HTTPServer):
    daemon_threads = True
    allow_reuse_address = True


def _run_mock_server(handler_fn: Callable[[http.server.BaseHTTPRequestHandler], None]):
    captured_headers: List[dict] = []

    class Handler(http.server.BaseHTTPRequestHandler):
        protocol_version = "HTTP/1.1"

        def do_POST(self):
            length = int(self.headers.get("Content-Length", "0"))
            _ = self.rfile.read(length) if length > 0 else b""
            captured_headers.append(dict(self.headers.items()))
            handler_fn(self)

        def log_message(self, format, *args):
            return

    server = _ReusableThreadingServer(("127.0.0.1", 0), Handler)
    port = server.server_address[1]
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    return server, port, captured_headers


def _run_raw_tcp_server(raw_response: bytes):
    """Serve exact raw HTTP response bytes over loopback TCP to test RFC 9112 edge cases."""
    srv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    srv.bind(("127.0.0.1", 0))
    port = srv.getsockname()[1]
    srv.listen(4)

    def _serve():
        try:
            conn, _ = srv.accept()
            with conn:
                conn.settimeout(2.0)
                req_buf = bytearray()
                try:
                    # Drain complete HTTP request (headers + Content-Length body) to avoid Windows TCP RST
                    while b"\r\n\r\n" not in req_buf:
                        chunk = conn.recv(65536)
                        if not chunk:
                            break
                        req_buf.extend(chunk)
                    sep = req_buf.find(b"\r\n\r\n")
                    if sep != -1:
                        hdr_text = req_buf[:sep].decode("iso-8859-1", errors="ignore")
                        cl = 0
                        for line in hdr_text.split("\r\n"):
                            if line.lower().startswith("content-length:"):
                                cl = int(line.split(":", 1)[1].strip())
                                break
                        body_got = len(req_buf) - (sep + 4)
                        while body_got < cl:
                            chunk = conn.recv(65536)
                            if not chunk:
                                break
                            body_got += len(chunk)
                except OSError:
                    pass
                conn.sendall(raw_response)
                try:
                    conn.shutdown(socket.SHUT_WR)
                except OSError:
                    pass
        except OSError:
            pass
        finally:
            srv.close()

    t = threading.Thread(target=_serve, daemon=True)
    t.start()
    return port, t


def _make_doc(
    *,
    dialect: str = "openai-chat",
    raw_frames: List[tuple],  # (sse_event, payload_text, raw_wire, dt_ms)
    body: Optional[Dict[str, Any]] = None,
    url: str = "http://127.0.0.1:8080/v1/chat/completions",
    status_code: int = 200,
    label: str = "srv",
    socket_eof_clean: bool = True,
) -> TraceDocument:
    req_body = body if body is not None else {"model": "m", "stream": True, "messages": [{"role": "user", "content": "hi"}]}
    hdr = TraceHeader(
        trace_id="tr_test",
        label=label,
        recorded_at_utc="2026-11-26T00:00:00.000Z",
        dialect=dialect,
        request={
            "method": "POST",
            "url": url,
            "headers_redacted": {"content-type": "application/json"},
            "body_sha256": body_sha256(req_body),
            "body": req_body,
            "effective_params": extract_effective_params(req_body, dialect),
        },
        response_meta={"status_code": status_code, "content_type": "text/event-stream", "t_headers_ms": 5.0},
    )
    frames = []
    prev_ms = 0.0
    t_ns = 0
    sgl_prev = ""
    for ev, payload_text, raw_wire, dt_ms in raw_frames:
        t_ns += int(dt_ms * 1_000_000)
        wc = WireChunk(t_mono_ns=t_ns, sse_event=ev, payload_text=payload_text, raw_wire=raw_wire)
        tf, sgl_prev = build_frame_from_chunk(
            wc,
            seq=len(frames),
            dialect=dialect,
            prev_rel_ms=prev_ms,
            t0_ns=0,
            sglang_prev_text=sgl_prev,
        )
        prev_ms = tf.t_rel_ms
        frames.append(tf)
    summary = assemble_summary(hdr, frames, total_ms=round(t_ns / 1_000_000.0, 3), socket_eof_clean=socket_eof_clean)
    return TraceDocument(header=hdr, frames=frames, summary=summary)


def _make_chat_doc(
    *,
    chunks: List[str],
    reasoning_chunks: Optional[List[str]] = None,
    finish_reason: str = "stop",
    stop_reason: Any = None,
    completion_tokens: int = 4,
    ignore_eos: bool = False,
    max_tokens: int | None = 64,
    stop: list | None = None,
    cached_tokens: int | None = None,
    frame_dt_ms: float = 40.0,
    label: str = "srv",
    url: str = "http://127.0.0.1:8080/v1/chat/completions",
    extra_body: Optional[Dict[str, Any]] = None,
) -> TraceDocument:
    body: Dict[str, Any] = {
        "model": "m",
        "stream": True,
        "messages": [{"role": "user", "content": "hi"}],
        "ignore_eos": ignore_eos,
    }
    if max_tokens is not None:
        body["max_tokens"] = max_tokens
    if stop is not None:
        body["stop"] = stop
    if extra_body:
        body.update(extra_body)

    raw_frames: List[tuple] = []
    for rc in reasoning_chunks or []:
        p = json.dumps({"choices": [{"index": 0, "delta": {"reasoning_content": rc}, "finish_reason": None}]})
        raw_frames.append((None, p, f"data: {p}\n\n", frame_dt_ms))
    for text in chunks:
        p = json.dumps({"choices": [{"index": 0, "delta": {"content": text}, "finish_reason": None}]})
        raw_frames.append((None, p, f"data: {p}\n\n", frame_dt_ms))

    usage_obj: dict = {"prompt_tokens": 10, "completion_tokens": completion_tokens}
    if cached_tokens is not None:
        usage_obj["prompt_tokens_details"] = {"cached_tokens": cached_tokens}
    ch_fin: Dict[str, Any] = {"index": 0, "delta": {}, "finish_reason": finish_reason}
    if stop_reason is not None:
        ch_fin["stop_reason"] = stop_reason
    fin_p = json.dumps({"choices": [ch_fin], "usage": usage_obj})
    raw_frames.append((None, fin_p, f"data: {fin_p}\n\n", frame_dt_ms))
    raw_frames.append((None, "[DONE]", "data: [DONE]\n\n", 5.0))
    return _make_doc(dialect="openai-chat", raw_frames=raw_frames, body=body, label=label, url=url)


class TestSecurityAndRedaction(unittest.TestCase):
    def test_redacts_sensitive_headers_and_only_preserves_recognized_auth_schemes(self):
        secret = "sk-live-super-secret-token-999"
        red = redact_headers(
            {
                "Authorization": f"Bearer {secret}",
                "Proxy-Authorization": "RawFirstWordSecret secondpart",
                "X-Api-Key": secret,
                "Cookie": "sid=abc123",
                "Content-Type": "application/json",
            }
        )
        self.assertNotIn(secret, json.dumps(red))
        self.assertNotIn("RawFirstWordSecret", json.dumps(red))
        self.assertTrue(red["authorization"].startswith("Bearer $REDACTED_sha256:"))
        self.assertTrue(red["proxy-authorization"].startswith("$REDACTED_sha256:"))
        self.assertEqual(red["x-api-key"], f"$REDACTED_sha256:{fingerprint8(secret)}")
        self.assertTrue(red["cookie"].startswith("$REDACTED_sha256:"))
        self.assertEqual(red["content-type"], "application/json")

    def test_p0_shell_injection_and_credential_isolation_in_exports(self):
        secret_q = "SYNTHETIC_QUERY_SECRET_999"
        secret_b = "SYNTHETIC_BODY_SECRET_888"
        secret_w = "sk-live-wire-echoed-secret-777777"
        doc = _make_chat_doc(
            chunks=[f"echoed {secret_w}"],
            url=f"http://127.0.0.1:8080/v1/chat/completions?api-version=2024-10-21&api_key={secret_q}&x=1&cmd=$(id)",
            extra_body={"api_key": secret_b, "messages": [{"role": "user", "content": f"use {secret_b}"}]},
            label="evil;rm -rf /",
        )
        # Default github-issue export must shell-quote URL, use --globoff --url, and leak ZERO secrets
        md = render_github_issue(
            doc,
            None,
            audit_findings=[],
            before_path="a b;echo pwn.trace.jsonl",
        )
        self.assertLessEqual(len(md.splitlines()), MAX_ISSUE_LINES)
        self.assertIn("--globoff --url 'http://127.0.0.1:8080/v1/chat/completions?", md)
        self.assertIn("api-version=2024-10-21", md)
        self.assertNotIn(secret_q, md)
        self.assertNotIn(secret_b, md)
        self.assertNotIn(secret_w, md)
        self.assertIn("'a b;echo pwn.trace.jsonl'", md)

        # Even with --include-body and --include-wire, secret fields & sk-live patterns are redacted!
        md_inc = render_github_issue(doc, None, audit_findings=[], include_body=True, include_wire=True)
        self.assertNotIn(secret_q, md_inc)
        self.assertNotIn(secret_b, md_inc)
        self.assertNotIn(secret_w, md_inc)

        # Default single-trace JSON export omits raw body & raw wire content
        with tempfile.TemporaryDirectory() as td:
            tr_path = Path(td) / "sec.trace.jsonl"
            write_trace(tr_path, doc)
            buf = io.StringIO()
            with redirect_stdout(buf):
                rc = cli_main(["export", str(tr_path), "--format", "json"])
            self.assertEqual(rc, EXIT_OK)
            out_txt = buf.getvalue()
            self.assertNotIn(secret_q, out_txt)
            self.assertNotIn(secret_b, out_txt)
            self.assertNotIn(secret_w, out_txt)
            parsed = json.loads(out_txt)
            self.assertNotIn("body", parsed["header"]["request"])

    def test_p0_401_error_does_not_leak_query_string_or_response_body(self):
        def handle(req: http.server.BaseHTTPRequestHandler):
            req.send_response(401)
            req.send_header("Content-Type", "text/plain")
            body = b"Invalid API key: LEAKED_RESP_BODY_XYZ"
            req.send_header("Content-Length", str(len(body)))
            req.end_headers()
            req.wfile.write(body)

        server, port, _ = _run_mock_server(handle)
        try:
            with self.assertRaises(RecorderError) as ctx:
                record_stream(
                    url=f"http://127.0.0.1:{port}/v1/chat/completions?api_key=LEAKED_QUERY_ABC",
                    request_body={"model": "m1", "messages": []},
                )
            err = str(ctx.exception)
            self.assertIn("HTTP 401", err)
            self.assertNotIn("LEAKED_QUERY_ABC", err)
            self.assertNotIn("LEAKED_RESP_BODY_XYZ", err)
        finally:
            server.shutdown()
            server.server_close()

    def test_centralized_url_and_header_validation_in_record_stream(self):
        with self.assertRaises(RecorderError):
            record_stream(url="http://127.0.0.1:8080/v1\r\nX-Injected: 1", request_body={"model": "m"})
        with self.assertRaises(RecorderError):
            record_stream(
                url="http://127.0.0.1:8080/v1",
                request_body={"model": "m"},
                headers={"Content-Length": "999"},
            )
        with self.assertRaises(RecorderError):
            record_stream(
                url="http://127.0.0.1:8080/v1",
                request_body={"model": "m"},
                headers={"Bad Header": "val"},
            )


class TestFramersAndHttpTruncation(unittest.TestCase):
    def test_sse_framer_split_utf8_comment_crlf_and_unterminated_event_tail(self):
        # Comment-only CRLF block must NOT leak stray LF into next event's raw_wire!
        comment = ": keepalive\r\n\r\n"
        msg1 = 'data: {"choices":[{"index":0,"delta":{"content":"你好🚀"}}]}\r\n\r\n'
        msg2 = 'data: {"choices":[{"index":0,"delta":{"content":"世界"},"finish_reason":"stop"}]}\n\n'
        msg3 = "data: [DONE]\r\n\r\n"
        raw = b"\xef\xbb\xbf" + (comment + msg1 + msg2 + msg3).encode("utf-8")

        framer = SSEFramer()
        chunks = []
        for idx in range(len(raw)):
            chunks.extend(framer.feed(raw[idx : idx + 1], idx * 1_000_000))
        chunks.extend(framer.finish(len(raw) * 1_000_000))

        self.assertEqual(len(chunks), 3)
        self.assertEqual(chunks[0].raw_wire, msg1)  # No leading '\n'!
        self.assertEqual(json.loads(chunks[0].payload_text)["choices"][0]["delta"]["content"], "你好🚀")
        self.assertEqual(chunks[1].raw_wire, msg2)
        self.assertEqual(chunks[2].payload_text, "[DONE]")

        # Unterminated event:-only tail must be preserved as incomplete evidence
        f_tail = SSEFramer()
        ev_tail = f_tail.feed(b"event: response.completed\n", 1) + f_tail.finish(2)
        self.assertEqual(len(ev_tail), 1)
        self.assertTrue(ev_tail[0].is_incomplete)
        self.assertEqual(ev_tail[0].sse_event, "response.completed")

    def test_ndjson_framer_strict_crlf_rejects_bare_cr_and_accepts_final_object_without_lf(self):
        # Reject \r\r\n (embedded bare CR)
        f_bad = NDJSONFramer()
        out_bad = f_bad.feed(b'{"done":true}\r\r\n', 1) + f_bad.finish(2)
        self.assertEqual(len(out_bad), 1)
        self.assertEqual(out_bad[0].framing_error, "invalid_ndjson_cr")

        # Compatibility choice pinned: valid final Ollama JSON object without trailing LF
        f_ok = NDJSONFramer()
        out_ok = f_ok.feed(b'{"message":{"content":"hi"},"done":false}\n{"done":true}', 1) + f_ok.finish(2)
        self.assertEqual(len(out_ok), 2)
        self.assertFalse(out_ok[1].is_incomplete)
        self.assertIsNone(out_ok[1].framing_error)

    def test_p1_duplicate_content_length_short_body_fails_d4(self):
        body = b'data: {"choices":[{"index":0,"delta":{"content":"hi"},"finish_reason":"stop"}]}\n\ndata: [DONE]\n\n'
        declared = len(body) + 50
        raw_resp = (
            f"HTTP/1.1 200 OK\r\n"
            f"Content-Type: text/event-stream\r\n"
            f"Content-Length: {declared}\r\n"
            f"Content-Length: {declared}\r\n"
            f"Connection: close\r\n\r\n"
        ).encode("ascii") + body
        port, t = _run_raw_tcp_server(raw_resp)
        try:
            doc = record_stream(url=f"http://127.0.0.1:{port}/v1/chat/completions", request_body={"model": "m"})
            self.assertFalse(doc.summary.eof_clean)
            self.assertIn(D4, [f.detector_id for f in audit_trace(doc)])
        finally:
            t.join(timeout=2)

    def test_p1_chunked_missing_final_crlf_and_oversized_trailer_fail_d4_cleanly(self):
        body = b'data: {"choices":[{"index":0,"delta":{"content":"ok"},"finish_reason":"stop"}]}\n\ndata: [DONE]\n\n'
        # Ends at 0\r\n WITHOUT the required terminating \r\n!
        raw_trunc = (
            b"HTTP/1.1 200 OK\r\n"
            b"Content-Type: text/event-stream\r\n"
            b"Transfer-Encoding: chunked\r\n"
            b"Connection: close\r\n\r\n"
            + f"{len(body):x}\r\n".encode("ascii")
            + body
            + b"\r\n0\r\n"
        )
        port1, t1 = _run_raw_tcp_server(raw_trunc)
        try:
            doc1 = record_stream(url=f"http://127.0.0.1:{port1}/v1/chat/completions", request_body={"model": "m"})
            self.assertFalse(doc1.summary.eof_clean)
            self.assertIn(D4, [f.detector_id for f in audit_trace(doc1)])
        finally:
            t1.join(timeout=2)

        # Oversized trailer (>64 KiB) must NOT crash with LineTooLong and MUST finalize unclean summary
        raw_trailer = (
            b"HTTP/1.1 200 OK\r\n"
            b"Content-Type: text/event-stream\r\n"
            b"Transfer-Encoding: chunked\r\n"
            b"Connection: close\r\n\r\n"
            + f"{len(body):x}\r\n".encode("ascii")
            + body
            + b"\r\n0\r\nX-Big: "
            + (b"A" * 70000)
            + b"\r\n\r\n"
        )
        port2, t2 = _run_raw_tcp_server(raw_trailer)
        try:
            with tempfile.TemporaryDirectory() as td:
                out_f = Path(td) / "trailer.trace.jsonl"
                doc2 = record_stream(
                    url=f"http://127.0.0.1:{port2}/v1/chat/completions",
                    request_body={"model": "m"},
                    out_path=out_f,
                )
                self.assertFalse(doc2.summary.eof_clean)
                reloaded = load_trace(out_f)
                self.assertFalse(reloaded.summary.eof_clean)
                self.assertIn(D4, [f.detector_id for f in audit_trace(reloaded)])
        finally:
            t2.join(timeout=2)

        # Valid chunked stream with 0\r\n\r\n passes cleanly!
        raw_valid = (
            b"HTTP/1.1 200 OK\r\n"
            b"Content-Type: text/event-stream\r\n"
            b"Transfer-Encoding: chunked\r\n"
            b"Connection: close\r\n\r\n"
            + f"{len(body):x}\r\n".encode("ascii")
            + body
            + b"\r\n0\r\n\r\n"
        )
        port3, t3 = _run_raw_tcp_server(raw_valid)
        try:
            doc3 = record_stream(url=f"http://127.0.0.1:{port3}/v1/chat/completions", request_body={"model": "m"})
            self.assertTrue(doc3.summary.eof_clean)
            self.assertEqual(audit_trace(doc3), [])
        finally:
            t3.join(timeout=2)

    def test_p1_malformed_huge_int_and_lone_surrogate_do_not_strand_evidence(self):
        huge_int_line = b'data: {"choices":[{"index":0,"delta":{"content":"first"}}]}\n\n'
        huge_int_line += b'data: {"bad": ' + (b"9" * 5000) + b"}\n\n"
        huge_int_line += b'data: {"choices":[{"index":0,"delta":{"content":"\\ud800"}}]}\n\n'
        huge_int_line += b'data: {"choices":[{"index":0,"delta":{},"finish_reason":"stop"}]}\n\ndata: [DONE]\n\n'
        raw_resp = (
            f"HTTP/1.1 200 OK\r\nContent-Type: text/event-stream\r\nContent-Length: {len(huge_int_line)}\r\nConnection: close\r\n\r\n"
        ).encode("ascii") + huge_int_line
        port, t = _run_raw_tcp_server(raw_resp)
        try:
            with tempfile.TemporaryDirectory() as td:
                out_f = Path(td) / "malformed.trace.jsonl"
                doc = record_stream(
                    url=f"http://127.0.0.1:{port}/v1/chat/completions",
                    request_body={"model": "m"},
                    out_path=out_f,
                )
                self.assertEqual(doc.summary.total_frames, 5)
                self.assertIsNotNone(doc.frames[1].parse_error)
                self.assertEqual(doc.frames[2].parse_error, "invalid_unicode_surrogate")
                reloaded = load_trace(out_f)
                self.assertEqual(reloaded.summary.total_frames, 5)
                self.assertIn(D4, [f.detector_id for f in audit_trace(reloaded)])
        finally:
            t.join(timeout=2)

    def test_p1_http_204_rejected_in_record_and_flagged_in_offline_audit(self):
        raw_204 = b"HTTP/1.1 204 No Content\r\nConnection: close\r\n\r\n"
        port, t = _run_raw_tcp_server(raw_204)
        try:
            with self.assertRaises(RecorderError):
                record_stream(url=f"http://127.0.0.1:{port}/v1/chat/completions", request_body={"model": "m"})
        finally:
            t.join(timeout=2)

        doc_204 = _make_doc(dialect="openai-chat", raw_frames=[], status_code=204)
        self.assertIn(D4, [f.detector_id for f in audit_trace(doc_204)])

    def test_v02_three_point_backend_probe_hook(self):
        events: List[str] = []

        class SpyProbe:
            name = "spy"

            def describe_topology(self):
                events.append("topology")
                return {"probe_version": "0.2.0", "target": "spy"}

            def sample_pre(self):
                events.append("pre")

            def sample_ttft(self):
                events.append("ttft")

            def sample_eof(self):
                events.append("eof")
                return {"probe_version": "0.2.0", "delta_read_bytes": 0}

        body = (
            b'data: {"choices":[{"index":0,"delta":{"role":"assistant","content":""}}]}\n\n'
            b'data: {"choices":[{"index":0,"delta":{"content":"hello"},"finish_reason":"stop"}]}\n\n'
            b"data: [DONE]\n\n"
        )
        raw_resp = (
            f"HTTP/1.1 200 OK\r\nContent-Type: text/event-stream\r\nContent-Length: {len(body)}\r\nConnection: close\r\n\r\n"
        ).encode("ascii") + body
        port, t = _run_raw_tcp_server(raw_resp)
        try:
            with tempfile.TemporaryDirectory() as td:
                out_f = Path(td) / "probe.trace.jsonl"
                doc = record_stream(
                    url=f"http://127.0.0.1:{port}/v1/chat/completions",
                    request_body={"model": "m"},
                    out_path=out_f,
                    probe=SpyProbe(),
                )
                self.assertEqual(events, ["topology", "pre", "ttft", "eof"])
                self.assertEqual(doc.header.backend_probe["probe_version"], "0.2.0")
                self.assertEqual(doc.summary.backend_probe["delta_read_bytes"], 0)
                reloaded = load_trace(out_f)
                self.assertEqual(reloaded.summary.backend_probe["delta_read_bytes"], 0)
        finally:
            t.join(timeout=2)


class TestProtocolDialectsDetectorsAndDiffer(unittest.TestCase):
    def test_p1_terminal_order_and_responses_status_validation(self):
        # 1) response.completed with status: "in_progress" must fail D4!
        bad_resp = _make_doc(
            dialect="openai-responses",
            raw_frames=[
                (
                    "response.completed",
                    json.dumps({"type": "response.completed", "response": {"status": "in_progress"}}),
                    'event: response.completed\ndata: {"type":"response.completed","response":{"status":"in_progress"}}\n\n',
                    10.0,
                )
            ],
        )
        self.assertFalse(bad_resp.summary.eof_clean)
        self.assertIn(D4, [f.detector_id for f in audit_trace(bad_resp)])

        # 2) Chat [DONE] BEFORE content & finish frame must fail eof_clean & diff!
        good = _make_chat_doc(chunks=["ok"], label="good")
        out_of_order = _make_doc(
            dialect="openai-chat",
            raw_frames=[
                (None, "[DONE]", "data: [DONE]\n\n", 10.0),
                (None, json.dumps({"choices": [{"index": 0, "delta": {"content": "ok"}, "finish_reason": "stop"}]}), "data: ...\n\n", 10.0),
            ],
            label="bad-order",
        )
        self.assertFalse(out_of_order.summary.eof_clean)
        self.assertIn(D4, [f.detector_id for f in audit_trace(out_of_order)])
        rep = diff_traces(good, out_of_order, ignore_timing=True, fail_on="any-diff")
        self.assertFalse(rep.semantic_equal)
        self.assertEqual(rep.exit_code, EXIT_SILENT_PROTOCOL_BREACH)

    def test_p1_tool_identity_conflict_reconciliation_ollama_multi_chunk_and_empty_delta(self):
        # 1) Conflicting item_id reusing output_index=0 must NOT inherit previous call's deltas
        conflict_doc = _make_doc(
            dialect="openai-responses",
            raw_frames=[
                (
                    "response.output_item.added",
                    json.dumps({"type": "response.output_item.added", "output_index": 0, "item": {"type": "function_call", "id": "fc_1", "call_id": "c1", "name": "f1"}}),
                    "data: ...\n\n",
                    5.0,
                ),
                (
                    "response.function_call_arguments.delta",
                    json.dumps({"type": "response.function_call_arguments.delta", "output_index": 0, "item_id": "fc_1", "delta": '{"a":1}'}),
                    "data: ...\n\n",
                    5.0,
                ),
                (
                    "response.function_call_arguments.done",
                    json.dumps({"type": "response.function_call_arguments.done", "output_index": 0, "item_id": "fc_1", "arguments": '{"a":1}'}),
                    "data: ...\n\n",
                    5.0,
                ),
                (
                    "response.output_item.added",
                    json.dumps({"type": "response.output_item.added", "output_index": 0, "item": {"type": "function_call", "id": "fc_2", "call_id": "c2", "name": "f2"}}),
                    "data: ...\n\n",
                    5.0,
                ),
                (
                    "response.completed",
                    json.dumps({"type": "response.completed", "response": {"status": "completed"}}),
                    "data: ...\n\n",
                    5.0,
                ),
            ],
        )
        tools = conflict_doc.summary.assembled["tool_calls"]
        self.assertEqual(len(tools), 2)
        self.assertEqual(tools[1]["raw_arguments"], "")  # Did NOT inherit fc_1's '{"a":1}'
        self.assertIn(D1, [f.detector_id for f in audit_trace(conflict_doc)])

        # 2) Provisional alias reconciliation merges two provisional records into one
        recon_doc = _make_doc(
            dialect="openai-responses",
            raw_frames=[
                ("response.function_call_arguments.delta", json.dumps({"type": "response.function_call_arguments.delta", "item_id": "fc_a", "delta": '{"x":'}), "data: ...\n\n", 5.0),
                ("response.function_call_arguments.delta", json.dumps({"type": "response.function_call_arguments.delta", "call_id": "call_a", "delta": "1}"}), "data: ...\n\n", 5.0),
                ("response.function_call_arguments.done", json.dumps({"type": "response.function_call_arguments.done", "item_id": "fc_a", "call_id": "call_a", "name": "fn", "arguments": '{"x":1}'}), "data: ...\n\n", 5.0),
                ("response.completed", json.dumps({"type": "response.completed", "response": {"status": "completed"}}), "data: ...\n\n", 5.0),
            ],
        )
        self.assertEqual(len(recon_doc.summary.assembled["tool_calls"]), 1)
        self.assertTrue(recon_doc.summary.assembled["tool_calls"][0]["json_valid"])
        self.assertEqual(audit_trace(recon_doc), [])

        # 3) Ollama two separate chunks with 1 tool call each -> 2 distinct calls
        ol_doc = _make_doc(
            dialect="ollama-ndjson",
            raw_frames=[
                (None, json.dumps({"message": {"tool_calls": [{"function": {"name": "a", "arguments": {"x": 1}}}]}, "done": False}), "{}\n", 5.0),
                (None, json.dumps({"message": {"tool_calls": [{"function": {"name": "b", "arguments": {"y": 2}}}]}, "done": False}), "{}\n", 5.0),
                (None, json.dumps({"message": {"content": ""}, "done": True, "done_reason": "stop"}), "{}\n", 5.0),
            ],
        )
        ol_tools = ol_doc.summary.assembled["tool_calls"]
        self.assertEqual(len(ol_tools), 2)
        self.assertEqual([t["name"] for t in ol_tools], ["a", "b"])

        # 4) Empty Responses arguments.delta without .done must trigger D1 even if final snapshot is valid
        empty_delta_doc = _make_doc(
            dialect="openai-responses",
            raw_frames=[
                ("response.output_item.added", json.dumps({"type": "response.output_item.added", "output_index": 0, "item": {"type": "function_call", "id": "fc_e", "call_id": "ce", "name": "fn"}}), "data: ...\n\n", 5.0),
                ("response.function_call_arguments.delta", json.dumps({"type": "response.function_call_arguments.delta", "output_index": 0, "item_id": "fc_e", "delta": ""}), "data: ...\n\n", 5.0),
                ("response.completed", json.dumps({"type": "response.completed", "response": {"status": "completed", "output": [{"type": "function_call", "id": "fc_e", "call_id": "ce", "name": "fn", "arguments": '{"k":1}'}]}}), "data: ...\n\n", 5.0),
            ],
        )
        self.assertIn(D1, [f.detector_id for f in audit_trace(empty_delta_doc)])

        # 5) Strict JSON rejects NaN in tool arguments
        nan_tool = _make_doc(
            dialect="openai-chat",
            raw_frames=[
                (None, json.dumps({"choices": [{"index": 0, "delta": {"tool_calls": [{"index": 0, "id": "c1", "function": {"name": "fn", "arguments": '{"x": NaN}'}}]}}]}), "data: ...\n\n", 5.0),
                (None, json.dumps({"choices": [{"index": 0, "delta": {}, "finish_reason": "tool_calls"}]}), "data: ...\n\n", 5.0),
                (None, "[DONE]", "data: [DONE]\n\n", 5.0),
            ],
        )
        self.assertFalse(nan_tool.summary.assembled["tool_calls"][0]["json_valid"])
        self.assertIn(D1, [f.detector_id for f in audit_trace(nan_tool)])

    def test_p1_diff_representation_reasoning_think_json_keys_cross_dialect_and_same_dialect_terminal(self):
        # 1) Reasoning-only change must NOT exit 0 under --fail-on any-diff
        r1 = _make_chat_doc(chunks=["42"], reasoning_chunks=["step A"])
        r2 = _make_chat_doc(chunks=["42"], reasoning_chunks=["step B"])
        rep_r = diff_traces(r1, r2, ignore_timing=True, fail_on="any-diff")
        self.assertFalse(rep_r.semantic_equal)
        self.assertEqual(rep_r.first_divergence.category, "REASONING")
        self.assertEqual(rep_r.exit_code, EXIT_SEMANTIC_REGRESSION)

        # 2) Equivalent inline <think> vs dedicated reasoning_content must be semantically equal!
        t_inline = _make_chat_doc(chunks=["<think>plan</think>Answer"])
        t_ded = _make_chat_doc(chunks=["Answer"], reasoning_chunks=["plan"])
        rep_eq = diff_traces(t_inline, t_ded, ignore_timing=True, fail_on="any-diff")
        self.assertTrue(rep_eq.semantic_equal)
        self.assertEqual(rep_eq.exit_code, EXIT_OK)

        # 3) Reordered JSON keys + healthy Chat vs healthy Responses tool calls must be equal!
        chat_tool = _make_doc(
            dialect="openai-chat",
            raw_frames=[
                (None, json.dumps({"choices": [{"index": 0, "delta": {"tool_calls": [{"index": 0, "id": "c1", "function": {"name": "f", "arguments": '{"a":1,"b":2}'}}]}}]}), "data: ...\n\n", 5.0),
                (None, json.dumps({"choices": [{"index": 0, "delta": {}, "finish_reason": "tool_calls"}]}), "data: ...\n\n", 5.0),
                (None, "[DONE]", "data: [DONE]\n\n", 5.0),
            ],
        )
        resp_tool = _make_doc(
            dialect="openai-responses",
            raw_frames=[
                ("response.output_item.added", json.dumps({"type": "response.output_item.added", "output_index": 0, "item": {"type": "function_call", "id": "fc1", "call_id": "c1", "name": "f"}}), "data: ...\n\n", 5.0),
                ("response.function_call_arguments.delta", json.dumps({"type": "response.function_call_arguments.delta", "output_index": 0, "item_id": "fc1", "delta": '{"b":2,"a":1}'}), "data: ...\n\n", 5.0),
                ("response.function_call_arguments.done", json.dumps({"type": "response.function_call_arguments.done", "output_index": 0, "item_id": "fc1", "arguments": '{"b":2,"a":1}'}), "data: ...\n\n", 5.0),
                ("response.completed", json.dumps({"type": "response.completed", "response": {"status": "completed"}}), "data: ...\n\n", 5.0),
            ],
        )
        rep_xd = diff_traces(chat_tool, resp_tool, ignore_timing=True, fail_on="any-diff")
        self.assertTrue(rep_xd.semantic_equal)
        self.assertEqual(rep_xd.exit_code, EXIT_OK)

        # 4) Same-dialect stop -> tool_calls must set terminal_drifted=True
        same_a = _make_chat_doc(chunks=["hi"], finish_reason="stop")
        same_b = _make_chat_doc(chunks=["hi"], finish_reason="tool_calls")
        rep_term = diff_traces(same_a, same_b, ignore_timing=True, fail_on="p1")
        self.assertTrue(rep_term.terminal_drifted)
        self.assertEqual(rep_term.exit_code, EXIT_SEMANTIC_REGRESSION)

    def test_p1_d2_observed_stop_think_depth_and_ollama_absent_reason(self):
        # 1) Observed stop_reason with 2 completion tokens -> NO D2 false positive
        ok_stop = _make_chat_doc(chunks=[], finish_reason="stop", stop_reason="STOP", completion_tokens=2, stop=["STOP"])
        self.assertEqual(audit_trace(ok_stop), [])

        # 2) Configured stop WITHOUT observed stop_reason on empty stop -> D2 fires!
        unexplained = _make_chat_doc(chunks=[], finish_reason="stop", completion_tokens=0, stop=["STOP"])
        self.assertEqual([f.detector_id for f in audit_trace(unexplained)], [D2])

        # 3) </think><think>orphan -> scanner reports unclosed=True despite equal counts
        vis, reas, unclosed = scan_think_tags("</think><think>orphan")
        self.assertTrue(unclosed)
        self.assertEqual(reas, "orphan")
        self.assertEqual(vis, "</think>")

        # 4) Ollama done=true without done_reason preserves "unknown" and avoids spurious D2
        ol_no_reason = _make_doc(
            dialect="ollama-ndjson",
            raw_frames=[(None, json.dumps({"message": {"content": ""}, "done": True, "eval_count": 0}), "{}\n", 5.0)],
        )
        self.assertEqual(ol_no_reason.summary.assembled["finish_reason"], "unknown")
        self.assertEqual(audit_trace(ol_no_reason), [])

    def test_p1_effective_params_precedence_and_empty_stop_filter(self):
        eff = extract_effective_params(
            {
                "max_tokens": 100,
                "stop": ["OUTER"],
                "extra_request_body": {"max_output_tokens": 256, "stop": []},
            },
            "openai-responses",
        )
        self.assertEqual(eff["max_budget_tokens"], 256)
        self.assertEqual(eff["stop_conditions"], [])  # Explicit empty override wins!

        # List containing only "" must NOT disable D3
        bad_d3 = _make_chat_doc(chunks=["Hi"], finish_reason="length", completion_tokens=2, ignore_eos=True, max_tokens=100, stop=[""])
        self.assertEqual([f.detector_id for f in audit_trace(bad_d3)], [D3])

    def test_p1_ttft_excludes_tool_name_only_and_d5_no_20ms_floor_or_unknown_cache_fp(self):
        # Tool name-only frame at 10ms, first args delta at 50ms -> ttft_effective_ms must be 50.0 (not 10.0)
        tool_ttft = _make_doc(
            dialect="openai-chat",
            raw_frames=[
                (None, json.dumps({"choices": [{"index": 0, "delta": {"tool_calls": [{"index": 0, "id": "c1", "function": {"name": "fn", "arguments": ""}}]}}]}), "data: ...\n\n", 10.0),
                (None, json.dumps({"choices": [{"index": 0, "delta": {"tool_calls": [{"index": 0, "function": {"arguments": '{"a":1}'}}]}}]}), "data: ...\n\n", 40.0),
                (None, json.dumps({"choices": [{"index": 0, "delta": {}, "finish_reason": "tool_calls"}]}), "data: ...\n\n", 10.0),
                (None, "[DONE]", "data: [DONE]\n\n", 5.0),
            ],
        )
        self.assertEqual(tool_ttft.summary.timing["ttff_ms"], 10.0)
        self.assertEqual(tool_ttft.summary.timing["ttft_effective_ms"], 50.0)

        # Sub-20ms TTFT +100% regression (10ms -> 20ms) is NOT suppressed
        fast = _make_chat_doc(chunks=["ok"], frame_dt_ms=10.0)
        slow = _make_chat_doc(chunks=["ok"], frame_dt_ms=20.0)
        rep_reg = diff_traces(fast, slow, fail_on="p1")
        self.assertTrue(rep_reg.ttft_regressed)
        self.assertEqual(rep_reg.exit_code, EXIT_SEMANTIC_REGRESSION)

        # D5a must NOT fire when both cached_tokens == "unknown"
        unk_a = _make_chat_doc(chunks=["ok"], frame_dt_ms=200.0)
        unk_b = _make_chat_doc(chunks=["ok"], frame_dt_ms=20.0)
        rep_unk = diff_traces(unk_a, unk_b, fail_on="p1")
        self.assertEqual(rep_unk.pair_findings, [])

        # D5a DOES fire on sub-20ms speedup when reported cached_tokens jumps
        c_cold = _make_chat_doc(chunks=["ok"], cached_tokens=0, frame_dt_ms=18.0)
        c_warm = _make_chat_doc(chunks=["ok"], cached_tokens=512, frame_dt_ms=4.0)
        rep_c = diff_traces(c_cold, c_warm, fail_on="p1")
        self.assertEqual([f.detector_id for f in rep_c.pair_findings], [D5])

    def test_p1_cli_validation_jsonl_suite_and_p2_terminal_banner_and_issue_budget(self):
        with tempfile.TemporaryDirectory() as td:
            td_p = Path(td)
            # Invalid trace missing request / string boolean eof_clean -> TraceSchemaError (exit 1)
            bad_tr = td_p / "bad.trace.jsonl"
            bad_tr.write_text(
                '{"type":"header","schema_version":"inferdiff.trace.v1","trace_id":"t","recorded_at_utc":"z","dialect":"openai-chat","response_meta":{"status_code":200}}\n'
                '{"type":"summary","eof_clean":"false","total_frames":0,"timing":{},"assembled":{}}\n',
                encoding="utf-8",
            )
            with self.assertRaises(TraceSchemaError):
                load_trace(bad_tr)
            self.assertEqual(cli_main(["audit", str(bad_tr)]), EXIT_USAGE_OR_IO_ERROR)

            # audit --only D9 / D5 / "" -> exit 1!
            good_tr = td_p / "good.trace.jsonl"
            write_trace(good_tr, _make_chat_doc(chunks=["hi"]))
            for bad_only in ("D9", "D5", "", ","):
                err_buf = io.StringIO()
                with redirect_stderr(err_buf):
                    rc = cli_main(["audit", str(good_tr), "--only", bad_only])
                self.assertEqual(rc, EXIT_USAGE_OR_IO_ERROR)

            # JSONL request suite in `record` writes distinct traces
            def handle(req: http.server.BaseHTTPRequestHandler):
                b = b'data: {"choices":[{"index":0,"delta":{"content":"ok"},"finish_reason":"stop"}]}\n\ndata: [DONE]\n\n'
                req.send_response(200)
                req.send_header("Content-Type", "text/event-stream")
                req.send_header("Content-Length", str(len(b)))
                req.end_headers()
                req.wfile.write(b)

            srv, port, cap_hdrs = _run_mock_server(handle)
            try:
                suite = td_p / "suite.jsonl"
                suite.write_text(
                    '{"model":"m","messages":[{"role":"user","content":"1"}]}\n'
                    '{"model":"m","messages":[{"role":"user","content":"2"}]}\n',
                    encoding="utf-8",
                )
                out_base = td_p / "run.trace.jsonl"
                out_buf = io.StringIO()
                with redirect_stdout(out_buf):
                    rc = cli_main(["record", "--url", f"http://127.0.0.1:{port}/v1/chat/completions", "-d", str(suite), "-o", str(out_base), "--no-color"])
                self.assertEqual(rc, EXIT_OK)
                self.assertTrue((td_p / "run_001.trace.jsonl").exists())
                self.assertTrue((td_p / "run_002.trace.jsonl").exists())

                # compare with scoped --before-header and --after-header
                cap_hdrs.clear()
                req1 = td_p / "single.json"
                req1.write_text('{"model":"m","messages":[{"role":"user","content":"hi"}]}', encoding="utf-8")
                with redirect_stdout(io.StringIO()):
                    rc_cmp = cli_main([
                        "compare",
                        "--before-url", f"http://127.0.0.1:{port}/v1/chat/completions",
                        "--after-url", f"http://127.0.0.1:{port}/v1/chat/completions",
                        "-d", str(req1),
                        "--before-header", "Authorization: Bearer BEFORE_ONLY",
                        "--after-header", "Authorization: Bearer AFTER_ONLY",
                        "--ignore-timing",
                        "--no-color",
                    ])
                self.assertEqual(rc_cmp, EXIT_OK)
                self.assertEqual(cap_hdrs[0].get("Authorization"), "Bearer BEFORE_ONLY")
                self.assertEqual(cap_hdrs[1].get("Authorization"), "Bearer AFTER_ONLY")
            finally:
                srv.shutdown()
                srv.server_close()

        # P2: Multiline terminal reason must NOT exceed 25 physical lines
        ml_doc = _make_chat_doc(chunks=["hi"], finish_reason="line1\n" * 30)
        md_ml = render_github_issue(ml_doc, None, audit_findings=[])
        self.assertLessEqual(len(md_ml.splitlines()), MAX_ISSUE_LINES)
        self.assertEqual(sum(1 for l in md_ml.splitlines() if l.startswith("```")) % 2, 0)

        # P2: Terminal must NOT print PASS when exit_code == 3 (--fail-on any-diff content change)
        d_a = _make_chat_doc(chunks=["hello"])
        d_b = _make_chat_doc(chunks=["world"])
        rep_c = diff_traces(d_a, d_b, ignore_timing=True, fail_on="any-diff")
        self.assertEqual(rep_c.exit_code, EXIT_SEMANTIC_REGRESSION)
        term_out = render_diff_terminal(rep_c, no_color=True)
        self.assertIn("FAIL (exit 3)", term_out)
        self.assertNotIn("  PASS", term_out)

    def test_bundled_examples_and_25_line_export_contract(self):
        root = Path(__file__).resolve().parents[1] / "examples"
        if not (root / "case1_responses_truncated_tool" / "baseline.trace.jsonl").exists():
            self.skipTest("Examples not generated yet")

        b1 = load_trace(root / "case1_responses_truncated_tool" / "baseline.trace.jsonl")
        a1 = load_trace(root / "case1_responses_truncated_tool" / "target.trace.jsonl")
        r1 = diff_traces(b1, a1, fail_on="p0")
        self.assertEqual(r1.exit_code, EXIT_SILENT_PROTOCOL_BREACH)
        self.assertIn(D1, [f.detector_id for f in r1.after_findings])
        self.assertTrue(r1.terminal_drifted)
        md1 = render_github_issue(b1, a1, diff_report=r1)
        self.assertLessEqual(len(md1.splitlines()), MAX_ISSUE_LINES)
        self.assertIn("D1:UNCLOSED_TOOL_CALL_SUCCESS", md1)

        b2 = load_trace(root / "case2_ollama_ghost_thinking_tokens" / "baseline.trace.jsonl")
        a2 = load_trace(root / "case2_ollama_ghost_thinking_tokens" / "target.trace.jsonl")
        r2 = diff_traces(b2, a2, fail_on="p0")
        self.assertEqual(r2.exit_code, EXIT_SILENT_PROTOCOL_BREACH)
        self.assertIn(D2, [f.detector_id for f in r2.after_findings])
        md2 = render_github_issue(b2, a2, diff_report=r2)
        self.assertLessEqual(len(md2.splitlines()), MAX_ISSUE_LINES)

        b3 = load_trace(root / "case3_sglang_8_of_8000_short_gen" / "baseline.trace.jsonl")
        a3 = load_trace(root / "case3_sglang_8_of_8000_short_gen" / "target.trace.jsonl")
        r3 = diff_traces(b3, a3, fail_on="p1")
        self.assertEqual(r3.exit_code, EXIT_SEMANTIC_REGRESSION)
        ids3 = [f.detector_id for f in (r3.after_findings + r3.pair_findings)]
        self.assertIn(D3, ids3)
        self.assertIn(D5, ids3)
        md3 = render_github_issue(b3, a3, diff_report=r3)
        self.assertLessEqual(len(md3.splitlines()), MAX_ISSUE_LINES)

    def test_chunk_jitter_invariance_and_exact_frame_back_mapping_and_chronological_order(self):
        # Jitter invariance
        before = _make_chat_doc(chunks=["Hel", "lo ", "world!"], label="v1")
        after = _make_chat_doc(chunks=["Hello world!"], label="v2")
        rep_eq = diff_traces(before, after, ignore_timing=True, fail_on="any-diff")
        self.assertTrue(rep_eq.semantic_equal)
        self.assertIsNone(rep_eq.first_divergence)
        self.assertEqual(rep_eq.exit_code, EXIT_OK)

        # Exact physical frame back-mapping
        after_diff = _make_chat_doc(chunks=["Hello ", "earth!"], label="v2")
        rep_d = diff_traces(before, after_diff, ignore_timing=True, fail_on="any-diff")
        self.assertEqual(rep_d.first_divergence.category, "CONTENT")
        self.assertEqual(rep_d.first_divergence.before_seq, 2)
        self.assertEqual(rep_d.first_divergence.after_seq, 1)

        # Chronological ordering: earlier tool name change (frame #0) must precede later content change (frame #1)
        t_a = _make_doc(
            dialect="openai-chat",
            raw_frames=[
                (None, json.dumps({"choices": [{"index": 0, "delta": {"tool_calls": [{"index": 0, "id": "c1", "function": {"name": "tool_a", "arguments": '{"k":1}'}}]}}]}), "data: a\n\n", 5.0),
                (None, json.dumps({"choices": [{"index": 0, "delta": {"content": "hello"}}]}), "data: c1\n\n", 5.0),
                (None, json.dumps({"choices": [{"index": 0, "delta": {}, "finish_reason": "tool_calls"}]}), "data: fin\n\n", 5.0),
                (None, "[DONE]", "data: [DONE]\n\n", 5.0),
            ],
        )
        t_b = _make_doc(
            dialect="openai-chat",
            raw_frames=[
                (None, json.dumps({"choices": [{"index": 0, "delta": {"tool_calls": [{"index": 0, "id": "c1", "function": {"name": "tool_b", "arguments": '{"k":1}'}}]}}]}), "data: b\n\n", 5.0),
                (None, json.dumps({"choices": [{"index": 0, "delta": {"content": "world"}}]}), "data: c2\n\n", 5.0),
                (None, json.dumps({"choices": [{"index": 0, "delta": {}, "finish_reason": "tool_calls"}]}), "data: fin\n\n", 5.0),
                (None, "[DONE]", "data: [DONE]\n\n", 5.0),
            ],
        )
        rep_ord = diff_traces(t_a, t_b, ignore_timing=True, fail_on="any-diff")
        self.assertEqual(rep_ord.first_divergence.category, "TOOL_CALL")
        self.assertEqual(rep_ord.first_divergence.before_seq, 0)
        self.assertEqual(rep_ord.first_divergence.after_seq, 0)

    def test_d5c_requires_consecutive_burst_intervals(self):
        # Scattered single sub-0.5ms intervals separated by 40ms must NOT trigger D5c
        base = _make_chat_doc(chunks=["a", "b", "c", "d", "e", "f"], frame_dt_ms=50.0)
        raw_scattered = [
            (None, json.dumps({"choices": [{"index": 0, "delta": {"content": "ab"}}]}), "data: 1\n\n", 10.0),
            (None, json.dumps({"choices": [{"index": 0, "delta": {"content": "cd"}}]}), "data: 2\n\n", 0.1),  # run=1
            (None, json.dumps({"choices": [{"index": 0, "delta": {"content": "ef"}}]}), "data: 3\n\n", 10.0),  # breaks run!
            (None, json.dumps({"choices": [{"index": 0, "delta": {"content": "gh"}}]}), "data: 4\n\n", 0.1),  # run=1
            (None, json.dumps({"choices": [{"index": 0, "delta": {}, "finish_reason": "stop"}]}), "data: fin\n\n", 1.0),
            (None, "[DONE]", "data: [DONE]\n\n", 1.0),
        ]
        scattered = _make_doc(dialect="openai-chat", raw_frames=raw_scattered)
        rep_scat = diff_traces(base, scattered, fail_on="p1")
        self.assertEqual(rep_scat.pair_findings, [])

        # Two consecutive sub-0.5ms intervals with >=2x bytes/frame DOES trigger D5c!
        raw_burst = [
            (None, json.dumps({"choices": [{"index": 0, "delta": {"content": "abcdef"}}]}), "data: 1\n\n", 10.0),
            (None, json.dumps({"choices": [{"index": 0, "delta": {"content": "ghijkl"}}]}), "data: 2\n\n", 0.1),
            (None, json.dumps({"choices": [{"index": 0, "delta": {"content": "mnopqr"}}]}), "data: 3\n\n", 0.1),
            (None, json.dumps({"choices": [{"index": 0, "delta": {}, "finish_reason": "stop"}]}), "data: fin\n\n", 1.0),
            (None, "[DONE]", "data: [DONE]\n\n", 1.0),
        ]
        burst = _make_doc(dialect="openai-chat", raw_frames=raw_burst)
        rep_burst = diff_traces(base, burst, fail_on="p1")
        self.assertEqual([f.detector_id for f in rep_burst.pair_findings], [D5])

    def test_live_split_utf8_and_include_usage_and_midstream_drop(self):
        def handle_ok(req: http.server.BaseHTTPRequestHandler):
            req.send_response(200)
            req.send_header("Content-Type", "text/event-stream; charset=utf-8")
            req.send_header("Connection", "close")
            req.end_headers()
            req.wfile.write(b'data: {"choices":[{"index":0,"delta":{"role":"assistant","content":""}}]}\n\n')
            req.wfile.flush()
            time.sleep(0.03)
            p = 'data: {"choices":[{"index":0,"delta":{"content":"你好"}}]}\r\n\r\n'.encode("utf-8")
            req.wfile.write(p[:48])
            req.wfile.flush()
            time.sleep(0.01)
            req.wfile.write(p[48:])
            req.wfile.write(b'data: {"choices":[{"index":0,"delta":{},"finish_reason":"stop"}]}\n\n')
            req.wfile.write(b'data: {"choices":[],"usage":{"prompt_tokens":12,"completion_tokens":4}}\n\n')
            req.wfile.write(b"data: [DONE]\n\n")
            req.wfile.flush()

        srv, port, _ = _run_mock_server(handle_ok)
        try:
            with tempfile.TemporaryDirectory() as td:
                out_file = Path(td) / "chat.trace.jsonl"
                doc = record_stream(
                    url=f"http://127.0.0.1:{port}/v1/chat/completions",
                    request_body={"model": "m1", "messages": [{"role": "user", "content": "hi"}]},
                    headers={"Authorization": "Bearer secret-abc-123"},
                    out_path=out_file,
                )
                self.assertTrue(doc.summary.eof_clean)
                self.assertEqual(doc.summary.assembled["content_text"], "你好")
                self.assertTrue(doc.summary.assembled["saw_textless_usage_frame"])
                self.assertLess(doc.summary.timing["ttff_ms"], doc.summary.timing["ttft_effective_ms"])
                self.assertNotIn("secret-abc-123", out_file.read_text(encoding="utf-8"))
                self.assertEqual(audit_trace(load_trace(out_file)), [])
        finally:
            srv.shutdown()
            srv.server_close()

    def test_codex_signoff_edge_cases_all_closed(self):
        # 1) Offline filename with backtick & >80 chars must NOT be mangled or truncated in markdown export
        long_fname = "dir/" + ("a" * 90) + "`name|pipe.trace.jsonl"
        doc_fn = _make_chat_doc(chunks=["ok"])
        md_fn = render_github_issue(doc_fn, None, audit_findings=[], before_path=long_fname)
        self.assertIn(f"'{long_fname}'", md_fn)
        self.assertLessEqual(len(md_fn.splitlines()), MAX_ISSUE_LINES)

        # 2) Arbitrary string inside nested extra_request_body & imported raw header secret must NOT leak
        doc_sec = _make_chat_doc(
            chunks=["ok"],
            extra_body={"extra_request_body": {"custom_secret": "NESTED_ARBITRARY_SECRET_123"}},
        )
        doc_sec.header.request["headers_redacted"]["authorization"] = "Bearer IMPORTED_RAW_TOKEN_999"
        doc_sec.header.request["extra_imported_field"] = "IMPORTED_EXTRA_LEAK_777"
        md_sec = render_github_issue(doc_sec, None, audit_findings=[])
        self.assertNotIn("NESTED_ARBITRARY_SECRET_123", md_sec)
        with tempfile.TemporaryDirectory() as td:
            p = Path(td) / "imp.trace.jsonl"
            write_trace(p, doc_sec)
            buf = io.StringIO()
            with redirect_stdout(buf):
                rc = cli_main(["export", str(p), "--format", "json"])
            self.assertEqual(rc, EXIT_OK)
            out_j = buf.getvalue()
            self.assertNotIn("IMPORTED_RAW_TOKEN_999", out_j)
            self.assertNotIn("IMPORTED_EXTRA_LEAK_777", out_j)
            self.assertNotIn("NESTED_ARBITRARY_SECRET_123", out_j)

        # 3) Chat content AFTER finish_reason fails eof_clean & D4
        post_fin = _make_doc(
            dialect="openai-chat",
            raw_frames=[
                (None, json.dumps({"choices": [{"index": 0, "delta": {"content": "a"}, "finish_reason": "stop"}]}), "data: 1\n\n", 5.0),
                (None, json.dumps({"choices": [{"index": 0, "delta": {"content": "late"}}]}), "data: 2\n\n", 5.0),
                (None, "[DONE]", "data: [DONE]\n\n", 5.0),
            ],
        )
        self.assertFalse(post_fin.summary.eof_clean)
        self.assertIn(D4, [f.detector_id for f in audit_trace(post_fin)])

        # 4) Responses terminal with missing status fails D4
        no_stat = _make_doc(
            dialect="openai-responses",
            raw_frames=[
                ("response.completed", json.dumps({"type": "response.completed", "response": {}}), "data: ...\n\n", 5.0),
            ],
        )
        self.assertFalse(no_stat.summary.eof_clean)
        self.assertIn(D4, [f.detector_id for f in audit_trace(no_stat)])

        # 5) Valid Responses output_item.added(arguments="") + delta + arguments.done must NOT trigger D1
        valid_resp = _make_doc(
            dialect="openai-responses",
            raw_frames=[
                ("response.output_item.added", json.dumps({"type": "response.output_item.added", "output_index": 0, "item": {"type": "function_call", "id": "fc1", "call_id": "c1", "name": "fn", "arguments": ""}}), "data: 1\n\n", 10.0),
                ("response.function_call_arguments.delta", json.dumps({"type": "response.function_call_arguments.delta", "output_index": 0, "item_id": "fc1", "delta": '{"a":1}'}), "data: 2\n\n", 40.0),
                ("response.function_call_arguments.done", json.dumps({"type": "response.function_call_arguments.done", "output_index": 0, "item_id": "fc1", "arguments": '{"a":1}'}), "data: 3\n\n", 5.0),
                ("response.completed", json.dumps({"type": "response.completed", "response": {"status": "completed"}}), "data: 4\n\n", 5.0),
            ],
        )
        self.assertEqual(audit_trace(valid_resp), [])
        self.assertEqual(valid_resp.summary.timing["ttft_effective_ms"], 50.0)

        # 6) Known item_id reusing another call's output_index flags identity_conflict -> D1
        known_reuse = _make_doc(
            dialect="openai-responses",
            raw_frames=[
                ("response.output_item.added", json.dumps({"type": "response.output_item.added", "output_index": 0, "item": {"type": "function_call", "id": "fc1", "call_id": "c1", "name": "f1"}}), "data: 1\n\n", 5.0),
                ("response.output_item.added", json.dumps({"type": "response.output_item.added", "output_index": 1, "item": {"type": "function_call", "id": "fc2", "call_id": "c2", "name": "f2"}}), "data: 2\n\n", 5.0),
                ("response.function_call_arguments.delta", json.dumps({"type": "response.function_call_arguments.delta", "output_index": 1, "item_id": "fc1", "delta": '{"x":1}'}), "data: 3\n\n", 5.0),
                ("response.function_call_arguments.done", json.dumps({"type": "response.function_call_arguments.done", "output_index": 0, "item_id": "fc1", "arguments": '{"x":1}'}), "data: 4\n\n", 5.0),
                ("response.function_call_arguments.done", json.dumps({"type": "response.function_call_arguments.done", "output_index": 1, "item_id": "fc2", "arguments": '{"y":2}'}), "data: 5\n\n", 5.0),
                ("response.completed", json.dumps({"type": "response.completed", "response": {"status": "completed"}}), "data: 6\n\n", 5.0),
            ],
        )
        self.assertIn(D1, [f.detector_id for f in audit_trace(known_reuse)])

        # 7) Mixed inline <think> + dedicated reasoning_delta in chronological order == pure dedicated reasoning
        mixed_doc = _make_doc(
            dialect="openai-chat",
            raw_frames=[
                (None, json.dumps({"choices": [{"index": 0, "delta": {"content": "<think>part1</think>"}}]}), "data: 1\n\n", 5.0),
                (None, json.dumps({"choices": [{"index": 0, "delta": {"reasoning_content": "part2"}}]}), "data: 2\n\n", 5.0),
                (None, json.dumps({"choices": [{"index": 0, "delta": {"content": "ans"}, "finish_reason": "stop"}]}), "data: 3\n\n", 5.0),
                (None, "[DONE]", "data: [DONE]\n\n", 5.0),
            ],
        )
        pure_doc = _make_chat_doc(chunks=["ans"], reasoning_chunks=["part1part2"])
        rep_mix = diff_traces(mixed_doc, pure_doc, ignore_timing=True, fail_on="any-diff")
        self.assertTrue(rep_mix.semantic_equal)
        self.assertEqual(rep_mix.exit_code, EXIT_OK)

        # 8) JSON true vs 1 in tool arguments must diverge under --fail-on any-diff!
        t_true = _make_doc(
            dialect="openai-chat",
            raw_frames=[
                (None, json.dumps({"choices": [{"index": 0, "delta": {"tool_calls": [{"index": 0, "id": "c1", "function": {"name": "f", "arguments": '{"flag":true}'}}]}}]}), "data: 1\n\n", 5.0),
                (None, json.dumps({"choices": [{"index": 0, "delta": {}, "finish_reason": "tool_calls"}]}), "data: 2\n\n", 5.0),
                (None, "[DONE]", "data: [DONE]\n\n", 5.0),
            ],
        )
        t_one = _make_doc(
            dialect="openai-chat",
            raw_frames=[
                (None, json.dumps({"choices": [{"index": 0, "delta": {"tool_calls": [{"index": 0, "id": "c1", "function": {"name": "f", "arguments": '{"flag":1}'}}]}}]}), "data: 1\n\n", 5.0),
                (None, json.dumps({"choices": [{"index": 0, "delta": {}, "finish_reason": "tool_calls"}]}), "data: 2\n\n", 5.0),
                (None, "[DONE]", "data: [DONE]\n\n", 5.0),
            ],
        )
        rep_bool = diff_traces(t_true, t_one, ignore_timing=True, fail_on="any-diff")
        self.assertFalse(rep_bool.semantic_equal)
        self.assertEqual(rep_bool.exit_code, EXIT_SEMANTIC_REGRESSION)

        # 9) Unrelated reported stop_reason must NOT suppress D2; nested stop: null clears outer stop for D3
        unrel_stop = _make_chat_doc(chunks=[], finish_reason="stop", stop_reason="UNRELATED", completion_tokens=2, stop=["END"])
        self.assertEqual([f.detector_id for f in audit_trace(unrel_stop)], [D2])
        eff_null = extract_effective_params({"stop": ["OUTER"], "extra_request_body": {"stop": None}}, "openai-chat")
        self.assertEqual(eff_null["stop_conditions"], [])

        # 10) D5c must NOT count a burst across intervening 100ms non-text frames
        base_d5 = _make_chat_doc(chunks=["a", "b", "c", "d", "e", "f"], frame_dt_ms=50.0)
        gapped = _make_doc(
            dialect="openai-chat",
            raw_frames=[
                (None, json.dumps({"choices": [{"index": 0, "delta": {"content": "abcdef"}}]}), "data: 1\n\n", 10.0),
                (None, json.dumps({"choices": [{"index": 0, "delta": {}}]}), "data: k1\n\n", 100.0),
                (None, json.dumps({"choices": [{"index": 0, "delta": {"content": "ghijkl"}}]}), "data: 2\n\n", 0.1),
                (None, json.dumps({"choices": [{"index": 0, "delta": {}}]}), "data: k2\n\n", 100.0),
                (None, json.dumps({"choices": [{"index": 0, "delta": {"content": "mnopqr"}}]}), "data: 3\n\n", 0.1),
                (None, json.dumps({"choices": [{"index": 0, "delta": {}, "finish_reason": "stop"}]}), "data: fin\n\n", 1.0),
                (None, "[DONE]", "data: [DONE]\n\n", 1.0),
            ],
        )
        self.assertEqual(diff_traces(base_d5, gapped, fail_on="p1").pair_findings, [])

        # 11) Oversized timing int (>float max) & non-dict tool_calls item raise TraceSchemaError (exit 1)
        with tempfile.TemporaryDirectory() as td:
            bad_ovf = Path(td) / "ovf.trace.jsonl"
            big_int = "9" * 400
            bad_ovf.write_text(
                '{"type":"header","schema_version":"inferdiff.trace.v1","trace_id":"t","recorded_at_utc":"z","dialect":"openai-chat","request":{"method":"POST","url":"http://127.0.0.1/v1"},"response_meta":{"status_code":200}}\n'
                f'{{"type":"summary","eof_clean":true,"total_frames":0,"timing":{{"total_ms":{big_int}}},"assembled":{{"tool_calls":["bad"]}}}}\n',
                encoding="utf-8",
            )
            with self.assertRaises(TraceSchemaError):
                load_trace(bad_ovf)
            with redirect_stderr(io.StringIO()):
                self.assertEqual(cli_main(["audit", str(bad_ovf)]), EXIT_USAGE_OR_IO_ERROR)


if __name__ == "__main__":
    unittest.main()
