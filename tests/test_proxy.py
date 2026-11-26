"""Exercise the proxy against a real loopback HTTP upstream and client."""

from __future__ import annotations

import gzip
import http.client
import http.server
import io
import json
import tempfile
import threading
import time
import unittest
from contextlib import contextmanager, redirect_stderr, redirect_stdout
from pathlib import Path
from urllib.parse import urlsplit

from inferdiff.cli import main
from inferdiff.schema import strict_json_loads


CHAT_PATH = "/v1/chat/completions"
BODY = b'{"model":"proxy-model","stream":true}'
FIRST = b'data: {"choices":[{"index":0,"delta":{"content":"hello"}}]}\r\n\r\n'
TERMINAL = b'data: {"choices":[{"index":0,"delta":{},"finish_reason":"stop"}]}\r\n\r\ndata: [DONE]\r\n\r\n'


def _breach(tool_name="lookup"):
    call = {"index": 0, "id": "call_1", "type": "function",
            "function": {"name": tool_name, "arguments": '{"city":'}}
    payload = {"choices": [{"index": 0, "delta": {"tool_calls": [call]}}]}
    return b"data: " + json.dumps(payload).encode("ascii") + b"\n\n" + TERMINAL


@contextmanager
def _running(server):
    with server:
        thread = threading.Thread(target=server.serve_forever, kwargs={"poll_interval": 0.01}, daemon=True)
        thread.start()
        try:
            yield server.server_port, thread
        finally:
            server.shutdown()
            thread.join(timeout=5)


@contextmanager
def _upstream(respond):
    requests = []

    class Handler(http.server.BaseHTTPRequestHandler):
        protocol_version = "HTTP/1.1"

        def log_message(self, format, *args):
            pass

        def do_request(self):
            body = self.rfile.read(int(self.headers.get("Content-Length", "0")))
            requests.append((self.command, self.path, dict(self.headers.items()), body))
            respond(self)

        do_GET = do_POST = do_OPTIONS = do_PATCH = do_request

    with _running(http.server.ThreadingHTTPServer(("127.0.0.1", 0), Handler)) as (port, _):
        yield f"http://127.0.0.1:{port}", requests


@contextmanager
def _proxy(upstream, **options):
    from inferdiff.proxy import create_proxy_server

    with _running(create_proxy_server(upstream, port=0, no_color=True, **options)) as running:
        yield running


@contextmanager
def _response(port, method, path, *, body=None, headers=None):
    client = http.client.HTTPConnection("127.0.0.1", port, timeout=3)
    try:
        client.request(method, path, body=body, headers=headers or {})
        with client.getresponse() as response:
            yield response
    finally:
        client.close()


def _reply(handler, body, *, status=200, content_type="text/event-stream", headers=()):
    handler.send_response(status)
    handler.send_header("Content-Type", content_type)
    handler.send_header("Content-Length", str(len(body)))
    for name, value in headers:
        handler.send_header(name, value)
    handler.end_headers()
    handler.wfile.write(body)


class TestProxy(unittest.TestCase):
    def status(self, port, *, events):
        deadline = time.monotonic() + 3
        while True:
            with _response(port, "GET", "/_inferdiff/status") as response:
                self.assertEqual(response.status, 200)
                self.assertEqual(response.headers.get_content_type(), "application/json")
                raw = response.read().decode("utf-8")
            status = strict_json_loads(raw)
            if len(status["recent_events"]) >= events:
                return status, raw
            if time.monotonic() >= deadline:
                self.fail(f"Proxy status never recorded {events} completed requests")
            time.sleep(0.01)

    def test_first_sse_chunk_reaches_client_before_upstream_releases_second(self):
        for chunked in (False, True):
            with self.subTest(chunked=chunked):
                release = threading.Event()

                def respond(handler):
                    handler.send_response(200)
                    handler.send_header("Content-Type", "text/event-stream")
                    if chunked:
                        handler.send_header("Transfer-Encoding", "chunked")
                    else:
                        handler.send_header("Content-Length", str(len(FIRST) + len(TERMINAL)))
                    handler.end_headers()

                    def write(data):
                        if chunked:
                            data = f"{len(data):X}\r\n".encode("ascii") + data + b"\r\n"
                        handler.wfile.write(data)
                        handler.wfile.flush()

                    try:
                        write(FIRST)
                        if release.wait(timeout=8):
                            write(TERMINAL)
                            if chunked:
                                handler.wfile.write(b"0\r\n\r\n")
                    except (BrokenPipeError, ConnectionResetError):
                        pass

                with _upstream(respond) as (origin, _), _proxy(origin) as (port, _):
                    try:
                        with _response(port, "POST", CHAT_PATH, body=BODY) as response:
                            self.assertEqual(response.status, 200)
                            self.assertEqual(response.read(len(FIRST)), FIRST)
                            self.assertFalse(release.is_set())
                            release.set()
                            self.assertEqual(response.read(), TERMINAL)
                    finally:
                        release.set()
                    status, _ = self.status(port, events=1)
                    self.assertEqual(status["streaming_requests"], 1)
                    event = status["recent_events"][0]
                    self.assertGreaterEqual(event["ttft_ms"], 0)
                    self.assertGreaterEqual(event["total_ms"], event["ttft_ms"])

    def test_live_breach_forwards_original_bytes_and_saves_auditable_trace(self):
        wire = _breach()
        with tempfile.TemporaryDirectory() as tmp, _upstream(lambda h: _reply(h, wire)) as (origin, _):
            with _proxy(origin, save_dir=Path(tmp)) as (port, _):
                with _response(port, "POST", CHAT_PATH, body=BODY) as response:
                    self.assertEqual(response.read(), wire)
                summary, _ = self.status(port, events=1)

            self.assertEqual(summary["requests_total"], 1)
            self.assertEqual(summary["streaming_requests"], 1)
            self.assertGreaterEqual(summary["p0_breaches"], 1)
            self.assertEqual(summary["p1_warnings"], 0)
            event = summary["recent_events"][0]
            self.assertEqual((event["method"], event["path"], event["status"]), ("POST", CHAT_PATH, 200))
            self.assertGreaterEqual(event["findings_count"], 1)

            traces = list(Path(tmp).glob("*.trace.jsonl"))
            self.assertEqual(len(traces), 1)
            stdout = io.StringIO()
            with redirect_stdout(stdout):
                rc = main(["audit", str(traces[0]), "--only", "D1", "--json"])
            self.assertNotEqual(rc, 0)
            findings = strict_json_loads(stdout.getvalue())["findings"]
            self.assertIn(("D1", "P0"), [(f["detector_id"], f["severity"]) for f in findings])

    def test_truncated_transport_is_reported_even_after_terminal_frames(self):
        wire = FIRST + TERMINAL

        def respond(handler):
            handler.send_response(200)
            handler.send_header("Content-Type", "text/event-stream")
            handler.send_header("Content-Length", str(len(wire) + 16))
            handler.send_header("Connection", "close")
            handler.end_headers()
            handler.wfile.write(wire)

        logs = io.StringIO()
        with redirect_stdout(logs), _upstream(respond) as (origin, _), _proxy(origin) as (port, _):
            with _response(port, "POST", CHAT_PATH, body=BODY) as response:
                with self.assertRaises(http.client.IncompleteRead) as incomplete:
                    response.read()
                self.assertEqual(incomplete.exception.partial, wire)
            status, _ = self.status(port, events=1)

        self.assertGreaterEqual(status["p0_breaches"], 1)
        self.assertIn("D4", logs.getvalue())

    def test_gzip_stream_remains_compressed_on_wire_and_saves_auditable_trace(self):
        compressed = gzip.compress(_breach())
        with tempfile.TemporaryDirectory() as tmp, _upstream(
            lambda h: _reply(h, compressed, headers=(("Content-Encoding", "gzip"),))
        ) as (origin, _), _proxy(origin, save_dir=Path(tmp)) as (port, _):
            with _response(port, "POST", CHAT_PATH, body=BODY) as response:
                self.assertEqual(response.headers["Content-Encoding"], "gzip")
                self.assertEqual(response.read(), compressed)
            summary, _ = self.status(port, events=1)
            self.assertGreaterEqual(summary["p0_breaches"], 1)
            traces = list(Path(tmp).glob("*.trace.jsonl"))
            self.assertEqual(len(traces), 1)
            stdout = io.StringIO()
            with redirect_stdout(stdout):
                rc = main(["audit", str(traces[0]), "--only", "D1", "--json"])
            self.assertNotEqual(rc, 0)
            findings = strict_json_loads(stdout.getvalue())["findings"]
            self.assertIn(("D1", "P0"), [(f["detector_id"], f["severity"]) for f in findings])

    def test_only_breaches_saves_failing_stream_and_skips_honest_stream(self):
        wires = iter((FIRST + TERMINAL, _breach()))
        with tempfile.TemporaryDirectory() as tmp, _upstream(lambda h: _reply(h, next(wires))) as (origin, _):
            with _proxy(origin, save_dir=Path(tmp), only_breaches=True) as (port, _):
                with _response(port, "POST", CHAT_PATH, body=BODY) as response:
                    self.assertEqual(response.read(), FIRST + TERMINAL)
                status, _ = self.status(port, events=1)
                self.assertEqual(status["p0_breaches"], 0)
                self.assertEqual(status["p1_warnings"], 0)
                self.assertEqual(list(Path(tmp).glob("*.trace.jsonl")), [])
                with _response(port, "POST", CHAT_PATH, body=BODY) as response:
                    self.assertEqual(response.read(), _breach())
                self.status(port, events=2)
            self.assertEqual(len(list(Path(tmp).glob("*.trace.jsonl"))), 1)

    def test_non_streaming_response_preserves_status_body_and_end_to_end_headers(self):
        wire = b'{"object":"list","data":[{"id":"fixture-model"}]}'
        headers = (("X-Limit", "100"), ("X-Multi", "a"), ("X-Multi", "b"),
                   ("Connection", "X-Internal"), ("X-Internal", "strip-me"))
        with _upstream(lambda h: _reply(h, wire, status=202, content_type="application/json", headers=headers)) as (
            origin, requests
        ), _proxy(origin) as (port, _):
            with _response(port, "GET", "/v1/models", headers={"Connection": "X-Downstream", "X-Downstream": "skip",
                                                                 "X-Retained": "keep", "Host": "downstream.test"}) as response:
                self.assertEqual(response.status, 202)
                self.assertEqual(response.headers["Content-Type"], "application/json")
                self.assertEqual(response.headers["X-Limit"], "100")
                self.assertEqual(response.headers.get_all("X-Multi"), ["a", "b"])
                self.assertIsNone(response.headers["X-Internal"])
                self.assertEqual(response.read(), wire)
            status, _ = self.status(port, events=1)
        self.assertEqual(status["streaming_requests"], 0)
        method, path, outgoing, body = requests[0]
        self.assertEqual((method, path, body), ("GET", "/v1/models", b""))
        outgoing = {key.lower(): val for key, val in outgoing.items()}
        self.assertEqual(outgoing["host"], urlsplit(origin).netloc)
        self.assertEqual(outgoing["x-retained"], "keep")
        self.assertNotIn("x-downstream", outgoing)

    def test_chunked_json_models_response_passes_through_as_non_streaming(self):
        def respond(handler):
            handler.send_response(200)
            handler.send_header("Content-Type", "application/json")
            handler.send_header("Transfer-Encoding", "chunked")
            handler.end_headers()
            handler.wfile.write(b'7\r\n{"objec\r\nB\r\nt":"list"}\n\r\n0\r\n\r\n')

        with _upstream(respond) as (origin, _), _proxy(origin) as (port, _):
            with _response(port, "GET", "/v1/models") as response:
                self.assertEqual(response.status, 200)
                self.assertEqual(response.read(), b'{"object":"list"}\n')
            summary, _ = self.status(port, events=1)
        self.assertEqual(summary["streaming_requests"], 0)
        self.assertEqual(summary["recent_events"][0]["findings_count"], 0)

    def test_informational_upstream_response_does_not_hide_final_response(self):
        wire = b'{"object":"list","data":[]}'

        def respond(handler):
            handler.send_response_only(103)
            handler.send_header("Link", "</warmup>; rel=preload")
            handler.end_headers()
            _reply(handler, wire, content_type="application/json")

        with _upstream(respond) as (origin, _), _proxy(origin) as (port, _):
            with _response(port, "GET", "/v1/models") as response:
                self.assertEqual(response.status, 200)
                self.assertEqual(response.read(), wire)

    def test_credentials_are_forwarded_and_redacted_even_when_echoed_by_upstream(self):
        secrets = ("sk-proxy-secret-999", "private-vendor-alpha", "private-vendor-beta", "private-query-alpha",
                   "private-query-beta", "hidden-upstream-cookie")
        bearer, api_key, google_key, query_key, second_query_key, upstream_cookie = secrets
        path = f"{CHAT_PATH}?key={query_key}&unknown={second_query_key}"
        credentials = {"Authorization": f"Bearer {bearer}", "x-api-key": api_key, "x-goog-api-key": google_key}
        wire = _breach(" ".join(secrets))
        logs = io.StringIO()
        with tempfile.TemporaryDirectory() as tmp:
            with redirect_stdout(logs), redirect_stderr(logs), _upstream(
                lambda h: _reply(h, wire, headers=(("Set-Cookie", f"session={upstream_cookie}"),))
            ) as (origin, requests), _proxy(origin, save_dir=Path(tmp)) as (port, _):
                with _response(port, "POST", path, body=BODY, headers=credentials) as response:
                    self.assertEqual(response.headers["Set-Cookie"], f"session={upstream_cookie}")
                    self.assertEqual(response.read(), wire)
                status, status_raw = self.status(port, events=1)
            traces = list(Path(tmp).glob("*.trace.jsonl"))
            self.assertEqual(len(traces), 1)
            trace = traces[0].read_text(encoding="utf-8")

        self.assertEqual(len(requests), 1)
        method, sent_path, headers, sent_body = requests[0]
        self.assertEqual((method, sent_path, sent_body), ("POST", path, BODY))
        headers = {key.lower(): val for key, val in headers.items()}
        for name, value in credentials.items():
            self.assertEqual(headers[name.lower()], value)
        self.assertTrue(status["recent_events"][0]["path"].startswith(CHAT_PATH))
        self.assertIn("D1", logs.getvalue())
        self.assertIn(CHAT_PATH, logs.getvalue())
        for source, text in (("logs", logs.getvalue()), ("status", status_raw), ("trace", trace)):
            with self.subTest(source=source):
                for secret in secrets:
                    self.assertNotIn(secret, text)

    def test_upstream_url_credentials_in_tool_name_are_redacted(self):
        secret = "some-private-value"
        wire = _breach(f"https://provider.example/tool?opaque={secret}")
        logs = io.StringIO()
        with tempfile.TemporaryDirectory() as tmp, redirect_stdout(logs), redirect_stderr(logs), _upstream(
            lambda h: _reply(h, wire)
        ) as (origin, _), _proxy(origin, save_dir=Path(tmp)) as (port, _):
            with _response(port, "POST", CHAT_PATH, body=BODY) as response:
                self.assertEqual(response.read(), wire)
            _, status_raw = self.status(port, events=1)
            traces = list(Path(tmp).glob("*.trace.jsonl"))
            self.assertEqual(len(traces), 1)
            trace = traces[0].read_text(encoding="utf-8")
        for source, text in (("logs", logs.getvalue()), ("status", status_raw), ("trace", trace)):
            with self.subTest(source=source):
                self.assertNotIn(secret, text)

    def test_max_requests_stops_after_forwarding_and_excludes_status(self):
        with _upstream(lambda h: _reply(h, b"", status=204, content_type="application/json")) as (origin, requests):
            with _proxy(origin, max_requests=1) as (port, thread):
                summary, _ = self.status(port, events=0)
                self.assertEqual(summary["requests_total"], 0)
                with _response(port, "OPTIONS", "/v1/models") as response:
                    self.assertEqual(response.status, 204)
                    self.assertEqual(response.read(), b"")
                thread.join(timeout=3)
                self.assertFalse(thread.is_alive(), "Proxy did not stop after its request limit")
        self.assertEqual([(method, path) for method, path, _, _ in requests], [("OPTIONS", "/v1/models")])

    def test_invalid_upstream_is_rejected_without_printing_url_credentials(self):
        help_text = io.StringIO()
        with redirect_stdout(help_text), redirect_stderr(help_text):
            self.assertEqual(main(["proxy", "--help"]), 0)
        self.assertIn("--upstream", help_text.getvalue())
        for url in ("ftp://user:private-url-value@example.test", "http://", "http://example.test:bad"):
            with self.subTest(url=url):
                output = io.StringIO()
                with redirect_stdout(output), redirect_stderr(output):
                    rc = main(["proxy", "--upstream", url, "--port", "0"])
                self.assertNotEqual(rc, 0)
                self.assertNotIn("private-url-value", output.getvalue())
