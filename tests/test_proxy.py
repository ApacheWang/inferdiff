"""Exercise the proxy against a real loopback HTTP upstream and client."""

from __future__ import annotations

import gzip
import http.client
import http.server
import io
import json
import socket
import tempfile
import threading
import time
import unittest
from contextlib import closing, contextmanager, redirect_stderr, redirect_stdout
from pathlib import Path
from unittest.mock import patch
from urllib.parse import parse_qsl, quote, urlencode, urlsplit

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
            if self.headers.get("Transfer-Encoding") == "chunked":
                chunks = []
                while size := int(self.rfile.readline(), 16):
                    chunks.append(self.rfile.read(size))
                    self.rfile.readline()
                self.rfile.readline()
                body = b"".join(chunks)
            else:
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
def _response(port, method, path, *, body=None, headers=None, timeout=3):
    client = http.client.HTTPConnection("127.0.0.1", port, timeout=timeout)
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

    def test_dashboard_serves_static_html_on_both_routes_without_credentials(self):
        credentials = {
            "Authorization": "Bearer private-dashboard-bearer",
            "x-api-key": "private-dashboard-key",
            "x-goog-api-key": "private-dashboard-google-key",
        }
        query_secret = "private-dashboard-query-token"
        with _upstream(lambda h: _reply(h, FIRST + TERMINAL)) as (origin, requests), _proxy(origin) as (port, _):
            with _response(port, "POST", f"{CHAT_PATH}?key={query_secret}", body=BODY, headers=credentials) as response:
                self.assertEqual(response.read(), FIRST + TERMINAL)
            self.status(port, events=1)

            pages = []
            for route in ("/_inferdiff/", "/_inferdiff"):
                with _response(port, "GET", f"{route}?key={query_secret}", headers=credentials) as response:
                    html = response.read().decode("utf-8")
                    self.assertEqual(response.status, 200)
                    self.assertEqual(response.headers.get_content_type(), "text/html")
                    self.assertEqual(response.headers["Cache-Control"], "no-store")
                    csp = {directive.strip() for directive in response.headers["Content-Security-Policy"].split(";")
                           if directive.strip()}
                    self.assertTrue({"default-src 'none'", "style-src 'unsafe-inline'",
                                     "script-src 'unsafe-inline'", "connect-src 'self'"}.issubset(csp))
                self.assertIn("Copy Redacted Issue Report", html)
                self.assertIn("\u4e2d\u6587", html)
                self.assertNotRegex(html, r"(?i)(?:https?:)?//[\w.-]+\.[a-z]{2,}")
                for secret in (*credentials.values(), "private-dashboard-bearer", query_secret):
                    self.assertNotIn(secret, html)
                pages.append(html)
            self.assertEqual(pages[0], pages[1])
            status, _ = self.status(port, events=1)
            self.assertEqual(status["requests_total"], 1)
        self.assertEqual(len(requests), 1)

    def test_dashboard_event_contains_redacted_frames_findings_and_issue_markdown(self):
        bearer, api_key, google_key, query_key, response_key = (
            "odd-bearer-secret", "odd-api-secret", "odd-google-secret", "odd-query-secret", "odd-response-secret",
        )
        credentials = {"Authorization": f"Bearer {bearer}", "x-api-key": api_key, "x-goog-api-key": google_key}
        path = f"{CHAT_PATH}?key={query_key}"
        echo = f"Authorization: Bearer {bearer}\nx-api-key: {api_key}\nx-goog-api-key: {google_key}\n"
        echo += f"/other/path?key={response_key} {query_key}"
        content = json.dumps({"choices": [{"index": 0, "delta": {"content": echo}}]}).encode("ascii")
        wire = b"data: " + content + b"\n\n" + _breach(echo)
        with _upstream(lambda h: _reply(h, wire)) as (origin, requests), _proxy(origin) as (port, _):
            with _response(port, "POST", path, body=BODY, headers=credentials) as response:
                self.assertEqual(response.read(), wire)
            status, status_raw = self.status(port, events=1)
            summary = status["recent_events"][0]
            self.assertEqual(status["median_ttft_ms"], summary["ttft_ms"])
            self.assertGreaterEqual(summary["ttft_ms"], 0)
            self.assertGreaterEqual(summary["p0_breaches"], 1)
            self.assertTrue(summary["streaming"])
            self.assertNotIn("frames", summary)
            self.assertNotIn("issue_markdown", summary)

            with _response(port, "GET", f"/_inferdiff/event/{summary['id']}") as response:
                self.assertEqual(response.status, 200)
                self.assertEqual(response.headers.get_content_type(), "application/json")
                self.assertEqual(response.headers["Cache-Control"], "no-store")
                event_raw = response.read().decode("utf-8")
            with _response(port, "GET", "/_inferdiff/event/unknown") as response:
                self.assertEqual(response.status, 404)
                response.read()

        self.assertEqual(len(requests), 1)
        event = strict_json_loads(event_raw)
        self.assertEqual(event["id"], summary["id"])
        self.assertEqual((event["method"], event["path"], event["status"]), ("POST", CHAT_PATH, 200))
        self.assertEqual(event["dialect"], "openai-chat")
        self.assertEqual(event["finish_reason"], "stop")
        self.assertGreaterEqual(event["total_ms"], event["ttft_ms"])
        self.assertIn(("D1", "P0"), [(item["detector_id"], item["severity"]) for item in event["findings"]])
        self.assertEqual(event["frame_count"], 4)
        self.assertEqual([frame["seq"] for frame in event["frames"]], list(range(event["frame_count"])))
        arrivals = [frame["t_rel_ms"] for frame in event["frames"]]
        self.assertEqual(arrivals, sorted(arrivals))
        self.assertIn("stop", [frame["finish_reason"] for frame in event["frames"]])
        self.assertTrue(any(frame["terminal"] for frame in event["frames"]))
        report = event["issue_markdown"]
        self.assertIn("inferdiff", report)
        self.assertIn("D1", report)
        self.assertIn("P0", report)
        for source, output in (("status", status_raw), ("event", event_raw), ("report", report)):
            with self.subTest(source=source):
                for secret in (bearer, api_key, google_key, query_key, response_key):
                    self.assertNotIn(secret, output)

    def test_dashboard_evicts_old_event_and_inspector_data_at_ring_capacity(self):
        def no_content(handler):
            _reply(handler, b"", status=204, content_type="application/json")

        with redirect_stdout(io.StringIO()), _upstream(no_content) as (origin, _), _proxy(origin) as (port, _):
            with _response(port, "GET", "/v1/models/0") as response:
                self.assertEqual(response.status, 204)
                response.read()
            initial, _ = self.status(port, events=1)
            old_id = initial["recent_events"][0]["id"]

            # The final status request follows the last capture on the same downstream connection.
            with closing(http.client.HTTPConnection("127.0.0.1", port, timeout=3)) as client:
                for index in range(1, 101):
                    client.request("GET", f"/v1/models/{index}")
                    with client.getresponse() as response:
                        self.assertEqual(response.status, 204)
                        response.read()
                client.request("GET", "/_inferdiff/status")
                with client.getresponse() as response:
                    self.assertEqual(response.status, 200)
                    status = strict_json_loads(response.read())

            self.assertEqual(status["requests_total"], 101)
            self.assertEqual(len(status["recent_events"]), 100)
            self.assertEqual(status["recent_events"][0]["path"], "/v1/models/100")
            self.assertEqual(status["recent_events"][-1]["path"], "/v1/models/1")
            self.assertIsNone(status["median_ttft_ms"])
            with _response(port, "GET", f"/_inferdiff/event/{old_id}") as response:
                self.assertEqual(response.status, 404)
                response.read()

    def test_dashboard_redacts_credentials_in_percent_encoded_path(self):
        bearer, query_key = "odd-path-token-reflected", "odd-encoded-path-query"
        path = f"/v1/models/{bearer}/nested%3Fkey%3D%27{query_key}%27"
        headers = {"Authorization": f"Bearer {bearer}"}
        with _upstream(lambda h: _reply(h, b"", status=204)) as (origin, requests), _proxy(origin) as (port, _):
            with _response(port, "GET", path, headers=headers) as response:
                self.assertEqual(response.status, 204)
                response.read()
            status, raw = self.status(port, events=1)
            self.assertNotIn(bearer, raw)
            self.assertNotIn(query_key, raw)
            event_id = status["recent_events"][0]["id"]
            with _response(port, "GET", f"/_inferdiff/event/{event_id}") as response:
                self.assertEqual(response.status, 200)
                detail = response.read().decode("utf-8")
            self.assertNotIn(bearer, detail)
            self.assertNotIn(query_key, detail)
        self.assertEqual(requests[0][1], path)

    def test_dashboard_clear_rejects_foreign_origins_and_releases_event_details(self):
        with _upstream(lambda h: _reply(h, FIRST + TERMINAL)) as (origin, requests), _proxy(origin) as (port, _):
            with _response(port, "POST", CHAT_PATH, body=BODY) as response:
                response.read()
            initial, _ = self.status(port, events=1)
            event_id = initial["recent_events"][0]["id"]
            valid_origin = f"http://127.0.0.1:{port}"
            for foreign in ("https://evil.example", "null", f"http://localhost:{port}",
                            f"https://127.0.0.1:{port}", f"{valid_origin}/another-path"):
                with self.subTest(origin=foreign), _response(
                    port, "POST", "/_inferdiff/clear", headers={"Origin": foreign},
                ) as response:
                    self.assertEqual(response.status, 403)
                    response.read()
            status, _ = self.status(port, events=1)
            self.assertEqual(status, initial)

            for count, headers in enumerate(({"Origin": valid_origin}, {}), 1):
                if count == 2:
                    with _response(port, "POST", CHAT_PATH, body=BODY) as response:
                        response.read()
                    status, _ = self.status(port, events=1)
                    event_id = status["recent_events"][0]["id"]
                with _response(port, "POST", "/_inferdiff/clear", headers=headers) as response:
                    self.assertEqual(response.status, 204)
                    self.assertEqual(response.read(), b"")
                cleared, _ = self.status(port, events=0)
                self.assertEqual(cleared["recent_events"], [])
                self.assertIsNone(cleared["median_ttft_ms"])
                self.assertEqual(cleared["requests_total"], count)
                with _response(port, "GET", f"/_inferdiff/event/{event_id}") as response:
                    self.assertEqual(response.status, 404)
                    response.read()
        self.assertEqual(len(requests), 2)

    def test_proxy_no_ui_disables_local_routes_and_still_forwards_traffic(self):
        with _upstream(lambda h: _reply(h, FIRST + TERMINAL)) as (origin, requests), _proxy(
            origin, no_ui=True,
        ) as (port, _):
            for method, path in (("GET", "/_inferdiff/"), ("GET", "/_inferdiff"), ("GET", "/_inferdiff/status"),
                                 ("GET", "/_inferdiff/event/unknown"), ("POST", "/_inferdiff/clear")):
                with self.subTest(path=path), _response(port, method, path) as response:
                    self.assertEqual(response.status, 404)
                    response.read()
            with _response(port, "POST", CHAT_PATH, body=BODY) as response:
                self.assertEqual(response.status, 200)
                self.assertEqual(response.read(), FIRST + TERMINAL)
        self.assertEqual([path for _, path, _, _ in requests], [CHAT_PATH])

    def test_proxy_cli_announces_dashboard_unless_no_ui_is_set(self):
        from inferdiff.proxy import create_proxy_server

        for enabled in (True, False):
            with self.subTest(enabled=enabled):
                args = ["proxy", "--upstream", "http://127.0.0.1:8080", "--port", "0"]
                if not enabled:
                    args.append("--no-ui")
                output = io.StringIO()
                with (
                    redirect_stdout(output), redirect_stderr(output),
                    patch("inferdiff.cli.create_proxy_server", wraps=create_proxy_server) as create,
                    patch("inferdiff.proxy.ProxyServer.serve_forever", autospec=True) as serve,
                ):
                    self.assertEqual(main(args), 0)
                self.assertEqual(create.call_args.kwargs.get("no_ui", False), not enabled)
                serve.assert_called_once()
                server = serve.call_args.args[0]
                dashboard = f"Dashboard: http://127.0.0.1:{server.server_port}/_inferdiff/"
                self.assertEqual(dashboard in output.getvalue().splitlines(), enabled)

    def test_proxy_cli_resolves_fallback_key_from_environment_without_logging_it(self):
        from inferdiff.proxy import create_proxy_server

        fallback = "http://127.0.0.1:8081"
        key, name = "fake-environment-fallback-secret", "INFERDIFF_TEST_FALLBACK_KEY"
        args = ["proxy", "--upstream", "http://127.0.0.1:8080", "--port", "0",
                "--fallback-url", fallback, "--fallback-api-key", f"env:{name}"]
        output = io.StringIO()
        with (
            redirect_stdout(output), redirect_stderr(output),
            patch("inferdiff.cli.create_proxy_server", wraps=create_proxy_server) as create,
            patch("inferdiff.proxy.ProxyServer.serve_forever", autospec=True),
        ):
            with patch.dict("os.environ", {name: key}):
                self.assertEqual(main(args), 0)
            self.assertEqual(create.call_args.kwargs["fallback_url"], fallback)
            self.assertEqual(create.call_args.kwargs["fallback_api_key"], key)
            with patch.dict("os.environ", clear=True):
                self.assertNotEqual(main(args), 0)
            self.assertEqual(create.call_count, 1)
        self.assertNotIn(key, output.getvalue())
        self.assertNotIn(name, output.getvalue())

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

    def test_primary_503_fails_over_to_unbuffered_sse_and_redacts_both_keys(self):
        primary_key = "fake-primary-failover-secret"
        primary_header_key = "fake-primary-header-secret"
        fallback_key = "fake-fallback-secret+/"
        encoded_fallback = quote(fallback_key, safe="")
        path = f"/{primary_key}/{encoded_fallback}{CHAT_PATH}"
        query = urlencode({"key": primary_header_key, "mode": "fixture"})
        headers = {"Authorization": f"Api-Key {primary_key}", "x-api-key": primary_header_key}
        echoed = json.dumps({"choices": [{"index": 0, "delta": {"content": f"{primary_key} {fallback_key}"}}]})
        first = b"data: " + echoed.encode("ascii") + b"\n\n"
        release = threading.Event()

        def unavailable(handler):
            # The fallback must start without consuming the primary error body.
            handler.send_response(503)
            handler.send_header("Content-Length", "20")
            handler.end_headers()
            release.wait(timeout=5)
            handler.close_connection = True

        def stream(handler):
            handler.send_response(200)
            handler.send_header("Content-Type", "text/event-stream")
            handler.send_header("Transfer-Encoding", "chunked")
            handler.send_header("X-Inferdiff-Upstream", "untrusted")
            handler.end_headers()
            try:
                handler.wfile.write(f"{len(first):X}\r\n".encode("ascii") + first + b"\r\n")
                handler.wfile.flush()
                if release.wait(timeout=5):
                    handler.wfile.write(f"{len(TERMINAL):X}\r\n".encode("ascii") + TERMINAL + b"\r\n0\r\n\r\n")
            except (BrokenPipeError, ConnectionResetError):
                pass

        logs, errors, export = io.StringIO(), io.StringIO(), io.StringIO()
        with (
            tempfile.TemporaryDirectory() as tmp,
            redirect_stdout(logs), redirect_stderr(errors),
            _upstream(unavailable) as (primary, primary_requests),
            _upstream(stream) as (fallback, fallback_requests),
            _proxy(primary, fallback_url=fallback + "/fallback?region=west",
                   fallback_api_key=fallback_key, save_dir=tmp) as (port, _),
        ):
            try:
                with _response(port, "POST", f"{path}?{query}", body=BODY, headers=headers) as response:
                    self.assertEqual(response.status, 200)
                    self.assertEqual(response.headers.get_all("X-Inferdiff-Upstream"), ["fallback"])
                    self.assertEqual(response.read(len(first)), first)
                    live, _ = self.status(port, events=0)
                    self.assertEqual(live["failovers_total"], 1)
                    release.set()
                    self.assertEqual(response.read(), TERMINAL)
            finally:
                release.set()
            status, status_raw = self.status(port, events=1)
            self.assertEqual(status["requests_total"], 1)
            self.assertEqual(status["streaming_requests"], 1)
            self.assertEqual(status["failovers_total"], 1)
            summary = status["recent_events"][0]
            self.assertIs(summary["failover_used"], True)
            self.assertEqual(summary["primary_failure_reason"], "HTTP 503")
            with _response(port, "GET", "/_inferdiff/") as response:
                self.assertEqual(response.status, 200)
                html = response.read().decode("utf-8")
            with _response(port, "GET", f"/_inferdiff/event/{summary['id']}") as response:
                self.assertEqual(response.status, 200)
                event_raw = response.read().decode("utf-8")
            traces = list(Path(tmp).glob("*.trace.jsonl"))
            self.assertEqual(len(traces), 1)
            trace = traces[0].read_text(encoding="utf-8")
            with redirect_stdout(export):
                self.assertEqual(main(["export", str(traces[0]), "--include-body", "--include-wire"]), 0)

        self.assertEqual(len(primary_requests), 1)
        method, target, sent_headers, sent_body = primary_requests[0]
        self.assertEqual((method, target, sent_body), ("POST", f"{path}?{query}", BODY))
        sent_headers = {name.lower(): value for name, value in sent_headers.items()}
        self.assertEqual(sent_headers["authorization"], f"Api-Key {primary_key}")
        self.assertEqual(sent_headers["x-api-key"], primary_header_key)

        self.assertEqual(len(fallback_requests), 1)
        method, target, sent_headers, sent_body = fallback_requests[0]
        self.assertEqual((method, urlsplit(target).path, sent_body), ("POST", "/fallback" + path, BODY))
        self.assertCountEqual(parse_qsl(urlsplit(target).query), [("region", "west"), ("key", fallback_key),
                                                                 ("mode", "fixture")])
        sent_headers = {name.lower(): value for name, value in sent_headers.items()}
        self.assertEqual(sent_headers["host"], urlsplit(fallback).netloc)
        self.assertEqual(sent_headers["authorization"], f"Api-Key {fallback_key}")
        self.assertEqual(sent_headers["x-api-key"], fallback_key)

        event = strict_json_loads(event_raw)
        self.assertIs(event["failover_used"], True)
        self.assertEqual(event["primary_failure_reason"], "HTTP 503")
        for label in ("Failovers", "FAILOVER", "故障切换次数", "故障切换"):
            self.assertIn(label, html)
        for name, output in (("dashboard", html), ("status", status_raw), ("event", event_raw),
                             ("Issue Markdown", event["issue_markdown"]), ("stdout", logs.getvalue()),
                             ("stderr", errors.getvalue()), ("trace", trace), ("CLI export", export.getvalue())):
            with self.subTest(surface=name):
                for secret in (primary_key, primary_header_key, fallback_key, encoded_fallback):
                    self.assertNotIn(secret, output)

    def test_failed_fallback_returns_502_with_fallback_attribution(self):
        def disconnect(handler):
            handler.close_connection = True

        with (
            _upstream(lambda h: _reply(h, b"", status=503, headers=(("Connection", "close"),))) as (
                primary, primary_requests,
            ),
            _upstream(disconnect) as (fallback, fallback_requests),
            _proxy(primary, fallback_url=fallback) as (port, _),
        ):
            with _response(port, "POST", CHAT_PATH, body=BODY) as response:
                self.assertEqual(response.status, 502)
                self.assertEqual(response.headers.get_all("X-Inferdiff-Upstream"), ["fallback"])
                response.read()
            status, _ = self.status(port, events=1)
        self.assertEqual(status["failovers_total"], 1)
        summary = status["recent_events"][0]
        self.assertIs(summary["failover_used"], True)
        self.assertEqual(summary["primary_failure_reason"], "HTTP 503")
        self.assertEqual(len(primary_requests), 1)
        self.assertEqual(len(fallback_requests), 1)

    def test_only_retryable_http_statuses_use_fallback(self):
        def respond(handler):
            code = int(handler.path.rsplit("/", 1)[-1])
            _reply(handler, b"primary", status=code, content_type="text/plain",
                   headers=(("Connection", "close"),))

        with (
            _upstream(respond) as (primary, _),
            _upstream(lambda h: _reply(h, b"fallback", content_type="text/plain")) as (fallback, requests),
            _proxy(primary, fallback_url=fallback) as (port, _),
        ):
            cases = [(400, False), (500, False), (429, True), (502, True), (503, True), (504, True)]
            for code, retries in cases:
                with self.subTest(code=code), _response(port, "GET", f"/status/{code}") as response:
                    expected_upstream = "fallback" if retries else "primary"
                    self.assertEqual(response.status, 200 if retries else code)
                    self.assertEqual(response.headers["X-Inferdiff-Upstream"], expected_upstream)
                    self.assertEqual(response.read(), expected_upstream.encode("ascii"))
            status, _ = self.status(port, events=len(cases))
        self.assertEqual(status["failovers_total"], 4)
        self.assertEqual([target for _, target, _, _ in requests],
                         ["/status/429", "/status/502", "/status/503", "/status/504"])

    def test_primary_stream_with_d1_breach_never_uses_fallback(self):
        wire = FIRST + _breach()
        with (
            _upstream(lambda h: _reply(h, wire)) as (primary, primary_requests),
            _upstream(lambda h: _reply(h, TERMINAL)) as (fallback, fallback_requests),
            _proxy(primary, fallback_url=fallback) as (port, _),
        ):
            with _response(port, "POST", CHAT_PATH, body=BODY) as response:
                self.assertEqual(response.status, 200)
                self.assertEqual(response.headers["X-Inferdiff-Upstream"], "primary")
                self.assertEqual(response.read(), wire)
            status, _ = self.status(port, events=1)
            self.assertEqual(status["failovers_total"], 0)
            summary = status["recent_events"][0]
            self.assertIs(summary["failover_used"], False)
            self.assertIsNone(summary["primary_failure_reason"])
            with _response(port, "GET", f"/_inferdiff/event/{summary['id']}") as response:
                event = strict_json_loads(response.read())
            self.assertIn(("D1", "P0"), [(finding["detector_id"], finding["severity"]) for finding in event["findings"]])
        self.assertEqual(len(primary_requests), 1)
        self.assertEqual(fallback_requests, [])

    def test_primary_connection_refused_replays_post_with_incoming_auth(self):
        path = f"{CHAT_PATH}?key=fake-incoming-query-key"
        headers = {"Authorization": "Bearer fake-incoming-bearer", "x-api-key": "fake-incoming-header-key"}
        with socket.socket() as refused, _upstream(lambda h: _reply(h, FIRST + TERMINAL)) as (fallback, requests):
            refused.bind(("127.0.0.1", 0))
            primary = f"http://127.0.0.1:{refused.getsockname()[1]}"
            with _proxy(primary, fallback_url=fallback) as (port, _):
                with _response(port, "POST", path, body=BODY, headers=headers, timeout=5) as response:
                    self.assertEqual(response.status, 200)
                    self.assertEqual(response.headers["X-Inferdiff-Upstream"], "fallback")
                    self.assertEqual(response.read(), FIRST + TERMINAL)
                status, _ = self.status(port, events=1)
        self.assertEqual(status["failovers_total"], 1)
        summary = status["recent_events"][0]
        self.assertIs(summary["failover_used"], True)
        self.assertEqual(summary["primary_failure_reason"], "ConnectionRefused")
        self.assertEqual(len(requests), 1)
        method, target, sent_headers, sent_body = requests[0]
        self.assertEqual((method, target, sent_body), ("POST", path, BODY))
        sent_headers = {name.lower(): value for name, value in sent_headers.items()}
        for name, value in headers.items():
            self.assertEqual(sent_headers[name.lower()], value)

    def test_primary_header_timeout_replays_chunked_request(self):
        release = threading.Event()
        chunks = (BODY[:11], BODY[11:])

        def wait_without_sending_headers(handler):
            release.wait(timeout=5)
            handler.close_connection = True

        with (
            _upstream(wait_without_sending_headers) as (primary, primary_requests),
            _upstream(lambda h: _reply(h, FIRST + TERMINAL)) as (fallback, fallback_requests),
            _proxy(primary, fallback_url=fallback, timeout=0.3) as (port, _),
        ):
            try:
                with _response(port, "POST", CHAT_PATH, body=iter(chunks)) as response:
                    self.assertEqual(response.status, 200)
                    self.assertEqual(response.headers["X-Inferdiff-Upstream"], "fallback")
                    self.assertEqual(response.read(), FIRST + TERMINAL)
            finally:
                release.set()
            status, _ = self.status(port, events=1)
        self.assertEqual(status["failovers_total"], 1)
        self.assertEqual(status["recent_events"][0]["primary_failure_reason"], "Timeout")
        self.assertEqual([body for _, _, _, body in primary_requests], [BODY])
        self.assertEqual([body for _, _, _, body in fallback_requests], [BODY])

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
