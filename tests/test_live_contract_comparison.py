"""Exercise live canary comparison and the Messages contract over loopback HTTP."""

from __future__ import annotations

import http.server
import io
import json
import tempfile
import threading
import unittest
from contextlib import contextmanager, redirect_stderr, redirect_stdout
from pathlib import Path
from typing import Any, Callable, Iterator

from inferdiff.cli import main
from inferdiff.schema import EXIT_OK, EXIT_SILENT_PROTOCOL_BREACH, strict_json_loads


@contextmanager
def _serve(
    path: str, respond: Callable[[dict[str, Any]], bytes | tuple[int, bytes]], *, status: int = 200,
) -> Iterator[tuple[str, list[tuple[str, dict[str, str], dict[str, Any]]]]]:
    requests: list[tuple[str, dict[str, str], dict[str, Any]]] = []

    class Handler(http.server.BaseHTTPRequestHandler):
        protocol_version = "HTTP/1.1"

        def log_message(self, format, *args):
            return

        def _reply(self, code: int, body: bytes = b"") -> None:
            self.send_response(code)
            if code == 200:
                self.send_header("Content-Type", "text/event-stream; charset=utf-8")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)

        def do_GET(self) -> None:
            self._reply(404)

        def do_POST(self) -> None:
            request = json.loads(self.rfile.read(int(self.headers["Content-Length"])))
            requests.append((self.path, {k.lower(): v for k, v in self.headers.items()}, request))
            if self.path.split("?", 1)[0] != path:
                self._reply(404)
                return
            response = respond(request) if status == 200 else (status, b"")
            if isinstance(response, tuple):
                self._reply(*response)
            else:
                self._reply(200, response)

    with http.server.ThreadingHTTPServer(("127.0.0.1", 0), Handler) as server:
        thread = threading.Thread(target=server.serve_forever, kwargs={"poll_interval": 0.01}, daemon=True)
        thread.start()
        try:
            yield f"http://127.0.0.1:{server.server_port}", requests
        finally:
            server.shutdown()
            thread.join(timeout=2)


def _messages_stream(
    request: dict[str, Any], *, reason: str = "max_tokens", missing_stop: bool = False,
    delta_type: str = "input_json_delta", output_tokens: int | None = None,
) -> bytes:
    block, delta = {
        "input_json_delta": (
            {"type": "tool_use", "id": "call_1", "name": "record_numbers", "input": {}},
            {"partial_json": '{"numbers":[1,2,'},
        ),
        "thinking_delta": ({"type": "thinking", "thinking": ""}, {"thinking": "Consider the tool arguments."}),
        "text_delta": ({"type": "text", "text": ""}, {"text": "1, 2, 3, 4, 5, 6,"}),
    }[delta_type]
    events = [
        {"type": "message_start", "message": {"id": "msg_1", "type": "message", "role": "assistant",
                                             "model": request["model"], "content": [], "stop_reason": None,
                                             "usage": {"input_tokens": 30, "output_tokens": 1}}},
        {"type": "ping"},
        {"type": "content_block_start", "index": 0, "content_block": block},
        {"type": "content_block_delta", "index": 0, "delta": {"type": delta_type, **delta}},
    ]
    if delta_type == "thinking_delta":
        events.append({"type": "content_block_delta", "index": 0,
                       "delta": {"type": "signature_delta", "signature": "signed_mock_reasoning"}})
    if not missing_stop:
        events.append({"type": "content_block_stop", "index": 0})
    events.extend([
        {"type": "message_delta", "delta": {"stop_reason": reason, "stop_sequence": None},
         "usage": {"output_tokens": request["max_tokens"] if output_tokens is None else output_tokens}},
        {"type": "message_stop"},
    ])
    return "".join(f"event: {event['type']}\r\ndata: {json.dumps(event)}\r\n\r\n" for event in events).encode("utf-8")


def _chat_stream(model: str, fingerprint: str, *, reason: str = "length") -> bytes:
    identity = {"model": model, "system_fingerprint": fingerprint}
    events = [
        {**identity, "choices": [{"index": 0, "delta": {"role": "assistant", "tool_calls": [
            {"index": 0, "id": "call_1", "type": "function",
             "function": {"name": "write_config", "arguments": '{"description":"incomplete'}},
        ]}}]},
        {**identity, "choices": [{"index": 0, "delta": {}, "finish_reason": reason}]},
        {**identity, "choices": [], "usage": {"prompt_tokens": 45, "completion_tokens": 28, "total_tokens": 73}},
    ]
    return ("".join(f"data: {json.dumps(event)}\n\n" for event in events) + "data: [DONE]\n\n").encode("utf-8")


def _run_cli(*args: str) -> tuple[int, str, str]:
    stdout, stderr = io.StringIO(), io.StringIO()
    with redirect_stdout(stdout), redirect_stderr(stderr):
        code = main(args)
    return code, stdout.getvalue(), stderr.getvalue()


class TestLiveAnthropicContract(unittest.TestCase):
    def test_doctor_html_labels_messages_and_reports_output_usage(self):
        key = "relay-anthropic-credential"
        with (tempfile.TemporaryDirectory() as root,
              _serve("/v1/messages", _messages_stream) as (url, _)):
            path = Path(root) / "report.html"
            code, _, stderr = _run_cli(
                "doctor", url, "--model", "claude-mock", "--only", "C9", "--api-key", key,
                "--timeout", "2", "--html", str(path), "--save-dir", root,
            )
            report = path.read_text(encoding="utf-8")
        self.assertEqual((code, stderr), (EXIT_OK, ""))
        self.assertIn("Anthropic Messages SSE", report)
        self.assertIn("/v1/messages", report)
        self.assertIn('<span class="badge b-grn">PASS</span>', report)
        self.assertIn("<dt>stop_reason</dt><dd>max_tokens</dd>", report)
        self.assertIn("<dt>Output tokens</dt><dd>32</dd>", report)
        self.assertIn('href="https://platform.claude.com/', report)
        self.assertNotIn(key, report)
        self.assertNotIn(root, report)
        self.assertLess(len(report.encode("utf-8")), 80 * 1024)

    def _doctor(
        self, base_suffix: str = "", *, flags: tuple[str, ...] = ("--only", "C9"),
        status: int = 200, **stream_options: Any,
    ) -> tuple[int, dict[str, Any], dict[str, str], dict[str, Any]]:
        key = "relay-anthropic-credential"
        with (tempfile.TemporaryDirectory() as root,
              _serve("/v1/messages", lambda req: _messages_stream(req, **stream_options), status=status) as (url, requests)):
            code, stdout, stderr = _run_cli(
                "doctor", url + base_suffix, "--model", "claude-mock", "--api-key", key,
                "--timeout", "2", "--json", "--save-dir", root, *flags,
            )
        self.assertEqual(stderr, "")
        self.assertNotIn(key, stdout)
        report = strict_json_loads(stdout)
        self.assertEqual(len(requests), 1)
        path, headers, request = requests[0]
        self.assertEqual(path, "/v1/messages")
        self.assertEqual(headers["x-api-key"], key)
        self.assertTrue(request["stream"])
        self.assertEqual(request["model"], "claude-mock")
        self.assertIs(type(request["max_tokens"]), int)
        self.assertGreater(request["max_tokens"], 0)
        self.assertEqual([row["probe_id"] for row in report["results"]], ["C9"])
        return code, report["results"][0], headers, request

    def test_honest_tool_budget_cutoff(self):
        code, result, headers, request = self._doctor("/v1")
        self.assertEqual((code, result["status"]), (EXIT_OK, "PASS"))
        self.assertEqual(headers["anthropic-version"], "2023-06-01")
        self.assertTrue(request["tools"][0]["eager_input_streaming"])
        self.assertEqual(request["tool_choice"], {"type": "tool", "name": request["tools"][0]["name"]})
        self.assertGreaterEqual(result["tokens_used"], request["max_tokens"])

    def test_text_only_messages_endpoint_can_reject_tool_probe(self):
        def respond(request):
            return (400, b"") if "tools" in request else _messages_stream(request, delta_type="text_delta")

        with (tempfile.TemporaryDirectory() as root,
              _serve("/v1/messages", respond) as (url, requests)):
            code, stdout, stderr = _run_cli(
                "doctor", url, "--model", "claude-mock", "--only", "C9", "--timeout", "2",
                "--json", "--save-dir", root,
            )
        self.assertEqual((code, stderr), (EXIT_OK, ""))
        self.assertEqual(["tools" in request for _, _, request in requests], [True, False])
        self.assertEqual(strict_json_loads(stdout)["results"][0]["status"], "PASS")

    def test_budget_stop_without_content_evidence_is_inconclusive(self):
        def respond(request):
            stream = _messages_stream(request, output_tokens=0).split(b"\r\n\r\n")
            return b"\r\n\r\n".join(event for event in stream if not event.startswith(b"event: content_block_"))

        with (tempfile.TemporaryDirectory() as root,
              _serve("/v1/messages", respond) as (url, _)):
            code, stdout, stderr = _run_cli(
                "doctor", url, "--model", "claude-mock", "--only", "C9", "--timeout", "2",
                "--json", "--save-dir", root,
            )
        self.assertEqual((code, stderr), (EXIT_OK, ""))
        self.assertEqual(strict_json_loads(stdout)["results"][0]["status"], "SKIP")

    def test_honest_long_text_budget_cutoff_with_explicit_protocol(self):
        code, result, _, _ = self._doctor("/v1/messages", flags=("--protocol", "anthropic"), delta_type="text_delta")
        self.assertEqual((code, result["status"]), (EXIT_OK, "PASS"))

    def test_long_text_at_token_budget_cannot_claim_end_turn(self):
        code, result, _, _ = self._doctor(reason="end_turn", delta_type="text_delta")
        self.assertEqual((code, result["status"]), (EXIT_SILENT_PROTOCOL_BREACH, "FAIL"))
        self.assertIn("max_tokens", json.dumps(result))

    def test_truncated_tool_json_cannot_claim_success(self):
        for reason in ("end_turn", "tool_use"):
            with self.subTest(reason=reason):
                code, result, _, _ = self._doctor(reason=reason, output_tokens=4)
                self.assertEqual((code, result["status"]), (EXIT_SILENT_PROTOCOL_BREACH, "FAIL"))
                self.assertIn("max_tokens", json.dumps(result))

    def test_missing_content_block_stop_is_a_breach(self):
        code, result, _, _ = self._doctor(missing_stop=True)
        self.assertEqual((code, result["status"]), (EXIT_SILENT_PROTOCOL_BREACH, "FAIL"))
        self.assertIn("content_block_stop", json.dumps(result))

    def test_unsupported_messages_endpoint_is_skipped(self):
        for status in (404, 405):
            with self.subTest(status=status):
                code, result, _, _ = self._doctor(status=status)
                self.assertEqual((code, result["status"]), (EXIT_OK, "SKIP"))
                self.assertIn(str(status), result["summary"])

    def test_openai_only_target_keeps_passing_checks_when_c9_is_selected(self):
        with (tempfile.TemporaryDirectory() as root,
              _serve("/v1/chat/completions", lambda req: _chat_stream(req["model"], "fp_chat")) as (url, requests)):
            code, stdout, stderr = _run_cli(
                "doctor", url, "--model", "mock-model", "--only", "C1,C9", "--timeout", "2",
                "--json", "--save-dir", root,
            )
        self.assertEqual((code, stderr), (EXIT_OK, ""))
        self.assertEqual([path for path, _, _ in requests], ["/v1/chat/completions", "/v1/messages"])
        results = strict_json_loads(stdout)["results"]
        self.assertEqual([(row["probe_id"], row["status"]) for row in results], [("C1", "PASS"), ("C9", "SKIP")])

    def test_thinking_delta_and_version_override(self):
        code, result, headers, _ = self._doctor(
            flags=("--anthropic-version", "2024-01-01"), delta_type="thinking_delta",
        )
        self.assertEqual((code, result["status"]), (EXIT_OK, "PASS"))
        self.assertEqual(headers["anthropic-version"], "2024-01-01")

    def test_thinking_delta_requires_positive_output_usage(self):
        code, result, _, _ = self._doctor(delta_type="thinking_delta", output_tokens=0)
        self.assertEqual((code, result["status"]), (EXIT_SILENT_PROTOCOL_BREACH, "FAIL"))
        self.assertIn("output_tokens", json.dumps(result))

    def test_saved_messages_trace_scrubs_escaped_and_reassembled_credential_reflections(self):
        key = 'local-credential-"quoted"'
        escaped_key = json.dumps(key)[1:-1]
        query_key = "secret-query-value"

        def reflect(request):
            stream = _messages_stream(request, delta_type="text_delta", reason=key)
            chunks = stream.decode().split("\r\n\r\n")
            for index, event in enumerate(chunks):
                if event.startswith("event: content_block_delta"):
                    payload = json.loads(event.split("\r\ndata: ", 1)[1])
                    reflection = []
                    for fragment in (key[:10], key[10:], query_key[:8], query_key[8:]):
                        payload["delta"]["text"] = fragment
                        reflection.append(f"event: content_block_delta\r\ndata: {json.dumps(payload)}")
                    chunks[index:index + 1] = reflection
                    break
            return "\r\n\r\n".join(chunks).encode()

        with (tempfile.TemporaryDirectory() as root,
              _serve("/v1/messages", reflect) as (url, _)):
            html_file = Path(root) / "doctor.html"
            code, stdout, stderr = _run_cli(
                "doctor", f"{url}?api-key={query_key}", "--only", "C9", "--api-key", key, "--model", key,
                "--timeout", "2", "--save-dir", root, "--json", "--html", str(html_file),
            )
            self.assertEqual((code, stderr), (EXIT_SILENT_PROTOCOL_BREACH, ""))
            trace = Path(root) / "c9_anthropic_stream_contract.trace.jsonl"
            for publication in (stdout, trace.read_text(encoding="utf-8"), html_file.read_text(encoding="utf-8")):
                self.assertNotIn(key, publication)
                self.assertNotIn(escaped_key, publication)
                self.assertNotIn(query_key, publication)


class TestLiveTargetComparison(unittest.TestCase):
    PATH = "/v1/chat/completions"
    MODEL = "mock-model"
    A_KEY = "incognito-alpha-credential"
    B_KEY = "incognito-beta-credential"

    def _args(self, a: str, b: str, *, a_label: str = "Reference", b_label: str = "Candidate") -> tuple[str, ...]:
        return ("compare", "--a-url", a, "--a-key", self.A_KEY, "--a-model", self.MODEL, "--a-label", a_label,
                "--b-url", b + self.PATH, "--b-key", self.B_KEY, "--b-model", self.MODEL, "--b-label", b_label,
                "--only", "C1", "--timeout", "2", "--no-color")

    def test_matching_targets_report_identical_contract_and_export(self):
        stream = _chat_stream(self.MODEL, "fp_same")
        with (tempfile.TemporaryDirectory() as root,
              _serve(self.PATH, lambda _: stream) as (a, a_requests),
              _serve(self.PATH, lambda _: stream) as (b, b_requests)):
            json_out, markdown_out, html_out = (Path(root) / f"comparison.{suffix}" for suffix in ("json", "md", "html"))
            args = self._args(a, b)
            code, terminal, stderr = _run_cli(
                *args, "--out-json", str(json_out), "--out-md", str(markdown_out), "--out-html", str(html_out),
            )
            self.assertEqual((code, stderr), (EXIT_OK, ""))
            json_text = json_out.read_text(encoding="utf-8")
            report = strict_json_loads(json_text)
            markdown = markdown_out.read_text(encoding="utf-8")
            html = html_out.read_text(encoding="utf-8")
        self.assertEqual((report["verdict"], report["exit_code"]), ("IDENTICAL_CONTRACT", EXIT_OK))
        self.assertEqual(len(report["checks"]), 1)
        check = report["checks"][0]
        self.assertEqual((check["probe_id"], check["a"]["status"], check["b"]["status"]), ("C1", "PASS", "PASS"))
        self.assertEqual(len(a_requests), 1)
        self.assertEqual(len(b_requests), 1)
        self.assertEqual(a_requests[0][2], b_requests[0][2])
        self.assertEqual(a_requests[0][1]["authorization"], f"Bearer {self.A_KEY}")
        self.assertEqual(b_requests[0][1]["authorization"], f"Bearer {self.B_KEY}")
        self.assertIn("IDENTICAL_CONTRACT", terminal)
        self.assertNotIn("\x1b", terminal)
        self.assertRegex(markdown, r"(?m)^\|[^\n]+Reference[^\n]+Candidate[^\n]+\|")
        self.assertRegex(markdown, r"(?m)^\|[^\n]*C1[^\n]+PASS[^\n]+PASS[^\n]*\|")
        self.assertIn("<svg", html)
        self.assertIn("Reference", html)
        self.assertIn("Candidate", html)
        self.assertNotRegex(html, r'(?i)<(?:script|link|img)\b[^>]*\b(?:src|href)=["\']https?://')
        for report_text in (terminal, json_text, markdown, html):
            self.assertNotIn(self.A_KEY, report_text)
            self.assertNotIn(self.B_KEY, report_text)

    def test_same_model_and_fingerprint_can_have_contract_drift(self):
        a_stream = _chat_stream(self.MODEL, "fp_same")
        b_stream = _chat_stream(self.MODEL, "fp_same", reason="stop")
        with (_serve(self.PATH, lambda _: a_stream) as (a, _),
              _serve(self.PATH, lambda _: b_stream) as (b, _)):
            code, markdown, stderr = _run_cli(*self._args(a, b), "--markdown")
        self.assertEqual((code, stderr), (EXIT_SILENT_PROTOCOL_BREACH, ""))
        self.assertIn("CONTRACT_DRIFT", markdown)
        self.assertRegex(markdown, r"(?m)^\|[^\n]*C1[^\n]+PASS[^\n]+FAIL[^\n]*\|")
        self.assertIn("length", markdown)
        self.assertIn("stop", markdown)

    def test_model_fingerprint_drift_and_breach_are_reported_without_key_reflections(self):
        shared_key = "tiny1"
        a_stream = _chat_stream(self.MODEL, f"fp_reflect_{self.B_KEY}_{shared_key}")
        b_stream = _chat_stream(f"replacement-{self.A_KEY}", "fp_changed", reason="stop")
        with (tempfile.TemporaryDirectory() as root,
              _serve(self.PATH, lambda _: a_stream) as (a, _),
              _serve(self.PATH, lambda _: b_stream) as (b, _)):
            json_out, markdown_out, html_out = (Path(root) / f"comparison.{suffix}" for suffix in ("json", "md", "html"))
            code, terminal, stderr = _run_cli(
                *self._args(a + f"?version={self.B_KEY}", b, a_label=f"<candidate>\x1b[31m{self.A_KEY}",
                            b_label=f"relay|{self.B_KEY}"),
                "--header", f"x-api-key: {shared_key}",
                "--out-json", str(json_out), "--out-md", str(markdown_out), "--out-html", str(html_out),
            )
            self.assertEqual((code, stderr), (EXIT_SILENT_PROTOCOL_BREACH, ""))
            json_text, markdown, html = (path.read_text(encoding="utf-8") for path in (json_out, markdown_out, html_out))
        report = strict_json_loads(json_text)
        self.assertIn(report["verdict"], ("CONTRACT_DRIFT", "SUSPECTED_MODEL_MISMATCH"))
        self.assertTrue(report["contract_drift"])
        self.assertTrue(report["model_mismatch"])
        check = report["checks"][0]
        self.assertEqual((check["probe_id"], check["a"]["status"], check["b"]["status"]), ("C1", "PASS", "FAIL"))
        fields = {entry["field"] for entry in report["divergences"]}
        self.assertIn("system_fingerprint", fields)
        self.assertIn("finish_reason", fields)
        self.assertNotIn("<candidate>", html)
        self.assertRegex(markdown, r"relay(?:\\\||&#124;|&vert;)")
        for report_text in (terminal, json_text, markdown, html):
            self.assertNotIn(self.A_KEY, report_text)
            self.assertNotIn(self.B_KEY, report_text)
            self.assertNotIn(shared_key, report_text)
            self.assertNotIn("\x1b", report_text)

    def test_model_discovery_failure_preserves_other_target_results(self):
        with (_serve(self.PATH, lambda _: b"") as (a, a_requests),
              _serve(self.PATH, lambda _: _chat_stream(self.MODEL, "fp_same")) as (b, b_requests)):
            code, stdout, stderr = _run_cli(
                "compare", "--a-url", a, "--b-url", b, "--b-model", self.MODEL,
                "--only", "C1", "--timeout", "2", "--out-json", "-",
            )
        self.assertEqual((code, stderr), (1, ""))
        self.assertEqual(len(a_requests), 0)
        self.assertEqual(len(b_requests), 1)
        check, = strict_json_loads(stdout)["checks"]
        self.assertEqual((check["a"]["status"], check["b"]["status"]), ("ERROR", "PASS"))
