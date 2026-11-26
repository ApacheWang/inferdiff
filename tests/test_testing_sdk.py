"""Offline stream assertions, live endpoint assertions, and badge CLI coverage."""

from __future__ import annotations

import http.server
import io
import json
import subprocess
import sys
import tempfile
import threading
import traceback
import unittest
import xml.etree.ElementTree as ET
from contextlib import contextmanager, redirect_stderr, redirect_stdout
from pathlib import Path
from unittest.mock import patch

from inferdiff.cli import main
from inferdiff.testing import InferdiffAssertionError, assert_endpoint_honest, assert_sse_honest

from test_doctor_and_waterfall import _start_api_mock


_PRIVATE_URL = "https://private-upstream.invalid/v1/tenant"
_API_KEY = "sk-synthetic-sdk-test-key"
_BEARER = "opaque-bearer-credential"


def _sse(*payloads, done=False):
    frames = [f"data: {json.dumps(payload)}\r\n\r\n" for payload in payloads]
    if done:
        frames.append("data: [DONE]\r\n\r\n")
    return "".join(frames)


def _chat(delta=None, *, reason=None, index=0):
    return {"choices": [{"index": index, "delta": delta or {}, "finish_reason": reason}]}


def _tool(arguments, *, index=0, call_id=None):
    tool = {"index": index, "function": {"arguments": arguments}}
    if call_id is not None:
        tool.update(id=call_id, type="function")
        tool["function"]["name"] = "write_config"
    return tool


def _anthropic(reason):
    events = (
        {"type": "message_start", "message": {"usage": {"input_tokens": 2}}},
        {"type": "content_block_start", "index": 0, "content_block": {"type": "text", "text": ""}},
        {"type": "content_block_delta", "index": 0, "delta": {"type": "text_delta", "text": "Hi"}},
        {"type": "content_block_stop", "index": 0},
        {"type": "message_delta", "delta": {"stop_reason": reason}, "usage": {"output_tokens": 1}},
        {"type": "message_stop"},
    )
    return "".join(f"event: {event['type']}\r\n{_sse(event)}" for event in events)


def _gemini(reason, *, tokens=1):
    return _sse(
        {"candidates": [{"index": 0, "content": {"role": "model", "parts": [{"text": "Hi"}]}}]},
        {"candidates": [{"index": 0, "finishReason": reason}], "usageMetadata": {
            "promptTokenCount": 4, "candidatesTokenCount": tokens, "totalTokenCount": 4 + tokens,
        }},
    )


class OfflineAssertionTests(unittest.TestCase):
    def _assert_breach(self, stream, code, *, frame_seq=None, **options):
        with self.assertRaises(InferdiffAssertionError) as caught:
            assert_sse_honest(stream, **options)
        error = caught.exception
        self.assertIsInstance(error, AssertionError)
        self.assertEqual(error.report["grade"], "F")
        (finding,) = [finding for finding in error.findings if finding["code"] == code]
        self.assertEqual(finding["severity"], "P0")
        if frame_seq is not None:
            self.assertEqual(finding["frame_seq"], frame_seq)
        self.assertIn("Grade F", str(error))
        self.assertIn(code, str(error))
        if frame_seq is not None:
            self.assertRegex(str(error), rf"frame(?:\s+seq)?[ =#]+{frame_seq}\b")
        return error

    def test_honest_fragmented_tool_arguments_and_usage(self):
        stream = ": keep-alive\r\n\r\n" + _sse(
            _chat({"role": "assistant", "tool_calls": [_tool('{"name":', call_id="call_1")]}),
            _chat({"tool_calls": [_tool('"caf\u00e9"}')]}),
            _chat(reason="tool_calls"),
            {"choices": [], "usage": {"prompt_tokens": 5, "completion_tokens": 4, "total_tokens": 9}},
            done=True,
        )
        self.assertEqual(assert_sse_honest(stream, expect_usage=True)["grade"], "A+")

    def test_d1_truncated_tool_arguments_with_success_reason(self):
        stream = _sse(_chat({"tool_calls": [_tool('{"name":', call_id="call_1")]}),
                      _chat(reason="stop"), done=True)
        self._assert_breach(stream, "D1", allow_warnings=True)

    def test_explicit_length_cutoff_allows_incomplete_tool_arguments(self):
        stream = _sse(_chat({"tool_calls": [_tool('{"name":', call_id="call_1")]}),
                      _chat(reason="length"), done=True)
        self.assertEqual(assert_sse_honest(stream)["grade"], "A+")

    def test_d2_decoded_utf8_replacement_character(self):
        stream = _sse(_chat({"content": "caf\ufffd"}), _chat(reason="stop"), done=True)
        self.assertIn(r"\ufffd", stream)
        self._assert_breach(stream, "D2", frame_seq=0)

    def test_d3_tool_indices_collide(self):
        stream = _sse(
            _chat({"tool_calls": [_tool("{}", call_id="first"), _tool("{}", call_id="second")]}),
            _chat(reason="tool_calls"), done=True,
        )
        self._assert_breach(stream, "D3", frame_seq=0)

    def test_distinct_choices_can_each_have_tool_index_zero(self):
        stream = _sse({"choices": [
            _chat({"tool_calls": [_tool("{}", call_id="first")]}, index=0)["choices"][0],
            _chat({"tool_calls": [_tool("{}", call_id="second")]}, index=1)["choices"][0],
        ]}, _chat(reason="tool_calls", index=0), _chat(reason="tool_calls", index=1), done=True)
        self.assertEqual(assert_sse_honest(stream)["grade"], "A+")

    def test_d4_usage_required_warning_is_opt_in(self):
        stream = _sse(_chat({"content": "OK"}), _chat(reason="stop"), done=True)
        self.assertEqual(assert_sse_honest(stream)["grade"], "A+")
        with self.assertRaises(InferdiffAssertionError) as caught:
            assert_sse_honest(stream, expect_usage=True)
        (finding,) = caught.exception.findings
        self.assertEqual((finding["code"], finding["severity"]), ("D4", "P1"))
        self.assertEqual(assert_sse_honest(stream, expect_usage=True, allow_warnings=True)["grade"], "B")

    def test_c9_invalid_anthropic_stop_reason(self):
        self.assertEqual(assert_sse_honest(_anthropic("end_turn"))["grade"], "A+")
        self._assert_breach(_anthropic("unexpected-stop"), "C9", frame_seq=4)

    def test_c10_invalid_gemini_finish_reason(self):
        self.assertEqual(assert_sse_honest(_gemini("STOP"))["grade"], "A+")
        self._assert_breach(_gemini("unexpected-stop"), "C10", frame_seq=1)

    def test_sensitive_stream_values_never_enter_the_diagnostic(self):
        error = self._assert_breach(_anthropic(f"{_PRIVATE_URL} API key={_API_KEY} Bearer {_BEARER}"), "C9")
        for output in (str(error), repr(error), json.dumps(error.report), json.dumps(error.findings)):
            for sensitive in (_PRIVATE_URL, _API_KEY, _BEARER):
                self.assertNotIn(sensitive, output)


@contextmanager
def _gemini_endpoint(reason, *, status=200):
    seen = []

    class Handler(http.server.BaseHTTPRequestHandler):
        def log_message(self, format, *args):
            pass

        def do_GET(self):
            seen.append((self.path, self.headers.get("Authorization")))
            self.send_response(404)
            self.send_header("Content-Length", "0")
            self.end_headers()

        def do_POST(self):
            request = json.loads(self.rfile.read(int(self.headers["Content-Length"])))
            seen.append((self.path, self.headers.get("x-goog-api-key")))
            token_limit = request["generationConfig"]["maxOutputTokens"]
            payload = _gemini(reason, tokens=token_limit).encode("utf-8")
            self.send_response(status)
            self.send_header("Content-Type", "text/event-stream")
            self.send_header("Content-Length", str(len(payload)))
            self.end_headers()
            self.wfile.write(payload)

    with http.server.ThreadingHTTPServer(("127.0.0.1", 0), Handler) as server:
        thread = threading.Thread(target=server.serve_forever, kwargs={"poll_interval": 0.01})
        thread.start()
        try:
            yield f"http://127.0.0.1:{server.server_port}", seen
        finally:
            server.shutdown()
            thread.join()


class EndpointAssertionTests(unittest.TestCase):
    def test_honest_gemini_endpoint_passes_real_doctor_probe(self):
        with _gemini_endpoint("MAX_TOKENS") as (url, requests):
            report = assert_endpoint_honest(url, model="mock-gemini", api_key=_API_KEY,
                                            protocol="gemini", timeout=2)
        self.assertEqual(report["grade"], "A+")
        self.assertEqual(report["p0_count"], 0)
        (result,) = report["results"]
        self.assertEqual((result["probe_id"], result["status"]), ("C10", "PASS"))
        ((path, key),) = requests
        self.assertIn("mock-gemini:streamGenerateContent", path)
        self.assertEqual(key, _API_KEY)
        self.assertNotIn(_API_KEY, json.dumps(report))

    def test_p0_fails_at_grade_f_and_does_not_reflect_credentials(self):
        with _gemini_endpoint(f"{_API_KEY} Bearer {_BEARER} {_PRIVATE_URL}") as (url, _):
            with self.assertRaises(InferdiffAssertionError) as caught:
                assert_endpoint_honest(url, model="mock-gemini", api_key=_API_KEY, protocol="gemini",
                                       min_grade="F", allow_warnings=True, timeout=2)
        error = caught.exception
        self.assertEqual(error.report["p0_count"], 1)
        self.assertIn("Grade F", str(error))
        self.assertIn("C10", str(error))
        self.assertIn("last frame seq 1", str(error))
        self.assertTrue(error.findings)
        for output in (str(error), repr(error), json.dumps(error.report), json.dumps(error.findings)):
            for sensitive in (_API_KEY, _BEARER, _PRIVATE_URL, url):
                self.assertNotIn(sensitive, output)

    def test_inconclusive_probe_cannot_meet_a_plus_grade(self):
        with _gemini_endpoint("MAX_TOKENS", status=404) as (url, _):
            with self.assertRaises(InferdiffAssertionError) as caught:
                assert_endpoint_honest(url, model="mock-gemini", api_key=_API_KEY, protocol="gemini",
                                       min_grade="A+", allow_warnings=True, timeout=2)
        self.assertEqual(caught.exception.report["grade"], "A")
        self.assertEqual(caught.exception.report["p0_count"], 0)

    def test_openai_endpoint_gate_can_allow_p1_warnings(self):
        server, port, _ = _start_api_mock("p1_only")
        try:
            url = f"http://127.0.0.1:{port}/v1"
            with self.assertRaises(InferdiffAssertionError) as caught:
                assert_endpoint_honest(url, model="mock-openai", api_key=_API_KEY, min_grade="C", timeout=2)
            self.assertIn("C4", str(caught.exception))
            report = assert_endpoint_honest(url, model="mock-openai", api_key=_API_KEY, min_grade="C",
                                            allow_warnings=True, timeout=2)
        finally:
            server.shutdown()
            server.server_close()
        self.assertEqual(report["p0_count"], 0)
        self.assertGreater(report["warning_count"], 0)

    def test_discovery_error_does_not_chain_sensitive_upstream_details(self):
        with _gemini_endpoint("MAX_TOKENS") as (url, requests):
            with self.assertRaises(InferdiffAssertionError) as caught:
                assert_endpoint_honest(f"{url}/tenant/{_BEARER}/v1", api_key=_API_KEY, timeout=2)
        self.assertEqual(len(requests), 2)
        self.assertTrue(all(key == f"Bearer {_API_KEY}" for _, key in requests))
        error = caught.exception
        self.assertEqual(error.report["error_count"], 1)
        self.assertIsNone(error.__context__)
        self.assertIsNone(error.__cause__)
        rendered = "".join(traceback.TracebackException.from_exception(error).format())
        for sensitive in (_API_KEY, _BEARER, url):
            self.assertNotIn(sensitive, rendered)


class PytestPluginTests(unittest.TestCase):
    def test_plugin_imports_when_pytest_is_unavailable(self):
        imported = subprocess.run(
            [sys.executable, "-W", "error", "-c",
             "import sys; sys.modules['pytest'] = None; import inferdiff.pytest_plugin"],
            capture_output=True, text=True, check=False,
        )
        self.assertEqual(imported.returncode, 0, imported.stderr)


class BadgeCliTests(unittest.TestCase):
    def _summary(self, grade, *statuses):
        return {
            "grade": grade, "p0_count": statuses.count("FAIL"), "warning_count": statuses.count("WARN"),
            "error_count": statuses.count("ERROR"), "target_url": _PRIVATE_URL,
            "model": _API_KEY, "results": [{
                "probe_id": f"C{index}", "status": status,
                "severity": "P0" if status == "FAIL" else "P1", "summary": f"Bearer {_BEARER}",
                "details": {"api_key": _API_KEY, "url": _PRIVATE_URL},
            } for index, status in enumerate(statuses, 1)],
        }

    def _badge(self, summary, *args):
        stdout, stderr = io.StringIO(), io.StringIO()
        with patch("sys.stdin", io.StringIO(json.dumps(summary))), redirect_stdout(stdout), redirect_stderr(stderr):
            exit_code = main(["badge", "-", *args])
        self.assertEqual(exit_code, 0, stderr.getvalue())
        self.assertEqual(stderr.getvalue(), "")
        return stdout.getvalue()

    def test_grade_colors_and_offline_shield_text_from_stdin(self):
        examples = (
            ("A+", ("PASS",) * 8, "Grade A+ \u00b7 8/8 PASS", "#047857"),
            ("B", ("PASS", "WARN"), "Grade B \u00b7 WARN", "#b45309"),
            ("C", ("PASS", "WARN", "WARN"), "Grade C \u00b7 WARN", "#b45309"),
            ("F", ("PASS", "FAIL"), "Grade F \u00b7 P0 BREACH", "#be123c"),
        )
        for grade, statuses, shields, color in examples:
            with self.subTest(grade=grade):
                svg = self._badge(self._summary(grade, *statuses))
                root = ET.fromstring(svg)
                self.assertEqual(root.tag, "{http://www.w3.org/2000/svg}svg")
                self.assertIn("inferdiff", " ".join(root.itertext()))
                self.assertIn(shields, " ".join(root.itertext()))
                self.assertIn(color, svg)
                self.assertLess(len(svg.encode("utf-8")), 3 * 1024)
                self.assertNotIn("href=", svg)
                self.assertNotIn("https://", svg)
                for sensitive in (_PRIVATE_URL, _API_KEY, _BEARER):
                    self.assertNotIn(sensitive, svg)

    def test_cli_writes_xml_escaped_label_from_summary_file(self):
        label = '<CI & "nightly">'
        stdout, stderr = io.StringIO(), io.StringIO()
        with tempfile.TemporaryDirectory() as tmp:
            summary = Path(tmp) / "doctor_summary.json"
            output = Path(tmp) / "badge.svg"
            summary.write_text(json.dumps(self._summary("A+", "PASS")), encoding="utf-8")
            with redirect_stdout(stdout), redirect_stderr(stderr):
                exit_code = main(["badge", str(summary), "--out", str(output), "--label", label])
            self.assertEqual(exit_code, 0, stderr.getvalue())
            svg = output.read_text(encoding="utf-8")
        self.assertIn("&lt;CI &amp;", svg)
        self.assertIn(label, " ".join(ET.fromstring(svg).itertext()))

    def test_cli_scrubs_credentials_reflected_through_label(self):
        summary = self._summary("A+", "PASS")
        query_key = "synthetic-query-credential"
        summary["target_url"] += f"?key={query_key}"
        short_key = "qz7"
        private_host = "PRIVATE-UPSTREAM.INVALID"
        private_path = "/".join(("Q:", "work", "private"))
        summary["results"][0]["summary"] = f"Reflected Bearer {short_key}"
        labels = (_PRIVATE_URL, _API_KEY, f"Authorization: Bearer {_BEARER}", f"api_key={_BEARER}", query_key,
                  short_key, private_host, private_path)
        for label in labels:
            with self.subTest(label=label):
                svg = self._badge(summary, "--label", label)
                ET.fromstring(svg)
                for sensitive in (_PRIVATE_URL, _API_KEY, _BEARER, query_key, short_key, private_host, private_path):
                    self.assertNotIn(sensitive, svg)
