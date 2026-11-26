"""Regression tests for the v0.2 release hardening pass."""

from __future__ import annotations

import http.server
import io
import json
import math
import re
import tempfile
import threading
import unittest
import xml.etree.ElementTree as ET
from contextlib import contextmanager, redirect_stderr, redirect_stdout, suppress
from pathlib import Path, PurePosixPath
from unittest.mock import MagicMock, patch

from inferdiff.anthropic import inspect_anthropic_stream, record_anthropic_stream
from inferdiff.canary import _http_get_json
from inferdiff.cli import main
from inferdiff.comparison import compare_reports, render_comparison_html
from inferdiff.exporters import _ReportCase, render_junit, render_sarif
from inferdiff.gemini import inspect_gemini_stream, record_gemini_stream
from inferdiff.recorder import RecorderHTTPError, record_stream
from inferdiff.schema import (
    EXIT_USAGE_OR_IO_ERROR, TraceDocument, TraceHeader, TraceSummary, load_trace, strict_json_loads, write_trace,
)
from inferdiff.watch import _send_webhook

from test_comparison_unit import report as comparison_report_fixture
from test_gemini_and_replay import _end, _parts, _serve, _sse
from test_live_contract_comparison import _messages_stream


@contextmanager
def _hardening_http_server():
    requests = []

    class Handler(http.server.BaseHTTPRequestHandler):
        def log_message(self, format, *args):
            pass

        def _write_body(self, body):
            # The client may close an error response as soon as it receives the status.
            with suppress(BrokenPipeError, ConnectionResetError):
                self.wfile.write(body)

        def do_GET(self):
            requests.append(self.path)
            if self.path == "/v1/models":
                self.send_response(302)
                self.send_header("Location", "/redirected")
                self.send_header("Transfer-Encoding", "chunked")
                self.end_headers()
                self._write_body(b"4\r\n\xff")
            else:
                self.send_response(503)
                self.end_headers()
                self._write_body(b"\xff\x00 private-relay-body")

        def do_POST(self):
            requests.append(self.path)
            self.rfile.read(int(self.headers["Content-Length"]))
            self.send_response(307)
            self.send_header("Location", "/redirected")
            self.end_headers()
            self._write_body(b"\xff\x00 private-relay-body")

    with http.server.ThreadingHTTPServer(("127.0.0.1", 0), Handler) as server:
        thread = threading.Thread(target=server.serve_forever, kwargs={"poll_interval": 0.01}, daemon=True)
        thread.start()
        try:
            yield f"http://127.0.0.1:{server.server_port}", requests
        finally:
            server.shutdown()
            thread.join(timeout=2)


class LiveHardeningTests(unittest.TestCase):
    def test_compare_skips_redirect_and_error_bodies_and_preserves_http_status(self):
        stdout, stderr = io.StringIO(), io.StringIO()
        with _hardening_http_server() as (url, requests), redirect_stdout(stdout), redirect_stderr(stderr):
            code = main(["compare", "--a-url", url, "--b-url", url, "--b-model", "mock-model",
                         "--only", "C1", "--timeout", "2", "--out-json", "-"])
        self.assertEqual((code, stderr.getvalue()), (1, ""))
        self.assertEqual(requests, ["/v1/models", "/api/tags", "/v1/chat/completions"])
        check, = json.loads(stdout.getvalue())["checks"]
        self.assertIn("HTTP 302", check["a"]["summary"])
        self.assertIn("HTTP 503", check["a"]["summary"])
        self.assertIn("HTTP 307", check["b"]["summary"])
        self.assertNotIn("private-relay-body", stdout.getvalue())

    def test_discovery_does_not_promote_invalid_utf8_to_a_model_id(self):
        response = MagicMock(status=200)
        response.__enter__.return_value = response
        response.read.return_value = b'{"data":[{"id":"fixture\xff"}]}'
        with patch("inferdiff.canary.http.client.HTTPConnection") as connection:
            connection.return_value.getresponse.return_value = response
            self.assertEqual(_http_get_json("http://example.test/v1/models", {}, 1.0), (200, None))

    def test_doctor_discovery_error_redacts_known_credential_in_endpoint_path(self):
        stdout, stderr = io.StringIO(), io.StringIO()
        with _hardening_http_server() as (url, _), redirect_stdout(stdout), redirect_stderr(stderr):
            code = main(["doctor", url + "/length", "--api-key", "length", "--only", "C1", "--timeout", "2"])
        self.assertEqual(code, 1)
        self.assertEqual(stdout.getvalue(), "")
        self.assertIn("Could not auto-discover model", stderr.getvalue())
        self.assertNotIn("length", stderr.getvalue())

    def test_watch_records_redirect_as_failed_check_and_webhook_delivery(self):
        stdout, stderr = io.StringIO(), io.StringIO()
        with _hardening_http_server() as (url, requests), redirect_stdout(stdout), redirect_stderr(stderr):
            code = main(["watch", "--base-url", url, "--model", "mock-model", "--only", "C6",
                         "--interval", "0", "--max-runs", "1", "--webhook-url", url + "/hook", "--timeout", "2"])
        self.assertEqual(code, 2)
        self.assertEqual(requests, ["/v1/chat/completions", "/hook"])
        self.assertIn("C6 ERROR", stdout.getvalue())
        self.assertIn("Webhook delivery failed", stderr.getvalue())
        self.assertNotIn("private-relay-body", stdout.getvalue() + stderr.getvalue())

    def test_webhook_rejects_non_success_status_and_malformed_feishu_acknowledgment(self):
        opener = MagicMock()
        for feishu, status in ((False, 302), (True, 200)):
            with self.subTest(feishu=feishu, status=status):
                response = opener.open.return_value.__enter__.return_value
                response.status = status
                response.read.return_value = b'{"code":0,"echo":"\xff"}'
                self.assertFalse(_send_webhook(opener, "https://example.test/hook", feishu=feishu,
                                               text="check failed", line="{}\n", timeout=1.0))

    def test_zero_durations_have_no_baseline_ratio_and_render_waterfalls(self):
        a, b = comparison_report_fixture(ttft=0.0, total=0.0), comparison_report_fixture(ttft=40.0, total=80.0)
        a.results[0].traces[0].frames[0].t_rel_ms = 0.0
        a.results[0].traces[0].frames[0].dt_ms = 0.0
        for before, after, expected in ((a, a, None), (a, b, None), (b, a, 0.0)):
            with self.subTest(a=before.results[0].duration_ms, b=after.results[0].duration_ms):
                result = compare_reports(before, after)
                self.assertEqual(result.timing.ttft_ratio, expected)
                self.assertEqual(result.timing.total_latency_ratio, expected)
                self.assertFalse(result.latency_regression)
                self.assertIn("<svg", render_comparison_html(result))
                json.dumps(result.to_dict(), allow_nan=False)

    def test_comparison_keeps_distinct_protocol_enums_that_match_credentials(self):
        a = comparison_report_fixture(finish="length")
        b = comparison_report_fixture(finish="stop")
        result = compare_reports(a, b, known_secrets=["length", "stop"], ignore_timing=True)
        self.assertEqual(result.verdict, "CONTRACT_DRIFT")
        self.assertEqual([diff.field for diff in result.divergences], ["finish_reason"])

        stdout, stderr = io.StringIO(), io.StringIO()
        with patch("inferdiff.cli.run_doctor", side_effect=[a, b]), redirect_stdout(stdout), redirect_stderr(stderr):
            code = main(["compare", "--a-url", "https://a.example.test", "--a-key", "length",
                         "--b-url", "https://b.example.test", "--b-key", "stop", "--only", "C1",
                         "--b-label", "reflected-stop-credential", "--out-json", "-"])
        self.assertEqual((code, stderr.getvalue()), (3, ""))
        payload = json.loads(stdout.getvalue())
        diff, = payload["divergences"]
        self.assertEqual((diff["a"], diff["b"]), ("length", "stop"))
        self.assertNotIn("reflected-stop-credential", stdout.getvalue())


def _replay_cli(*args):
    stdout, stderr = io.StringIO(), io.StringIO()
    with redirect_stdout(stdout), redirect_stderr(stderr):
        status = main(('replay', *(str(arg) for arg in args)))
    return status, stdout.getvalue(), stderr.getvalue()


def _replay_trace(path, *, eof_clean=True):
    doc = TraceDocument(
        TraceHeader('test-trace', '', '', 'openai-chat', {}, {'status_code': 200}),
        [],
        TraceSummary(eof_clean, 0, {}, {'finish_reason': 'stop', 'content_text': 'ok'}),
    )
    write_trace(path, doc)
    return doc


class ReplayHardeningTests(unittest.TestCase):
    def test_replay_matches_windows_and_posix_relative_trace_keys(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            before, after = root / 'before', root / 'after'
            for bundle in (before, after):
                _replay_trace(bundle / 'nested' / 'run.trace.jsonl', eof_clean=False)

            relative_to = type(root).relative_to

            def mixed_separators(path, other):
                relative = relative_to(path, other)
                if other == before and path.name == 'run.trace.jsonl':
                    return PurePosixPath(r'nested\run.trace.jsonl')
                return relative

            with patch.object(type(root), 'relative_to', mixed_separators):
                status, stdout, stderr = _replay_cli(after, '--baseline', before, '--out-json', '-')

            self.assertEqual((status, stderr), (0, ''))
            changes = strict_json_loads(stdout)['regression']
            self.assertEqual(changes['NEW_BREACHES'], [])
            self.assertEqual(changes['FIXED_BREACHES'], [])
            self.assertEqual([breach['trace'] for breach in changes['UNCHANGED']], ['nested/run.trace.jsonl'])

    def test_replay_accepts_alternate_separators_in_relative_bundle_arguments(self):
        with tempfile.TemporaryDirectory(dir=Path.cwd()) as directory:
            root = Path(directory)
            for side in ('before', 'after'):
                _replay_trace(root / side / 'run.trace.jsonl', eof_clean=False)
            status, stdout, stderr = _replay_cli(f'./{root.name}/after', '--baseline',
                                                 rf'.\{root.name}\before', '--out-json', '-')
            self.assertEqual((status, stderr), (0, ''))
            changes = strict_json_loads(stdout)['regression']
            self.assertEqual([breach['trace'] for breach in changes['UNCHANGED']], ['run.trace.jsonl'])

    def test_replay_rejects_corrupt_jsonl_before_writing_reports(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            bundle = root / 'bundle'
            clean = bundle / 'clean.trace.jsonl'
            doc = _replay_trace(clean)
            header = clean.read_bytes().split(b'\n', 1)[0] + b'\n'
            broken = bundle / 'broken.trace.jsonl'
            output = root / 'report.json'
            malformed_summary = doc.summary.to_dict()
            malformed_summary['assembled']['protocol_violations'] = {'unexpected': True}
            cases = (
                (b'{"type":"summary",', 'invalid JSON'),
                (b'[]\n', 'JSON record must be an object'),
                (b'\xff\n', 'UTF-8'),
                (b'', 'header + summary'),
                (json.dumps(malformed_summary).encode('ascii'), 'protocol_violations'),
                (b'{"type":"summary","timing":NaN}', 'invalid JSON'),
            )
            for line, reason in cases:
                with self.subTest(reason=reason):
                    broken.write_bytes(header + line)
                    status, stdout, stderr = _replay_cli(bundle, '--out-json', output)
                    self.assertEqual((status, stdout), (EXIT_USAGE_OR_IO_ERROR, ''))
                    self.assertIn(broken.name, stderr)
                    self.assertIn(reason, stderr)
                    self.assertNotIn(str(root), stderr)
                    self.assertFalse(output.exists())

            status, stdout, stderr = _replay_cli(clean, '--baseline', bundle, '--out-json', output)
            self.assertEqual((status, stdout), (EXIT_USAGE_OR_IO_ERROR, ''))
            self.assertIn(f"Replay baseline trace '{broken.name}':2", stderr)
            self.assertFalse(output.exists())

    def test_replay_accepts_unicode_separators_inside_jsonl_strings(self):
        with tempfile.TemporaryDirectory() as directory:
            trace = Path(directory) / 'unicode.trace.jsonl'
            doc = _replay_trace(trace)
            doc.summary.assembled['content_text'] = 'first\x85second\u2028third\u2029last'
            records = (doc.header.to_dict(), doc.summary.to_dict())
            trace.write_text('\n'.join(json.dumps(record, ensure_ascii=False) for record in records), encoding='utf-8')
            status, stdout, stderr = _replay_cli(trace, '--out-json', '-')
            self.assertEqual((status, stderr), (0, ''))
            self.assertEqual(strict_json_loads(stdout)['traces'][0]['findings'], [])

    def test_replay_rejects_empty_or_missing_bundle_on_either_side(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            complete, empty, missing = root / 'complete', root / 'empty', root / 'missing'
            _replay_trace(complete / 'run.trace.jsonl', eof_clean=False)
            empty.mkdir()
            for path, baseline, reason in (
                (empty, complete, 'No .trace.jsonl files'),
                (complete, empty, 'No .trace.jsonl files'),
                (missing, complete, 'Replay input'),
                (complete, missing, '--baseline'),
            ):
                with self.subTest(path=path.name, baseline=baseline.name):
                    status, stdout, stderr = _replay_cli(path, '--baseline', baseline)
                    self.assertEqual((status, stdout), (EXIT_USAGE_OR_IO_ERROR, ''))
                    self.assertIn(reason, stderr)

    def test_replay_pair_accepts_absent_optional_output_counts(self):
        with tempfile.TemporaryDirectory() as directory:
            before, after = Path(directory) / 'before', Path(directory) / 'after'
            for bundle, total_ms in ((before, 100.0), (after, 10.0)):
                trace = bundle / 'run.trace.jsonl'
                doc = _replay_trace(trace)
                doc.summary.assembled['content_utf8_bytes'] = None
                doc.summary.assembled['observed_delta_frames'] = None
                doc.summary.timing['total_ms'] = total_ms
                write_trace(trace, doc)
            status, stdout, stderr = _replay_cli(after, '--baseline', before, '--out-json', '-')
            self.assertEqual((status, stderr), (0, ''))
            self.assertEqual(strict_json_loads(stdout)['regression']['NEW_BREACHES'], [])


class ReportHardeningTests(unittest.TestCase):
    def test_junit_removes_illegal_xml_characters_from_names_and_messages(self):
        forbidden = ''.join(chr(code) for code in (*range(9), 11, 12, *range(14, 32))) + '\ud800\ufffe\uffff'
        case = _ReportCase('C10', f'Relay{forbidden}', f'compare{forbidden}',
                           outcomes=(('FAIL', f'<wire>\t&\n🚀{forbidden}'),))
        xml = render_junit([case])
        testcase = ET.fromstring(xml).find('.//testcase')
        self.assertEqual(testcase.get('name').strip(), 'C10 Relay')
        self.assertEqual(testcase.get('classname').strip(), 'inferdiff.compare')
        self.assertEqual(testcase.find('failure').get('message').rstrip(), '<wire>\t&\n🚀')
        for char in forbidden:
            self.assertNotIn(char, xml)

    def test_export_reports_allow_missing_optional_fields_and_finite_durations(self):
        cases = [
            _ReportCase('C10', 'relay_error', 'canary', endpoint=None, outcomes=(('FAIL', None),), duration_seconds=float('nan')),
            _ReportCase(None, 'comparison_error', 'compare', outcomes=(('ERROR', None),), duration_seconds=float('inf')),
            _ReportCase('C9', 'normal', 'canary', duration_seconds=None),
        ]
        sarif = strict_json_loads(render_sarif(cases))
        finding, = sarif['runs'][0]['results']
        self.assertEqual(finding['message']['text'], 'C10')
        suite = ET.fromstring(render_junit(cases)).find('testsuite')
        self.assertTrue(math.isfinite(float(suite.get('time'))))
        self.assertEqual([float(case.get('time')) for case in suite.findall('testcase')], [0.0, 0.0, 0.0])
        self.assertEqual(suite.find('.//failure').get('message'), 'FAIL')


class ActionHardeningTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        path = Path(__file__).resolve().parents[1]
        cls.action = (path / "action.yml").read_text(encoding="utf-8")

    def test_action_preserves_legacy_inputs_and_defaults(self):
        inputs = self.action.split("\ninputs:\n", 1)[1].split("\noutputs:\n", 1)[0]
        defaults = dict(re.findall(r'^  ([\w-]+):\n(?:    .+\n)*?    default: "([^"]*)"$', inputs, re.M))
        legacy = {
            "url": "", "model": "", "api-key": "", "profile": "quick", "strict": "false",
            "before-trace": "", "after-trace": "", "fail-on": "p0", "html-out": "inferdiff-report.html",
            "upload-artifact": "true", "artifact-name": "inferdiff-waterfall", "version": "0.1.1",
        }
        for name, default in legacy.items():
            with self.subTest(name=name):
                self.assertEqual(defaults.get(name), default)
        self.assertIn("value: ${{ steps.run.outputs.exit_code }}", self.action)
        self.assertIn("value: ${{ inputs.html-out }}", self.action)
        self.assertIn("if: always() && inputs.upload-artifact == 'true'", self.action)

    def test_action_wires_reports_in_both_modes(self):
        inputs, runs = self.action.split("\nruns:\n", 1)
        for name, key, option in (
            ("sarif-output", "INPUT_SARIF", "--out-sarif"),
            ("junit-output", "INPUT_JUNIT", "--out-junit"),
        ):
            with self.subTest(name=name):
                self.assertRegex(inputs, rf'(?m)^  {name}:\n    description: .+\n    required: false\n    default: ""$')
                self.assertIn(f"{key}: ${{{{ inputs.{name} }}}}", runs)
                self.assertIn(f'[[ -n "${{{key}}}" ]] && report_args+=({option} "${{{key}}}")', runs)
        self.assertIn('args=(doctor ', runs)
        self.assertIn('inferdiff diff ', runs)
        self.assertEqual(runs.count('"${report_args[@]}"'), 2)
        self.assertIn('python -m pip install --quiet "${GITHUB_ACTION_PATH}"', runs)


class ProtocolCredentialHardeningTests(unittest.TestCase):
    def test_gemini_api_key_collision_preserves_finish_reason(self):
        for key, finish_reason in (("MAX_TOKENS", "MAX_TOKENS"), ("STOP", "STOP"), ("event", "MAX_TOKENS")):
            first = _parts({"text": f"echoed {key}"})
            first["debug"] = {"finishReason": key, "x-goog-api-key": "opaque-header-example"}
            wire = _sse(first, _end(finish_reason, candidates=8))
            with self.subTest(key=key), tempfile.TemporaryDirectory() as folder, _serve(
                lambda _: (200, wire)
            ) as (host, requests):
                path = Path(folder) / "gemini.trace.jsonl"
                doc = record_gemini_stream(
                    url=f"{host}/proxy/{key}/v1beta/models/demo:streamGenerateContent?key={key}",
                    request_body={}, out_path=path, timeout=2,
                )
                self.assertEqual(requests[0][1].get("x-goog-api-key"), key)
                for trace in (doc, load_trace(path)):
                    contract = inspect_gemini_stream(trace, max_tokens=8)
                    self.assertEqual(contract.finish_reason, finish_reason)
                    self.assertEqual(bool(contract.violations), finish_reason == "STOP")
                    self.assertEqual(trace.summary.assembled["finish_reason"], finish_reason)
                    self.assertNotIn(key, trace.summary.assembled["content_text"])
                    self.assertNotIn(key, trace.header.request["url"])
                    self.assertNotIn(key, trace.header.request["headers_redacted"]["x-goog-api-key"])
                    self.assertNotIn(f"echoed {key}", trace.frames[0].raw_wire)
                    self.assertNotIn(f'"finishReason": "{key}"', trace.frames[0].raw_wire)
                    self.assertNotIn("opaque-header-example", trace.frames[0].raw_wire)

    def test_anthropic_api_key_collision_preserves_stop_reason(self):
        key = "max_tokens"
        wire = _messages_stream({"model": "demo", "max_tokens": 8}, delta_type="text_delta", reason=key)
        wire = wire.replace(b"1, 2, 3, 4, 5, 6,", b"echoed max_tokens")
        with tempfile.TemporaryDirectory() as folder, _serve(lambda _: (200, wire)) as (host, _):
            path = Path(folder) / "anthropic.trace.jsonl"
            doc = record_anthropic_stream(
                url=f"{host}/v1/messages", request_body={"max_tokens": 8},
                headers={"x-api-key": key}, out_path=path, timeout=2,
            )
            for trace in (doc, load_trace(path)):
                contract = inspect_anthropic_stream(trace, max_tokens=8)
                self.assertEqual(contract.violations, ())
                self.assertEqual(contract.stop_reason, key)
                self.assertEqual(trace.summary.assembled["finish_reason"], key)
                self.assertNotIn(key, trace.summary.assembled["content_text"])
                self.assertNotIn(key, trace.header.request["headers_redacted"]["x-api-key"])

    def test_chat_api_key_collision_preserves_length(self):
        key = "length"
        wire = _sse(
            {"choices": [{"delta": {"content": "echoed length"}}]},
            {"choices": [{"delta": {}, "finish_reason": "length"}]},
        ) + b"data: [DONE]\n\n"
        with tempfile.TemporaryDirectory() as folder, _serve(lambda _: (200, wire)) as (host, _):
            path = Path(folder) / "chat.trace.jsonl"
            doc = record_stream(
                url=f"{host}/v1/chat/completions", request_body={},
                headers={"Authorization": f"Bearer {key}"}, out_path=path, timeout=2,
            )
            for trace in (doc, load_trace(path)):
                self.assertEqual(trace.summary.assembled["finish_reason"], key)
                self.assertNotIn(key, trace.summary.assembled["content_text"])
                self.assertNotIn(key, trace.header.request["headers_redacted"]["authorization"])
                self.assertNotIn(f"echoed {key}", trace.frames[0].raw_wire)

    def test_responses_api_key_collision_preserves_typed_terminal_status(self):
        key = "completed"
        wire = (
            b'event: response.output_text.delta\r\ndata: {"type":"response.output_text.delta",'
            b'"delta":"echoed completed"}\r\n\r\n'
            b'event: response.completed\r\ndata: {"type":"response.completed",\r\n'
            b'data: "response":{"status":"completed"}}\r\n\r\n'
        )
        with tempfile.TemporaryDirectory() as folder, _serve(lambda _: (200, wire)) as (host, _):
            path = Path(folder) / "responses.trace.jsonl"
            doc = record_stream(
                url=f"{host}/v1/responses", request_body={},
                headers={"Authorization": f"Bearer {key}"}, out_path=path, timeout=2,
            )
            for trace in (doc, load_trace(path)):
                self.assertTrue(trace.summary.eof_clean)
                self.assertEqual(trace.summary.assembled["terminal_status"], key)
                self.assertEqual(trace.frames[-1].sse_event, "response.completed")
                self.assertIn('"status":"completed"', trace.frames[-1].raw_wire)
                self.assertNotIn(key, trace.summary.assembled["content_text"])
                self.assertNotIn(f"echoed {key}", trace.frames[0].raw_wire)

    def test_chat_tool_calls_key_collision_keeps_tool_structure(self):
        key = "tool_calls"
        wire = _sse(
            {"choices": [{"delta": {"tool_calls": [{"index": 0, "id": "call_1", "type": "function",
                "function": {"name": "mock_tool", "arguments": '{"argument":"tool_calls"}'},
            }]}}]},
            {"choices": [{"delta": {}, "finish_reason": key}]},
        ) + b"data: [DONE]\n\n"
        with _serve(lambda _: (200, wire)) as (host, _):
            doc = record_stream(
                url=f"{host}/v1/chat/completions", request_body={}, headers={"x-api-key": key}, timeout=2,
            )
        self.assertEqual(doc.summary.assembled["finish_reason"], key)
        (tool,) = doc.summary.assembled["tool_calls"]
        self.assertTrue(tool["json_valid"])
        self.assertNotIn(key, tool["raw_arguments"])

    def test_gemini_api_key_collision_is_hidden_from_http_error(self):
        key = "MAX_TOKENS"
        with _serve(lambda _: (502, b"echoed MAX_TOKENS")) as (host, _):
            with self.assertRaises(RecorderHTTPError) as caught:
                record_gemini_stream(
                    url=f"{host}/proxy/{key}/v1beta/models/demo:streamGenerateContent?key={key}",
                    request_body={}, timeout=2,
                )
        self.assertEqual(caught.exception.status_code, 502)
        self.assertNotIn(key, str(caught.exception))

    def test_malformed_gemini_json_scrubs_escaped_key_reflections(self):
        wire = b'data: {"error":"echoed \\u004dAX_TOKENS"\n\n'
        with tempfile.TemporaryDirectory() as folder, _serve(lambda _: (200, wire)) as (host, _):
            path = Path(folder) / "gemini.trace.jsonl"
            doc = record_gemini_stream(
                url=f"{host}/v1beta/models/demo:streamGenerateContent?key=MAX_TOKENS",
                request_body={}, out_path=path, timeout=2,
            )
            self.assertTrue(doc.frames[0].parse_error.startswith("invalid_json:"))
            self.assertNotIn(r"\u004dAX_TOKENS", load_trace(path).frames[0].raw_wire)

    def test_gemini_key_matching_decoder_error_preserves_encoding_diagnostic(self):
        wire = b'data: {"error":"echoed invalid_utf8 \xff"}\n\n'
        with _serve(lambda _: (200, wire)) as (host, _):
            doc = record_gemini_stream(
                url=f"{host}/v1beta/models/demo:streamGenerateContent?key=invalid_utf8",
                request_body={}, timeout=2,
            )
        self.assertEqual(doc.frames[0].parse_error, "invalid_utf8")
        self.assertNotIn("invalid_utf8", doc.frames[0].raw_wire)
        self.assertTrue(any("invalid UTF-8" in item for item in inspect_gemini_stream(doc, max_tokens=8).violations))


if __name__ == "__main__":
    unittest.main()
