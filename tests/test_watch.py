"""Exercise continuous canaries, throttling and webhook delivery."""

from __future__ import annotations

import http.server
import io
import json
import tempfile
import threading
import unittest
from contextlib import contextmanager, redirect_stderr, redirect_stdout
from pathlib import Path
from types import SimpleNamespace
from urllib.parse import urlsplit
from unittest.mock import patch

from inferdiff.canary import PROBE_CATALOG, DoctorReport, ProbeResult
from inferdiff.cli import main
from inferdiff.recorder import RecorderError
from inferdiff.schema import strict_json_loads


API_KEY = "inference-key-fixture"
HEADER_VALUE = "private-session-value"
QUERY_SECRET = "query-secret-fixture"
HOOK_SECRET = "webhook-secret-fixture"


def _chat_stream(passed: bool) -> bytes:
    content = "\u541e\u5410\u91cf\u0394=99.8% [\U0001f525\U0001f680\U0001f9ea\U0001f30a]" if passed else (
        f"\ufffd {API_KEY} {HEADER_VALUE} {QUERY_SECRET} {HOOK_SECRET}"
    )
    events = [
        {"choices": [{"index": 0, "delta": {"role": "assistant", "content": content}}]},
        {"choices": [{"index": 0, "delta": {}, "finish_reason": "stop"}]},
    ]
    return ("".join(f"data: {json.dumps(event)}\n\n" for event in events) + "data: [DONE]\n\n").encode()


@contextmanager
def _server(*cycles: bool, webhook_status: int = 200, webhook_code: int = 0):
    responses = iter(cycles)
    requests = []
    webhooks = []

    class Handler(http.server.BaseHTTPRequestHandler):
        def log_message(self, format, *args):
            pass

        def do_POST(self):
            body = strict_json_loads(self.rfile.read(int(self.headers["Content-Length"])).decode())
            headers = {key.lower(): value for key, value in self.headers.items()}
            path = urlsplit(self.path).path
            if path.endswith("/chat/completions"):
                requests.append((self.path, headers, body))
                passed = next(responses, None)
                if passed is None:
                    self.send_error(500)
                    return
                data = _chat_stream(passed)
                response_status, content_type = 200, "text/event-stream"
            else:
                webhooks.append((self.path, headers, body))
                data = json.dumps({"code": webhook_code, "echo": HOOK_SECRET}).encode()
                response_status, content_type = webhook_status, "application/json"
            self.send_response(response_status)
            self.send_header("Content-Type", content_type)
            self.send_header("Content-Length", str(len(data)))
            if response_status == 307:
                self.send_header("Location", "/redirected")
            self.end_headers()
            self.wfile.write(data)

    with http.server.ThreadingHTTPServer(("127.0.0.1", 0), Handler) as server:
        thread = threading.Thread(target=server.serve_forever, kwargs={"poll_interval": 0.01}, daemon=True)
        thread.start()
        try:
            yield f"http://127.0.0.1:{server.server_port}", requests, webhooks
        finally:
            server.shutdown()
            thread.join(timeout=2)


def _run_cli(origin: str, *flags: str) -> tuple[int, str, str]:
    stdout, stderr = io.StringIO(), io.StringIO()
    with redirect_stdout(stdout), redirect_stderr(stderr):
        code = main(("watch", "--base-url", f"{origin}/v1?credential={QUERY_SECRET}", "--model", "mock-model",
                     "--api-key", API_KEY, "--header", f"X-Session-Token: {HEADER_VALUE}",
                     "--only", "C6", "--interval", "0", "--timeout", "1", *flags))
    return code, stdout.getvalue(), stderr.getvalue()


class TestWatchHTTP(unittest.TestCase):
    def test_short_query_secret_does_not_change_the_model_on_the_wire(self):
        for secret, model in (("a", "llama"), ("mock", "mock-model")):
            with self.subTest(secret=secret), _server(True) as (origin, requests, _):
                code, _, stderr = _run_cli(origin, "--base-url", f"{origin}/v1?token={secret}", "--model", model,
                                           "--max-runs", "1")
            self.assertEqual(code, 0, stderr)
            self.assertEqual(requests[0][2]["model"], model)

    def test_transitions_send_only_failure_and_recovery(self):
        with _server(True, False, False, True) as (origin, requests, webhooks), tempfile.TemporaryDirectory() as tmp:
            out = Path(tmp) / "nested" / "watch.jsonl"
            code, stdout, stderr = _run_cli(origin, "--max-runs", "4", "--cooldown", "60",
                                            "--webhook-url", f"{origin}/hook/{HOOK_SECRET}",
                                            "--out-jsonl", str(out))
            self.assertEqual(code, 0, stderr)
            raw = out.read_text(encoding="utf-8")

        records = [strict_json_loads(line) for line in raw.splitlines()]
        self.assertEqual([record["run"] for record in records], [1, 2, 3, 4])
        self.assertEqual([record["status"] for record in records], ["PASS", "FAIL", "FAIL", "PASS"])
        self.assertEqual([record["event"] for record in records], [None, "FAIL", None, "RECOVERED"])
        self.assertEqual([item[2] for item in webhooks], [records[1], records[3]])
        self.assertEqual(len(requests), 4)
        self.assertTrue(all(headers["authorization"] == f"Bearer {API_KEY}" and
                            headers["x-session-token"] == HEADER_VALUE for _, headers, _ in requests))
        for _, headers, _ in webhooks:
            self.assertEqual(headers["content-type"], "application/json")
            self.assertNotIn("authorization", headers)
            self.assertNotIn("x-session-token", headers)
        self.assertIn("RECOVERED", stdout)
        self.assertEqual(stderr, "")
        for secret in (API_KEY, HEADER_VALUE, QUERY_SECRET, HOOK_SECRET):
            self.assertNotIn(secret, stdout + stderr + raw)

    def test_max_runs_three_appends_and_retains_breach_exit_if_requested(self):
        with tempfile.TemporaryDirectory() as tmp:
            out = Path(tmp) / "watch.jsonl"
            out.write_text('{"previous":true}', encoding="utf-8")
            with _server(True, False, True) as (origin, requests, _):
                code, _, stderr = _run_cli(origin, "--max-runs", "3", "--fail-on-breach", "--out-jsonl", str(out))
                self.assertEqual(code, 2, stderr)
            records = [strict_json_loads(line) for line in out.read_text(encoding="utf-8").splitlines()]
        self.assertEqual(len(requests), 3)
        self.assertEqual(records[0], {"previous": True})
        self.assertEqual([record["event"] for record in records[1:]], [None, "FAIL", "RECOVERED"])

    def test_last_run_unhealthy_exits_two_and_cooldown_zero_sends_each_failure(self):
        with _server(False, False) as (origin, requests, webhooks):
            code, _, stderr = _run_cli(origin, "--max-runs", "2", "--cooldown", "0",
                                       "--webhook-url", f"{origin}/hook/{HOOK_SECRET}")
        self.assertEqual(code, 2, stderr)
        self.assertEqual(len(requests), 2)
        self.assertEqual([request[2]["event"] for request in webhooks], ["FAIL", "FAIL"])

    def test_feishu_hosts_use_text_payload_over_http(self):
        for hostname in ("open.feishu.cn", "open.larksuite.com", "larksuite.com"):
            with self.subTest(hostname=hostname), _server(False, True) as (origin, _, webhooks):
                # Route the fake Feishu host to our loopback server without changing URL detection.
                with patch("urllib.request.getproxies", return_value={"http": origin}), patch(
                    "urllib.request.proxy_bypass", return_value=False,
                ):
                    code, _, stderr = _run_cli(origin, "--max-runs", "2", "--webhook-url",
                                               f"http://{hostname}/open-apis/bot/v2/hook/{HOOK_SECRET}")
                self.assertEqual(code, 0, stderr)
                self.assertEqual([urlsplit(item[0]).hostname for item in webhooks], [hostname, hostname])
                self.assertEqual([item[2] for item in webhooks], [
                    {"msg_type": "text", "content": {"text": "inferdiff watch run 1 FAIL (C6 FAIL)"}},
                    {"msg_type": "text", "content": {"text": "inferdiff watch run 2 RECOVERED"}},
                ])

    def test_webhook_error_is_redacted_and_cycles_continue(self):
        for status in (500, 307):
            with self.subTest(status=status), _server(False, True, webhook_status=status) as (origin, requests, webhooks):
                code, stdout, stderr = _run_cli(origin, "--max-runs", "2", "--webhook-url",
                                               f"{origin}/hook/{HOOK_SECRET}")
                self.assertEqual(code, 0, stderr)
                self.assertEqual(len(requests), 2)
                self.assertEqual(len(webhooks), 2)
                self.assertEqual(stderr.count("Webhook delivery failed"), 2)
                self.assertNotIn(HOOK_SECRET, stdout + stderr)

    def test_feishu_application_failure_is_reported_without_response_body(self):
        with _server(False, webhook_code=19024) as (origin, _, webhooks), patch(
            "urllib.request.getproxies", return_value={"http": origin},
        ), patch("urllib.request.proxy_bypass", return_value=False):
            code, stdout, stderr = _run_cli(origin, "--max-runs", "1", "--webhook-url",
                                           f"http://open.feishu.cn/open-apis/bot/v2/hook/{HOOK_SECRET}")
        self.assertEqual(code, 2, stderr)
        self.assertEqual(len(webhooks), 1)
        self.assertIn("Webhook delivery failed", stderr)
        self.assertNotIn(HOOK_SECRET, stdout + stderr)

    def test_invalid_schedule_fails_without_contacting_endpoint(self):
        with _server() as (origin, requests, _):
            for flags in (("--interval", "NaN"), ("--cooldown", "inf"), ("--max-runs", "-1"),
                          ("--timeout", "0"), ("--timeout", "1e200")):
                with self.subTest(flags=flags):
                    code, stdout, stderr = _run_cli(origin, *flags)
                    self.assertEqual(code, 1, stderr)
                    self.assertEqual(stdout, "")
                    self.assertIn(flags[0], stderr)
        self.assertEqual(requests, [])

    def test_invalid_credentials_report_only_the_option_name(self):
        with _server() as (origin, requests, _):
            for flags, secret in ((("--api-key", f"${API_KEY}"), API_KEY),
                                  (("--webhook-url", f"http://{HOOK_SECRET}@127.0.0.1/"), HOOK_SECRET)):
                with self.subTest(option=flags[0]):
                    code, stdout, stderr = _run_cli(origin, "--max-runs", "1", *flags)
                    self.assertEqual(code, 1, stderr)
                    self.assertEqual(stdout, "")
                    self.assertIn(flags[0], stderr)
                    self.assertNotIn(secret, stderr)
        self.assertEqual(requests, [])


def _report(status: str) -> DoctorReport:
    code, severity, reference = PROBE_CATALOG["C6"]
    result = ProbeResult("C6", code, severity, status, API_KEY, float("nan"), 0, None, reference)
    return DoctorReport("https://example.test", "https://example.test/v1/chat/completions", "openai-chat",
                        API_KEY, "quick", "F", 2, 0, 0, 0, None, None, results=[result])


class TestWatchClock(unittest.TestCase):
    def test_monotonic_schedule_skips_missed_ticks_after_overrun(self):
        now = 100.0
        starts = []
        durations = iter((0.5, 5.0, 0.0))

        def canary(**options):
            nonlocal now
            starts.append(now)
            now += next(durations)
            return _report("PASS")

        def sleep(seconds):
            nonlocal now
            now += seconds

        with patch("inferdiff.watch.run_doctor", side_effect=canary), patch(
            "inferdiff.watch.time", SimpleNamespace(monotonic=lambda: now, sleep=sleep),
        ):
            code, _, stderr = _run_cli("http://127.0.0.1", "--interval", "2", "--max-runs", "3")
        self.assertEqual(code, 0, stderr)
        self.assertEqual(starts, [100.0, 102.0, 108.0])

    def test_cooldown_expires_and_next_outage_alerts_immediately(self):
        now = 100.0

        def sleep(seconds):
            nonlocal now
            now += seconds

        with tempfile.TemporaryDirectory() as tmp, patch(
            "inferdiff.watch.run_doctor", side_effect=map(_report, ("FAIL", "FAIL", "FAIL", "PASS", "FAIL")),
        ), patch("inferdiff.watch.time", SimpleNamespace(monotonic=lambda: now, sleep=sleep)):
            out = Path(tmp) / "watch.jsonl"
            code, _, stderr = _run_cli("http://127.0.0.1", "--interval", "2", "--max-runs", "5",
                                       "--cooldown", "4", "--out-jsonl", str(out))
            records = [strict_json_loads(line) for line in out.read_text(encoding="utf-8").splitlines()]
        self.assertEqual(code, 2, stderr)
        self.assertEqual([record["event"] for record in records], ["FAIL", None, "FAIL", "RECOVERED", "FAIL"])

    def test_interrupt_while_waiting_keeps_last_result_and_record(self):
        def interrupt(seconds):
            raise KeyboardInterrupt

        with tempfile.TemporaryDirectory() as tmp, patch("inferdiff.watch.run_doctor", return_value=_report("FAIL")), patch(
            "inferdiff.watch.time", SimpleNamespace(monotonic=lambda: 100.0, sleep=interrupt),
        ):
            out = Path(tmp) / "watch.jsonl"
            code, stdout, stderr = _run_cli("http://127.0.0.1", "--interval", "1", "--out-jsonl", str(out))
            records = [strict_json_loads(line) for line in out.read_text(encoding="utf-8").splitlines()]
        self.assertEqual(code, 2, stderr)
        self.assertEqual(stderr, "")
        self.assertIn("Stopped", stdout)
        self.assertEqual([record["status"] for record in records], ["FAIL"])

    def test_interrupt_during_first_run_stops_cleanly(self):
        with patch("inferdiff.watch.run_doctor", side_effect=KeyboardInterrupt):
            code, stdout, stderr = _run_cli("http://127.0.0.1")
        self.assertEqual(code, 0, stderr)
        self.assertEqual(stderr, "")
        self.assertIn("Stopped", stdout)

    def test_recorder_error_recovers_without_logging_external_details(self):
        with tempfile.TemporaryDirectory() as tmp, patch(
            "inferdiff.watch.run_doctor", side_effect=[RecorderError(f"Authentication failed: {API_KEY}"), _report("WARN")],
        ):
            out = Path(tmp) / "watch.jsonl"
            code, stdout, stderr = _run_cli("http://127.0.0.1", "--max-runs", "2", "--out-jsonl", str(out))
            raw = out.read_text(encoding="utf-8")
        self.assertEqual(code, 0, stderr)
        self.assertEqual([strict_json_loads(line)["event"] for line in raw.splitlines()], ["FAIL", "RECOVERED"])
        self.assertNotIn(API_KEY, raw + stdout + stderr)


if __name__ == "__main__":
    unittest.main()
