"""Verify Prometheus exposition, scrape access and the Grafana template."""

from __future__ import annotations

import http.client
import io
import json
import math
import os
import re
import tempfile
import threading
import time
import unittest
from concurrent.futures import ThreadPoolExecutor
from contextlib import closing, redirect_stderr, redirect_stdout
from pathlib import Path
from unittest.mock import patch

from inferdiff.canary import run_doctor
from inferdiff.cli import main
from inferdiff.detectors import Finding
from test_proxy import BODY, CHAT_PATH, FIRST, TERMINAL, _breach, _proxy, _reply, _response, _upstream
from test_watch import API_KEY, HEADER_VALUE, QUERY_SECRET, _run_cli, _server


METRICS_PATH = "/_inferdiff/metrics"
CONTENT_TYPE = "text/plain; version=0.0.4; charset=utf-8"
_SAMPLE = re.compile(r'([a-z_][a-z0-9_]*(?:\{[a-z]+="[^"]+"(?:,[a-z]+="[^"]+")*\})?) (\S+)')


def _samples(raw: str) -> dict[str, float]:
    samples = {}
    for line in raw.splitlines():
        if line.startswith("#"):
            continue
        match = _SAMPLE.fullmatch(line)
        if match is None or match[1] in samples:
            raise AssertionError(f"Invalid or duplicate sample: {line}")
        samples[match[1]] = float(match[2])
    return samples


class TestProxyMetrics(unittest.TestCase):
    def scrape(self, port, *, requests=0):
        deadline = time.monotonic() + 3
        while True:
            with _response(port, "GET", METRICS_PATH) as response:
                self.assertEqual(response.status, 200)
                self.assertEqual(response.headers["Content-Type"], CONTENT_TYPE)
                raw = response.read().decode("utf-8")
            samples = _samples(raw)
            if sum(value for key, value in samples.items() if key.startswith("inferdiff_proxy_requests_total{")) >= requests:
                return raw, samples
            if time.monotonic() >= deadline:
                self.fail(f"Metrics did not report {requests} completed proxy requests")
            time.sleep(0.01)

    def test_exposition_has_metadata_cumulative_buckets_and_bounded_labels(self):
        from inferdiff.metrics import ProxyMetrics

        metrics = ProxyMetrics()
        findings = [Finding("D1", "CODE", "P0", "private detail"),
                    Finding("untrusted detector", "CODE", "P0", ""),
                    Finding("D2", "CODE", "P2", "")]
        for delay in (0, 50, 75, 250, 5000, 6000, None, float("nan")):
            metrics.record_request("untrusted dialect", "primary", True, findings, delay)
        raw = metrics.render(failovers_total=0).decode("utf-8")
        self.assertTrue(raw.endswith("\n"))
        self.assertNotIn("\r", raw)
        self.assertNotRegex(raw, r"untrusted|private detail|P2")
        for name, metric_type in (
            ("requests_total", "counter"), ("streaming_requests_total", "counter"),
            ("findings_total", "counter"), ("failovers_total", "counter"),
            ("ttft_ms", "histogram"), ("active_streams", "gauge"),
        ):
            name = f"inferdiff_proxy_{name}"
            self.assertIn(f"# HELP {name} ", raw)
            self.assertIn(f"# TYPE {name} {metric_type}\n", raw)
        samples = _samples(raw)
        self.assertEqual(
            [(key, value) for key, value in samples.items() if key.startswith("inferdiff_proxy_ttft_ms_bucket")],
            [(f'inferdiff_proxy_ttft_ms_bucket{{le="{bound}"}}', value) for bound, value in
             zip(("50", "100", "250", "500", "1000", "2500", "5000", "+Inf"), (2, 3, 4, 4, 4, 4, 5, 6))],
        )
        self.assertEqual(samples["inferdiff_proxy_ttft_ms_sum"], 11375)
        self.assertEqual(samples["inferdiff_proxy_ttft_ms_count"], 6)
        self.assertEqual(samples['inferdiff_proxy_requests_total{dialect="other",upstream="primary"}'], 8)
        self.assertEqual(samples['inferdiff_proxy_findings_total{detector="D1",severity="P0"}'], 8)

    def test_headless_metrics_report_live_requests_findings_and_failover_privately(self):
        primary_key = "fixture-primary-secret"
        fallback_key = "fixture-fallback-secret"
        request_key = "fixture-request-secret"
        model = "fixture-untrusted-header-model"
        raw_path = "/fixture-private-upstream-path"

        def respond(handler):
            if handler.command == "GET":
                _reply(handler, b"{}", content_type="application/json")
            else:
                _reply(handler, b"", status=503)

        wire = FIRST + _breach(model)
        with (
            _upstream(respond) as (primary, primary_requests),
            _upstream(lambda h: _reply(h, wire)) as (fallback, fallback_requests),
            _proxy(f"{primary}{raw_path}?key={primary_key}", fallback_url=fallback,
                   fallback_api_key=fallback_key, no_ui=True) as (port, _),
        ):
            _, initial = self.scrape(port)
            self.assertEqual(initial["inferdiff_proxy_failovers_total"], 0)
            with _response(port, "GET", "/_inferdiff/status") as response:
                self.assertEqual(response.status, 404)
                response.read()
            with _response(port, "GET", "/v1/models") as response:
                self.assertEqual(response.read(), b"{}")
            with _response(port, "POST", CHAT_PATH, body=BODY, headers={
                "Authorization": f"Bearer {request_key}", "X-Model": model,
            }) as response:
                self.assertEqual(response.headers["X-Inferdiff-Upstream"], "fallback")
                self.assertEqual(response.read(), wire)
            raw, samples = self.scrape(port, requests=2)
        self.assertEqual(len(primary_requests), 2)
        self.assertEqual(len(fallback_requests), 1)
        self.assertEqual(samples['inferdiff_proxy_requests_total{dialect="other",upstream="primary"}'], 1)
        self.assertEqual(samples['inferdiff_proxy_requests_total{dialect="openai-chat",upstream="fallback"}'], 1)
        self.assertEqual(samples['inferdiff_proxy_streaming_requests_total{dialect="openai-chat"}'], 1)
        self.assertGreaterEqual(samples['inferdiff_proxy_findings_total{detector="D1",severity="P0"}'], 1)
        self.assertEqual(samples["inferdiff_proxy_failovers_total"], 1)
        self.assertEqual(samples["inferdiff_proxy_ttft_ms_count"], 1)
        self.assertEqual(samples["inferdiff_proxy_active_streams"], 0)
        for secret in (primary, fallback, raw_path, primary_key, fallback_key, request_key, model, CHAT_PATH):
            self.assertNotIn(secret, raw)

    def test_active_stream_gauge_tracks_in_progress_response(self):
        release = threading.Event()

        def respond(handler):
            handler.send_response(200)
            handler.send_header("Content-Type", "text/event-stream")
            handler.send_header("Content-Length", str(len(FIRST + TERMINAL)))
            handler.end_headers()
            handler.wfile.write(FIRST)
            release.wait(timeout=5)
            handler.wfile.write(TERMINAL)

        with _upstream(respond) as (origin, _), _proxy(origin) as (port, _):
            with _response(port, "POST", CHAT_PATH, body=BODY) as response:
                try:
                    self.assertEqual(response.read(len(FIRST)), FIRST)
                    _, active = self.scrape(port)
                    self.assertEqual(active["inferdiff_proxy_active_streams"], 1)
                finally:
                    release.set()
                self.assertEqual(response.read(), TERMINAL)
            _, complete = self.scrape(port, requests=1)
            self.assertEqual(complete["inferdiff_proxy_active_streams"], 0)

    def test_metrics_require_exact_bearer_when_configured(self):
        token = "fixture-scrape-token"
        with _upstream(lambda h: _reply(h, b"")) as (origin, requests):
            with _proxy(origin, host="0.0.0.0", metrics_token=token, no_ui=True) as (port, _):
                for header, status in ((None, 401), ("Bearer incorrect", 401), (f"bearer {token}", 401),
                                       (f"Bearer {token} ", 401), ("Bearer non-ascii-\xff", 401),
                                       (f"Bearer {token}", 200)):
                    with self.subTest(status=status, authorization_header=header), _response(
                        port, "GET", METRICS_PATH, headers={"Authorization": header} if header else {},
                    ) as response:
                        self.assertEqual(response.status, status)
                        raw = response.read().decode("utf-8")
                        self.assertNotIn(token, raw)
                        if status == 401:
                            self.assertEqual(response.headers["WWW-Authenticate"], "Bearer")
                        else:
                            self.assertEqual(response.headers["Content-Type"], CONTENT_TYPE)
                            self.assertIn("inferdiff_proxy_active_streams 0", raw)
        self.assertEqual(requests, [])

    def test_disabled_and_non_loopback_without_token_return_local_404(self):
        with _upstream(lambda h: _reply(h, b"")) as (origin, requests):
            for options in ({"no_metrics": True, "metrics_token": "irrelevant-token"}, {"host": "0.0.0.0"}):
                with self.subTest(options=options), _proxy(origin, **options) as (port, _):
                    with _response(port, "GET", METRICS_PATH) as response:
                        self.assertEqual(response.status, 404)
                        response.read()
        self.assertEqual(requests, [])

    def test_cli_resolves_prefixed_environment_token(self):
        from inferdiff.proxy import create_proxy_server

        output = io.StringIO()
        token = "fixture-environment-token"
        with (
            patch.dict("os.environ", {"FIXTURE_METRICS_TOKEN": token}),
            patch("inferdiff.proxy.ProxyServer.serve_forever"),
            patch("inferdiff.cli.create_proxy_server", wraps=create_proxy_server) as create,
            redirect_stdout(output), redirect_stderr(output),
        ):
            code = main(["proxy", "--upstream", "http://example.test", "--port", "0",
                         "--metrics-token", "env:FIXTURE_METRICS_TOKEN"])
            self.assertEqual(code, 0, output.getvalue())
            self.assertEqual(create.call_args.kwargs["metrics_token"], token)
        self.assertNotIn(token, output.getvalue())


class TestGrafanaDashboard(unittest.TestCase):
    def test_dashboard_expressions_reference_exported_metrics(self):
        from inferdiff.metrics import ProxyMetrics, render_watch_metrics

        path = Path(__file__).resolve().parents[1] / "examples" / "grafana-inferdiff-dashboard.json"
        dashboard = json.loads(path.read_text(encoding="utf-8"))
        raw = ProxyMetrics().render(failovers_total=0) + render_watch_metrics(
            up=True, grade_score=100, probes_passed=1, probes_total=1, p0_breaches=0,
            ttft_ms=10, last_check_timestamp_seconds=123,
        )
        exported = {name.partition("{")[0] for name in _samples(raw.decode("utf-8"))}
        expressions = [target["expr"] for panel in dashboard["panels"] for target in panel.get("targets", [])]
        referenced = set()
        for expr in expressions:
            with self.subTest(expr=expr):
                names = set(re.findall(r"\binferdiff_[a-z0-9_]+\b", expr))
                self.assertTrue(names)
                self.assertLessEqual(names, exported)
                referenced.update(names)
        self.assertLessEqual({
            "inferdiff_proxy_ttft_ms_bucket", "inferdiff_proxy_findings_total",
            "inferdiff_proxy_failovers_total", "inferdiff_watch_up",
        }, referenced)
        quantiles = {float(match[1]) for expr in expressions
                     if (match := re.search(r"histogram_quantile\(\s*(0\.\d+)\s*,", expr))}
        self.assertEqual(quantiles, {0.5, 0.95})
        self.assertTrue(any('severity="P0"' in expr and "rate(" in expr for expr in expressions))
        self.assertTrue(any("by (detector)" in expr for expr in expressions))


class TestWatchMetrics(unittest.TestCase):
    def test_textfile_atomically_replaces_previous_cycle_with_numeric_metrics(self):
        with tempfile.TemporaryDirectory() as tmp, _server(False, True) as (origin, requests, _):
            destination = Path(tmp) / "watch.prom"
            destination.write_text("previous\n", encoding="utf-8")
            replacements = []
            replace = os.replace

            def track_replace(source, target):
                source = Path(source)
                self.assertEqual(source.parent, destination.parent)
                self.assertNotEqual(source.suffix, ".prom")
                self.assertEqual(Path(target), destination)
                replacements.append((destination.read_text(encoding="utf-8"), source.read_bytes()))
                replace(source, target)

            with patch("os.replace", side_effect=track_replace):
                code, _, stderr = _run_cli(origin, "--max-runs", "2", "--prom-out", str(destination))

            self.assertEqual(code, 0, stderr)
            self.assertEqual(stderr, "")
            self.assertEqual(len(requests), 2)
            self.assertEqual(len(replacements), 2)
            self.assertEqual(replacements[0][0], "previous\n")
            self.assertEqual(replacements[1][0], replacements[0][1].decode("utf-8"))
            self.assertEqual(destination.read_bytes(), replacements[1][1])
            self.assertEqual(list(Path(tmp).iterdir()), [destination])

        for index, (_, data) in enumerate(replacements):
            raw = data.decode("utf-8")
            self.assertTrue(raw.endswith("\n"))
            samples = dict(line.split() for line in raw.splitlines() if not line.startswith("#"))
            self.assertEqual(set(samples), {
                "inferdiff_watch_up", "inferdiff_watch_grade_score", "inferdiff_watch_probes_passed",
                "inferdiff_watch_probes_total", "inferdiff_watch_p0_breaches", "inferdiff_watch_ttft_ms",
                "inferdiff_watch_last_check_timestamp_seconds",
            })
            for name in samples:
                self.assertIn(f"# HELP {name} ", raw)
                self.assertIn(f"# TYPE {name} gauge\n", raw)
            self.assertEqual(int(samples["inferdiff_watch_up"]), index)
            self.assertEqual(int(samples["inferdiff_watch_grade_score"]), 100 * index)
            self.assertEqual(int(samples["inferdiff_watch_probes_passed"]), index)
            self.assertEqual(int(samples["inferdiff_watch_probes_total"]), 1)
            self.assertEqual(int(samples["inferdiff_watch_p0_breaches"]), 1 - index)
            self.assertTrue(math.isfinite(float(samples["inferdiff_watch_ttft_ms"])))
            self.assertGreater(float(samples["inferdiff_watch_last_check_timestamp_seconds"]), 0)
            for value in (origin, API_KEY, HEADER_VALUE, QUERY_SECRET, "mock-model"):
                self.assertNotIn(value, raw)

    def test_metrics_listener_serves_startup_and_latest_cycle_then_closes(self):
        started = [threading.Event(), threading.Event()]
        release = [threading.Event(), threading.Event()]
        cycle = iter(range(2))

        def gated_doctor(**options):
            index = next(cycle)
            started[index].set()
            if not release[index].wait(5):
                raise RuntimeError("Timed out waiting to release canary cycle")
            return run_doctor(**options)

        def scrape(port, path):
            with closing(http.client.HTTPConnection("127.0.0.1", port, timeout=3)) as connection:
                connection.request("GET", path)
                with connection.getresponse() as response:
                    return response.status, response.getheader("Content-Type"), response.read()

        with _server(True, False) as (origin, _, _), ThreadPoolExecutor(max_workers=1) as workers, patch(
            "inferdiff.watch.run_doctor", side_effect=gated_doctor,
        ), redirect_stdout(io.StringIO()) as output, redirect_stderr(io.StringIO()) as errors:
            future = workers.submit(main, ("watch", "--base-url", f"{origin}/v1", "--model", "mock-model",
                                           "--only", "C6", "--interval", "0", "--max-runs", "2",
                                           "--metrics-port", "0"))
            try:
                self.assertTrue(started[0].wait(5), errors.getvalue())
                listener = re.search(r"http://127\.0\.0\.1:(\d+)/metrics", output.getvalue())
                self.assertIsNotNone(listener)
                port = int(listener.group(1))
                status, content_type, raw = scrape(port, "/metrics")
                self.assertEqual(status, 200)
                self.assertEqual(content_type, "text/plain; version=0.0.4; charset=utf-8")
                self.assertIn(b"inferdiff_watch_up 0\n", raw)
                samples = dict(line.split() for line in raw.splitlines() if not line.startswith(b"#"))
                self.assertEqual(float(samples[b"inferdiff_watch_last_check_timestamp_seconds"]), 0)
                release[0].set()
                self.assertTrue(started[1].wait(5), errors.getvalue())
                status, _, raw = scrape(port, "/_inferdiff/metrics")
                self.assertEqual(status, 200)
                self.assertIn(b"inferdiff_watch_up 1\n", raw)
                self.assertEqual(scrape(port, "/unknown")[0], 404)
            finally:
                for gate in release:
                    gate.set()
            self.assertEqual(future.result(timeout=5), 2, errors.getvalue())
            with self.assertRaises(ConnectionError):
                scrape(port, "/metrics")

    def test_prometheus_textfile_must_differ_from_json_log(self):
        with tempfile.TemporaryDirectory() as tmp, _server() as (origin, requests, _):
            destination = str(Path(tmp) / "watch.prom")
            code, _, stderr = _run_cli(origin, "--max-runs", "1", "--prom-out", destination,
                                       "--out-jsonl", destination)
            self.assertEqual(code, 1, stderr)
            self.assertIn("--prom-out", stderr)
            self.assertNotIn(destination, stderr)
            self.assertEqual(requests, [])
            self.assertFalse(Path(destination).exists())
