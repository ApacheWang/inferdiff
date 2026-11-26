"""Integration and regression coverage for the v0.2 storage probes."""

import base64
import hashlib
import io
import json
import re
import socket
import tempfile
import threading
import time
import unittest
from contextlib import contextmanager, redirect_stderr, redirect_stdout
from dataclasses import replace
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from unittest.mock import patch
from urllib.parse import urlsplit

from inferdiff.canary import DoctorReport, ProbeResult
from inferdiff.cli import main
from inferdiff.detectors import audit_trace
from inferdiff.differ import diff_traces
from inferdiff.exporter import sanitize_trace_for_json_export
from inferdiff.probes._http import get_text
from inferdiff.probes.composite import CompositeBackendProbe
from inferdiff.probes.lmcache import LmcacheMpProbe
from inferdiff.probes.mooncake import MooncakeStoreProbe
from inferdiff.probes.proc_io import LinuxProcIoProbe
from inferdiff.probes.prom import counter_delta, parse_prometheus, sum_deltas
from inferdiff.recorder import RecorderError, record_stream, validate_url
from inferdiff.schema import TraceSchemaError, load_trace, write_trace
from inferdiff.waterfall import render_audit_html, render_diff_html, render_doctor_html


MIB = 1024 * 1024
STREAM = (
    b'data: {"choices":[{"index":0,"delta":{"role":"assistant"}}]}\n\n'
    b'data: {"choices":[{"index":0,"delta":{"content":"hello"},"finish_reason":"stop"}]}\n\n'
    b'data: [DONE]\n\n'
)


@contextmanager
def serve(routes, *, between_body_chunks=None):
    calls = []

    class Handler(BaseHTTPRequestHandler):
        def log_message(self, *args):
            pass

        def respond(self):
            if self.command == "POST":
                self.rfile.read(int(self.headers.get("Content-Length", "0")))
            calls.append((self.command, self.path))
            route = routes[(self.command, self.path)]
            status, body = route() if callable(route) else route
            chunks = (body,) if isinstance(body, bytes) else body
            self.send_response(status)
            self.send_header("Content-Length", str(sum(len(chunk) for chunk in chunks)))
            if self.command == "POST":
                self.send_header("Content-Type", "text/event-stream")
            self.end_headers()
            for index, chunk in enumerate(chunks):
                if index and between_body_chunks is not None:
                    between_body_chunks()
                self.wfile.write(chunk)

        do_GET = do_POST = respond

    with ThreadingHTTPServer(("127.0.0.1", 0), Handler) as server:
        thread = threading.Thread(target=server.serve_forever, kwargs={"poll_interval": 0.01})
        thread.start()
        try:
            yield f"http://127.0.0.1:{server.server_port}", calls
        finally:
            server.shutdown()
            thread.join()


def proc_fixture(root):
    pid_dir = Path(root) / "123"
    pid_dir.mkdir()
    (pid_dir / "comm").write_text("kv-worker\n", encoding="ascii")

    def update(rchar, syscr, reads, writes=0, cancelled=0):
        (pid_dir / "io").write_text(
            f"rchar: {rchar}\nsyscr: {syscr}\nread_bytes: {reads}\n"
            f"write_bytes: {writes}\ncancelled_write_bytes: {cancelled}\n",
            encoding="ascii",
        )

    return update


def storage_findings(doc):
    return audit_trace(doc, only={"D6", "D7", "D8"})


class TestProbes(unittest.TestCase):
    def test_url_validation_and_ipv6_default_ports(self):
        for url, error in (
            ("http://user:pw@host／example/", "Invalid URL syntax."),
            ("http://localhost:private-port/", "Invalid URL port."),
            ("http://localhost:0/", "Invalid URL port."),
        ):
            for validate in (validate_url, LmcacheMpProbe, MooncakeStoreProbe):
                with self.subTest(url=url, validate=validate), self.assertRaises(RecorderError) as caught:
                    validate(url)
                self.assertEqual(str(caught.exception), error)
        with tempfile.TemporaryDirectory() as root:
            request = Path(root) / "request.json"
            request.write_text("{}", encoding="utf-8")
            stderr = io.StringIO()
            with redirect_stderr(stderr):
                self.assertEqual(main(["record", "--url", "http://localhost", "--request", str(request),
                                       "--out", str(Path(root) / "trace"), "--probe-lmcache",
                                       "http://user:pw@host／example/"]), 1)
            self.assertIn("Invalid URL syntax.", stderr.getvalue())
            self.assertNotIn("user:pw", stderr.getvalue())
        for scheme, default, connection in (("http", 80, "HTTPConnection"),
                                             ("https", 443, "HTTPSConnection")):
            for suffix, port in (("", default), (":8765", 8765)):
                with patch(f"inferdiff.probes._http.http.client.{connection}") as factory:
                    get_text(urlsplit(f"{scheme}://[2001:db8::80]{suffix}/metrics"), 0.2)
                    self.assertEqual(factory.call_args.args, ("2001:db8::80", port))
        self.assertEqual(get_text(urlsplit("http://localhost:0/"), 0.2), (None, ""))

    def test_scrape_deadline_includes_resolution_headers_and_chunked_body(self):
        release = threading.Event()
        with patch("socket.getaddrinfo", side_effect=lambda *args: release.wait(2)):
            try:
                start = time.monotonic()
                self.assertEqual(get_text(urlsplit("http://localhost/"), 0.1), (None, ""))
                self.assertLess(time.monotonic() - start, 0.5)
            finally:
                release.set()

        class SlowResponse(BaseHTTPRequestHandler):
            def log_message(self, *args):
                pass

            def do_GET(self):
                parts = [b"HTTP/1.1 200 OK\r\n"]
                if self.path == "/headers":
                    parts += [b"X-Slow: a\r\n"] * 60 + [b"Content-Length: 0\r\n\r\n"]
                else:
                    parts[0] += b"Transfer-Encoding: chunked\r\n\r\n"
                    parts += [b"1\r\na\r\n"] * 60 + [b"0\r\n\r\n"]
                try:
                    for part in parts:
                        self.wfile.write(part)
                        time.sleep(0.02)
                except OSError:
                    pass

        with ThreadingHTTPServer(("127.0.0.1", 0), SlowResponse) as server:
            thread = threading.Thread(target=server.serve_forever, kwargs={"poll_interval": 0.01})
            thread.start()
            try:
                for path in ("/headers", "/body"):
                    with self.subTest(path=path):
                        start = time.monotonic()
                        result = get_text(urlsplit(f"http://127.0.0.1:{server.server_port}{path}"), 0.15)
                        self.assertEqual(result, (None, ""))
                        self.assertLess(time.monotonic() - start, 0.6)
            finally:
                server.shutdown()
                thread.join()
        with serve({("GET", "/metrics"): (200, b"12345")}) as (url, _):
            self.assertEqual(get_text(urlsplit(url + "/metrics"), 1, max_bytes=4), (200, ""))
            self.assertEqual(get_text(urlsplit(url + "/metrics"), 1, max_bytes=5), (200, "12345"))

    def test_optional_probe_exceptions_preserve_frames_and_summary(self):
        class Probe:
            name = "proc_io"

            def describe_topology(self):
                return {"pid": 123}

            def sample_pre(self):
                pass

            def sample_ttft(self):
                pass

            def sample_eof(self):
                return {"status": "ok"}

        with tempfile.TemporaryDirectory() as root, serve({
            ("POST", "/v1/chat/completions"): (200, STREAM),
            ("GET", "/metrics"): (200, b"hit_l2_keys_total 4\n"),
            ("GET", "/version"): (200, b'{"display_version":"1.2.3"}'),
        }) as (url, _):
            path = Path(root) / "trace.jsonl"
            for hook in ("describe_topology", "sample_pre", "sample_ttft", "sample_eof"):
                for composite in (False, True):
                    with self.subTest(hook=hook, composite=composite):
                        source = Probe()
                        seen = []
                        def fail():
                            if hook == "sample_ttft":
                                seen.append("hello" in path.read_text(encoding="utf-8"))
                            raise RuntimeError("private failure")
                        probe = (CompositeBackendProbe(mooncake=MooncakeStoreProbe(client_url=url), proc_io=source)
                                 if composite else source)
                        with patch.object(source, hook, side_effect=fail) as mocked:
                            doc = record_stream(url=url + "/v1/chat/completions", request_body={"model": "m"},
                                                probe=probe, out_path=path)
                            mocked.assert_called_once()
                        self.assertTrue(doc.summary.eof_clean)
                        self.assertEqual(len(doc.frames), 3)
                        self.assertEqual(doc.summary.assembled["content_text"], "hello")
                        self.assertEqual(load_trace(path), doc)
                        self.assertNotIn("private failure", path.read_text())
                        if hook == "sample_ttft":
                            self.assertEqual(seen, [True])
                        if composite:
                            self.assertIn("mooncake", doc.summary.backend_probe)

    def test_blocked_ttft_hook_leaves_trace_complete(self):
        from inferdiff.probes import NullProbe

        release = threading.Event()
        started = threading.Event()
        class BlockingProbe(NullProbe):
            def sample_ttft(self):
                started.set()
                release.wait(2)

        with tempfile.TemporaryDirectory() as root, serve({("POST", "/infer"): (200, STREAM)}) as (url, _):
            path = Path(root) / "trace.jsonl"
            for composite in (False, True):
                with self.subTest(composite=composite):
                    release.clear()
                    started.clear()
                    source = BlockingProbe()
                    source.name = "proc_io"
                    probe = CompositeBackendProbe(proc_io=source) if composite else source
                    start = time.monotonic()
                    try:
                        doc = record_stream(url=url + "/infer", request_body={"model": "m"},
                                            probe=probe, out_path=path)
                        self.assertTrue(started.is_set())
                        self.assertLess(time.monotonic() - start, 0.5)
                        summary = doc.summary.backend_probe
                        if composite:
                            summary = summary["proc_io"]
                        self.assertEqual(summary, {"status": "ttft_unavailable"})
                        self.assertEqual(load_trace(path).summary.assembled["content_text"], "hello")
                    finally:
                        release.set()

    def test_proc_identity_and_unobserved_or_late_ttft(self):
        with tempfile.TemporaryDirectory() as root:
            update = proc_fixture(root)
            stat = Path(root) / "123" / "stat"
            def set_start(ticks):
                stat.write_text(f"123 (name with ) parens) S {'0 ' * 18}{ticks} 0\n", encoding="ascii")
            set_start(10)
            update(1, 1, 1)
            probe = LinuxProcIoProbe(123, root)
            probe.sample_pre()
            self.assertEqual(probe.sample_eof()["prefill_window"], {"status": "ttft_not_observed"})
            set_start(11)
            update(100, 100, 100)
            changed = probe.sample_eof()
            self.assertEqual(changed["status"], "process_changed")
            self.assertEqual(changed["full_window"], {})
            self.assertEqual(changed["prefill_window"], {"status": "process_changed"})
            probe.sample_pre()
            release = threading.Event()
            snapshot = probe._read_io
            def read_io():
                if threading.current_thread().name == "inferdiff-proc-ttft":
                    release.wait(2)
                return snapshot()
            with patch.object(probe, "_read_io", side_effect=read_io):
                try:
                    start = time.monotonic()
                    probe.sample_ttft()
                    self.assertLess(time.monotonic() - start, 0.5)
                    self.assertEqual(probe.sample_eof()["prefill_window"], {"status": "ttft_unavailable"})
                finally:
                    release.set()
            stat.unlink()
            probe.sample_pre()
            (stat.parent / "comm").write_text("replacement\n", encoding="ascii")
            self.assertEqual(probe.sample_eof()["status"], "process_changed")
            with serve({("POST", "/infer"): (200, b"data: [DONE]\n\n")}) as (url, _):
                doc = record_stream(url=url + "/infer", request_body={"model": "m"},
                                    probe=CompositeBackendProbe(proc_io=probe))
            self.assertIsNone(doc.summary.timing["ttft_effective_ms"])
            self.assertEqual(doc.summary.backend_probe["proc_io"]["prefill_window"],
                             {"status": "ttft_not_observed"})

    def test_counter_scrape_integrity(self):
        metric = "lmcache_hit_l2_keys_total"
        reason = 'lmcache_l2_prefetch_failures_total{reason="l1_oom"}'
        pairs = (
            (f"{metric} 1\n{metric} 2", f"{metric} 8"),
            (f"{metric} 1", f"{metric} 2\n{metric} 8"),
            (f"# TYPE {metric} gauge\n{metric} 1", f"# TYPE {metric} gauge\n{metric} 8"),
            (f"# TYPE {metric} counter\n{metric} 1", f"# TYPE {metric} gauge\n{metric} 8"),
            (f"{metric} 1 123", f"{metric} 8 123"),
            (f"{metric} 1 123", f"{metric} 8 124"),
            (f"process_start_time_seconds 1\n{metric} 1", f"process_start_time_seconds 2\n{metric} 8"),
            (f"lmcache_hit_l2_keys_created 1\n{metric} 1", f"lmcache_hit_l2_keys_created 2\n{metric} 8"),
        )
        for before, after in pairs:
            with self.subTest(before=before, after=after), patch(
                "inferdiff.probes.lmcache.get_text", side_effect=[(200, before), (200, after)],
            ):
                probe = LmcacheMpProbe("http://localhost")
                probe.sample_pre()
                result = probe.sample_eof()
                self.assertEqual(result["status"], "incomplete")
                self.assertNotIn("delta_hit_l2_keys", result)
        self.assertEqual(parse_prometheus("counter 1\ncounter 2\ncounter 3\n"), {})
        with patch("inferdiff.probes.lmcache.get_text", side_effect=[
            (200, f"{metric} 1"), (200, f"{metric} 3\n{reason} 1"),
        ]):
            probe = LmcacheMpProbe("http://localhost")
            probe.sample_pre()
            result = probe.sample_eof()
        self.assertEqual(result["delta_hit_l2_keys"], 2)
        self.assertEqual(result["status"], "incomplete")
        self.assertTrue(result["first_seen_at_eof"])
        self.assertNotIn("delta_l2_prefetch_failures", result)
        now = time.time_ns() // 1_000_000
        with patch("inferdiff.probes.lmcache.get_text", side_effect=[
            (200, f"{metric} 1 {now - 1}"), (200, f"{metric} 3 {now}"),
        ]):
            probe = LmcacheMpProbe("http://localhost")
            probe.sample_pre()
            result = probe.sample_eof()
        self.assertEqual(result["delta_hit_l2_keys"], 2)
        self.assertEqual(result["status"], "ok")

    def test_mooncake_checks_counter_types_at_both_boundaries(self):
        name = "mooncake_te_read_bytes_total"
        quota = "mooncake_tenant_quota_reject"
        with patch("inferdiff.probes.mooncake.get_text", side_effect=[
            (200, f"# TYPE {quota} gauge\n{quota}_total 1"),
            (200, f"# TYPE {name} gauge\n{name} 1"),
            (200, f"# TYPE {quota} counter\n{quota}_total 2"), (200, "OK"),
            (200, f"# TYPE {name} counter\n{name} 2"), (200, "{}"),
        ]):
            probe = MooncakeStoreProbe("http://localhost", "http://localhost")
            probe.sample_pre()
            result = probe.sample_eof()
        self.assertEqual(result["master_status"], "incomplete")
        self.assertEqual(result["client_status"], "incomplete")
        self.assertNotIn("delta_quota_rejects", result)
        self.assertNotIn("client_deltas", result)

    def test_prometheus_text_and_counter_resets(self):
        parsed = parse_prometheus(
            '# HELP cache_hits cache hits\n# TYPE cache_hits counter\n'
            'cache_hits_total{reason="one, two\\\"",path="a\\\\b\\n"} 9.5e1 123\n'
            'other 9007199254740993\ninvalid{reason=bad} 19\nnot_finite +Inf\n'
        )
        self.assertEqual(parsed[("cache_hits_total", (("path", "a\\b\n"), ("reason", 'one, two"')))], 95)
        self.assertEqual(parsed[("other", ())], 9007199254740993)
        self.assertEqual(len(parsed), 2)
        self.assertEqual(counter_delta(10, 10), 0)
        self.assertEqual(counter_delta(10, 12), 2)
        self.assertIsNone(counter_delta(10, 2))
        self.assertIsNone(counter_delta(None, 2))
        self.assertIsNone(sum_deltas([10**308, 10**308, 1.0]))

    def test_proc_windows_and_degradation(self):
        with tempfile.TemporaryDirectory() as root:
            update = proc_fixture(root)
            probe = LinuxProcIoProbe(123, root)
            update(100, 10, 200, 300, 20)
            probe.sample_pre()
            update(4196, 11, 200, 300, 20)
            probe.sample_ttft()
            self.assertIsNotNone(probe._ttft_task.wait_until(probe._ttft_deadline))
            update(8292, 13, 300, 300 + 64 * MIB + 5, 25)
            result = probe.sample_eof()
            self.assertEqual(result["comm"], "kv-worker")
            self.assertEqual(result["prefill_window"], {
                "delta_rchar_bytes": 4096, "delta_read_bytes": 0,
                "delta_syscr": 1, "avg_syscall_read_kb": 4.0, "delta_write_bytes_net": 0,
            })
            self.assertEqual(result["full_window"], {
                "delta_write_bytes_net": 64 * MIB, "delta_read_bytes_total": 100,
                "delta_rchar_bytes_total": 8192,
            })
            probe.sample_pre()
            update(8292, 13, 300, 300 + 64 * MIB + 6, 31)
            self.assertEqual(probe.sample_eof()["full_window"]["delta_write_bytes_net"], -5)
            probe.sample_pre()
            update(1, 1, 1)
            reset = probe.sample_eof()
            self.assertEqual(reset["prefill_window"], {"status": "ttft_not_observed"})
            self.assertEqual(reset["full_window"], {})
            with patch.object(Path, "read_text", side_effect=PermissionError):
                probe.sample_pre()
                probe.sample_ttft()
                self.assertEqual(probe.sample_eof()["status"], "skipped_permission")
            missing = LinuxProcIoProbe(123, str(Path(root) / "no-proc"))
            missing.sample_pre()
            missing.sample_ttft()
            self.assertEqual(missing.sample_eof()["status"], "skipped_unavailable")

    def test_lmcache_hybrid_metrics_resets_and_cold_http_endpoint(self):
        def metrics(n):
            return (
                f'# HELP lmcache_lookup_prompt_tokens_total Tokens\n'
                f'# TYPE lmcache_lookup_prompt_tokens_total counter\n'
                f'lmcache_lookup_prompt_tokens_total {100 * n}\n'
                f'hit_l1_tokens_total {20 * n}\n'
                f'lmcache_mp_lookup_hit_l2_total {60 * n}\n'
                f'lmcache_hit_l1_keys_total {n}\n'
                f'lmcache_mp_lookup_hit_l2_keys_total {3 * n}\n'
                f'lmcache_l2_load_completed_total {2 * n}\n'
                f'lmcache_mp_l2_prefetch_failure_chunks_total{{reason="l1_oom",worker="a"}} {n}\n'
                f'lmcache_mp_l2_prefetch_failure_chunks_total{{worker="b",reason="l1_oom"}} {2 * n}\n'
                f'lmcache_mp_l2_prefetch_failure_chunks_total{{reason="not_found"}} {5 - n}\n'
                f'lmcache_mp_l1_read_failure_chunks_total {n}\n'
                f'lmcache_event_bus_dropped_total {1e2 * n}\n'
            ).encode()

        path = "/metrics?token=private-value"
        routes = {("GET", path): (200, metrics(1))}
        with serve(routes) as (url, calls):
            probe = LmcacheMpProbe(url + "/?token=private-value#fragment")
            probe.sample_pre()
            probe.sample_ttft()
            routes[("GET", path)] = (200, metrics(2))
            result = probe.sample_eof()
            self.assertEqual(calls, [("GET", path)] * 2)
            self.assertNotIn("private-value", result["endpoint"])
            self.assertNotIn("fragment", result["endpoint"])
            for metric, expected in {
                "lookup_prompt_tokens": 100, "hit_l1_tokens": 20, "hit_l2_tokens": 60,
                "hit_l1_keys": 1, "hit_l2_keys": 3, "l2_load_completed": 2,
                "l1_read_failures": 1, "event_bus_dropped": 100,
                "l2_prefetch_failures": {"l1_oom": 3},
            }.items():
                self.assertEqual(result[f"delta_{metric}"], expected)
            for response in ((404, b"push mode"), (200, b"# HELP foo ignored"), (200, b"")):
                routes[("GET", path)] = response
                probe.sample_pre()
                self.assertEqual(probe.sample_eof(), {
                    "endpoint": result["endpoint"], "status": "unavailable_push_or_cold",
                })
        with self.assertRaises(RecorderError):
            LmcacheMpProbe("http://user:secret@localhost/")

    def test_mooncake_master_survives_client_503(self):
        master_metrics = b'mooncake_tenant_quota_reject_total{tenant_id="a"} 4\nmooncake_tenant_evict_bytes_total 100\n'
        master = {("GET", "/health"): (200, b'{"status":"ok","service_ready":false}'),
                  ("GET", "/metrics"): (200, master_metrics)}
        client = {("GET", "/version"): (200, b'{"display_version":"0.3.12 (git: abc)"}'),
                  ("GET", "/metrics"): (503, b"metrics not available")}
        with serve(master) as (master_url, _), serve(client) as (client_url, _):
            probe = MooncakeStoreProbe(master_url, client_url)
            probe.sample_pre()
            self.assertFalse(probe.sample_eof()["master_ready"])
            master[("GET", "/health")] = (200, b'{"status":"ok","role":"standby"}')
            self.assertFalse(probe.sample_eof()["master_ready"])
            probe.sample_pre()
            master[("GET", "/health")] = (200, b'{"service_ready":true}')
            master[("GET", "/metrics")] = (200, master_metrics.replace(b"} 4", b"} 6").replace(b"100", b"356"))
            result = probe.sample_eof()
            self.assertIs(result["master_ready"], True)
            self.assertEqual(result["delta_quota_rejects"], 2)
            self.assertEqual(result["delta_evict_bytes"], 256)
            self.assertEqual(result["client_version"], "0.3.12 (git: abc)")
            self.assertEqual(result["client_status"], "degraded_503")
            client[("GET", "/metrics")] = (200, (
                b"mooncake_te_read_bytes_total 5\n"
                b"# TYPE mooncake_transfer_read_bytes counter\nmooncake_transfer_read_bytes 10\n"
                b"# TYPE mooncake_ssd_bytes_total gauge\nmooncake_ssd_bytes_total 42\n"
            ))
            probe.sample_pre()
            content = client[("GET", "/metrics")][1]
            client[("GET", "/metrics")] = (200, content.replace(b" 5\n", b" 9\n").replace(
                b" 10\n", b" 17\n").replace(b" 42\n", b" 49\n"))
            result = probe.sample_eof()
            self.assertEqual(result["client_status"], "ok")
            self.assertEqual(result["client_deltas"], {
                "mooncake_te_read_bytes_total": 4, "mooncake_transfer_read_bytes": 7,
            })
        with serve(master) as (master_url, _), socket.socket() as offline:
            offline.bind(("127.0.0.1", 0))
            probe = MooncakeStoreProbe(master_url, f"http://127.0.0.1:{offline.getsockname()[1]}", timeout=0.2)
            probe.sample_pre()
            self.assertEqual(probe.sample_eof()["client_status"], "unavailable")

    def test_probe_response_fields_scrub_reflected_query_secrets(self):
        query = "?token=pw&version=1.2.3&alt=l1_oom"
        metric = (
            b'lmcache_l2_prefetch_failures_total{reason="l1_oom"} 1\n'
            b'lmcache_l2_prefetch_failures_total{reason="pw"} 1\n'
            b'lmcache_l2_prefetch_failures_total{reason="l1_oom\\n"} 1\n'
        )
        version = b'{"display_version":"1.2.3"}'
        routes = {("GET", "/metrics" + query): (200, metric),
                  ("GET", "/health" + query): (200, b"OK"), ("GET", "/version" + query): (200, version)}
        def infer():
            routes[("GET", "/metrics" + query)] = (200, metric.replace(b"} 1", b"} 2"))
            return 200, STREAM
        routes[("POST", "/infer")] = infer
        with tempfile.TemporaryDirectory() as root, serve(routes) as (url, _):
            endpoint = url + query + "#private-fragment"
            probe = CompositeBackendProbe(LmcacheMpProbe(endpoint), MooncakeStoreProbe(endpoint, endpoint))
            path = Path(root) / "probe.jsonl"
            doc = record_stream(url=url + "/infer", request_body={"model": "m"}, out_path=path, probe=probe)
            for record in (doc.header.backend_probe, doc.summary.backend_probe):
                self.assertEqual(record["lmcache_mp"]["endpoint"], url + "/metrics")
                self.assertEqual(record["mooncake"]["client_endpoint"], url + "/")
                self.assertEqual(record["mooncake"]["master_endpoint"], url + "/")
            failures = doc.summary.backend_probe["lmcache_mp"]["delta_l2_prefetch_failures"]
            self.assertEqual(failures, {"unknown": 3})
            self.assertNotIn("client_version", doc.summary.backend_probe["mooncake"])
            for secret in ("token=pw", "l1_oom", "1.2.3", "private-fragment", "?"):
                self.assertNotIn(secret, path.read_text(encoding="utf-8"))

    def test_record_samples_local_io_at_first_effective_payload_and_round_trips(self):
        with tempfile.TemporaryDirectory() as root:
            update = proc_fixture(root)
            update(0, 0, 0)
            ttft_complete = threading.Event()
            terminal = b"data: [DONE]\n\n"

            def infer():
                update(32 * MIB, 4, 0)
                return 200, (STREAM.removesuffix(terminal), terminal)

            routes = {("GET", "/metrics"): (200, b"hit_l2_keys_total 4\n"),
                      ("POST", "/v1/chat/completions"): infer}
            with serve(routes, between_body_chunks=lambda: ttft_complete.wait(1)) as (url, calls):
                proc = LinuxProcIoProbe(123, root)

                class ObservedProbe(CompositeBackendProbe):
                    def sample_ttft(self):
                        self.at_ttft = list(calls)
                        super().sample_ttft()
                        self.snapshot = proc._ttft_task.wait_until(proc._ttft_deadline)
                        self.after_ttft = list(calls)
                        update(40 * MIB, 8, MIB, 80 * MIB)
                        routes[("GET", "/metrics")] = (200, b"hit_l2_keys_total 8\n")
                        ttft_complete.set()

                probe = ObservedProbe(lmcache_mp=LmcacheMpProbe(url), proc_io=proc, concurrency_isolated=True)
                recorded = Path(root) / "recorded.jsonl"
                doc = record_stream(url=url + "/v1/chat/completions", request_body={"model": "m"},
                                    probe=probe, out_path=recorded)
                self.assertEqual(probe.at_ttft, [("GET", "/metrics"), ("POST", "/v1/chat/completions")])
                self.assertEqual(probe.after_ttft, probe.at_ttft)
                self.assertIsNotNone(probe.snapshot)
                self.assertEqual(calls, probe.at_ttft + [("GET", "/metrics")])
                self.assertEqual(doc.summary.timing["ttft_effective_ms"], doc.frames[1].t_rel_ms)
                self.assertEqual(doc.header.backend_probe["sources"], ["lmcache_mp", "proc_io"])
                self.assertIs(doc.header.backend_probe["concurrency_isolated"], True)
                summary = doc.summary.backend_probe
                self.assertEqual(summary["probe_version"], "0.2.0")
                self.assertIs(summary["concurrency_isolated"], True)
                self.assertEqual(summary["lmcache_mp"]["delta_hit_l2_keys"], 4)
                self.assertEqual(summary["proc_io"]["prefill_window"]["delta_rchar_bytes"], 32 * MIB)
                self.assertEqual(summary["proc_io"]["full_window"]["delta_write_bytes_net"], 80 * MIB)
                self.assertEqual(load_trace(recorded), doc)
                copied = Path(root) / "copied.jsonl"
                write_trace(copied, doc)
                self.assertEqual(load_trace(copied), doc)

    def test_record_and_compare_cli_probe_flags(self):
        routes = {("GET", "/metrics"): (200, b"hit_l2_keys_total 4\n"),
                  ("GET", "/health"): (200, b"OK"),
                  ("GET", "/version"): (200, b'{"display_version":"0.3.12"}'),
                  ("POST", "/v1/chat/completions"): (200, STREAM)}
        with tempfile.TemporaryDirectory() as root, serve(routes) as (url, calls):
            request = Path(root) / "request.json"
            request.write_text('{"model":"m"}', encoding="utf-8")
            endpoint = url + "/v1/chat/completions"
            flags = ["--request", str(request), "--probe-pid", "123", "--probe-lmcache", url,
                     "--probe-mooncake-master", url, "--probe-mooncake-client", url]
            one = Path(root) / "single.jsonl"
            with redirect_stdout(io.StringIO()):
                self.assertEqual(main(["record", "--url", endpoint, "--out", str(one), *flags]), 0)
                self.assertEqual(main(["compare", "--before-url", endpoint, "--after-url", endpoint,
                                       "--save-dir", root, "--ignore-timing", *flags]), 0)
            for path in (one, Path(root) / "before.trace.jsonl", Path(root) / "after.trace.jsonl"):
                doc = load_trace(path)
                self.assertEqual(doc.header.backend_probe["sources"], ["lmcache_mp", "mooncake", "proc_io"])
                self.assertEqual(doc.summary.backend_probe["mooncake"]["client_version"], "0.3.12")
                self.assertIs(doc.header.backend_probe["concurrency_isolated"], False)
                self.assertIs(doc.summary.backend_probe["concurrency_isolated"], False)
            self.assertEqual(calls.count(("POST", "/v1/chat/completions")), 3)

    def test_compare_scopes_probes_to_distinct_endpoints(self):
        before_version = {("GET", "/version"): (200, b'{"display_version":"1.2.3"}')}
        after_version = {("GET", "/version"): (200, b'{"display_version":"4.5.6"}')}
        routes = {("POST", "/infer"): (200, STREAM), ("GET", "/metrics"): (200, b"hit_l2_keys_total 4\n"),
                  ("GET", "/health"): (200, b"OK")}
        with (tempfile.TemporaryDirectory() as root,
              serve({**routes, **before_version}) as (before, before_calls),
              serve({**routes, **after_version}) as (after, after_calls)):
            request = Path(root) / "request.json"
            request.write_text('{"model":"m"}', encoding="utf-8")
            args = ["compare", "--before-url", before + "/infer", "--after-url", after + "/infer",
                    "--save-dir", root, "--request", str(request), "--ignore-timing"]
            stderr = io.StringIO()
            with redirect_stderr(stderr):
                self.assertEqual(main([*args, "--probe-lmcache", before]), 1)
                same_target = [before + "/infer" if arg == after + "/infer" else arg for arg in args]
                self.assertEqual(main([*same_target, "--probe-lmcache", before, "--after-header", "X-Backend: next"]), 1)
            self.assertIn("--before-probe-", stderr.getvalue())
            self.assertEqual(before_calls, [])
            self.assertEqual(after_calls, [])
            with redirect_stdout(io.StringIO()):
                self.assertEqual(main([*args,
                                       "--before-probe-lmcache", before, "--before-probe-pid", "111",
                                       "--before-probe-mooncake-master", before,
                                       "--before-probe-mooncake-client", before,
                                       "--after-probe-pid", "222", "--after-probe-mooncake-client", after]), 0)
            for side, url, pid, version in (("before", before, 111, "1.2.3"), ("after", after, 222, "4.5.6")):
                doc = load_trace(Path(root) / f"{side}.trace.jsonl")
                self.assertEqual(doc.header.backend_probe["proc_io"]["pid"], pid)
                self.assertEqual(doc.header.backend_probe["mooncake"]["client_endpoint"], url + "/")
                self.assertEqual(doc.summary.backend_probe["mooncake"]["client_version"], version)
                self.assertIs(doc.header.backend_probe["concurrency_isolated"], False)
            self.assertEqual(before_calls.count(("GET", "/metrics")), 6)
            self.assertIn(("GET", "/health"), before_calls)
            self.assertNotIn(("GET", "/health"), after_calls)
            self.assertEqual(after_calls.count(("GET", "/metrics")), 2)

    def test_public_probe_exports(self):
        from inferdiff import probes
        for cls in (CompositeBackendProbe, LinuxProcIoProbe, LmcacheMpProbe, MooncakeStoreProbe):
            self.assertIs(getattr(probes, cls.__name__), cls)


class TestStorageDetectors(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        with serve({("POST", "/v1/chat/completions"): (200, STREAM)}) as (url, _):
            cls.clean = record_stream(url=url + "/v1/chat/completions", request_body={"model": "m"})

    def trace(self, probe, ttft=100):
        return replace(self.clean, summary=replace(
            self.clean.summary, backend_probe=probe,
            timing={**self.clean.summary.timing, "ttft_effective_ms": ttft},
        ))

    def test_doctor_html_surfaces_storage_findings_and_probe_metrics(self):
        warm = self.trace({
            "lmcache_mp": {
                "status": "ok", "delta_hit_l2_keys": 3, "delta_hit_l2_tokens": 96,
                "delta_l2_prefetch_failures": {"l1_oom": 2},
                "endpoint": "https://metrics.invalid/secret-path?key=private-key",
            },
            "mooncake": {"master_ready": False, "master_status": "ok", "client_status": "degraded_503",
                         "delta_quota_rejects": 4},
            "proc_io": {"status": "ok", "comm": "local-process-name",
                        "prefill_window": {"delta_rchar_bytes": 32 * MIB, "delta_read_bytes": 0}},
        })
        fragmented = self.trace({
            "mooncake": {"client_status": "ok", "client_deltas": {"mooncake_ssd_read_bytes_total": 16 * MIB}},
            "proc_io": {"status": "ok", "prefill_window": {
                "delta_read_bytes": 16 * MIB, "delta_syscr": 2048, "avg_syscall_read_kb": 8,
                "delta_write_bytes_net": -1024,
            }},
        })
        findings = storage_findings(warm) + storage_findings(fragmented)
        self.assertEqual([f.detector_id for f in findings], ["D6", "D7", "D8"])
        result = ProbeResult(
            "C7", "FAKE_STREAMING_BUFFER", "P1", "WARN", "Storage findings", 100, 6, None, "",
            findings=findings, traces=[warm, fragmented],
        )
        report = DoctorReport(
            "https://example.invalid/v1", "https://example.invalid/v1/chat/completions", "openai-chat",
            "m", "quick", "B", 0, 0, 1, 0, None, None, [result],
        )
        with tempfile.TemporaryDirectory() as root:
            path = Path(root) / "doctor.html"
            with patch("inferdiff.cli.run_doctor", return_value=report), redirect_stdout(io.StringIO()):
                self.assertEqual(main(["doctor", report.target_url, "--html", str(path)]), 0)
            rendered = path.read_text(encoding="utf-8")
        for detector in ("D6", "D7", "D8"):
            self.assertIn(f'<span class="badge b-amb">{detector} P1</span>', rendered)
        for source in ("LMCache MP", "Mooncake Store", "Linux proc_io"):
            self.assertIn(source, rendered)
        for label, value in (
            ("L2 hits (keys)", "3"), ("L2 hits (tokens)", "96"), ("L2 prefetch failures (l1_oom)", "2"),
            ("Quota rejects", "4"), ("Logical reads (rchar)", "32 MiB"), ("Physical reads (read_bytes)", "0 B"),
            ("SSD read bytes", "16 MiB"), ("Read syscalls (syscr)", "2,048"), ("Average read size", "8 KiB"),
            ("Net writes", "-1 KiB"),
        ):
            self.assertIn(f"<dt>{label}</dt><dd>{value}</dd>", rendered)
        self.assertIn('<span class="badge b-amb">Master not ready</span>', rendered)
        self.assertIn('<span class="badge b-amb">Client HTTP 503</span>', rendered)
        self.assertNotIn("private-key", rendered)
        self.assertNotIn("secret-path", rendered)
        self.assertNotIn("local-process-name", rendered)
        self.assertLess(len(rendered.encode("utf-8")), 80 * 1024)

    def test_doctor_html_embeds_hash_locked_assets_without_external_dependencies(self):
        result = ProbeResult("C7", "FAKE_STREAMING_BUFFER", "P1", "PASS", "Streaming", 100, 3, None,
                             "https://github.com/BerriAI/litellm/issues/5803", traces=[self.clean])
        rendered = render_doctor_html(DoctorReport(
            "https://example.invalid/v1", "https://example.invalid/v1/chat/completions", "openai-chat",
            "m", "quick", "A+", 0, 0, 0, 0, None, None, [result],
        ))
        self.assertIn("default-src 'none'", rendered)
        self.assertIn("connect-src 'none'", rendered)
        for tag in ("script", "style"):
            (body,) = re.findall(rf"<{tag}>(.*?)</{tag}>", rendered, re.DOTALL)
            digest = base64.b64encode(hashlib.sha256(body.encode("utf-8")).digest()).decode("ascii")
            self.assertIn(f"{tag}-src 'sha256-{digest}'", rendered)
        self.assertNotIn("'unsafe-inline'", rendered)
        self.assertNotIn("'unsafe-eval'", rendered)
        self.assertNotRegex(rendered, r"<(?:script|img|link|iframe)\b[^>]*\b(?:src|href)\s*=")
        self.assertNotRegex(rendered, r"\bstyle\s*=")
        self.assertNotIn("@import", rendered)
        self.assertLess(len(rendered.encode("utf-8")), 80 * 1024)

    def test_probe_schema_and_strict_json_export(self):
        probe = {
            "sources": ["lmcache_mp", "mooncake", "secret-source"],
            "unknown": {"note": "secret-top"},
            "lmcache_mp": {"endpoint": "http://user:pw@[2001:db8::80]:80/metrics?version=secret-value#frag",
                           "extension": "secret-field",
                           "delta_l2_prefetch_failures": {"l1_oom": 2, "secret-label": 3}},
            "mooncake": {"master_url": "http://localhost/a?key=hidden#frag",
                         "client_url": "https://localhost/b?version=1.2.3",
                         "client_version": "1.2.3", "client_deltas": {"arbitrary-secret": 9}},
        }
        doc = self.trace(probe)
        doc = replace(doc, header=replace(doc.header, backend_probe=probe))
        safe = sanitize_trace_for_json_export(doc)
        self.assertEqual(safe["header"]["backend_probe"]["sources"], ["lmcache_mp", "mooncake"])
        for record in safe.values():
            safe_probe = record["backend_probe"]
            self.assertEqual(safe_probe["lmcache_mp"]["endpoint"], "http://[2001:db8::80]:80/metrics")
            self.assertEqual(safe_probe["mooncake"]["master_url"], "http://localhost/a")
            self.assertEqual(safe_probe["mooncake"]["client_url"], "https://localhost/b")
            self.assertNotIn("client_version", safe_probe["mooncake"])
            self.assertNotIn("secret", json.dumps(safe_probe, allow_nan=False))
        with tempfile.TemporaryDirectory() as root:
            path = Path(root) / "trace.jsonl"
            write_trace(path, doc)
            raw = path.read_text(encoding="utf-8")
            for cli in (["audit", str(path), "--json"], ["export", str(path), "--format", "json"]):
                stdout = io.StringIO()
                with redirect_stdout(stdout):
                    self.assertIn(main(cli), (0, 3))
                self.assertNotIn("secret", stdout.getvalue())
                self.assertEqual(json.loads(stdout.getvalue())["header"]["backend_probe"], safe["header"]["backend_probe"])
            nested = 0
            for _ in range(15):
                nested = [nested]
            for broken in ({"proc_io": []}, {"proc_io": {"prefill_window": []}},
                           {"mooncake": {"client_deltas": []}}, {"sources": [1]},
                           {"lmcache_mp": {"delta_l2_prefetch_failures": {"l1_oom": []}}},
                           {"extra": nested}, {"extra": [0] * 5000},
                           {"extra": {"bad": "overflow-number"}}):
                for index in (0, -1):
                    with self.subTest(probe=repr(broken)[:60], index=index):
                        lines = raw.splitlines()
                        record = json.loads(lines[index])
                        record["backend_probe"] = broken
                        lines[index] = json.dumps(record).replace('"overflow-number"', '1e309')
                        path.write_text("\n".join(lines), encoding="utf-8")
                        with self.assertRaisesRegex(TraceSchemaError, "backend_probe"):
                            load_trace(path)
            lines = raw.splitlines()
            header = json.loads(lines[0])
            header["request"]["effective_params"]["temperature"] = "overflow-number"
            lines[0] = json.dumps(header).replace('"overflow-number"', '1e309')
            path.write_text("\n".join(lines), encoding="utf-8")
            for cli in (["audit", str(path), "--json"], ["export", str(path), "--format", "json"]):
                stdout, stderr = io.StringIO(), io.StringIO()
                with redirect_stdout(stdout), redirect_stderr(stderr):
                    self.assertEqual(main(cli), 1)
                self.assertEqual(stdout.getvalue(), "")

    def test_d6_process_wide_correlation_and_strict_counts(self):
        for logical, physical, expected in ((32 * MIB, 0, []), (64 * MIB, 0, ["P2"]),
                                            (64 * MIB, 0.0, []), (64 * MIB + 0.5, 0, [])):
            findings = storage_findings(self.trace({"proc_io": {"prefill_window": {
                "delta_rchar_bytes": logical, "delta_read_bytes": physical,
            }}}))
            self.assertEqual([f.severity for f in findings], expected)
            if findings:
                self.assertIn("process-wide", findings[0].message.lower())
                self.assertEqual(diff_traces(self.trace(None), self.trace({
                    "proc_io": {"prefill_window": {"delta_rchar_bytes": logical, "delta_read_bytes": physical}},
                }), fail_on="p1").exit_code, 0)
        self.assertEqual(storage_findings(self.trace({
            "lmcache_mp": {"delta_hit_l2_keys": 0.5}, "proc_io": {"prefill_window": {
                "delta_rchar_bytes": 32 * MIB, "delta_read_bytes": 0,
            }},
        })), [])
        proc = {"proc_io": {"prefill_window": {"delta_rchar_bytes": 64 * MIB, "delta_read_bytes": 0}}}
        result = diff_traces(self.trace(proc), self.trace({**proc, "lmcache_mp": {"delta_hit_l2_keys": 1}}),
                             fail_on="p1")
        self.assertEqual([(f.detector_id, f.severity) for f in result.new_findings], [("D6", "P1")])
        self.assertEqual(result.exit_code, 3)

    def test_d6_page_cache_guard(self):
        for logical, physical, expected in ((32 * MIB, 0, True), (64 * MIB, 0, True),
                                            (32 * MIB - 1, 0, False), (64 * MIB, 1, False),
                                            (64 * MIB, None, False), (64 * MIB, False, False)):
            with self.subTest(logical=logical, physical=physical):
                doc = self.trace({"proc_io": {"prefill_window": {
                    "delta_rchar_bytes": logical, "delta_read_bytes": physical,
                }}, "lmcache_mp": {"delta_hit_l2_keys": 1}})
                findings = storage_findings(doc)
                self.assertEqual([x.detector_id for x in findings], ["D6"] if expected else [])
                if expected:
                    self.assertEqual((findings[0].code, findings[0].severity), ("PAGE_CACHE_WARM_ILLUSION", "P1"))
                    self.assertIn("LMCache#4364", findings[0].message)

    def test_d7_direct_failures_and_indirect_hit_attribution(self):
        for lmcache, mooncake, expected in (
            ({"delta_hit_l2_tokens": 1, "delta_l2_prefetch_failures": {"l1_oom": 1}}, {}, True),
            ({"delta_hit_l2_keys": 1, "delta_l1_read_failures": 1}, {}, True),
            ({"delta_hit_l2_keys": 1, "event_bus_dropped": 1}, {}, True),
            ({"delta_hit_l2_keys": 1}, {"delta_quota_rejects": 1}, True),
            ({"delta_hit_l2_keys": 0, "delta_l1_read_failures": 1}, {}, True),
            ({"delta_hit_l2_keys": 0, "delta_l2_prefetch_failures": {"not_found": 1}}, {}, True),
            ({"delta_hit_l2_keys": 0, "delta_event_bus_dropped": 1}, {"delta_quota_rejects": 1}, False),
            ({"delta_hit_l2_keys": 0.5}, {"delta_quota_rejects": 1}, False),
            ({"delta_hit_l2_keys": True, "delta_event_bus_dropped": 1}, {}, False),
            ({"delta_hit_l2_keys": 1, "delta_event_bus_dropped": 0.5}, {}, False),
            ({"delta_l1_read_failures": 0.5}, {}, False),
            ({"delta_hit_l2_keys": 1, "delta_l2_prefetch_failures": {"l1_oom": 0}}, {}, False),
            ({"delta_hit_l2_keys": 1, "delta_l2_prefetch_failures": {"l1_oom": "10"}}, {}, False),
        ):
            with self.subTest(lmcache=lmcache, mooncake=mooncake):
                findings = storage_findings(self.trace({"lmcache_mp": lmcache, "mooncake": mooncake}))
                self.assertEqual([x.detector_id for x in findings], ["D7"] if expected else [])
                if expected:
                    self.assertEqual((findings[0].code, findings[0].severity), ("LOOKUP_HIT_PREFETCH_DROP", "P1"))

    def test_d8_severe_single_trace_guard(self):
        for reads, avg, calls, expected in ((16 * MIB, 8, 2048, True), (16 * MIB - 1, 8, 2048, False),
                                            (16 * MIB, 8.01, 2048, False), (16 * MIB, 8, 2047, False),
                                            (16 * MIB, 7.5, 2048, True), (16 * MIB + 0.5, 8, 2048, False),
                                            (16 * MIB, 8, 2048.5, False), (16 * MIB, True, 2048, False)):
            with self.subTest(reads=reads, avg=avg, calls=calls):
                doc = self.trace({"proc_io": {"prefill_window": {
                    "delta_read_bytes": reads, "avg_syscall_read_kb": avg, "delta_syscr": calls,
                }}, "lmcache_mp": {"delta_l2_load_completed": 2}})
                findings = storage_findings(doc)
                self.assertEqual([x.detector_id for x in findings], ["D8"] if expected else [])

    def test_d8_pair_needs_regression_and_storage_evidence(self):
        before = self.trace(None)
        for prefill, full, after_ttft, expected in (
            ({"avg_syscall_read_kb": 8, "delta_syscr": 1024, "delta_read_bytes": MIB}, {}, 130, True),
            ({"avg_syscall_read_kb": 8, "delta_syscr": 1024}, {}, 130, False),
            ({"avg_syscall_read_kb": 8, "delta_syscr": 1024, "delta_read_bytes": 1}, {}, 130, False),
            ({"delta_write_bytes_net": 64 * MIB}, {}, 130, True),
            ({}, {"delta_write_bytes_net": 64 * MIB}, 130, False),
            ({"delta_rchar_bytes": MIB, "delta_read_bytes": 2 * MIB}, {}, 130, True),
            ({"delta_write_bytes_net": 64 * MIB}, {}, 129.999, False),
            ({"delta_write_bytes_net": 64 * MIB - 1}, {}, 200, False),
            ({"delta_write_bytes_net": 64 * MIB + 0.5}, {}, 200, False),
            ({"delta_write_bytes_net": True}, {}, 200, False),
            ({"delta_write_bytes_net": 64 * MIB, "status": "ttft_unavailable"}, {}, 200, False),
            ({"delta_rchar_bytes": 0, "delta_read_bytes": 0}, {}, 200, False),
            ({"delta_read_bytes": MIB}, {}, 200, False),
            ({"delta_rchar_bytes": MIB, "delta_read_bytes": 2 * MIB - 1}, {}, 200, False),
            ({"avg_syscall_read_kb": 8, "delta_syscr": 1023}, {}, 200, False),
        ):
            with self.subTest(prefill=prefill, full=full, after_ttft=after_ttft):
                after = self.trace({
                    "lmcache_mp": {"delta_l2_load_completed": 1},
                    "proc_io": {"prefill_window": prefill, "full_window": full},
                }, after_ttft)
                report = diff_traces(before, after, fail_on="p1")
                self.assertEqual([x.detector_id for x in report.pair_findings], ["D8"] if expected else [])
                self.assertEqual(diff_traces(before, after, ignore_timing=True).pair_findings, [])
                if expected:
                    self.assertEqual(report.exit_code, 3)
                    self.assertEqual(report.pair_findings[0].code, "OFFLOAD_SLOWER_THAN_RECOMPUTE")
        self.assertEqual(diff_traces(self.trace(None, 0), after).pair_findings, [])
        self.assertEqual(diff_traces(before, self.trace(None, 200)).pair_findings, [])
        proc_only = {"proc_io": {"prefill_window": {"delta_write_bytes_net": 64 * MIB}}}
        self.assertEqual(diff_traces(before, self.trace(proc_only, 130)).pair_findings, [])
        write_probe = {**proc_only, "lmcache_mp": {"delta_hit_l2_tokens": 1}}
        fractional = diff_traces(self.trace(None, 0.010), self.trace(write_probe, 0.013), min_ttft_delta_ms=0.003)
        self.assertEqual([x.detector_id for x in fractional.pair_findings], ["D8"])
        self.assertEqual(diff_traces(
            self.trace(None, 0.010), self.trace(write_probe, 0.013), min_ttft_delta_ms=0.0030001,
        ).pair_findings, [])

    def test_audit_only_and_waterfall_probe_cards(self):
        payload = '<img src=x onerror="alert(7)">'
        before = self.trace(None)
        after = self.trace({
            "lmcache_mp": {"delta_hit_l2_keys": 3, "delta_l1_read_failures": 1},
            "proc_io": {"prefill_window": {"delta_rchar_bytes": 32 * MIB, "delta_read_bytes": 0,
                                           "delta_write_bytes_net": 64 * MIB}},
            "mooncake": {"client_version": payload},
        }, 130)
        with tempfile.TemporaryDirectory() as root:
            path = Path(root) / "trace.jsonl"
            write_trace(path, after)
            stdout = io.StringIO()
            with redirect_stdout(stdout):
                self.assertEqual(main(["audit", str(path), "--only", "D6,D7,D8", "--json"]), 0)
            self.assertEqual([f["detector_id"] for f in json.loads(stdout.getvalue())["findings"]], ["D6", "D7"])
            for only in ("D5", "D1,D5"):
                stderr = io.StringIO()
                with redirect_stderr(stderr):
                    self.assertEqual(main(["audit", str(path), "--only", only]), 1)
                self.assertIn("D5", stderr.getvalue())
        report = diff_traces(before, after)
        audit_html = render_audit_html(after, storage_findings(after))
        diff_html = render_diff_html(before, after, report)
        for rendered in (audit_html, diff_html):
            self.assertIn("Backend Probe (v0.2)", rendered)
            self.assertIn("active", rendered)
            self.assertIn("L2 hits", rendered)
            self.assertIn("rchar", rendered)
            self.assertIn("read_bytes", rendered)
            self.assertIn("D6, D7", rendered)
            self.assertNotIn(payload, rendered)
            self.assertLess(len(rendered.encode("utf-8")), 80 * 1024)
        self.assertIn("D6, D7, D8", diff_html)

    def test_diff_waterfall_labels_probe_metrics_from_either_trace(self):
        baseline = self.trace({"lmcache_mp": {"status": "ok", "delta_hit_l2_keys": 9}})
        target = self.trace({"mooncake": {"client_status": "ok", "delta_quota_rejects": 2}})
        for before, after, omit in ((baseline, target, None), (baseline, self.clean, "Target")):
            with self.subTest(omit=omit):
                rendered = render_diff_html(before, after, diff_traces(before, after))
                self.assertIn('<h3>Baseline</h3>', rendered)
                self.assertIn('<dt>L2 hits (keys)</dt><dd>9</dd>', rendered)
                if omit:
                    self.assertNotIn('<h3>Target</h3>', rendered)
                else:
                    self.assertIn('<h3>Target</h3>', rendered)
                    self.assertIn('<dt>Quota rejects</dt><dd>2</dd>', rendered)
                self.assertLess(len(rendered.encode("utf-8")), 80 * 1024)
