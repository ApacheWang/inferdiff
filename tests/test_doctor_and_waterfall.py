"""End-to-end loopback tests for inferdiff doctor (C1..C8) and single-file --html SVG waterfall."""

from __future__ import annotations

import http.server
import io
import json
import re
import socketserver
import tempfile
import threading
import time
import unittest
from contextlib import redirect_stdout
from pathlib import Path
from typing import Any, Callable, Dict, List

from inferdiff.canary import C6_TARGET_TEXT, render_doctor_terminal, run_doctor
from inferdiff.cli import main as cli_main
from inferdiff.detectors import audit_trace
from inferdiff.differ import diff_traces
from inferdiff.schema import (
    EXIT_OK,
    EXIT_SEMANTIC_REGRESSION,
    EXIT_SILENT_PROTOCOL_BREACH,
    TraceDocument,
    TraceFrame,
    TraceHeader,
    assemble_summary,
    body_sha256,
    extract_effective_params,
    load_trace,
)
from inferdiff.waterfall import MAX_HTML_BYTES, render_audit_html, render_diff_html, render_doctor_html


class _ThreadingServer(socketserver.ThreadingMixIn, http.server.HTTPServer):
    daemon_threads = True
    allow_reuse_address = True


def _start_api_mock(mode: str):
    """Programmable loopback OpenAI/Ollama mock server.

    Modes:
      - 'healthy': clean OpenAI-compatible engine passing C1..C8 (Grade A+)
      - 'faulty_relay': reproduces C1 P0, C4 stripped usage, C5 role strip + idx=0 merge,
                       C6 U+FFFD, C7 buffered fake streaming, C8 prompt_tokens drift (Grade F)
      - 'p1_only': zero P0 breaches, triggers C4 & C7 P1 warnings (Grade B, exit 0 / --strict 3)
      - 'ollama_tags': Ollama /api/tags auto-discovery + clean /api/chat NDJSON stream
    """
    state = {"c8_calls": 0, "seen_auth": []}

    class Handler(http.server.BaseHTTPRequestHandler):
        protocol_version = "HTTP/1.1"

        def log_message(self, format, *args):
            return

        def do_GET(self):
            state["seen_auth"].append(self.headers.get("Authorization"))
            if mode == "ollama_tags":
                if self.path == "/api/tags":
                    body = json.dumps({"models": [{"name": "qwen3:8b"}]}).encode("utf-8")
                    self.send_response(200)
                    self.send_header("Content-Type", "application/json")
                    self.send_header("Content-Length", str(len(body)))
                    self.end_headers()
                    self.wfile.write(body)
                    return
                self.send_response(404)
                self.send_header("Content-Length", "0")
                self.end_headers()
                return

            if self.path.endswith("/models"):
                body = json.dumps(
                    {"data": [{"id": "text-embedding-3-small"}, {"id": "qwen3-32b-instruct"}]}
                ).encode("utf-8")
                self.send_response(200)
                self.send_header("Content-Type", "application/json")
                self.send_header("Content-Length", str(len(body)))
                self.end_headers()
                self.wfile.write(body)
                return

            self.send_response(404)
            self.send_header("Content-Length", "0")
            self.end_headers()

        def _send_sse(self, events: List[str], *, delay_before_first: float = 0.0, delay_between: float = 0.0):
            self.send_response(200)
            self.send_header("Content-Type", "text/event-stream; charset=utf-8")
            self.send_header("Connection", "close")
            self.end_headers()
            if delay_before_first > 0:
                time.sleep(delay_before_first)
            for idx, ev in enumerate(events):
                if idx > 0 and delay_between > 0:
                    time.sleep(delay_between)
                self.wfile.write(ev.encode("utf-8"))
                self.wfile.flush()

        def do_POST(self):
            state["seen_auth"].append(self.headers.get("Authorization"))
            length = int(self.headers.get("Content-Length", "0"))
            raw = self.rfile.read(length) if length > 0 else b"{}"
            req = json.loads(raw.decode("utf-8"))
            msgs = req.get("messages") or []
            user_txt = msgs[0].get("content", "") if msgs else ""

            if mode == "ollama_tags":
                lines = [
                    json.dumps({"message": {"role": "assistant", "content": C6_TARGET_TEXT if "原样" in user_txt else "01,02,03,04,05,06,07,08,09,10"}, "done": False}) + "\n",
                    json.dumps({"message": {"role": "assistant", "content": ",11,12,13"}, "done": False}) + "\n",
                    json.dumps({"message": {"role": "assistant", "content": ",14,15,16"}, "done": False}) + "\n",
                    json.dumps({"message": {"role": "assistant", "content": ",17,18"}, "done": False}) + "\n",
                    json.dumps({"message": {"role": "assistant", "content": ""}, "done": True, "done_reason": "stop", "prompt_eval_count": 320 if req.get("tools") else 18, "eval_count": 12}) + "\n",
                ]
                payload = "".join(lines).encode("utf-8")
                self.send_response(200)
                self.send_header("Content-Type", "application/x-ndjson")
                self.send_header("Content-Length", str(len(payload)))
                self.end_headers()
                self.wfile.write(payload)
                return

            # Identify probe from deterministic canary request payload
            if "write_config" in user_txt:  # C1
                if mode == "faulty_relay":
                    # Truncated tool JSON claiming finish_reason="stop" (D1 P0!)
                    self._send_sse([
                        'data: {"model":"qwen3-32b","choices":[{"index":0,"delta":{"role":"assistant","tool_calls":[{"index":0,"id":"c1","function":{"name":"write_config","arguments":"{\\"service_name\\": \\"api\\", \\"desc"}}]}}]}\n\n',
                        'data: {"model":"qwen3-32b","choices":[{"index":0,"delta":{},"finish_reason":"stop"}]}\n\n',
                        'data: {"model":"qwen3-32b","choices":[],"usage":{"prompt_tokens":45,"completion_tokens":28,"total_tokens":73}}\n\n',
                        "data: [DONE]\n\n",
                    ])
                else:
                    # Honest length cutoff
                    self._send_sse([
                        'data: {"model":"qwen3-32b","choices":[{"index":0,"delta":{"role":"assistant","tool_calls":[{"index":0,"id":"c1","function":{"name":"write_config","arguments":"{\\"service_name\\": \\"api\\", \\"desc"}}]}}]}\n\n',
                        'data: {"model":"qwen3-32b","choices":[{"index":0,"delta":{},"finish_reason":"length"}]}\n\n',
                        'data: {"model":"qwen3-32b","choices":[],"usage":{"prompt_tokens":45,"completion_tokens":28,"total_tokens":73}}\n\n',
                        "data: [DONE]\n\n",
                    ])
                return

            if "digits 42" in user_txt:  # C2
                self._send_sse([
                    'data: {"model":"qwen3-32b","choices":[{"index":0,"delta":{"role":"assistant","content":"42"}}]}\n\n',
                    'data: {"model":"qwen3-32b","choices":[{"index":0,"delta":{},"finish_reason":"stop"}]}\n\n',
                    'data: {"model":"qwen3-32b","choices":[],"usage":{"prompt_tokens":14,"completion_tokens":2,"total_tokens":16}}\n\n',
                    "data: [DONE]\n\n",
                ])
                return

            if req.get("ignore_eos") is True:  # C3
                if mode == "p1_only":
                    self.send_response(400)
                    self.send_header("Content-Length", "0")
                    self.end_headers()
                    return
                self._send_sse([
                    'data: {"model":"qwen3-32b","choices":[{"index":0,"delta":{"role":"assistant","content":"1 2 3 ... 96"}}]}\n\n',
                    'data: {"model":"qwen3-32b","choices":[{"index":0,"delta":{},"finish_reason":"length"}]}\n\n',
                    'data: {"model":"qwen3-32b","choices":[],"usage":{"prompt_tokens":18,"completion_tokens":96,"total_tokens":114}}\n\n',
                    "data: [DONE]\n\n",
                ])
                return

            if "Reply OK." in user_txt:  # C4a / C4b
                has_tools = bool(req.get("tools"))
                if mode in ("faulty_relay", "p1_only") and has_tools:
                    # Strip trailing usage chunk when tools present (LiteLLM #16112)
                    self._send_sse([
                        'data: {"model":"qwen3-32b","choices":[{"index":0,"delta":{"role":"assistant","content":"OK"}}]}\n\n',
                        'data: {"model":"qwen3-32b","choices":[{"index":0,"delta":{},"finish_reason":"stop"}]}\n\n',
                        "data: [DONE]\n\n",
                    ])
                else:
                    pt = 420 if has_tools else 12
                    self._send_sse([
                        'data: {"model":"qwen3-32b","choices":[{"index":0,"delta":{"role":"assistant","content":"OK"}}]}\n\n',
                        'data: {"model":"qwen3-32b","choices":[{"index":0,"delta":{},"finish_reason":"stop"}]}\n\n',
                        f'data: {{"model":"qwen3-32b","choices":[],"usage":{{"prompt_tokens":{pt},"completion_tokens":1,"total_tokens":{pt + 1}}}}}\n\n',
                        "data: [DONE]\n\n",
                    ])
                return

            if "node-a" in user_txt:  # C5
                if mode == "faulty_relay":
                    # Missing role AND parallel tools merged onto idx=0 producing corrupt JSON!
                    self._send_sse([
                        'data: {"model":"qwen3-32b","choices":[{"index":0,"delta":{"tool_calls":[{"index":0,"id":"c1","function":{"name":"get_node_status","arguments":"{\\"node\\":\\"node-a\\"}"}}]}}]}\n\n',
                        'data: {"model":"qwen3-32b","choices":[{"index":0,"delta":{"tool_calls":[{"index":0,"function":{"arguments":"{\\"node\\":\\"node-b\\"}"}}]}}]}\n\n',
                        'data: {"model":"qwen3-32b","choices":[{"index":0,"delta":{},"finish_reason":"tool_calls"}]}\n\n',
                        "data: [DONE]\n\n",
                    ])
                else:
                    self._send_sse([
                        'data: {"model":"qwen3-32b","choices":[{"index":0,"delta":{"role":"assistant","tool_calls":[{"index":0,"id":"c1","function":{"name":"get_node_status","arguments":"{\\"node\\":\\"node-a\\"}"}}]}}]}\n\n',
                        'data: {"model":"qwen3-32b","choices":[{"index":0,"delta":{"tool_calls":[{"index":1,"id":"c2","function":{"name":"get_node_status","arguments":"{\\"node\\":\\"node-b\\"}"}}]}}]}\n\n',
                        'data: {"model":"qwen3-32b","choices":[{"index":0,"delta":{},"finish_reason":"tool_calls"}]}\n\n',
                        'data: {"model":"qwen3-32b","choices":[],"usage":{"prompt_tokens":48,"completion_tokens":24,"total_tokens":72}}\n\n',
                        "data: [DONE]\n\n",
                    ])
                return

            if "原样逐字复述" in user_txt:  # C6
                out_str = "吞吐量Δ=99.8% [🔥\ufffd]" if mode == "faulty_relay" else C6_TARGET_TEXT
                self._send_sse([
                    f'data: {json.dumps({"model": "qwen3-32b", "choices": [{"index": 0, "delta": {"role": "assistant", "content": out_str}}]}, ensure_ascii=False)}\n\n',
                    'data: {"model":"qwen3-32b","choices":[{"index":0,"delta":{},"finish_reason":"stop"}]}\n\n',
                    'data: {"model":"qwen3-32b","choices":[],"usage":{"prompt_tokens":28,"completion_tokens":16,"total_tokens":44}}\n\n',
                    "data: [DONE]\n\n",
                ])
                return

            if "01 through 25" in user_txt:  # C7
                if mode in ("faulty_relay", "p1_only"):
                    # Leave room for a Windows clock tick in the 96% TTFT ratio.
                    full_seq = ",".join(f"{i:02d}" for i in range(1, 26))
                    self._send_sse(
                        [
                            f'data: {json.dumps({"model": "qwen3-32b", "choices": [{"index": 0, "delta": {"role": "assistant", "content": full_seq}}]})}\n\n',
                            'data: {"model":"qwen3-32b","choices":[{"index":0,"delta":{},"finish_reason":"stop"}]}\n\n',
                            "data: [DONE]\n\n",
                        ],
                        delay_before_first=0.6,
                    )
                else:
                    # True incremental streaming across 5 frames
                    chunks = ["01,02,03,04,05,", "06,07,08,09,10,", "11,12,13,14,15,", "16,17,18,19,20,", "21,22,23,24,25"]
                    evs = [
                        f'data: {json.dumps({"model": "qwen3-32b", "choices": [{"index": 0, "delta": {"role": "assistant" if i == 0 else None, "content": ch}}]})}\n\n'
                        for i, ch in enumerate(chunks)
                    ]
                    evs.append('data: {"model":"qwen3-32b","choices":[{"index":0,"delta":{},"finish_reason":"stop"}]}\n\n')
                    evs.append('data: {"model":"qwen3-32b","choices":[],"usage":{"prompt_tokens":22,"completion_tokens":50,"total_tokens":72}}\n\n')
                    evs.append("data: [DONE]\n\n")
                    self._send_sse(evs, delay_between=0.006)
                return

            if "[nonce:" in user_txt:  # C8
                state["c8_calls"] += 1
                pt = 24 if state["c8_calls"] == 1 else (34 if mode == "faulty_relay" else 24)
                fp = "fp_backend_a" if (state["c8_calls"] == 1 or mode != "faulty_relay") else "fp_backend_b"
                self._send_sse([
                    f'data: {{"model":"qwen3-32b","system_fingerprint":"{fp}","choices":[{{"index":0,"delta":{{"role":"assistant","content":"READY"}}}}]}}\n\n',
                    'data: {"model":"qwen3-32b","choices":[{"index":0,"delta":{},"finish_reason":"stop"}]}\n\n',
                    f'data: {{"model":"qwen3-32b","choices":[],"usage":{{"prompt_tokens":{pt},"completion_tokens":1,"total_tokens":{pt + 1}}}}}\n\n',
                    "data: [DONE]\n\n",
                ])
                return

            self.send_response(404)
            self.send_header("Content-Length", "0")
            self.end_headers()

    srv = _ThreadingServer(("127.0.0.1", 0), Handler)
    port = srv.server_address[1]
    t = threading.Thread(target=srv.serve_forever, daemon=True)
    t.start()
    return srv, port, state


class TestDoctorCanarySuite(unittest.TestCase):
    def test_doctor_healthy_full_profile_auto_discovers_model_and_grades_a_plus(self):
        srv, port, state = _start_api_mock("healthy")
        try:
            with tempfile.TemporaryDirectory() as td:
                save_dir = Path(td) / "traces"
                html_out = Path(td) / "doctor.html"
                rep = run_doctor(
                    base_url=f"http://127.0.0.1:{port}/v1",
                    api_key="sk-live-secret-doctor-key-999",
                    profile="full",
                    save_dir=str(save_dir),
                )
                self.assertEqual(rep.model, "qwen3-32b-instruct")  # Skipped embedding model!
                self.assertEqual(rep.grade, "A+")
                self.assertEqual(rep.exit_code, EXIT_OK)
                self.assertEqual(rep.p0_count, 0)
                self.assertEqual(rep.warning_count, 0)
                self.assertEqual(len(rep.results), 8)
                self.assertTrue(all(r.status == "PASS" for r in rep.results))

                # Auth header sent on wire, NEVER written to saved traces or terminal/HTML
                self.assertIn("Bearer sk-live-secret-doctor-key-999", state["seen_auth"])
                term = render_doctor_terminal(rep, no_color=True)
                self.assertIn("Wire Health Grade: A+", term)
                self.assertNotIn("sk-live-secret-doctor-key-999", term)

                html_text = render_doctor_html(rep)
                html_out.write_text(html_text, encoding="utf-8")
                self.assertNotIn("sk-live-secret-doctor-key-999", html_text)
                self.assertLessEqual(len(html_text.encode("utf-8")), MAX_HTML_BYTES)
                self.assertIn("Generated by inferdiff", html_text)
                for p in save_dir.glob("*.trace.jsonl"):
                    self.assertNotIn("sk-live-secret-doctor-key-999", p.read_text(encoding="utf-8"))
        finally:
            srv.shutdown()
            srv.server_close()

    def test_doctor_faulty_relay_catches_c1_c4_c5_c6_c7_c8_and_exits_2(self):
        srv, port, _ = _start_api_mock("faulty_relay")
        try:
            with tempfile.TemporaryDirectory() as td:
                html_file = Path(td) / "relay.html"
                buf = io.StringIO()
                with redirect_stdout(buf):
                    rc = cli_main([
                        "doctor",
                        f"http://127.0.0.1:{port}/v1",
                        "--profile", "relay",
                        "--save-dir", str(Path(td) / "saved"),
                        "--html", str(html_file),
                        "--no-color",
                    ])
                self.assertEqual(rc, EXIT_SILENT_PROTOCOL_BREACH)
                out = buf.getvalue()
                self.assertIn("Wire Health Grade: F", out)
                self.assertIn("[FAIL] C1", out)
                self.assertIn("[WARN] C4", out)
                self.assertIn("[FAIL] C5", out)
                self.assertIn("[FAIL] C6", out)
                self.assertIn("[WARN] C7", out)
                self.assertIn("[WARN] C8", out)
                self.assertTrue(html_file.exists())
                h_txt = html_file.read_text(encoding="utf-8")
                self.assertIn("DOCTOR GRADE: F", h_txt)
                self.assertLessEqual(len(h_txt.encode("utf-8")), MAX_HTML_BYTES)

                # Closed loop: saved doctor_summary.json exists and saved C1 trace exports cleanly <=25 lines
                saved_dir = Path(td) / "saved"
                self.assertTrue((saved_dir / "doctor_summary.json").exists())
                c1_trace = saved_dir / "c1_tool_call_budget_clip.trace.jsonl"
                self.assertTrue(c1_trace.exists())
                exp_buf = io.StringIO()
                with redirect_stdout(exp_buf):
                    rc_exp = cli_main(["export", str(c1_trace), "--format", "github-issue"])
                self.assertEqual(rc_exp, EXIT_SILENT_PROTOCOL_BREACH)
                self.assertLessEqual(len(exp_buf.getvalue().splitlines()), 25)
        finally:
            srv.shutdown()
            srv.server_close()

    def test_doctor_p1_only_strict_flag_and_c3_http_400_skip(self):
        srv, port, _ = _start_api_mock("p1_only")
        try:
            rep_relaxed = run_doctor(base_url=f"http://127.0.0.1:{port}/v1", profile="full", save_dir=None, strict=False)
            self.assertEqual(rep_relaxed.exit_code, EXIT_OK)
            self.assertIn(rep_relaxed.grade, ("B", "C"))
            by_id = {r.probe_id: r for r in rep_relaxed.results}
            self.assertEqual(by_id["C3"].status, "SKIP")
            self.assertEqual(by_id["C4"].status, "WARN")
            self.assertEqual(by_id["C7"].status, "WARN")

            rep_strict = run_doctor(base_url=f"http://127.0.0.1:{port}/v1", profile="full", save_dir=None, strict=True)
            self.assertEqual(rep_strict.exit_code, EXIT_SEMANTIC_REGRESSION)
        finally:
            srv.shutdown()
            srv.server_close()

    def test_doctor_ollama_tags_auto_discovery(self):
        srv, port, _ = _start_api_mock("ollama_tags")
        try:
            rep = run_doctor(base_url=f"http://127.0.0.1:{port}", profile="quick", save_dir=None)
            self.assertEqual(rep.dialect, "ollama-ndjson")
            self.assertEqual(rep.model, "qwen3:8b")
            self.assertEqual(rep.p0_count, 0)
        finally:
            srv.shutdown()
            srv.server_close()


class TestSingleFileHtmlWaterfall(unittest.TestCase):
    def test_diff_and_audit_html_airgap_csp_xss_safe_and_under_80kb(self):
        root = Path(__file__).resolve().parents[1] / "examples"
        b1 = load_trace(root / "case1_responses_truncated_tool" / "baseline.trace.jsonl")
        a1 = load_trace(root / "case1_responses_truncated_tool" / "target.trace.jsonl")
        # Inject XSS payload into label to verify strict escaping
        a1.header.label = '<script>alert("xss")</script>'
        rep = diff_traces(b1, a1, fail_on="p0")
        html_diff = render_diff_html(b1, a1, rep)

        self.assertLessEqual(len(html_diff.encode("utf-8")), MAX_HTML_BYTES)
        self.assertIn("default-src 'none'; style-src 'unsafe-inline'; script-src 'sha256-", html_diff)
        self.assertNotIn("script-src 'unsafe-inline'", html_diff)
        self.assertIn("Generated by inferdiff", html_diff)
        self.assertNotIn('<script>alert("xss")</script>', html_diff)
        self.assertIn("&lt;script&gt;alert(&quot;xss&quot;)&lt;/script&gt;", html_diff)
        # Zero external CDN links (<script src= / <link href= / <img src=)
        self.assertIsNone(re.search(r"<(?:script|link|img)[^>]*(?:src|href)=[\"']https?://", html_diff, re.I))

        # Test CLI `diff --html`, `export --format html`, and overwrite protection
        with tempfile.TemporaryDirectory() as td:
            out_h = Path(td) / "case1.html"
            with redirect_stdout(io.StringIO()):
                rc = cli_main([
                    "diff",
                    str(root / "case1_responses_truncated_tool" / "baseline.trace.jsonl"),
                    str(root / "case1_responses_truncated_tool" / "target.trace.jsonl"),
                    "--html", str(out_h),
                    "--no-color",
                ])
            self.assertEqual(rc, EXIT_SILENT_PROTOCOL_BREACH)
            self.assertTrue(out_h.exists())
            self.assertLessEqual(out_h.stat().st_size, MAX_HTML_BYTES)

            # Actually invoke `export --format html` on diff and single-trace audit
            exp_h = Path(td) / "exported.html"
            rc_eh = cli_main([
                "export",
                str(root / "case1_responses_truncated_tool" / "baseline.trace.jsonl"),
                str(root / "case1_responses_truncated_tool" / "target.trace.jsonl"),
                "--format", "html",
                "-o", str(exp_h),
            ])
            self.assertEqual(rc_eh, EXIT_SILENT_PROTOCOL_BREACH)
            self.assertTrue(exp_h.exists())
            self.assertLessEqual(exp_h.stat().st_size, MAX_HTML_BYTES)
            self.assertIn("script-src 'sha256-", exp_h.read_text(encoding="utf-8"))

            # Reject --html aliasing an input trace (must NOT overwrite evidence!)
            tr_copy = Path(td) / "input.trace.jsonl"
            orig_bytes = (root / "case1_responses_truncated_tool" / "baseline.trace.jsonl").read_bytes()
            tr_copy.write_bytes(orig_bytes)
            err_buf = io.StringIO()
            from contextlib import redirect_stderr
            with redirect_stderr(err_buf):
                rc_alias = cli_main(["audit", str(tr_copy), "--html", str(tr_copy)])
            self.assertEqual(rc_alias, 1)
            self.assertEqual(tr_copy.read_bytes(), orig_bytes)

            # Audit HTML on Case 2
            a2 = load_trace(root / "case2_ollama_ghost_thinking_tokens" / "target.trace.jsonl")
            f2 = audit_trace(a2)
            html_aud = render_audit_html(a2, f2)
            self.assertIn("GHOST_BUDGET_EMPTY_OUTPUT", html_aud)
            self.assertLessEqual(len(html_aud.encode("utf-8")), MAX_HTML_BYTES)

    def test_2000_frame_and_1200_stall_frames_and_oversized_tool_name_stay_under_80kb(self):
        body = {"model": "m", "stream": True, "messages": [{"role": "user", "content": "long"}]}
        hdr = TraceHeader(
            trace_id="tr_2000",
            label="long-gen",
            recorded_at_utc="2026-11-26T00:00:00.000Z",
            dialect="openai-chat",
            request={
                "method": "POST",
                "url": "http://127.0.0.1:8080/v1/chat/completions",
                "headers_redacted": {},
                "body_sha256": body_sha256(body),
                "body": body,
                "effective_params": extract_effective_params(body, "openai-chat"),
            },
            response_meta={"status_code": 200, "content_type": "text/event-stream", "t_headers_ms": 5.0},
        )
        # 1) 1,200 ALL-STALL frames (dt=300ms each) + lone surrogate in raw_wire MUST stay < 80 KiB and never crash
        stall_frames: List[TraceFrame] = []
        t_ms = 0.0
        for seq in range(1200):
            t_ms += 300.0
            stall_frames.append(
                TraceFrame(
                    seq=seq,
                    t_rel_ms=t_ms,
                    dt_ms=300.0,
                    sse_event=None,
                    raw_wire='data: {"choices":[{"index":0,"delta":{"content":"x\ud800"}}]}\n\n',
                    is_done_sentinel=False,
                    parse_error=None,
                    norm={"phase": "CONTENT", "text_delta": "x", "reasoning_delta": "", "tool_deltas": [], "closed_events": [], "finish_reason": None, "terminal_status": None, "usage": {}},
                )
            )
        stall_frames.append(
            TraceFrame(
                seq=1200,
                t_rel_ms=t_ms + 1.0,
                dt_ms=1.0,
                sse_event=None,
                raw_wire="data: [DONE]\n\n",
                is_done_sentinel=True,
                parse_error=None,
                norm={"phase": "TERMINAL", "text_delta": "", "reasoning_delta": "", "tool_deltas": [], "closed_events": ["[DONE]"], "finish_reason": "stop", "terminal_status": None, "usage": {}},
            )
        )
        summary_s = assemble_summary(hdr, stall_frames, total_ms=t_ms + 1.0, socket_eof_clean=True)
        html_stall = render_audit_html(TraceDocument(header=hdr, frames=stall_frames, summary=summary_s), [])
        self.assertLessEqual(len(html_stall.encode("utf-8")), MAX_HTML_BYTES)
        self.assertIn("Collapsed", html_stall)

        # 2) Malformed tool call with 120 KiB tool name MUST still render strictly < 80 KiB
        big_name = "T" * 120_000
        f_big = [
            TraceFrame(
                seq=0,
                t_rel_ms=10.0,
                dt_ms=10.0,
                sse_event=None,
                raw_wire="data: {}\n\n",
                is_done_sentinel=False,
                parse_error=None,
                norm={"phase": "TOOL", "text_delta": "", "reasoning_delta": "", "tool_deltas": [{"index": 0, "id": "c1", "name": big_name, "arguments_delta": '{"broken'}], "closed_events": [], "finish_reason": "tool_calls", "terminal_status": None, "usage": {}},
            ),
            TraceFrame(
                seq=1,
                t_rel_ms=11.0,
                dt_ms=1.0,
                sse_event=None,
                raw_wire="data: [DONE]\n\n",
                is_done_sentinel=True,
                parse_error=None,
                norm={"phase": "TERMINAL", "text_delta": "", "reasoning_delta": "", "tool_deltas": [], "closed_events": ["[DONE]"], "finish_reason": None, "terminal_status": None, "usage": {}},
            ),
        ]
        doc_big = TraceDocument(header=hdr, frames=f_big, summary=assemble_summary(hdr, f_big, total_ms=11.0, socket_eof_clean=True))
        html_big = render_audit_html(doc_big, audit_trace(doc_big))
        self.assertLessEqual(len(html_big.encode("utf-8")), MAX_HTML_BYTES)

    def test_codex_v011_adversarial_probes_reflected_secret_false_pass_ipv6_and_exits(self):
        from inferdiff.canary import _build_url, resolve_api_key, resolve_endpoints_and_model
        import urllib.parse

        # 1) Empty explicit --api-key rejected
        with self.assertRaises(ValueError):
            resolve_api_key("")
        with self.assertRaises(ValueError):
            resolve_api_key("   ")

        # 2) IPv6 bracket preservation & query-bearing URL normalization & proxy prefix preservation
        p_v6 = urllib.parse.urlsplit("http://[::1]:11434/proxy?api-version=2024-10-21")
        self.assertEqual(_build_url(p_v6, "/proxy/api/chat"), "http://[::1]:11434/proxy/api/chat?api-version=2024-10-21")
        chat_u, resp_u, dial, mdl = resolve_endpoints_and_model(
            "http://[::1]:8080/gateway/v1?api-version=2024-10-21",
            model="m1",
            headers={},
            timeout=5.0,
        )
        self.assertEqual(chat_u, "http://[::1]:8080/gateway/v1/chat/completions?api-version=2024-10-21")
        self.assertEqual(resp_u, "http://[::1]:8080/gateway/v1/responses?api-version=2024-10-21")
        self.assertEqual(dial, "openai-chat")

        # 3) Reflected opaque secret + C1 plain text + C6 ASCII-only + C5 invalid raw indices + C3 104/96 + C7 2-chunk slow
        opaque_secret = "OPAQUE_SYNTHETIC_RELAY_SECRET_98765"

        class AdversarialHandler(http.server.BaseHTTPRequestHandler):
            protocol_version = "HTTP/1.1"
            def log_message(self, format, *args):
                return
            def do_GET(self):
                if self.path.endswith("/models"):
                    body = json.dumps({"data": [{"id": f"mdl-{opaque_secret}"}]}).encode("utf-8")
                    self.send_response(200)
                    self.send_header("Content-Type", "application/json")
                    self.send_header("Content-Length", str(len(body)))
                    self.end_headers()
                    self.wfile.write(body)
                    return
                self.send_response(401)
                self.send_header("Content-Length", "0")
                self.end_headers()

            def _sse(self, evs: List[str], gap: float = 0.0):
                self.send_response(200)
                self.send_header("Content-Type", "text/event-stream")
                self.send_header("Connection", "close")
                self.end_headers()
                for i, e in enumerate(evs):
                    if i > 0 and gap > 0:
                        time.sleep(gap)
                    self.wfile.write(e.encode("utf-8"))
                    self.wfile.flush()

            def do_POST(self):
                n = int(self.headers.get("Content-Length", "0"))
                req = json.loads((self.rfile.read(n) if n else b"{}").decode("utf-8"))
                txt = (req.get("messages") or [{}])[0].get("content", "")
                if self.path.endswith("/responses"):
                    self.send_response(404)
                    self.send_header("Content-Length", "0")
                    self.end_headers()
                    return
                if "write_config" in txt:  # C1: plain text 0 tools + reflected secret -> SKIP (not PASS!)
                    self._sse([
                        f'data: {{"model":"mdl-{opaque_secret}","choices":[{{"index":0,"delta":{{"role":"assistant","content":"plain text {opaque_secret}"}}}}]}}\n\n',
                        'data: {"choices":[{"index":0,"delta":{},"finish_reason":"stop"}]}\n\n',
                        "data: [DONE]\n\n",
                    ])
                elif "digits 42" in txt:  # C2: 400 on stream_options, retry succeeds with "42"
                    if "stream_options" in req:
                        self.send_response(400)
                        self.send_header("Content-Length", "0")
                        self.end_headers()
                        return
                    self._sse([
                        'data: {"choices":[{"index":0,"delta":{"role":"assistant","content":"42"},"finish_reason":"stop"}]}\n\n',
                        "data: [DONE]\n\n",
                    ])
                elif req.get("ignore_eos") is True:  # C3: 104/96 tokens -> WARN (not PASS!)
                    self._sse([
                        'data: {"choices":[{"index":0,"delta":{"role":"assistant","content":"1 2 3"}}]}\n\n',
                        'data: {"choices":[{"index":0,"delta":{},"finish_reason":"length"}]}\n\n',
                        'data: {"choices":[],"usage":{"prompt_tokens":10,"completion_tokens":104,"total_tokens":114}}\n\n',
                        "data: [DONE]\n\n",
                    ])
                elif "Reply OK." in txt:  # C4: usage attached on content frame (missing empty choices tail) -> WARN!
                    pt = 400 if req.get("tools") else 10
                    self._sse([
                        f'data: {{"choices":[{{"index":0,"delta":{{"role":"assistant","content":"OK"}},"finish_reason":"stop"}}],"usage":{{"prompt_tokens":{pt},"completion_tokens":1,"total_tokens":{pt + 1}}}}}\n\n',
                        "data: [DONE]\n\n",
                    ])
                elif "node-a" in txt:  # C5: invalid negative/sparse raw indices [-1, 9] -> WARN (not PASS!)
                    self._sse([
                        'data: {"choices":[{"index":0,"delta":{"role":"assistant","tool_calls":[{"index":-1,"id":"c1","function":{"name":"get_node_status","arguments":"{\\"node\\":\\"node-a\\"}"}}]}}]}\n\n',
                        'data: {"choices":[{"index":0,"delta":{"tool_calls":[{"index":9,"id":"c2","function":{"name":"get_node_status","arguments":"{\\"node\\":\\"node-b\\"}"}}]}}]}\n\n',
                        'data: {"choices":[{"index":0,"delta":{},"finish_reason":"tool_calls"}]}\n\n',
                        "data: [DONE]\n\n",
                    ])
                elif "原样逐字复述" in txt:  # C6: ASCII-only reply -> SKIP (inconclusive, not PASS!)
                    self._sse([
                        'data: {"choices":[{"index":0,"delta":{"role":"assistant","content":"ASCII only"},"finish_reason":"stop"}]}\n\n',
                        "data: [DONE]\n\n",
                    ])
                elif "01 through 25" in txt:  # C7: 2 chunks 290ms apart -> NOT flagged as buffered WARN!
                    self._sse([
                        'data: {"choices":[{"index":0,"delta":{"role":"assistant","content":"01,02,03,04,05,06,07,08,09,10,11,12,"}}]}\n\n',
                        'data: {"choices":[{"index":0,"delta":{"content":"13,14,15,16,17,18,19,20,21,22,23,24,25"},"finish_reason":"stop"}]}\n\n',
                        "data: [DONE]\n\n",
                    ], gap=0.29)
                else:  # C8: differing output with unknown usage -> WARN (P2)
                    val = "READY_1" if "a" in txt else "READY_2"
                    self._sse([
                        f'data: {{"choices":[{{"index":0,"delta":{{"role":"assistant","content":"{val}"}},"finish_reason":"stop"}}],"model":"m"}}\n\n',
                        "data: [DONE]\n\n",
                    ])

        srv = _ThreadingServer(("127.0.0.1", 0), AdversarialHandler)
        port = srv.server_address[1]
        threading.Thread(target=srv.serve_forever, daemon=True).start()
        try:
            with tempfile.TemporaryDirectory() as td:
                sdir = Path(td) / "adv_traces"
                rep = run_doctor(
                    base_url=f"http://127.0.0.1:{port}/v1",
                    api_key=opaque_secret,
                    profile="full",
                    save_dir=str(sdir),
                )
                by = {r.probe_id: r for r in rep.results}
                self.assertEqual(by["C1"].status, "SKIP")
                self.assertEqual(by["C2"].status, "PASS")
                self.assertEqual(by["C3"].status, "WARN")
                self.assertEqual(by["C4"].status, "WARN")
                self.assertEqual(by["C5"].status, "WARN")
                self.assertEqual(by["C6"].status, "SKIP")
                self.assertEqual(by["C7"].status, "SKIP")  # 2 chunks 290ms apart: NOT buffered WARN, NOT false PASS
                self.assertNotEqual(rep.grade, "A+")

                # Opaque reflected secret MUST NOT appear in JSON, terminal, HTML, or saved traces!
                self.assertNotIn(opaque_secret, json.dumps(rep.to_dict()))
                self.assertNotIn(opaque_secret, render_doctor_terminal(rep, no_color=True))
                self.assertNotIn(opaque_secret, render_doctor_html(rep))
                for p in sdir.glob("*.trace.jsonl"):
                    self.assertNotIn(opaque_secret, p.read_text(encoding="utf-8"))

                # Explicit-model HTTP 500 server must exit 1 (NOT exit 2!)
                class Err500(http.server.BaseHTTPRequestHandler):
                    def log_message(self, format, *args): return
                    def do_POST(self):
                        n = int(self.headers.get("Content-Length", "0"))
                        if n: self.rfile.read(n)
                        self.send_response(500)
                        self.send_header("Content-Length", "0")
                        self.end_headers()
                srv5 = _ThreadingServer(("127.0.0.1", 0), Err500)
                p5 = srv5.server_address[1]
                threading.Thread(target=srv5.serve_forever, daemon=True).start()
                try:
                    rep5 = run_doctor(base_url=f"http://127.0.0.1:{p5}/v1", model="m1", profile="quick", save_dir=None)
                    self.assertEqual(rep5.exit_code, 1)
                finally:
                    srv5.shutdown()
                    srv5.server_close()
        finally:
            srv.shutdown()
            srv.server_close()

    def test_v011_default_thinking_retry_c5_required_fallback_c7_reasoning_c8_variance_and_action_yml(self):
        seen_c2_kwargs: List[Any] = []
        seen_c5_choices: List[Any] = []
        c8_calls = {"n": 0}

        class ThinkingModelHandler(http.server.BaseHTTPRequestHandler):
            protocol_version = "HTTP/1.1"
            def log_message(self, format, *args): return

            def do_GET(self):
                if self.path.endswith("/models"):
                    body = json.dumps({"data": [{"id": "qwen3-0.6b-thinking"}]}).encode("utf-8")
                    self.send_response(200)
                    self.send_header("Content-Type", "application/json")
                    self.send_header("Content-Length", str(len(body)))
                    self.end_headers()
                    self.wfile.write(body)
                    return
                self.send_response(404)
                self.send_header("Content-Length", "0")
                self.end_headers()

            def _sse(self, evs: List[str], gap: float = 0.0):
                self.send_response(200)
                self.send_header("Content-Type", "text/event-stream; charset=utf-8")
                self.send_header("Connection", "close")
                self.end_headers()
                for i, e in enumerate(evs):
                    if i > 0 and gap > 0:
                        time.sleep(gap)
                    self.wfile.write(e.encode("utf-8"))
                    self.wfile.flush()

            def do_POST(self):
                n = int(self.headers.get("Content-Length", "0"))
                req = json.loads((self.rfile.read(n) if n else b"{}").decode("utf-8"))
                no_think_chat = (req.get("chat_template_kwargs") or {}).get("enable_thinking") is False
                no_think_resp = (req.get("reasoning") or {}).get("effort") == "none"

                if self.path.endswith("/responses"):
                    if not no_think_resp:
                        # First attempt burns 28-tok cap in reasoning_text.delta
                        self._sse([
                            'event: response.reasoning_text.delta\ndata: {"type":"response.reasoning_text.delta","delta":"thinking about write_config..."}\n\n',
                            'event: response.completed\ndata: {"type":"response.completed","response":{"status":"completed","usage":{"input_tokens":50,"output_tokens":28}}}\n\n',
                        ])
                    else:
                        # Retry with reasoning.effort="none" triggers real truncated tool call breach!
                        self._sse([
                            'event: response.output_item.added\ndata: {"type":"response.output_item.added","output_index":0,"item":{"id":"fc_1","call_id":"call_1","name":"write_config","type":"function_call","arguments":""}}\n\n',
                            'event: response.function_call_arguments.delta\ndata: {"type":"response.function_call_arguments.delta","output_index":0,"item_id":"fc_1","delta":"{\\"description\\": \\"cut"}\n\n',
                            'event: response.completed\ndata: {"type":"response.completed","response":{"status":"completed","usage":{"input_tokens":50,"output_tokens":28}}}\n\n',
                        ])
                    return

                txt = (req.get("messages") or [{}])[0].get("content", "")
                if "write_config" in txt:  # C1 chat
                    if not no_think_chat:
                        self._sse([
                            'data: {"model":"qwen3-0.6b-thinking","choices":[{"index":0,"delta":{"role":"assistant","reasoning_content":"Thinking..."}}]}\n\n',
                            'data: {"model":"qwen3-0.6b-thinking","choices":[{"index":0,"delta":{},"finish_reason":"length"}]}\n\n',
                            "data: [DONE]\n\n",
                        ])
                    else:
                        self._sse([
                            'data: {"model":"qwen3-0.6b-thinking","choices":[{"index":0,"delta":{"role":"assistant","tool_calls":[{"index":0,"id":"c1","function":{"name":"write_config","arguments":"{\\"description\\": \\"cut"}}]}}]}\n\n',
                            'data: {"model":"qwen3-0.6b-thinking","choices":[{"index":0,"delta":{},"finish_reason":"length"}]}\n\n',
                            "data: [DONE]\n\n",
                        ])
                elif "digits 42" in txt:  # C2 must NOT disable thinking
                    seen_c2_kwargs.append(req.get("chat_template_kwargs"))
                    self._sse([
                        'data: {"model":"qwen3-0.6b-thinking","choices":[{"index":0,"delta":{"role":"assistant","reasoning_content":"Step 1..."}}]}\n\n',
                        'data: {"model":"qwen3-0.6b-thinking","choices":[{"index":0,"delta":{},"finish_reason":"length"}]}\n\n',
                        'data: {"model":"qwen3-0.6b-thinking","choices":[],"usage":{"prompt_tokens":16,"completion_tokens":32,"total_tokens":48}}\n\n',
                        "data: [DONE]\n\n",
                    ])
                elif req.get("ignore_eos") is True:  # C3
                    self._sse([
                        'data: {"model":"qwen3-0.6b-thinking","choices":[{"index":0,"delta":{"role":"assistant","reasoning_content":"1 2 3"}}]}\n\n',
                        'data: {"model":"qwen3-0.6b-thinking","choices":[{"index":0,"delta":{},"finish_reason":"length"}]}\n\n',
                        'data: {"model":"qwen3-0.6b-thinking","choices":[],"usage":{"prompt_tokens":18,"completion_tokens":96,"total_tokens":114}}\n\n',
                        "data: [DONE]\n\n",
                    ])
                elif "Reply OK." in txt:  # C4
                    pt = 716 if req.get("tools") else 11
                    self._sse([
                        'data: {"model":"qwen3-0.6b-thinking","choices":[{"index":0,"delta":{"role":"assistant","content":"OK"}}]}\n\n',
                        'data: {"model":"qwen3-0.6b-thinking","choices":[{"index":0,"delta":{},"finish_reason":"stop"}]}\n\n',
                        f'data: {{"model":"qwen3-0.6b-thinking","choices":[],"usage":{{"prompt_tokens":{pt},"completion_tokens":1,"total_tokens":{pt + 1}}}}}\n\n',
                        "data: [DONE]\n\n",
                    ])
                elif "node-a" in txt:  # C5: reject tool_choice="required" with 400 -> fallback "auto" -> thinking retry succeeds!
                    seen_c5_choices.append(req.get("tool_choice"))
                    if req.get("tool_choice") == "required":
                        self.send_response(400)
                        self.send_header("Content-Length", "0")
                        self.end_headers()
                        return
                    if not no_think_chat:
                        self._sse([
                            'data: {"model":"qwen3-0.6b-thinking","choices":[{"index":0,"delta":{"role":"assistant","reasoning_content":"Thinking..."}}]}\n\n',
                            'data: {"model":"qwen3-0.6b-thinking","choices":[{"index":0,"delta":{},"finish_reason":"length"}]}\n\n',
                            "data: [DONE]\n\n",
                        ])
                    else:
                        self._sse([
                            'data: {"model":"qwen3-0.6b-thinking","choices":[{"index":0,"delta":{"role":"assistant","tool_calls":[{"index":0,"id":"c1","function":{"name":"get_node_status","arguments":"{\\"node\\":\\"node-a\\"}"}}]}}]}\n\n',
                            'data: {"model":"qwen3-0.6b-thinking","choices":[{"index":0,"delta":{"tool_calls":[{"index":1,"id":"c2","function":{"name":"get_node_status","arguments":"{\\"node\\":\\"node-b\\"}"}}]}}]}\n\n',
                            'data: {"model":"qwen3-0.6b-thinking","choices":[{"index":0,"delta":{},"finish_reason":"tool_calls"}]}\n\n',
                            "data: [DONE]\n\n",
                        ])
                elif "原样逐字复述" in txt:  # C6: thinking-starved on try 1 -> retry with enable_thinking=False passes!
                    if not no_think_chat:
                        self._sse([
                            'data: {"model":"qwen3-0.6b-thinking","choices":[{"index":0,"delta":{"role":"assistant","reasoning_content":"Let me repeat..."}}]}\n\n',
                            'data: {"model":"qwen3-0.6b-thinking","choices":[{"index":0,"delta":{},"finish_reason":"length"}]}\n\n',
                            "data: [DONE]\n\n",
                        ])
                    else:
                        self._sse([
                            f'data: {json.dumps({"model":"qwen3-0.6b-thinking","choices":[{"index":0,"delta":{"role":"assistant","content":C6_TARGET_TEXT}}]}, ensure_ascii=False)}\n\n',
                            'data: {"model":"qwen3-0.6b-thinking","choices":[{"index":0,"delta":{},"finish_reason":"stop"}]}\n\n',
                            "data: [DONE]\n\n",
                        ])
                elif "01 through 25" in txt:  # C7: pure incremental reasoning_content frames -> PASS (not SKIP!)
                    evs = [
                        f'data: {{"model":"qwen3-0.6b-thinking","choices":[{{"index":0,"delta":{{"role":"assistant","reasoning_content":"step {i} "}}}}]}}\n\n'
                        for i in range(6)
                    ]
                    evs.append('data: {"model":"qwen3-0.6b-thinking","choices":[{"index":0,"delta":{},"finish_reason":"length"}]}\n\n')
                    evs.append("data: [DONE]\n\n")
                    self._sse(evs, gap=0.005)
                else:  # C8: identical model/fingerprint/prompt_tokens, slight text variance -> PASS with note!
                    c8_calls["n"] += 1
                    txt_out = "READY" if c8_calls["n"] == 1 else "READY."
                    self._sse([
                        f'data: {{"model":"qwen3-0.6b-thinking","system_fingerprint":"b0-local","choices":[{{"index":0,"delta":{{"role":"assistant","content":"{txt_out}"}}}}]}}\n\n',
                        'data: {"model":"qwen3-0.6b-thinking","choices":[{"index":0,"delta":{},"finish_reason":"stop"}]}\n\n',
                        'data: {"model":"qwen3-0.6b-thinking","choices":[],"usage":{"prompt_tokens":26,"completion_tokens":2,"total_tokens":28}}\n\n',
                        "data: [DONE]\n\n",
                    ])

        srv = _ThreadingServer(("127.0.0.1", 0), ThinkingModelHandler)
        port = srv.server_address[1]
        threading.Thread(target=srv.serve_forever, daemon=True).start()
        try:
            rep = run_doctor(base_url=f"http://127.0.0.1:{port}/v1", profile="full", save_dir=None)
            by = {r.probe_id: r for r in rep.results}
            self.assertEqual(by["C1"].status, "FAIL")
            self.assertIn("/v1/responses breach", by["C1"].summary)
            self.assertEqual(by["C2"].status, "PASS")
            self.assertEqual(seen_c2_kwargs, [None])  # C2 never disables thinking!
            self.assertEqual(by["C5"].status, "PASS")
            self.assertEqual(seen_c5_choices[:2], ["required", "auto"])
            self.assertEqual(by["C6"].status, "PASS")
            self.assertEqual(by["C7"].status, "PASS")
            self.assertIn("reasoning frames", by["C7"].summary)
            self.assertEqual(by["C8"].status, "PASS")
            self.assertIn("minor text variance", by["C8"].summary)
            self.assertEqual(rep.exit_code, EXIT_SILENT_PROTOCOL_BREACH)
        finally:
            srv.shutdown()
            srv.server_close()

        # Verify action.yml exists and avoids direct ${{ inputs.* }} interpolation inside run: shell blocks
        action_yml = Path(__file__).resolve().parents[1] / "action.yml"
        self.assertTrue(action_yml.exists())
        txt = action_yml.read_text(encoding="utf-8")
        self.assertIn('using: "composite"', txt)
        self.assertIn("branding:", txt)
        for line in txt.splitlines():
            stripped = line.strip()
            if stripped.startswith(("inferdiff ", "python ", "args=", "if [[", "exit ")):
                self.assertNotIn("${{ inputs.", line)


if __name__ == "__main__":
    unittest.main()
