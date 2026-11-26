"""CLI coverage for offline stream and trace audits."""

from __future__ import annotations

import json
import subprocess
import sys
import tempfile
import unittest
import xml.etree.ElementTree as ET
from dataclasses import replace
from pathlib import Path

from inferdiff.recorder import SSEFramer, build_frame_from_chunk
from inferdiff.schema import TraceDocument, TraceHeader, assemble_summary, write_trace


_ROOT = Path(__file__).resolve().parents[1]
_RESPONSES_TRACE = _ROOT / "examples" / "case1_responses_truncated_tool" / "target.trace.jsonl"


def _audit(*args: str, source: str = "-", capture: str | None = None) -> subprocess.CompletedProcess:
    return subprocess.run(
        [sys.executable, "-m", "inferdiff", "audit", source, *args],
        input=capture,
        capture_output=True,
        encoding="utf-8",
        timeout=10,
    )


def _audit_stdin(capture: str, *args: str) -> subprocess.CompletedProcess:
    return _audit(*args, capture=capture)


def _sse(*events: dict, done: bool = False, named: bool = False) -> str:
    frames = []
    for event in events:
        if named:
            frames.append(f"event: {event['type']}\n")
        frames.append(f"data: {json.dumps(event)}\n\n")
    if done:
        frames.append("data: [DONE]\n\n")
    return "".join(frames)


def _chat() -> str:
    return _sse(
        {"choices": [{"index": 0, "delta": {"role": "assistant", "content": "Hello"}}]},
        {"choices": [{"index": 0, "delta": {}, "finish_reason": "stop"}]},
        done=True,
    )


def _responses() -> str:
    return _sse(
        {"type": "response.output_item.added", "output_index": 0, "item": {
            "type": "function_call", "id": "fc_1", "call_id": "call_1", "name": "write_config",
            "arguments": "", "status": "in_progress",
        }},
        {"type": "response.function_call_arguments.delta", "item_id": "fc_1", "output_index": 0,
         "delta": '{"name":'},
        {"type": "response.completed", "response": {"id": "resp_1", "status": "completed"}},
        named=True,
    )


def _anthropic(stop_reason: str = "end_turn") -> str:
    return _sse(
        {"type": "message_start", "message": {"id": "msg_1", "type": "message", "role": "assistant",
                                              "content": [], "usage": {"input_tokens": 2}}},
        {"type": "content_block_start", "index": 0, "content_block": {
            "type": "tool_use", "id": "toolu_1", "name": "write_config", "input": {},
        }},
        {"type": "content_block_delta", "index": 0, "delta": {
            "type": "input_json_delta", "partial_json": '{"name":',
        }},
        {"type": "content_block_stop", "index": 0},
        {"type": "message_delta", "delta": {"stop_reason": stop_reason}, "usage": {"output_tokens": 1}},
        {"type": "message_stop"},
        named=True,
    )


def _gemini(first_reason: object) -> str:
    return _sse(
        {"candidates": [{"index": 0, "content": {"role": "model", "parts": [{"text": "Hello"}]}}]},
        {"candidates": [{"index": 0, "finishReason": first_reason}]},
        {"candidates": [{"index": 0, "finishReason": "STOP"}], "usageMetadata": {
            "promptTokenCount": 2, "candidatesTokenCount": 1, "totalTokenCount": 3,
        }},
    )


def _write_chat_trace(path: Path, capture: str, *, omit_wire: tuple[int, ...] = ()) -> None:
    framer = SSEFramer()
    chunks = framer.feed(capture.encode("utf-8"), 1_000_000) + framer.finish(1_000_000)
    frames = []
    for seq, chunk in enumerate(chunks):
        frame, _ = build_frame_from_chunk(
            chunk, seq=seq, dialect="openai-chat", prev_rel_ms=frames[-1].t_rel_ms if frames else 0.0,
            t0_ns=0, sglang_prev_text="",
        )
        frames.append(frame)
    header = TraceHeader(
        trace_id="tr_audit_chat", label="offline-test", recorded_at_utc="2026-01-01T00:00:00Z",
        dialect="openai-chat", request={}, response_meta={"status_code": 200, "content_type": "text/event-stream"},
    )
    summary = assemble_summary(header, frames, total_ms=1.0)
    available_frames = [replace(frame, raw_wire="") if frame.seq in omit_wire else frame for frame in frames]
    write_trace(path, TraceDocument(header, available_frames, summary))


class AuditCommandTests(unittest.TestCase):
    def _report(self, result, exit_code, dialect, grade):
        self.assertEqual(result.returncode, exit_code, result.stderr)
        self.assertEqual(result.stderr, "")
        report = json.loads(result.stdout)
        self.assertTrue({"grade", "dialect", "p0_count", "warning_count", "findings"} <= report.keys())
        self.assertEqual(report["dialect"], dialect)
        self.assertEqual(report["grade"], grade)
        self.assertIsInstance(report["p0_count"], int)
        self.assertIsInstance(report["warning_count"], int)
        for finding in report["findings"]:
            self.assertIsInstance(finding["code"], str)
            self.assertIsInstance(finding["severity"], str)
            self.assertTrue(finding["frame_seq"] is None or isinstance(finding["frame_seq"], int))
            self.assertTrue(finding["message"])
        return report

    def test_honest_chat_piped_to_stdin(self):
        result = _audit_stdin(_chat())
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(result.stderr, "")
        self.assertIn("Grade A+", result.stdout)

        report = self._report(_audit_stdin(_chat(), "--json"), 0, "openai-chat", "A+")
        self.assertEqual((report["p0_count"], report["warning_count"], report["findings"]), (0, 0, []))

    def test_responses_completed_with_truncated_tool_json(self):
        report = self._report(_audit_stdin(_responses(), "--json"), 2, "openai-responses", "F")
        self.assertGreaterEqual(report["p0_count"], 1)
        self.assertIn(("D1", "P0"), [(finding["code"], finding["severity"]) for finding in report["findings"]])

    def test_anthropic_end_turn_with_truncated_tool_input(self):
        report = self._report(_audit_stdin(_anthropic(), "--json"), 2, "anthropic-messages", "F")
        self.assertIn(("C9", "P0"), [(finding["code"], finding["severity"]) for finding in report["findings"]])

    def test_gemini_stop_does_not_clear_bad_earlier_finish_reasons(self):
        for first_reason in ("MAX_TOKENS", {"unexpected": "broken"}):
            with self.subTest(first_reason=first_reason):
                result = _audit_stdin(_gemini(first_reason), "--json")
                report = self._report(result, 2, "gemini-sse", "F")
                findings = [(finding["code"], finding["severity"]) for finding in report["findings"]]
                self.assertIn(("C10", "P0"), findings)

    def test_missing_usage_warns_when_requested_and_fails_only_under_strict(self):
        for options, exit_code in (((), 0), (("--strict",), 3)):
            with self.subTest(options=options):
                result = _audit_stdin(_chat(), "--json", "--expect-usage", *options)
                report = self._report(result, exit_code, "openai-chat", "B")
                self.assertEqual((report["p0_count"], report["warning_count"]), (0, 1))
                (finding,) = report["findings"]
                self.assertEqual((finding["code"], finding["severity"]), ("D4", "P1"))

    def test_recorded_trace_is_detected_from_its_content(self):
        capture = _RESPONSES_TRACE.read_text(encoding="utf-8")
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "capture.sse"
            path.write_text(capture, encoding="utf-8")
            results = {"file": _audit("--json", source=str(path)), "stdin": _audit_stdin(capture, "--json")}
        for source, result in results.items():
            with self.subTest(source=source):
                report = self._report(result, 2, "openai-responses", "F")
                self.assertIn("D1", {finding["code"] for finding in report["findings"]})

    def test_recorded_chat_can_finish_interleaved_choices_independently(self):
        capture = _sse(
            {"choices": [{"index": 0, "delta": {"content": "Hello"}}]},
            {"choices": [{"index": 1, "delta": {"content": "Good"}}]},
            {"choices": [{"index": 0, "delta": {}, "finish_reason": "stop"}]},
            {"choices": [{"index": 1, "delta": {"content": " morning"}}]},
            {"choices": [{"index": 1, "delta": {}, "finish_reason": "stop"}]},
            done=True,
        )
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "interleaved.trace.jsonl"
            _write_chat_trace(path, capture)
            result = _audit("--json", source=str(path))
        report = self._report(result, 0, "openai-chat", "A+")
        self.assertEqual(report["findings"], [])

    def test_recorded_finding_preserves_frame_sequence_with_missing_wire(self):
        capture = _sse(
            {"choices": [{"index": 0, "delta": {"content": "Hello"}}]},
            {"choices": [{"index": 0, "delta": {"content": "\ufffd"}}]},
            {"choices": [{"index": 0, "delta": {}, "finish_reason": "stop"}]},
            done=True,
        )
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "missing-wire.trace.jsonl"
            _write_chat_trace(path, capture, omit_wire=(0,))
            result = _audit("--json", source=str(path))
        report = self._report(result, 2, "openai-chat", "F")
        self.assertEqual([finding["frame_seq"] for finding in report["findings"] if finding["code"] == "D2"], [1])

    def test_recorded_usage_can_be_checked_when_wire_is_unavailable(self):
        for has_usage, exit_code, grade in ((False, 3, "B"), (True, 0, "A+")):
            with self.subTest(has_usage=has_usage), tempfile.TemporaryDirectory() as directory:
                frames = [
                    {"choices": [{"index": 0, "delta": {"content": "Hello"}}]},
                    {"choices": [{"index": 0, "delta": {}, "finish_reason": "stop"}]},
                ]
                if has_usage:
                    frames.append({"choices": [], "usage": {
                        "prompt_tokens": 2, "completion_tokens": 1, "total_tokens": 3,
                    }})
                path = Path(directory) / "normalized-only.trace.jsonl"
                _write_chat_trace(path, _sse(*frames, done=True), omit_wire=tuple(range(len(frames) + 1)))
                result = _audit("--json", "--expect-usage", "--strict", source=str(path))
                report = self._report(result, exit_code, "openai-chat", grade)
                findings = [(finding["code"], finding["severity"]) for finding in report["findings"]]
                self.assertEqual(findings, [] if has_usage else [("D4", "P1")])

    def test_honest_ollama_and_sglang_ndjson(self):
        captures = {
            "ollama-ndjson": (
                {"model": "test", "message": {"role": "assistant", "content": "Hello"}, "done": False},
                {"model": "test", "message": {"role": "assistant", "content": ""}, "done": True,
                 "done_reason": "stop", "prompt_eval_count": 2, "eval_count": 1},
            ),
            "sglang-native": (
                {"text": "Hel", "meta_info": {"id": "req_1", "finish_reason": None}},
                {"text": "Hello", "meta_info": {"id": "req_1", "finish_reason": {"type": "stop"},
                                                 "prompt_tokens": 2, "completion_tokens": 2}},
            ),
        }
        for dialect, payloads in captures.items():
            with self.subTest(dialect=dialect):
                capture = "".join(f"{json.dumps(payload)}\n" for payload in payloads)
                report = self._report(_audit_stdin(capture, "--json", "--expect-usage"),
                                      0, dialect, "A+")
                self.assertEqual(report["findings"], [])

    def test_early_usage_does_not_satisfy_expected_ollama_final_usage(self):
        capture = "\n".join(map(json.dumps, (
            {"response": "Hello", "done": False, "prompt_eval_count": 2, "eval_count": 1},
            {"response": "", "done": True, "done_reason": "stop"},
        )))
        report = self._report(_audit_stdin(capture, "--json", "--expect-usage", "--strict"),
                              3, "ollama-ndjson", "B")
        self.assertEqual([(finding["code"], finding["severity"]) for finding in report["findings"]], [("D4", "P1")])

    def test_report_formats_preserve_findings_and_omit_provider_data(self):
        secrets = (
            "sk-secret-value-12345", "b-7Y", "x-3Q", "g-5V", "q-9W",
        )
        provider_text = (
            f"reflected provider detail {secrets[0]} Authorization: Bearer {secrets[1]} "
            f"x-api-key: {secrets[2]} x-goog-api-key: {secrets[3]} https://example.test/?key={secrets[4]}"
        )
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "private-customer-path.sse"
            path.write_text(_anthropic(provider_text), encoding="utf-8")
            sarif_path = Path(directory) / "audit.sarif"
            junit_path = Path(directory) / "audit.xml"
            options = {
                "text": ("--sarif", str(sarif_path), "--junit", str(junit_path)),
                "json": ("--json",),
                "github": ("--github-issue",),
                "github-alias": ("--format", "github-issue"),
            }
            outputs = {}
            for output_format, args in options.items():
                result = _audit(*args, source=str(path))
                self.assertEqual(result.returncode, 2, result.stderr)
                self.assertEqual(result.stderr, "", output_format)
                outputs[output_format] = result.stdout
            outputs["sarif"] = sarif_path.read_text(encoding="utf-8")
            outputs["junit"] = junit_path.read_text(encoding="utf-8")

        for output_format, output in outputs.items():
            with self.subTest(format=output_format):
                self.assertIn("C9", output)
                for sensitive in (*secrets, "reflected provider detail", directory, path.name):
                    self.assertNotIn(sensitive, output)

        self.assertIn("Grade F", outputs["text"])
        self.assertEqual(json.loads(outputs["json"])["grade"], "F")
        sarif = json.loads(outputs["sarif"])
        self.assertEqual(sarif["version"], "2.1.0")
        results = sarif["runs"][0]["results"]
        self.assertIn(("C9", "error"), [(result["ruleId"], result["level"]) for result in results])
        junit = ET.fromstring(outputs["junit"])
        self.assertIsNotNone(junit.find(".//failure"))
        self.assertEqual(outputs["github-alias"], outputs["github"])

    def test_github_report_stays_within_25_lines_with_many_findings(self):
        damaged_frame = {"choices": [{"index": 0, "delta": {"content": "\ufffd"}}]}
        terminal_frame = {"choices": [{"index": 0, "delta": {}, "finish_reason": "stop"}]}
        capture = _sse(*([damaged_frame] * 32), terminal_frame, done=True)
        report = self._report(_audit_stdin(capture, "--json"), 2, "openai-chat", "F")
        self.assertGreaterEqual(report["p0_count"], 32)

        result = _audit_stdin(capture, "--github-issue")
        self.assertEqual(result.returncode, 2, result.stderr)
        self.assertIn("D2", result.stdout)
        self.assertLessEqual(len(result.stdout.splitlines()), 25)

    def test_malformed_frame_in_a_recognizable_stream_is_a_breach(self):
        capture = (
            _sse({"choices": [{"index": 0, "delta": {"content": "Hello"}}]})
            + 'data: {"content": "malformed-capture-marker"\n\n'
            + _sse({"choices": [{"index": 0, "delta": {}, "finish_reason": "stop"}]}, done=True)
        )
        result = _audit_stdin(capture, "--json", "--dialect", "openai")
        report = self._report(result, 2, "openai-chat", "F")
        findings = [(finding["code"], finding["severity"]) for finding in report["findings"]]
        self.assertIn(("D4", "P0"), findings)
        self.assertNotIn("malformed-capture-marker", result.stdout)

    def test_empty_and_malformed_capture_fail_without_echoing_input(self):
        for capture in ("", 'data: {"private": "malformed-capture-marker"\n\n'):
            with self.subTest(capture=bool(capture)):
                result = _audit_stdin(capture, "--json")
                self.assertEqual(result.returncode, 1, result.stderr)
                self.assertEqual(result.stdout, "")
                self.assertTrue(result.stderr)
                self.assertNotIn("usage: inferdiff", result.stderr)
                self.assertNotIn("file not found", result.stderr.lower())
                self.assertNotIn("malformed-capture-marker", result.stderr)
