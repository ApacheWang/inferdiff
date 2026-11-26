"""Offline Anthropic Messages SSE framing, normalization, and contract tests."""

import json
import unittest

from inferdiff.anthropic import inspect_anthropic_stream
from inferdiff.recorder import SSEFramer, build_frame_from_chunk
from inferdiff.schema import TraceDocument, TraceHeader, assemble_summary


DIALECT = "anthropic-messages"


def _event(event_type, **fields):
    return event_type, {"type": event_type, **fields}


def _start():
    return _event("message_start", message={"model": "claude-test", "usage": {"input_tokens": 3}})


def _block(index, kind):
    block = {"type": kind}
    if kind == "tool_use":
        block.update(id="tool_1", name="write_config", input={})
    return _event("content_block_start", index=index, content_block=block)


def _delta(index, kind, field, value):
    return _event("content_block_delta", index=index, delta={"type": kind, field: value})


def _end_block(index):
    return _event("content_block_stop", index=index)


def _end(reason="max_tokens", output_tokens=8):
    return [
        _event("message_delta", delta={"stop_reason": reason}, usage={"output_tokens": output_tokens}),
        _event("message_stop"),
    ]


def _document(events, *, content_type="text/event-stream; charset=utf-8", clean=True, tail=b""):
    encoded = b"".join(
        f"event: {name}\r\n".encode() +
        b"".join(
            f"data: {line}\r\n".encode()
            for line in json.dumps(payload, indent=2, ensure_ascii=False).splitlines()
        ) +
        b"\r\n"
        for name, payload in events
    ) + tail
    framer = SSEFramer()
    chunks = []
    for seq, value in enumerate(encoded, 1):
        chunks.extend(framer.feed(bytes([value]), seq * 1_000_000))
    chunks.extend(framer.finish((len(encoded) + 1) * 1_000_000))
    frames = []
    for seq, chunk in enumerate(chunks):
        frame, _ = build_frame_from_chunk(
            chunk, seq=seq, dialect=DIALECT,
            prev_rel_ms=frames[-1].t_rel_ms if frames else 0.0, t0_ns=0, sglang_prev_text="",
        )
        frames.append(frame)
    header = TraceHeader(
        trace_id="tr_test", label="test", recorded_at_utc="2026-11-26T00:00:00Z",
        dialect=DIALECT, request={}, response_meta={"content_type": content_type, "status_code": 200},
    )
    summary = assemble_summary(header, frames, total_ms=float(len(encoded)), socket_eof_clean=clean)
    return TraceDocument(header, frames, summary)


class TestAnthropicStreamContract(unittest.TestCase):
    def test_fragmented_multiline_sse_normalizes_thinking_text_and_tools(self):
        doc = _document([
            _start(),
            _event("ping"),
            _event("new_event", value="extensible"),
            _block(0, "thinking"),
            _delta(0, "thinking_delta", "thinking", "推理"),
            _delta(0, "signature_delta", "signature", "token"),
            _end_block(0),
            _block(1, "text"),
            _delta(1, "text_delta", "text", "你好"),
            _end_block(1),
            _block(2, "tool_use"),
            _delta(2, "input_json_delta", "partial_json", '{"city":'),
            _delta(2, "input_json_delta", "partial_json", '"深圳"}'),
            _end_block(2),
            _event("message_delta", delta={}, usage={"output_tokens": 8}),
            *_end("tool_use", 11),
        ])
        report = inspect_anthropic_stream(doc, max_tokens=25)
        self.assertEqual(report.violations, ())
        self.assertEqual(report.observed_model, "claude-test")
        self.assertEqual(report.stop_reason, "tool_use")
        self.assertEqual(report.output_tokens, 11)
        self.assertIn("thinking_delta", report.delta_types)
        self.assertTrue(doc.summary.eof_clean)
        self.assertIsNotNone(doc.summary.timing["ttft_effective_ms"])
        assembled = doc.summary.assembled
        self.assertEqual(assembled["content_text"], "你好")
        self.assertEqual(assembled["reasoning_text"], "推理")
        self.assertEqual(assembled["finish_reason"], "tool_use")
        self.assertEqual(assembled["reported_usage"]["completion_tokens"], 11)
        self.assertEqual(len(assembled["tool_calls"]), 1)
        self.assertEqual(assembled["tool_calls"][0]["raw_arguments"], '{"city":"深圳"}')
        self.assertFalse(assembled["tool_calls"][0]["args_mismatch"])

    def test_incomplete_tool_json_is_allowed_only_for_max_tokens(self):
        for partial in ('{"city":', '[]', " "):
            for reason in ("max_tokens", "end_turn", "tool_use"):
                with self.subTest(partial=partial, reason=reason):
                    doc = _document([
                        _start(), _block(0, "tool_use"), _delta(0, "input_json_delta", "partial_json", partial),
                        _end_block(0), *_end(reason, 7),
                    ])
                    report = inspect_anthropic_stream(doc, max_tokens=8)
                    self.assertEqual(report.incomplete_tool_indices, (0,))
                    self.assertEqual(bool(report.violations), reason != "max_tokens")
                    self.assertFalse(doc.summary.assembled["tool_calls"][0]["json_valid"])

    def test_missing_stop_wrong_index_duplicate_start_and_trailing_content_fail(self):
        correct = [_start(), _block(0, "text"), _delta(0, "text_delta", "text", "hello")]
        for events in (
            [*correct, *_end()],
            [*correct, _end_block(1), *_end()],
            [*correct, _start(), _end_block(0), *_end()],
            [*correct, _end_block(0), *_end(), _block(1, "text")],
            [*correct, _end_block(0), *_end()[:-1]],
            [_block(0, "text"), *correct, _end_block(0), *_end()],
            [_start(), _block(0, "text"), _end_block(0), _block(0, "text"), _end_block(0), *_end()],
        ):
            with self.subTest(events=events):
                self.assertTrue(inspect_anthropic_stream(_document(events), max_tokens=8).violations)

    def test_bad_sse_envelope_and_incomplete_http_are_rejected(self):
        complete = [_start(), _block(0, "text"), _delta(0, "text_delta", "text", "hi"), _end_block(0), *_end()]
        mismatch = [*complete[:-1], ("message_stop", {"type": "something_else"})]
        for doc in (
            _document(mismatch),
            _document(complete, content_type="application/json"),
            _document(complete, clean=False),
            _document(complete, tail=b'event: message_delta\ndata: {"type":"message_delta"}\n'),
        ):
            with self.subTest(doc=doc.header.response_meta, clean=doc.summary.eof_clean):
                self.assertTrue(inspect_anthropic_stream(doc, max_tokens=8).violations)

    def test_usage_is_cumulative_and_exhaustion_requires_max_tokens(self):
        content = [_start(), _block(0, "text"), _delta(0, "text_delta", "text", "response"), _end_block(0)]
        for events in (
            [*content, *_end(output_tokens=0)],
            [*content, *_end(output_tokens=True)],
            [*content, _event("message_delta", delta={"stop_reason": "max_tokens"}), _event("message_stop")],
            [*content, _event("message_delta", delta={}, usage={"output_tokens": 7}), *_end(output_tokens=5)],
            [*content, *_end("end_turn", 8)],
        ):
            with self.subTest(events=events):
                self.assertTrue(inspect_anthropic_stream(_document(events), max_tokens=8).violations)

    def test_initial_empty_tool_fragment_is_valid_when_tool_input_is_empty(self):
        doc = _document([
            _start(), _block(0, "tool_use"), _delta(0, "input_json_delta", "partial_json", ""),
            _end_block(0), *_end("tool_use", 4),
        ])
        self.assertEqual(inspect_anthropic_stream(doc, max_tokens=8).violations, ())
        self.assertTrue(doc.summary.assembled["tool_calls"][0]["json_valid"])

