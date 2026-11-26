"""Offline contract checks for captured inference streams."""

from __future__ import annotations

from collections.abc import Iterator
from dataclasses import asdict, replace
from typing import Any

from .detectors import detect_d1, detect_d4
from .dialects import normalize_payload
from .dialects.anthropic_messages import TOOL_TYPES
from .recorder import NDJSONFramer, SSEFramer, WireChunk, build_frame_from_chunk
from .redact import is_protocol_enum, is_protocol_event
from .schema import (
    VALID_DIALECTS,
    TraceDocument,
    TraceFrame,
    TraceHeader,
    assemble_summary,
    is_strict_int,
    strict_json_loads,
)

_ALIASES = {"openai": "openai-chat", "anthropic": "anthropic-messages", "gemini": "gemini-sse"}
CAPTURE_DIALECTS = ("auto", *VALID_DIALECTS, *_ALIASES)
_MESSAGES = {
    "D1": "The stream reported success with an incomplete or inconsistent tool call.",
    "D2": "The stream contains U+FFFD or invalid Unicode.",
    "D3": "Multiple tool calls used the same tool index.",
    "D4": "The stream contains an invalid event or ended without a clean terminal state.",
    "C9": "Anthropic Messages sent a missing, invalid, or changing stop_reason.",
    "C10": "Gemini sent a missing, invalid, or changing finishReason.",
}


def _object(value: Any) -> dict:
    return value if isinstance(value, dict) else {}


def _objects(value: Any) -> Iterator[tuple[int, dict]]:
    if isinstance(value, list):
        yield from ((pos, obj) for pos, obj in enumerate(value) if isinstance(obj, dict))


def _load_payload(data: str) -> dict | None:
    try:
        payload = strict_json_loads(data)
    except (ValueError, RecursionError):
        return None
    return payload if isinstance(payload, dict) else None


def _detect_dialect(chunks: list[WireChunk], payloads: list[dict]) -> str:
    for chunk, payload in zip(chunks, payloads):
        for event in (chunk.sse_event, payload.get("type")):
            if not isinstance(event, str):
                continue
            if event.startswith("response."):
                return "openai-responses"
            if event not in {"ping", "error"} and is_protocol_event("anthropic-messages", event):
                return "anthropic-messages"
        if "candidates" in payload or "usageMetadata" in payload or "promptFeedback" in payload:
            return "gemini-sse"
        if "choices" in payload:
            return "openai-chat"
        if "meta_info" in payload:
            return "sglang-native"
        if isinstance(payload.get("done"), bool):
            return "ollama-ndjson"
    return "openai-chat"


def _has_corrupt_unicode(value: Any) -> bool:
    pending = [value]
    while pending:
        item = pending.pop()
        if isinstance(item, dict):
            pending.extend(item.keys())
            pending.extend(item.values())
        elif isinstance(item, list):
            pending.extend(item)
        elif isinstance(item, str):
            if "\ufffd" in item:
                return True
            try:
                item.encode("utf-8")
            except UnicodeEncodeError:
                return True
    return False


def _index(obj: dict, position: int) -> int:
    index = obj.get("index")
    return index if is_strict_int(index) else position


def _chat_choice(choice: dict, ids: dict[int, str]) -> tuple[dict, bool]:
    delta = _object(choice.get("delta"))
    seen = set()
    collision = False
    for slot, tool in _objects(delta.get("tool_calls")):
        index = _index(tool, slot)
        call_id = tool.get("id")
        if index in seen:
            collision = True
        seen.add(index)
        if isinstance(call_id, str) and call_id and ids.setdefault(index, call_id) != call_id:
            collision = True

    legacy = delta.get("function_call")
    if isinstance(legacy, dict) and not delta.get("tool_calls"):
        delta = {**delta, "tool_calls": [{"index": 0, "function": legacy}]}
        choice = {**choice, "delta": delta}
    if choice.get("finish_reason") == "function_call":
        choice = {**choice, "finish_reason": "tool_calls"}
    return choice, collision


def _candidate_streams(
    dialect: str, frames: list[TraceFrame], payloads: list[dict],
) -> tuple[list[list[TraceFrame]], set[int]]:
    """Normalize each choice or candidate independently since token deltas may interleave."""
    field = "choices" if dialect == "openai-chat" else "candidates"
    streams: dict[int, list[TraceFrame]] = {}
    ids: dict[int, dict[int, str]] = {}
    collisions = set()
    shared = []
    for frame in frames:
        payload = payloads[frame.seq]
        choices = list(_objects(payload.get(field)))
        if not choices or frame.parse_error:
            shared.append(frame)
            continue
        for position, choice in choices:
            index = _index(choice, position)
            if dialect == "openai-chat":
                choice, collision = _chat_choice(choice, ids.setdefault(index, {}))
                if collision:
                    collisions.add(frame.seq)
            try:
                norm = normalize_payload(dialect, {**payload, field: [choice]})
                candidate = replace(frame, norm=asdict(norm))
            except (ValueError, TypeError, OverflowError, RecursionError):
                candidate = replace(frame, norm={}, parse_error="invalid_candidate")
            streams.setdefault(index, []).append(candidate)

    return [sorted(stream + shared, key=lambda frame: frame.seq) for stream in streams.values()] or [shared], collisions


def _stop_reason_violations(dialect: str, payloads: list[dict]) -> Iterator[int | None]:
    """Validate stop signals without assuming the request used a doctor probe's budget."""
    anthropic = dialect == "anthropic-messages"
    field = "stop_reason" if anthropic else "finishReason"
    last_seen: dict[int, int] = {}
    final_reasons: dict[int, str] = {}
    stopped = False
    for seq, payload in enumerate(payloads):
        if anthropic:
            event = payload.get("type")
            if event == "message_stop":
                if stopped:
                    yield seq
                stopped = True
            if event != "message_delta":
                continue
            if stopped:
                yield seq
            candidates = [(0, _object(payload.get("delta")))]
        else:
            candidates = _objects(payload.get("candidates"))
        for pos, candidate in candidates:
            index = pos if anthropic else _index(candidate, pos)
            last_seen[index] = seq
            reason = candidate.get(field)
            if reason is None or (not anthropic and reason == "FINISH_REASON_UNSPECIFIED"):
                continue
            if not is_protocol_enum(dialect, "finish_reason", reason) or final_reasons.get(index, reason) != reason:
                yield seq
            else:
                final_reasons[index] = reason
    for index in last_seen.keys() - final_reasons.keys():
        yield last_seen[index]
    if not last_seen:
        yield len(payloads) - 1 if payloads else None


def _anthropic_tool_violations(doc: TraceDocument, payloads: list[dict]) -> Iterator[int]:
    if doc.summary.assembled["finish_reason"] not in {"end_turn", "stop_sequence", "tool_use", "pause_turn"}:
        return
    stopped = {payload.get("index") for payload in payloads if payload.get("type") == "content_block_stop"
               and is_strict_int(payload.get("index"))}
    for tool in doc.summary.assembled["tool_calls"]:
        if not tool["json_valid"] or tool["index"] not in stopped:
            yield tool["last_seq"]
    for seq, payload in enumerate(payloads):
        block = _object(payload.get("content_block"))
        index = payload.get("index")
        if (payload.get("type") == "content_block_start" and isinstance(block.get("type"), str)
                and block["type"] in TOOL_TYPES and not (is_strict_int(index) and index >= 0)):
            yield seq
        delta = _object(payload.get("delta"))
        if (payload.get("type") == "content_block_delta" and delta.get("type") == "input_json_delta"
                and not isinstance(delta.get("partial_json"), str)):
            yield seq


def _token_count(usage: dict, field: str) -> bool:
    value = usage.get(field)
    return is_strict_int(value) and value >= 0


def _has_expected_usage(dialect: str, payloads: list[dict], frames: list[TraceFrame]) -> bool:
    fields = ("prompt_tokens", "completion_tokens")
    if dialect == "openai-chat":
        # With include_usage, the extra empty-choices event follows all finished choices.
        if len(frames) < 2 or not frames[-1].is_done_sentinel:
            return False
        previous = frames[-2]
        payload = payloads[previous.seq]
        if payload:
            if payload.get("choices") != []:
                return False
            usage = _object(payload.get("usage"))
        elif previous.norm.get("phase") == "USAGE":
            usage = _object(previous.norm.get("usage"))
        else:
            return False
        return not previous.parse_error and all(_token_count(usage, name) for name in fields)

    def has_usage(field: str, start: int) -> bool:
        return any(not frame.parse_error and _token_count(_object(frame.norm.get("usage")), field)
                   for frame in frames[start:])

    terminal = next((pos for pos in range(len(frames) - 1, -1, -1)
                     if any(isinstance(value, str) and value not in ("", "unknown") for value in
                            (frames[pos].norm.get("finish_reason"), frames[pos].norm.get("terminal_status")))), None)
    if terminal is None:
        return False
    prompt_start = 0 if dialect == "anthropic-messages" else terminal
    return has_usage("prompt_tokens", prompt_start) and has_usage("completion_tokens", terminal)


def inspect_sse(sse_text: str, *, dialect: str, expect_usage: bool) -> tuple[str, list[dict]]:
    if not isinstance(sse_text, str):
        raise TypeError("SSE input must be text.")
    return _inspect_stream(sse_text.encode("utf-8", errors="surrogatepass"), dialect, expect_usage, ndjson=False)


def inspect_capture(raw: bytes, *, dialect: str, expect_usage: bool) -> tuple[str, list[dict]]:
    """Inspect a UTF-8 wire capture, detecting its framing independently of its dialect."""
    raw = raw.removeprefix(b"\xef\xbb\xbf")
    ndjson = raw.lstrip().startswith((b"{", b"["))
    return _inspect_stream(raw, dialect, expect_usage, ndjson=ndjson, require_payload=True)


def inspect_recording(doc: TraceDocument, *, dialect: str, expect_usage: bool) -> tuple[str, list[dict]]:
    """Run the wire checks with the recorded frame numbers and HTTP evidence."""
    resolved = doc.header.dialect if dialect == "auto" else _resolve_dialect(dialect)
    first_wire = next((frame.raw_wire.lstrip() for frame in doc.frames if frame.raw_wire.strip()), "")
    ndjson = doc.header.dialect == "ollama-ndjson" or first_wire.startswith(("{", "["))
    chunks = []
    for frame in doc.frames:
        raw = frame.raw_wire.encode("utf-8", errors="surrogatepass")
        framed = _frame_wire(raw, ndjson=ndjson)
        chunks.append(framed[0] if len(framed) == 1 else WireChunk(0, frame.sse_event, "", frame.raw_wire))
    findings = _inspect_chunks(chunks, replace(doc.header, dialect=resolved), expect_usage, ndjson=ndjson,
                               recording=doc)
    return resolved, findings


def contract_report(dialect: str, findings: list[dict]) -> dict:
    p0_count = sum(finding["severity"] == "P0" for finding in findings)
    warning_count = sum(finding["severity"] == "P1" for finding in findings)
    grade = "F" if p0_count else "C" if warning_count >= 2 else "B" if warning_count else "A+"
    return {"grade": grade, "dialect": dialect, "p0_count": p0_count,
            "warning_count": warning_count, "findings": findings}


def _resolve_dialect(dialect: str) -> str:
    if not isinstance(dialect, str):
        raise ValueError("Unsupported SSE dialect.")
    dialect = _ALIASES.get(dialect, dialect)
    if dialect != "auto" and dialect not in VALID_DIALECTS:
        raise ValueError("Unsupported SSE dialect.")
    return dialect


def _frame_wire(raw: bytes, *, ndjson: bool) -> list[WireChunk]:
    framer = NDJSONFramer() if ndjson else SSEFramer()
    return framer.feed(raw, 0) + framer.finish(0)


def _inspect_stream(
    raw: bytes, dialect: str, expect_usage: bool, *, ndjson: bool, require_payload: bool = False,
) -> tuple[str, list[dict]]:
    chunks = _frame_wire(raw, ndjson=ndjson)
    decoded = [_load_payload(chunk.payload_text) for chunk in chunks]
    if require_payload and not any(payload is not None or chunk.payload_text == "[DONE]"
                                   for chunk, payload in zip(chunks, decoded)):
        raise ValueError("Capture contains no readable SSE events or NDJSON objects.")
    payloads = [payload or {} for payload in decoded]
    dialect = _resolve_dialect(dialect)
    if dialect == "auto":
        dialect = _detect_dialect(chunks, payloads)
    header = TraceHeader("", "", "", dialect, {}, {"status_code": 200})
    findings = _inspect_chunks(chunks, header, expect_usage, ndjson=ndjson, payloads=payloads)
    if not any(finding["code"] == "D2" for finding in findings):
        # Framing skips comments and empty lines, where the original bytes can still be corrupt.
        if _has_corrupt_unicode(raw.decode("utf-8", errors="surrogateescape")):
            findings.append(_finding("D2", None))
    return dialect, findings


def _finding(code: str, seq: int | None, *, severity: str = "P0", message: str | None = None) -> dict:
    return {"code": code, "detector_id": code, "severity": severity,
            "frame_seq": seq, "message": message or _MESSAGES[code]}


def _recording_eof_clean(recording: TraceDocument, group_count: int) -> bool:
    if recording.summary.eof_clean:
        return True
    violations = recording.summary.assembled.get("protocol_violations") or []
    # Older summaries assemble the first candidate in each frame as one stream.
    return group_count > 1 and bool(violations) and all(
        isinstance(item, str) and item.endswith(": payload_after_finish_reason") for item in violations
    )


def _inspect_chunks(
    chunks: list[WireChunk], header: TraceHeader, expect_usage: bool, *, ndjson: bool,
    payloads: list[dict] | None = None, recording: TraceDocument | None = None,
) -> list[dict]:
    dialect = header.dialect
    if payloads is None:
        payloads = [_load_payload(chunk.payload_text) or {} for chunk in chunks]
    findings: list[dict] = []

    has_provider_payloads = recording is None or any(payloads)

    def add(code: str, seq: int | None, *, severity: str = "P0", message: str | None = None) -> None:
        findings.append(_finding(code, seq, severity=severity, message=message))

    frames, previous_text = [], ""
    for seq, (chunk, payload) in enumerate(zip(chunks, payloads)):
        original = recording.frames[seq] if recording is not None else None
        if (_has_corrupt_unicode(chunk.raw_wire) or _has_corrupt_unicode(payload)
                or chunk.invalid_utf8 or (original is not None and original.parse_error == "invalid_utf8")):
            add("D2", seq)
        event_type = payload.get("type")
        if (dialect == "anthropic-messages" and chunk.sse_event is None and isinstance(event_type, str)
                and is_protocol_event(dialect, event_type)):
            # A saved capture may retain data frames while dropping SSE event names.
            chunk = replace(chunk, sse_event=event_type)
        try:
            if original is not None and (dialect == recording.header.dialect or not chunk.payload_text):
                frame = original
            else:
                frame, previous_text = build_frame_from_chunk(
                    chunk, seq=seq, dialect=dialect, prev_rel_ms=0, t0_ns=0, sglang_prev_text=previous_text,
                )
        except RecursionError:
            add("D4", seq)
            continue
        frames.append(frame)
        if frame.norm.get("phase") == "ERROR" and not frame.parse_error:
            add("D4", seq)
    frame_groups = [frames]
    if dialect in {"openai-chat", "gemini-sse"}:
        frame_groups, collisions = _candidate_streams(dialect, frames, payloads)
        for seq in sorted(collisions):
            add("D3", seq)
    socket_clean = recording is None or _recording_eof_clean(recording, len(frame_groups))
    docs = [TraceDocument(header, group, assemble_summary(header, group, total_ms=0, ndjson=ndjson,
                                                         socket_eof_clean=socket_clean)) for group in frame_groups]
    for doc in docs:
        broken_tools = detect_d1(doc)
        broken_stream = detect_d4(doc)
        for finding in broken_tools:
            add("D1", finding.frame_seq)
        for finding in broken_stream:
            add("D4", finding.frame_seq)
        if dialect == "openai-responses":
            for tool in doc.summary.assembled["tool_calls"]:
                if tool["identity_conflict"]:
                    add("D3", tool["last_seq"])
        elif dialect == "anthropic-messages" and has_provider_payloads:
            for seq in _anthropic_tool_violations(doc, payloads):
                add("D1", seq)
                add("C9", seq, message="Anthropic Messages reported success with an incomplete tool call.")
        elif dialect == "gemini-sse" and doc.summary.assembled["finish_reason"] == "STOP":
            for finding in broken_tools + broken_stream:
                add("C10", finding.frame_seq, message="Gemini reported STOP with a malformed or incomplete stream.")

    if dialect in {"anthropic-messages", "gemini-sse"} and has_provider_payloads:
        for seq in _stop_reason_violations(dialect, payloads):
            add("C9" if dialect == "anthropic-messages" else "C10", seq)
    if expect_usage and not _has_expected_usage(dialect, payloads, frames):
        add("D4", len(chunks) - 1 if chunks else None, severity="P1", message="Requested usage is missing.")

    return list({(item["code"], item["severity"], item["frame_seq"]): item for item in findings}.values())
