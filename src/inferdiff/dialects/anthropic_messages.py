"""Anthropic Messages named SSE events normalized for trace assembly."""

from __future__ import annotations

from typing import Any

from ..schema import NormalizedDelta, UsageValue, canonical_json_line, empty_usage, is_strict_int

TOOL_TYPES = frozenset({"tool_use", "server_tool_use"})
DELTA_FIELDS = {
    "text_delta": "text",
    "thinking_delta": "thinking",
    "signature_delta": "signature",
    "input_json_delta": "partial_json",
}


def _usage(source: Any) -> dict[str, UsageValue]:
    usage = empty_usage()
    if isinstance(source, dict):
        for target, source_key in (
            ("prompt_tokens", "input_tokens"),
            ("completion_tokens", "output_tokens"),
            ("cached_tokens", "cache_read_input_tokens"),
        ):
            value = source.get(source_key)
            if is_strict_int(value) and value >= 0:
                usage[target] = value
    return usage


def normalize_frame(payload: dict[str, Any], sse_event: str | None = None) -> NormalizedDelta:
    event_type = payload.get("type")
    if not isinstance(event_type, str) or not event_type or event_type != sse_event:
        return NormalizedDelta(phase="ERROR", protocol_error="SSE event name does not match JSON type")

    norm = NormalizedDelta(phase="HANDSHAKE")
    if event_type == "error":
        return NormalizedDelta(phase="ERROR", inband_error="Anthropic stream error")
    if event_type == "message_start":
        message = payload.get("message")
        if isinstance(message, dict):
            norm.usage = _usage(message.get("usage"))
        return norm
    if event_type == "message_delta":
        norm.phase = "USAGE"
        norm.usage = _usage(payload.get("usage"))
        delta = payload.get("delta")
        if isinstance(delta, dict):
            reason = delta.get("stop_reason")
            if isinstance(reason, str) and reason:
                norm.finish_reason = reason
            if isinstance(delta.get("stop_sequence"), str):
                norm.matched_stop = delta["stop_sequence"]
        return norm
    if event_type == "message_stop":
        return NormalizedDelta(phase="TERMINAL", closed_events=["message_stop"])

    index = payload.get("index")
    if not is_strict_int(index) or index < 0:
        return norm
    if event_type == "content_block_start":
        block = payload.get("content_block")
        if (isinstance(block, dict) and isinstance(block.get("type"), str)
                and block["type"] in TOOL_TYPES):
            args = block.get("input")
            norm.phase = "TOOL"
            norm.tool_deltas.append({
                "index": index,
                "id": block.get("id") if isinstance(block.get("id"), str) else None,
                "name": block.get("name") if isinstance(block.get("name"), str) else None,
                "arguments_snapshot": canonical_json_line(args) if isinstance(args, dict) else None,
            })
        return norm
    if event_type != "content_block_delta" or not isinstance(payload.get("delta"), dict):
        return norm

    delta = payload["delta"]
    kind = delta.get("type")
    if not isinstance(kind, str) or kind not in DELTA_FIELDS:
        return norm
    value = delta.get(DELTA_FIELDS[kind])
    if not isinstance(value, str):
        return norm
    if kind == "text_delta":
        norm.phase = "CONTENT"
        norm.text_delta = value
    elif kind == "thinking_delta":
        norm.phase = "REASONING"
        norm.reasoning_delta = value
    elif kind == "signature_delta":
        norm.phase = "REASONING"
    elif kind == "input_json_delta":
        norm.phase = "TOOL"
        norm.tool_deltas.append({"index": index, "arguments_delta": value, "is_args_delta_event": True})
    return norm
