"""Gemini streamGenerateContent SSE data normalized for trace assembly."""

from __future__ import annotations

from typing import Any

from ..schema import NormalizedDelta, canonical_json_line, is_strict_int

USAGE_FIELDS = {
    "prompt_tokens": "promptTokenCount",
    "completion_tokens": "candidatesTokenCount",
    "reasoning_tokens": "thoughtsTokenCount",
    "cached_tokens": "cachedContentTokenCount",
    "total_tokens": "totalTokenCount",
}


def first_candidate(payload: dict[str, Any]) -> dict[str, Any]:
    candidates = payload.get("candidates")
    if isinstance(candidates, list) and candidates and isinstance(candidates[0], dict):
        return candidates[0]
    return {}


def content_parts(candidate: dict[str, Any]) -> list[dict[str, Any]]:
    content = candidate.get("content")
    parts = content.get("parts") if isinstance(content, dict) else None
    return [part for part in parts if isinstance(part, dict)] if isinstance(parts, list) else []


def candidate_finish_reason(candidate: dict[str, Any]) -> str | None:
    reason = candidate.get("finishReason")
    return reason if isinstance(reason, str) and reason not in ("", "FINISH_REASON_UNSPECIFIED") else None


def normalize_frame(payload: dict[str, Any]) -> NormalizedDelta:
    if payload.get("error") is not None:
        return NormalizedDelta(phase="ERROR", inband_error="Gemini stream error")

    delta = NormalizedDelta(phase="HANDSHAKE")
    usage = payload.get("usageMetadata")
    if isinstance(usage, dict):
        for field, wire_name in USAGE_FIELDS.items():
            value = usage.get(wire_name)
            if is_strict_int(value) and value >= 0:
                delta.usage[field] = value
        delta.phase = "USAGE"

    candidate = first_candidate(payload)
    text_parts, thought_parts = [], []
    for part in content_parts(candidate):
        text = part.get("text")
        if part.get("thought") is True:
            if isinstance(text, str):
                thought_parts.append(text)
            delta.phase = "REASONING"
            continue
        if isinstance(text, str):
            text_parts.append(text)
        call = part.get("functionCall")
        if not isinstance(call, dict):
            continue
        name, call_id = call.get("name"), call.get("id")
        args = call.get("args", {})
        complete = isinstance(args, dict)
        delta.tool_deltas.append({
            "id": call_id if isinstance(call_id, str) else None,
            "name": name if isinstance(name, str) else None,
            "arguments_snapshot": canonical_json_line(args) if complete else None,
            "arguments_delta": args if isinstance(args, str) else "",
            "is_args_done": complete,
            "tool_accumulate_mode": "append",
        })

    delta.text_delta = "".join(text_parts)
    delta.reasoning_delta = "".join(thought_parts)
    delta.finish_reason = candidate_finish_reason(candidate)
    if delta.finish_reason:
        delta.phase = "TERMINAL"
        delta.terminal_status = "completed" if delta.finish_reason == "STOP" else "incomplete"
    elif delta.tool_deltas:
        delta.phase = "TOOL"
    elif delta.text_delta:
        delta.phase = "CONTENT"
    return delta
