"""Google Gemini streaming capture and C10 contract inspection."""

from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
from typing import Any, Mapping, Sequence

from .dialects.gemini_sse import USAGE_FIELDS, candidate_finish_reason, content_parts, first_candidate
from .recorder import SSEFramer, record_stream, validate_and_merge_headers
from .schema import TraceDocument, TraceFrame, is_strict_int, strict_json_loads


@dataclass(frozen=True)
class GeminiContract:
    violations: tuple[str, ...]
    finish_reason: str | None
    candidate_tokens: int | None
    prompt_tokens: int | None
    thoughts_tokens: int | None
    total_tokens: int | None
    thought_frames: int
    candidate_parts: int


def record_gemini_stream(
    *,
    url: str,
    request_body: dict[str, Any],
    out_path: str | Path | None = None,
    headers: Mapping[str, str] | None = None,
    label: str = "",
    timeout: float = 120.0,
    known_secrets: Sequence[str] = (),
) -> TraceDocument:
    """POST using Gemini SSE with header-only authentication and redacted trace capture."""
    headers = validate_and_merge_headers({"Accept": "text/event-stream"}, headers)
    return record_stream(url=url, request_body=request_body, out_path=out_path, headers=headers,
                         dialect="gemini-sse", label=label, timeout=timeout, known_secrets=known_secrets)


def _payload(frame: TraceFrame) -> dict[str, Any] | None:
    if frame.parse_error:
        return None
    framer = SSEFramer()
    try:
        chunks = framer.feed(frame.raw_wire.encode("utf-8"), 0) + framer.finish(0)
        if len(chunks) != 1 or chunks[0].is_incomplete:
            return None
        value = strict_json_loads(chunks[0].payload_text)
    except (ValueError, RecursionError):
        return None
    return value if isinstance(value, dict) else None


def _has_replacement_character(value: Any) -> bool:
    if isinstance(value, str):
        return "\ufffd" in value
    if isinstance(value, list):
        return any(_has_replacement_character(item) for item in value)
    if isinstance(value, dict):
        return any(_has_replacement_character(key) or _has_replacement_character(item)
                   for key, item in value.items())
    return False


def _is_candidate_output(part: dict[str, Any]) -> bool:
    return part.get("thought") is not True and any(
        value not in (None, "") for key, value in part.items() if key not in {"thought", "thoughtSignature"}
    )


def inspect_gemini_stream(doc: TraceDocument, *, max_tokens: int) -> GeminiContract:
    """Check a Gemini response to a deliberate, tightly capped generation request."""
    violations: list[str] = []
    content_type = doc.header.response_meta.get("content_type")
    if not isinstance(content_type, str) or content_type.split(";", 1)[0].strip().lower() != "text/event-stream":
        violations.append("Gemini streaming response is missing text/event-stream content type")

    finish_reason = None
    candidate_parts = thought_frames = 0
    final_usage = None
    for frame in doc.frames:
        payload = _payload(frame)
        if payload is None:
            if frame.parse_error in ("invalid_utf8", "invalid_unicode_surrogate"):
                violations.append(f"frame {frame.seq} contains invalid UTF-8 or Unicode")
            else:
                violations.append(f"frame {frame.seq} is not a complete Gemini SSE JSON object")
            continue
        if "\ufffd" in frame.raw_wire or _has_replacement_character(payload):
            violations.append(f"frame {frame.seq} contains the U+FFFD replacement character")
        if payload.get("error") is not None:
            violations.append("Gemini stream sent an in-band error")
        candidate = first_candidate(payload)
        parts = content_parts(candidate)
        thought_frames += any(part.get("thought") is True for part in parts)
        candidate_parts += sum(_is_candidate_output(part) for part in parts)
        reason = candidate_finish_reason(candidate)
        if reason is not None:
            if finish_reason is not None and reason != finish_reason:
                violations.append("Gemini stream changed finishReason after the candidate stopped")
            finish_reason = reason
        final_usage = payload.get("usageMetadata")

    usage: dict[str, int] = {}
    if not isinstance(final_usage, dict):
        violations.append("final Gemini SSE frame must report usageMetadata")
    else:
        for name in USAGE_FIELDS.values():
            if name in final_usage:
                value = final_usage[name]
                if is_strict_int(value) and value >= 0:
                    usage[name] = value
                else:
                    violations.append(f"usageMetadata.{name} must be a nonnegative integer")

    prompt = usage.get("promptTokenCount")
    output = usage.get("candidatesTokenCount")
    thoughts = usage.get("thoughtsTokenCount")
    total = usage.get("totalTokenCount")
    if candidate_parts and not output:
        violations.append("usageMetadata.candidatesTokenCount must be greater than zero after streamed candidate parts")
    if isinstance(final_usage, dict):
        if prompt is None or total is None:
            violations.append("final usageMetadata must report promptTokenCount and totalTokenCount")
        elif total < prompt + (output or 0):
            violations.append("usageMetadata.totalTokenCount is less than promptTokenCount + candidatesTokenCount")
    if not (candidate_parts or thought_frames or thoughts):
        violations.append("Gemini stream returned neither candidate parts nor thinking output")

    if finish_reason is None:
        violations.append("Gemini stream is missing candidates[0].finishReason")
    elif finish_reason != "MAX_TOKENS":
        if (output or 0) + (thoughts or 0) >= max_tokens:
            violations.append("Gemini output reached maxOutputTokens without finishReason=MAX_TOKENS")
        else:
            violations.append("expected finishReason=MAX_TOKENS for the deliberately capped Gemini prompt")
    if not doc.summary.eof_clean:
        violations.append("Gemini stream did not end cleanly after finishReason")

    return GeminiContract(tuple(violations), finish_reason, output, prompt, thoughts, total,
                          thought_frames, candidate_parts)
