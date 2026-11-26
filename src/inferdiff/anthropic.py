"""Anthropic Messages streaming capture and C9 contract inspection."""

from __future__ import annotations

import json
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Mapping, Sequence
from urllib.parse import quote, quote_plus, urlsplit

from .dialects.anthropic_messages import DELTA_FIELDS, TOOL_TYPES
from .recorder import SSEFramer, record_stream, validate_and_merge_headers
from .redact import extract_header_secret_values, extract_query_secret_values, scrub_known_secrets
from .schema import TraceDocument, TraceFrame, has_lone_surrogate, is_strict_int, strict_json_loads, write_trace

ANTHROPIC_VERSION = "2023-06-01"

_BLOCK_EVENTS = frozenset({"content_block_start", "content_block_delta", "content_block_stop"})
_MESSAGE_EVENTS = frozenset({"message_start", "message_delta", "message_stop"})


@dataclass(frozen=True)
class AnthropicContract:
    violations: tuple[str, ...]
    stop_reason: str | None
    output_tokens: int | None
    incomplete_tool_indices: tuple[int, ...]
    observed_model: str | None
    system_fingerprint: str | None
    delta_types: tuple[str, ...]


@dataclass
class _Block:
    kind: str
    fragments: list[str] = field(default_factory=list)
    stopped: bool = False


def _scrub_trace_values(value: Any, secrets: Sequence[str]) -> Any:
    if isinstance(value, str):
        return scrub_known_secrets(value, secrets)
    if isinstance(value, dict):
        return {key: _scrub_trace_values(item, secrets) for key, item in value.items()}
    if isinstance(value, list):
        return [_scrub_trace_values(item, secrets) for item in value]
    return value


def _scrub_credential_reflections(doc: TraceDocument, secrets: Sequence[str]) -> None:
    # Credentials may be JSON-escaped on the wire or recreated by joining multiple deltas.
    variants = sorted({form for secret in secrets for form in (
        secret, json.dumps(secret, ensure_ascii=True)[1:-1], json.dumps(secret, ensure_ascii=False)[1:-1],
        quote(secret, safe="", errors="replace"), quote_plus(secret, errors="replace"),
    )}, key=len, reverse=True)
    doc.header.label = scrub_known_secrets(doc.header.label, variants)
    doc.header.request = _scrub_trace_values(doc.header.request, variants)
    doc.header.response_meta = _scrub_trace_values(doc.header.response_meta, variants)
    for frame in doc.frames:
        frame.raw_wire = scrub_known_secrets(frame.raw_wire, variants)
        frame.sse_event = _scrub_trace_values(frame.sse_event, variants)
        frame.norm = _scrub_trace_values(frame.norm, variants)
    doc.summary.assembled = _scrub_trace_values(doc.summary.assembled, variants)


def record_anthropic_stream(
    *,
    url: str,
    request_body: dict[str, Any],
    out_path: str | Path | None = None,
    headers: Mapping[str, str] | None = None,
    label: str = "",
    timeout: float = 120.0,
) -> TraceDocument:
    """POST to an Anthropic Messages endpoint using the shared strict HTTP and SSE recorder."""
    request_headers = validate_and_merge_headers(
        {"Accept": "text/event-stream", "anthropic-version": ANTHROPIC_VERSION}, headers,
    )
    doc = record_stream(
        url=url, request_body=request_body, headers=request_headers,
        dialect="anthropic-messages", label=label, timeout=timeout,
    )
    secrets = extract_header_secret_values(request_headers)
    secrets.extend(extract_query_secret_values(urlsplit(url).query))
    if secrets:
        _scrub_credential_reflections(doc, secrets)
    if out_path is not None:
        write_trace(out_path, doc)
    return doc


def _payload(frame: TraceFrame) -> dict[str, Any] | None:
    # Reuse the wire framer to join multiple data: lines and honor all SSE line endings.
    if frame.parse_error:
        return None
    framer = SSEFramer()
    try:
        chunks = framer.feed(frame.raw_wire.encode("utf-8"), 0) + framer.finish(0)
        if len(chunks) != 1 or chunks[0].is_incomplete:
            return None
        chunk = chunks[0]
        obj = strict_json_loads(chunk.payload_text)
    except (ValueError, RecursionError):
        return None
    if isinstance(obj, dict) and obj.get("type") == chunk.sse_event and isinstance(chunk.sse_event, str):
        return obj
    return None


def _complete_tool_input(fragments: list[str]) -> bool:
    try:
        value = strict_json_loads("".join(fragments))
        return isinstance(value, dict) and not has_lone_surrogate(value)
    except (ValueError, RecursionError):
        return False


def _record_block_event(
    event_type: str,
    payload: dict[str, Any],
    blocks: dict[int, _Block],
    delta_types: set[str],
    violations: list[str],
) -> None:
    index = payload.get("index")
    if not is_strict_int(index) or index < 0:
        violations.append(f"{event_type} requires a nonnegative integer block index")
        return
    if event_type == "content_block_start":
        block = payload.get("content_block")
        kind = block.get("type") if isinstance(block, dict) else None
        if index in blocks:
            violations.append(f"duplicate content_block_start for index {index}")
        elif not isinstance(kind, str) or not kind:
            violations.append(f"content_block_start at index {index} has no block type")
        else:
            blocks[index] = _Block(kind)
        return

    block = blocks.get(index)
    if block is None or block.stopped:
        violations.append(f"{event_type} at index {index} has no open content_block_start")
        return
    if event_type == "content_block_stop":
        block.stopped = True
        return

    delta = payload.get("delta")
    kind = delta.get("type") if isinstance(delta, dict) else None
    if not isinstance(kind, str) or not kind:
        violations.append(f"content_block_delta at index {index} has no delta type")
        return
    delta_types.add(kind)
    if kind not in DELTA_FIELDS:
        return  # Anthropic may add delta types without a breaking API version change.
    value = delta.get(DELTA_FIELDS[kind])
    if not isinstance(value, str):
        violations.append(f"{kind} at index {index} requires a string {DELTA_FIELDS[kind]}")
        return
    if kind == "input_json_delta":
        if block.kind not in TOOL_TYPES:
            violations.append(f"input_json_delta at index {index} belongs to a non-tool block")
        elif value:
            block.fragments.append(value)
    elif kind == "text_delta" and block.kind != "text":
        violations.append(f"text_delta at index {index} belongs to a non-text block")
    elif kind in ("thinking_delta", "signature_delta") and block.kind != "thinking":
        violations.append(f"{kind} at index {index} belongs to a non-thinking block")


def inspect_anthropic_stream(doc: TraceDocument, *, max_tokens: int) -> AnthropicContract:
    """Validate lifecycle, stop reason and cumulative output usage of a captured Messages stream."""
    violations: list[str] = []
    content_type = doc.header.response_meta.get("content_type")
    if not isinstance(content_type, str) or content_type.split(";", 1)[0].strip().lower() != "text/event-stream":
        violations.append("Anthropic streaming response is missing text/event-stream content type")

    phase = "start"
    blocks: dict[int, _Block] = {}
    delta_types: set[str] = set()
    stop_reason = None
    output_tokens = None
    observed_model = None
    system_fingerprint = None

    for frame in doc.frames:
        payload = _payload(frame)
        if payload is None:
            violations.append(f"frame {frame.seq} is not a complete, matching named SSE JSON event")
            continue
        event_type = payload["type"]
        if event_type == "error":
            violations.append("Anthropic stream sent an in-band error")
            continue
        if event_type not in _BLOCK_EVENTS and event_type not in _MESSAGE_EVENTS:
            continue  # Ignore ping and unknown extension events.
        if phase == "stopped":
            violations.append(f"{event_type} arrived after message_stop")
            continue
        if event_type == "message_start":
            if phase != "start":
                violations.append("duplicate or out-of-order message_start")
                continue
            phase = "blocks"
            message = payload.get("message")
            if not isinstance(message, dict):
                violations.append("message_start requires a message object")
                continue
            model = message.get("model")
            if isinstance(model, str) and model:
                observed_model = model
            fingerprint = message.get("system_fingerprint", payload.get("system_fingerprint"))
            if isinstance(fingerprint, str) and fingerprint:
                system_fingerprint = fingerprint
        elif event_type in _BLOCK_EVENTS:
            if phase != "blocks":
                violations.append(f"{event_type} arrived outside the content block sequence")
            else:
                _record_block_event(event_type, payload, blocks, delta_types, violations)
        elif event_type == "message_delta":
            if phase == "start":
                violations.append("message_delta arrived before message_start")
            if phase == "blocks" and any(not block.stopped for block in blocks.values()):
                violations.append("message_delta arrived before all content_block_stop events")
            phase = "delta"
            delta = payload.get("delta")
            if not isinstance(delta, dict):
                violations.append("message_delta requires a delta object")
            else:
                reason = delta.get("stop_reason")
                if isinstance(reason, str) and reason:
                    if stop_reason is not None and reason != stop_reason:
                        violations.append("message_delta changed the final stop_reason")
                    stop_reason = reason
                elif reason is not None:
                    violations.append("message_delta.delta.stop_reason must be a nonempty string")
            usage = payload.get("usage")
            if isinstance(usage, dict) and "output_tokens" in usage:
                count = usage["output_tokens"]
                if not is_strict_int(count) or count < 0:
                    violations.append("message_delta.usage.output_tokens must be a nonnegative integer")
                else:
                    if output_tokens is not None and count < output_tokens:
                        violations.append("cumulative message_delta.usage.output_tokens decreased")
                    output_tokens = count
        elif event_type == "message_stop":
            if phase != "delta":
                violations.append("message_stop arrived before message_delta")
            phase = "stopped"

    if phase == "start":
        violations.append("missing message_start")
    if phase != "stopped" or not doc.summary.eof_clean:
        violations.append("stream ended without a clean message_stop")
    for index, block in blocks.items():
        if not block.stopped:
            violations.append(f"missing content_block_stop for index {index}")
    if stop_reason is None:
        violations.append("missing message_delta.delta.stop_reason")
    if delta_types and (output_tokens is None or output_tokens <= 0):
        violations.append("message_delta.usage.output_tokens must be greater than zero after streamed deltas")

    incomplete_tools = tuple(sorted(
        index for index, block in blocks.items()
        if block.fragments and not _complete_tool_input(block.fragments)
    ))
    if stop_reason != "max_tokens":
        if incomplete_tools:
            violations.append("incomplete tool input JSON requires stop_reason=max_tokens")
        if output_tokens is not None and output_tokens >= max_tokens:
            violations.append("output exhausted the max_tokens budget without stop_reason=max_tokens")

    return AnthropicContract(
        violations=tuple(dict.fromkeys(violations)), stop_reason=stop_reason, output_tokens=output_tokens,
        incomplete_tool_indices=incomplete_tools, observed_model=observed_model,
        system_fingerprint=system_fingerprint, delta_types=tuple(sorted(delta_types)),
    )
