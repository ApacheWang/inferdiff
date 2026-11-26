"""Ollama /api/chat and /api/generate NDJSON dialect normalizer (covers Ollama #17274)."""

from __future__ import annotations

import json
from typing import Any, Dict, List, Optional

from ..schema import NormalizedDelta, empty_usage, is_strict_int


def normalize_frame(payload: Dict[str, Any], sse_event: Optional[str] = None) -> NormalizedDelta:
    """Normalize one NDJSON line from Ollama /api/chat or /api/generate."""
    usage = empty_usage()
    if is_strict_int(payload.get("prompt_eval_count")) and payload["prompt_eval_count"] >= 0:
        usage["prompt_tokens"] = payload["prompt_eval_count"]
    if is_strict_int(payload.get("eval_count")) and payload["eval_count"] >= 0:
        usage["completion_tokens"] = payload["eval_count"]

    delta = NormalizedDelta(usage=usage)

    if "error" in payload and payload["error"] is not None:
        delta.phase = "ERROR"
        delta.inband_error = str(payload["error"])
        return delta

    msg = payload.get("message") if isinstance(payload.get("message"), dict) else {}
    # /api/chat uses message.content / message.thinking / message.tool_calls
    # /api/generate uses top-level response / thinking
    text = msg.get("content") if isinstance(msg.get("content"), str) else payload.get("response")
    if isinstance(text, str) and text != "":
        delta.text_delta = text

    thinking = msg.get("thinking") if isinstance(msg.get("thinking"), str) else payload.get("thinking")
    if isinstance(thinking, str) and thinking != "":
        delta.reasoning_delta = thinking

    tcalls = msg.get("tool_calls")
    if isinstance(tcalls, list):
        tool_deltas: List[Dict[str, Any]] = []
        for tc in tcalls:
            if not isinstance(tc, dict):
                continue
            fn = tc.get("function") if isinstance(tc.get("function"), dict) else {}
            args = fn.get("arguments")
            if isinstance(args, dict):
                try:
                    arg_str = json.dumps(args, ensure_ascii=False, separators=(",", ":"), allow_nan=False)
                except (ValueError, TypeError, OverflowError):
                    delta.protocol_error = "invalid_ollama_tool_arguments"
                    arg_str = ""
            elif isinstance(args, str):
                arg_str = args
            else:
                arg_str = ""
            # Ollama streaming emits complete tool calls per chunk with frame-local positions;
            # mark append mode so consecutive chunks accumulate distinct calls instead of colliding.
            raw_idx = tc.get("index") if is_strict_int(tc.get("index")) else None
            raw_id = tc.get("id") if isinstance(tc.get("id"), str) and tc.get("id") else None
            tool_deltas.append(
                {
                    "index": raw_idx,
                    "id": raw_id,
                    "item_id": None,
                    "name": fn.get("name") if isinstance(fn.get("name"), str) else None,
                    "arguments_delta": "",
                    "is_args_delta_event": False,
                    "arguments_snapshot": arg_str,
                    "is_args_done": True,
                    "tool_accumulate_mode": "append",
                }
            )
        delta.tool_deltas = tool_deltas

    done = payload.get("done") is True
    done_reason = payload.get("done_reason") if isinstance(payload.get("done_reason"), str) and payload.get("done_reason") else None
    if done:
        delta.is_done_sentinel = True
        delta.closed_events.append("ollama.done")
        delta.terminal_status = "completed"
        # Preserve absent done_reason as "unknown" instead of fabricating "stop"
        delta.finish_reason = done_reason if done_reason is not None else "unknown"
        delta.phase = "TERMINAL"
        return delta

    if delta.tool_deltas:
        delta.phase = "TOOL"
    elif delta.reasoning_delta and not delta.text_delta:
        delta.phase = "REASONING"
    elif delta.text_delta:
        delta.phase = "CONTENT"
    else:
        delta.phase = "HANDSHAKE"

    return delta
