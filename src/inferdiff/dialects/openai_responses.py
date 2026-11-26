"""OpenAI /v1/responses typed-event SSE dialect normalizer (covers llama.cpp #30773)."""

from __future__ import annotations

from typing import Any, Dict, List, Optional

from ..schema import NormalizedDelta, empty_usage, is_strict_int

TERMINAL_EVENT_TO_STATUS = {
    "response.completed": "completed",
    "response.incomplete": "incomplete",
    "response.failed": "failed",
}


def _parse_usage(obj: Any) -> Dict[str, Any]:
    usage = empty_usage()
    if not isinstance(obj, dict):
        return usage
    if is_strict_int(obj.get("input_tokens")) and obj["input_tokens"] >= 0:
        usage["prompt_tokens"] = obj["input_tokens"]
    if is_strict_int(obj.get("output_tokens")) and obj["output_tokens"] >= 0:
        usage["completion_tokens"] = obj["output_tokens"]

    od = obj.get("output_tokens_details")
    reas = od.get("reasoning_tokens") if isinstance(od, dict) else None
    if not (is_strict_int(reas) and reas >= 0):
        reas = obj.get("reasoning_tokens")
    if is_strict_int(reas) and reas >= 0:
        usage["reasoning_tokens"] = reas

    ind = obj.get("input_tokens_details")
    cached = ind.get("cached_tokens") if isinstance(ind, dict) else None
    if not (is_strict_int(cached) and cached >= 0):
        cached = obj.get("cached_tokens")
    if is_strict_int(cached) and cached >= 0:
        usage["cached_tokens"] = cached
    return usage


def _extract_item_tool(item: Dict[str, Any], out_idx: Optional[int], *, is_done_item: bool) -> Optional[Dict[str, Any]]:
    if item.get("type") != "function_call":
        return None
    # Only record arguments_snapshot on done/terminal items (never treat initial output_item.added "" as final snapshot)
    snap = item.get("arguments") if (is_done_item and isinstance(item.get("arguments"), str)) else None
    return {
        "index": out_idx,
        "id": item.get("call_id") if isinstance(item.get("call_id"), str) else None,
        "item_id": item.get("id") if isinstance(item.get("id"), str) else None,
        "name": item.get("name") if isinstance(item.get("name"), str) else None,
        "arguments_delta": "",
        "is_args_delta_event": False,
        "arguments_snapshot": snap,
        "is_item_done_snapshot": is_done_item,
        "is_args_done": False,
    }


def normalize_frame(payload: Dict[str, Any], sse_event: Optional[str] = None) -> NormalizedDelta:
    """Normalize one parsed OpenAI Responses SSE event."""
    ev_type = payload.get("type") if isinstance(payload.get("type"), str) else (sse_event or "")
    delta = NormalizedDelta()

    if ev_type == "error" or ("error" in payload and payload["error"] is not None):
        delta.phase = "ERROR"
        delta.inband_error = str(payload.get("error") or payload)
        return delta

    if ev_type in ("response.output_text.delta", "response.refusal.delta"):
        txt = payload.get("delta")
        if isinstance(txt, str):
            delta.text_delta = txt
        delta.phase = "CONTENT" if delta.text_delta else "HANDSHAKE"
        return delta

    if ev_type in ("response.reasoning_summary_text.delta", "response.reasoning_text.delta"):
        txt = payload.get("delta")
        if isinstance(txt, str):
            delta.reasoning_delta = txt
        delta.phase = "REASONING" if delta.reasoning_delta else "HANDSHAKE"
        return delta

    if ev_type == "response.output_item.added":
        item = payload.get("item")
        out_idx = payload.get("output_index") if is_strict_int(payload.get("output_index")) else None
        if isinstance(item, dict):
            td = _extract_item_tool(item, out_idx, is_done_item=False)
            if td is not None:
                delta.tool_deltas.append(td)
                delta.phase = "TOOL"
                return delta
        delta.phase = "HANDSHAKE"
        return delta

    if ev_type == "response.function_call_arguments.delta":
        out_idx = payload.get("output_index") if is_strict_int(payload.get("output_index")) else None
        arg_delta = payload.get("delta") if isinstance(payload.get("delta"), str) else ""
        delta.tool_deltas.append(
            {
                "index": out_idx,
                "id": payload.get("call_id") if isinstance(payload.get("call_id"), str) else None,
                "item_id": payload.get("item_id") if isinstance(payload.get("item_id"), str) else None,
                "name": None,
                "arguments_delta": arg_delta,
                "is_args_delta_event": True,  # Track receipt even when arg_delta == ""
                "arguments_snapshot": None,
                "is_args_done": False,
            }
        )
        delta.phase = "TOOL"
        return delta

    if ev_type == "response.function_call_arguments.done":
        out_idx = payload.get("output_index") if is_strict_int(payload.get("output_index")) else None
        arg_snap = payload.get("arguments") if isinstance(payload.get("arguments"), str) else None
        delta.tool_deltas.append(
            {
                "index": out_idx,
                "id": payload.get("call_id") if isinstance(payload.get("call_id"), str) else None,
                "item_id": payload.get("item_id") if isinstance(payload.get("item_id"), str) else None,
                "name": payload.get("name") if isinstance(payload.get("name"), str) else None,
                "arguments_delta": "",
                "is_args_delta_event": False,
                "arguments_snapshot": arg_snap,
                "is_args_done": True,
            }
        )
        delta.closed_events.append("response.function_call_arguments.done")
        delta.phase = "TOOL"
        return delta

    if ev_type == "response.output_item.done":
        item = payload.get("item")
        out_idx = payload.get("output_index") if is_strict_int(payload.get("output_index")) else None
        delta.closed_events.append("response.output_item.done")
        if isinstance(item, dict):
            td = _extract_item_tool(item, out_idx, is_done_item=True)
            if td is not None:
                delta.tool_deltas.append(td)
                delta.phase = "TOOL"
                return delta
        delta.phase = "HANDSHAKE"
        return delta

    if ev_type in TERMINAL_EVENT_TO_STATUS:
        expected_status = TERMINAL_EVENT_TO_STATUS[ev_type]
        resp = payload.get("response") if isinstance(payload.get("response"), dict) else {}
        raw_status = resp.get("status")
        if raw_status != expected_status:
            delta.protocol_error = (
                f"invalid_responses_terminal_status: event={ev_type} status={raw_status!r} expected={expected_status!r}"
            )
            delta.phase = "ERROR"
            delta.terminal_status = str(raw_status) if raw_status is not None else "unknown"
            delta.is_done_sentinel = False
            delta.usage = _parse_usage(resp.get("usage"))
            return delta

        status = expected_status
        inc = resp.get("incomplete_details") if isinstance(resp.get("incomplete_details"), dict) else {}
        inc_reason = inc.get("reason") if isinstance(inc.get("reason"), str) else None

        delta.phase = "TERMINAL"
        delta.terminal_status = status
        delta.finish_reason = inc_reason
        delta.closed_events.append(ev_type)
        delta.is_done_sentinel = True
        delta.usage = _parse_usage(resp.get("usage"))

        out_items = resp.get("output")
        if isinstance(out_items, list):
            for pos, item in enumerate(out_items):
                if isinstance(item, dict):
                    td = _extract_item_tool(item, pos, is_done_item=True)
                    if td is not None:
                        delta.tool_deltas.append(td)
        return delta

    delta.phase = "HANDSHAKE"
    return delta
