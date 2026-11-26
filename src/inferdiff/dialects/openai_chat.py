"""OpenAI /v1/chat/completions SSE dialect normalizer (llama-server, vLLM, SGLang, LiteLLM)."""

from __future__ import annotations

from typing import Any, Dict, List, Optional

from ..schema import NormalizedDelta, empty_usage, is_strict_int


def _parse_usage(obj: Any) -> Dict[str, Any]:
    usage = empty_usage()
    if not isinstance(obj, dict):
        return usage
    if is_strict_int(obj.get("prompt_tokens")) and obj["prompt_tokens"] >= 0:
        usage["prompt_tokens"] = obj["prompt_tokens"]
    if is_strict_int(obj.get("completion_tokens")) and obj["completion_tokens"] >= 0:
        usage["completion_tokens"] = obj["completion_tokens"]

    cd = obj.get("completion_tokens_details")
    reas = cd.get("reasoning_tokens") if isinstance(cd, dict) else None
    if not (is_strict_int(reas) and reas >= 0):
        reas = obj.get("reasoning_tokens")
    if is_strict_int(reas) and reas >= 0:
        usage["reasoning_tokens"] = reas

    pd = obj.get("prompt_tokens_details")
    cached = pd.get("cached_tokens") if isinstance(pd, dict) else None
    if not (is_strict_int(cached) and cached >= 0):
        cached = obj.get("cached_tokens")
    if is_strict_int(cached) and cached >= 0:
        usage["cached_tokens"] = cached
    return usage


def normalize_frame(payload: Dict[str, Any], sse_event: Optional[str] = None) -> NormalizedDelta:
    """Normalize one parsed OpenAI Chat Completions JSON chunk."""
    delta = NormalizedDelta(usage=_parse_usage(payload.get("usage")))

    if "error" in payload and payload["error"] is not None:
        delta.phase = "ERROR"
        delta.inband_error = str(payload["error"])
        return delta

    choices = payload.get("choices")
    if not isinstance(choices, list) or not choices:
        # vLLM include_usage trailing chunk has choices: [] with usage
        has_usage = any(v != "unknown" for v in delta.usage.values())
        delta.phase = "USAGE" if has_usage else "HANDSHAKE"
        return delta

    ch0 = choices[0] if isinstance(choices[0], dict) else {}
    d = ch0.get("delta") if isinstance(ch0.get("delta"), dict) else {}

    content = d.get("content")
    refusal = d.get("refusal")
    if isinstance(content, str) and content != "":
        delta.text_delta = content
    elif isinstance(refusal, str) and refusal != "":
        delta.text_delta = refusal

    reas = d.get("reasoning_content")
    if not isinstance(reas, str) or reas == "":
        reas = d.get("reasoning")
    if isinstance(reas, str) and reas != "":
        delta.reasoning_delta = reas

    tcalls = d.get("tool_calls")
    tool_deltas: List[Dict[str, Any]] = []
    if isinstance(tcalls, list):
        for pos, tc in enumerate(tcalls):
            if not isinstance(tc, dict):
                continue
            fn = tc.get("function") if isinstance(tc.get("function"), dict) else {}
            idx = tc.get("index") if is_strict_int(tc.get("index")) else pos
            raw_arg = fn.get("arguments")
            has_arg_field = isinstance(raw_arg, str)
            tool_deltas.append(
                {
                    "index": idx,
                    "id": tc.get("id") if isinstance(tc.get("id"), str) else None,
                    "item_id": None,
                    "name": fn.get("name") if isinstance(fn.get("name"), str) else None,
                    "arguments_delta": raw_arg if has_arg_field else "",
                    "is_args_delta_event": has_arg_field and raw_arg != "",
                    "arguments_snapshot": None,
                    "is_args_done": False,
                }
            )
    delta.tool_deltas = tool_deltas

    fin = ch0.get("finish_reason")
    if isinstance(fin, str) and fin:
        delta.finish_reason = fin

    # vLLM / SGLang OpenAI-compatible servers emit stop_reason when an explicit user stop matched
    stop_reason = ch0.get("stop_reason")
    if stop_reason is not None and stop_reason != "":
        delta.matched_stop = stop_reason

    if delta.finish_reason:
        delta.phase = "TERMINAL"
    elif delta.tool_deltas:
        delta.phase = "TOOL"
    elif delta.reasoning_delta and not delta.text_delta:
        delta.phase = "REASONING"
    elif delta.text_delta:
        delta.phase = "CONTENT"
    elif any(v != "unknown" for v in delta.usage.values()):
        delta.phase = "USAGE"
    else:
        delta.phase = "HANDSHAKE"

    return delta
