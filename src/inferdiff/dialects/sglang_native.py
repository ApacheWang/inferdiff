"""SGLang native /generate SSE dialect normalizer (covers SGLang #53119 / #50443)."""

from __future__ import annotations

from typing import Any, Dict, Optional

from ..schema import NormalizedDelta, empty_usage, is_strict_int


def _parse_usage(meta: Any) -> Dict[str, Any]:
    usage = empty_usage()
    if not isinstance(meta, dict):
        return usage
    if is_strict_int(meta.get("prompt_tokens")) and meta["prompt_tokens"] >= 0:
        usage["prompt_tokens"] = meta["prompt_tokens"]
    if is_strict_int(meta.get("completion_tokens")) and meta["completion_tokens"] >= 0:
        usage["completion_tokens"] = meta["completion_tokens"]
    reas = meta.get("reasoning_tokens")
    if is_strict_int(reas) and reas >= 0:
        usage["reasoning_tokens"] = reas
    cached = meta.get("cached_tokens")
    if is_strict_int(cached) and cached >= 0:
        usage["cached_tokens"] = cached
    return usage


def normalize_frame(
    payload: Dict[str, Any],
    sse_event: Optional[str] = None,
    *,
    prev_text: str = "",
) -> NormalizedDelta:
    """Normalize one parsed SGLang /generate chunk (handles cumulative text & textless terminal meta_info)."""
    meta = payload.get("meta_info") if isinstance(payload.get("meta_info"), dict) else {}
    delta = NormalizedDelta(usage=_parse_usage(meta), is_cumulative_text=True)

    if "error" in payload and payload["error"] is not None:
        delta.phase = "ERROR"
        delta.inband_error = str(payload["error"])
        return delta

    if isinstance(payload.get("text"), str):
        cum = payload["text"]
        if cum.startswith(prev_text):
            delta.text_delta = cum[len(prev_text) :]
        else:
            # Non-monotonic prefix rewrite: keep literal string for forensic visibility
            delta.text_delta = cum

    fr_obj = meta.get("finish_reason")
    if isinstance(fr_obj, dict) and isinstance(fr_obj.get("type"), str) and fr_obj["type"]:
        delta.finish_reason = fr_obj["type"]
        matched = fr_obj.get("matched")
        if matched is not None and matched != "":
            delta.matched_stop = matched
    elif isinstance(fr_obj, str) and fr_obj:
        delta.finish_reason = fr_obj

    if delta.finish_reason:
        delta.phase = "TERMINAL"
    elif delta.text_delta:
        delta.phase = "CONTENT"
    elif any(v != "unknown" for v in delta.usage.values()):
        delta.phase = "USAGE"
    else:
        delta.phase = "HANDSHAKE"

    return delta
