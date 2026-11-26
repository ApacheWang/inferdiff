"""Streaming dialect detection and normalization registry."""

from __future__ import annotations

from typing import Any, Dict, Optional

from ..schema import NormalizedDelta
from . import anthropic_messages, gemini_sse, ollama_ndjson, openai_chat, openai_responses, sglang_native


def detect_dialect(url_path: str, content_type: str = "") -> str:
    """Infer dialect from URL path and Content-Type when --dialect=auto."""
    path = url_path.rstrip("/").lower()
    ct = content_type.split(";", 1)[0].strip().lower()
    if path.endswith(":streamgeneratecontent"):
        return "gemini-sse"
    if path.endswith("/v1/messages"):
        return "anthropic-messages"
    if path.endswith("/v1/responses") or path.endswith("/responses"):
        return "openai-responses"
    if path.endswith("/v1/chat/completions") or path.endswith("/chat/completions"):
        return "openai-chat"
    if path.endswith("/api/chat") or path.endswith("/api/generate") or ct == "application/x-ndjson":
        return "ollama-ndjson"
    if path.endswith("/generate"):
        return "sglang-native"
    return "openai-chat"


def normalize_payload(
    dialect: str,
    payload: Dict[str, Any],
    *,
    sse_event: Optional[str] = None,
    prev_text: str = "",
) -> NormalizedDelta:
    if dialect == "openai-chat":
        return openai_chat.normalize_frame(payload, sse_event)
    if dialect == "openai-responses":
        return openai_responses.normalize_frame(payload, sse_event)
    if dialect == "sglang-native":
        return sglang_native.normalize_frame(payload, sse_event, prev_text=prev_text)
    if dialect == "ollama-ndjson":
        return ollama_ndjson.normalize_frame(payload, sse_event)
    if dialect == "anthropic-messages":
        return anthropic_messages.normalize_frame(payload, sse_event)
    if dialect == "gemini-sse":
        return gemini_sse.normalize_frame(payload)
    raise ValueError(f"Unsupported dialect: {dialect!r}")
