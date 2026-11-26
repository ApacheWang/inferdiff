"""inferdiff doctor: zero-setup C1..C8 canary probe suite for local engines & API relays."""

from __future__ import annotations

import datetime
import http.client
import json
import os
import secrets
import ssl
import time
import urllib.parse
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Dict, List, Mapping, Optional, Sequence, Tuple

from . import __version__
from .detectors import D1, D2, D3, D4, Finding, audit_trace
from .recorder import RecorderError, record_stream, validate_and_merge_headers, validate_url
from .redact import (
    extract_header_secret_values,
    sanitize_url_for_error,
    sanitize_url_for_export,
    scrub_known_secrets,
)
from .schema import (
    EXIT_OK,
    EXIT_SEMANTIC_REGRESSION,
    EXIT_SILENT_PROTOCOL_BREACH,
    EXIT_USAGE_OR_IO_ERROR,
    TraceDocument,
    is_strict_int,
    strict_json_loads,
)

PROFILE_PROBES: Dict[str, Tuple[str, ...]] = {
    "quick": ("C1", "C4", "C5", "C6", "C7"),
    "full": ("C1", "C2", "C3", "C4", "C5", "C6", "C7", "C8"),
    "relay": ("C1", "C2", "C4", "C5", "C6", "C7", "C8"),
}

PROBE_CATALOG: Dict[str, Tuple[str, str, str]] = {
    "C1": ("TOOL_CALL_BUDGET_CLIP", "P0", "https://github.com/ggml-org/llama.cpp/issues/30773"),
    "C2": ("REASONING_STARVATION_GUARD", "P0", "https://github.com/ollama/ollama/issues/17274"),
    "C3": ("FIXED_BUDGET_HONOR", "P1", "https://github.com/sgl-project/sglang/pull/53119"),
    "C4": ("STREAM_INCLUDE_USAGE_CONTRACT", "P1", "https://github.com/BerriAI/litellm/issues/16112"),
    "C5": ("INITIAL_ROLE_AND_TOOL_INDEX", "P1", "https://github.com/BerriAI/litellm/issues/24221"),
    "C6": ("UTF8_MULTIBYTE_INTEGRITY", "P0", "https://github.com/vllm-project/vllm/issues/68324"),
    "C7": ("FAKE_STREAMING_BUFFER", "P1", "https://github.com/BerriAI/litellm/issues/5803"),
    "C8": ("SEED_AND_RELAY_DRIFT", "P2", "https://docs.vllm.ai/en/stable/benchmarking/cli/"),
}

C6_TARGET_TEXT = "吞吐量Δ=99.8% [🔥🚀🧪🌊]"
C6_TRAILING_EMOJI = "🌊"


def _clean_display(text: Any, secrets_list: Sequence[str] = (), max_chars: int = 180) -> str:
    """Strip terminal control characters and scrub known/pattern secrets before display or JSON export."""
    scrubbed = scrub_known_secrets(str(text), secrets_list)
    out: List[str] = []
    for ch in scrubbed:
        code = ord(ch)
        if ch in ("\r", "\n", "\u0085", "\u2028", "\u2029"):
            out.append(" ")
        elif code < 32 or code == 127:
            out.append(f"\\x{code:02x}")
        else:
            out.append(ch)
    s = "".join(out).strip()
    if len(s) > max_chars:
        return s[: max_chars - 3] + "..."
    return s


@dataclass
class ProbeResult:
    probe_id: str
    code: str
    severity: str  # "P0" | "P1" | "P2"
    status: str  # "PASS" | "WARN" | "FAIL" | "SKIP" | "ERROR"
    summary: str
    duration_ms: float
    total_frames: int
    tokens_used: Optional[int]
    reference_url: str
    trace_paths: List[str] = field(default_factory=list)
    findings: List[Finding] = field(default_factory=list)
    traces: List[TraceDocument] = field(default_factory=list)
    details: Dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "probe_id": self.probe_id,
            "code": self.code,
            "severity": self.severity,
            "status": self.status,
            "summary": self.summary,
            "duration_ms": round(self.duration_ms, 1),
            "total_frames": self.total_frames,
            "tokens_used": self.tokens_used if self.tokens_used is not None else "unknown",
            "reference_url": self.reference_url,
            "trace_paths": self.trace_paths,
            "findings": [
                {
                    "detector_id": f.detector_id,
                    "code": f.code,
                    "severity": f.severity,
                    "frame_seq": f.frame_seq,
                    "message": _clean_display(f.message, max_chars=240),
                }
                for f in self.findings
            ],
            "details": self.details,
        }


@dataclass
class DoctorReport:
    target_url: str
    chat_url: str
    dialect: str
    model: str
    profile: str
    grade: str  # "A+" | "A" | "B" | "C" | "F"
    exit_code: int
    p0_count: int
    warning_count: int
    error_count: int
    total_tokens: Optional[int]
    save_dir: Optional[str]
    results: List[ProbeResult] = field(default_factory=list)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "version": __version__,
            "target_url": sanitize_url_for_export(self.target_url) if self.target_url else "",
            "dialect": self.dialect,
            "model": self.model,
            "profile": self.profile,
            "grade": self.grade,
            "exit_code": self.exit_code,
            "p0_count": self.p0_count,
            "warning_count": self.warning_count,
            "error_count": self.error_count,
            "total_tokens": self.total_tokens if self.total_tokens is not None else "unknown",
            "save_dir": self.save_dir,
            "results": [r.to_dict() for r in self.results],
        }


def resolve_api_key(raw_key: Optional[str]) -> Optional[str]:
    """Resolve explicit --api-key (rejecting empty values) or return None for caller fallback."""
    if raw_key is None:
        return None
    cand = raw_key.strip()
    if not cand:
        raise ValueError("Explicit --api-key cannot be empty.")
    if cand.startswith("$"):
        env_name = cand[1:]
        if not env_name:
            raise ValueError("Invalid --api-key environment variable reference '$'.")
        val = (os.environ.get(env_name) or "").strip()
        if not val:
            raise ValueError(f"Environment variable {env_name!r} specified in --api-key is empty or not set.")
        return val
    if cand in os.environ and cand.isupper() and "_" in cand:
        val = (os.environ.get(cand) or "").strip()
        if not val:
            raise ValueError(f"Environment variable {cand!r} specified in --api-key is empty.")
        return val
    return cand


def _format_origin(parsed: urllib.parse.SplitResult) -> str:
    host = parsed.hostname or ""
    if ":" in host and not host.startswith("["):
        host = f"[{host}]"
    return f"{parsed.scheme}://{host}" + (f":{parsed.port}" if parsed.port is not None else "")


def _build_url(parsed: urllib.parse.SplitResult, new_path: str) -> str:
    """Rebuild URL safely from parsed components (preserving IPv6 brackets and query cleanly)."""
    origin = _format_origin(parsed)
    norm_path = "/" + new_path.lstrip("/")
    if parsed.query:
        return f"{origin}{norm_path}?{parsed.query}"
    return f"{origin}{norm_path}"


def _http_get_json(url: str, headers: Mapping[str, str], timeout: float) -> Tuple[int, Optional[Dict[str, Any]]]:
    parsed = validate_url(url)
    path = parsed.path or "/"
    if parsed.query:
        path = f"{path}?{parsed.query}"
    conn: http.client.HTTPConnection
    if parsed.scheme == "https":
        conn = http.client.HTTPSConnection(
            parsed.hostname,
            parsed.port or 443,
            timeout=timeout,
            context=ssl.create_default_context(),
        )
    else:
        conn = http.client.HTTPConnection(parsed.hostname, parsed.port or 80, timeout=timeout)
    try:
        conn.request("GET", path, headers=dict(headers))
        resp = conn.getresponse()
        status = resp.status
        raw = resp.read(262144)
        if status != 200:
            return status, None
        obj = strict_json_loads(raw.decode("utf-8", errors="replace"))
        return status, obj if isinstance(obj, dict) else None
    except (OSError, http.client.HTTPException, ValueError, json.JSONDecodeError):
        return 0, None
    finally:
        conn.close()


def _pick_preferred_model(ids: List[str]) -> Optional[str]:
    if not ids:
        return None
    skip_words = ("embed", "embedding", "whisper", "tts-", "dall-e", "moderation", "rerank")
    for mid in ids:
        low = mid.lower()
        if not any(w in low for w in skip_words):
            return mid
    return ids[0]


def resolve_endpoints_and_model(
    base_url: str,
    *,
    model: Optional[str],
    headers: Mapping[str, str],
    timeout: float,
    known_secrets: Sequence[str] = (),
) -> Tuple[str, Optional[str], str, str]:
    """Return (chat_url, responses_url, dialect, resolved_model) using safe parsed URL components."""
    parsed = validate_url(base_url)
    base_path = (parsed.path or "").rstrip("/")
    path_low = base_path.lower()

    is_ollama_hint = (
        path_low.endswith("/api/chat")
        or path_low.endswith("/api")
        or (parsed.port == 11434 and not path_low.endswith("/v1") and not path_low.endswith("/chat/completions"))
    )

    if path_low.endswith("/chat/completions"):
        prefix = base_path[: -len("/chat/completions")]
        chat_url = _build_url(parsed, base_path)
        responses_url: Optional[str] = _build_url(parsed, f"{prefix}/responses")
        models_url = _build_url(parsed, f"{prefix}/models")
        tags_url = _build_url(parsed, f"{prefix[:-3] if prefix.lower().endswith('/v1') else prefix}/api/tags")
        dialect = "openai-chat"
    elif path_low.endswith("/api/chat"):
        prefix = base_path[: -len("/api/chat")]
        chat_url = _build_url(parsed, base_path)
        responses_url = None
        models_url = _build_url(parsed, f"{prefix}/v1/models")
        tags_url = _build_url(parsed, f"{prefix}/api/tags")
        dialect = "ollama-ndjson"
    elif is_ollama_hint:
        prefix = base_path[: -len("/api")] if path_low.endswith("/api") else base_path
        chat_url = _build_url(parsed, f"{prefix}/api/chat")
        responses_url = None
        models_url = _build_url(parsed, f"{prefix}/v1/models")
        tags_url = _build_url(parsed, f"{prefix}/api/tags")
        dialect = "ollama-ndjson"
    elif path_low.endswith("/v1"):
        prefix = base_path[: -len("/v1")]
        chat_url = _build_url(parsed, f"{base_path}/chat/completions")
        responses_url = _build_url(parsed, f"{base_path}/responses")
        models_url = _build_url(parsed, f"{base_path}/models")
        tags_url = _build_url(parsed, f"{prefix}/api/tags")
        dialect = "openai-chat"
    else:
        chat_url = _build_url(parsed, f"{base_path}/v1/chat/completions")
        responses_url = _build_url(parsed, f"{base_path}/v1/responses")
        models_url = _build_url(parsed, f"{base_path}/v1/models")
        tags_url = _build_url(parsed, f"{base_path}/api/tags")
        dialect = "openai-chat"

    if model and model.strip():
        return chat_url, responses_url, dialect, _clean_display(model.strip(), known_secrets, 128)

    st_models = 0
    st_tags = 0

    if dialect != "ollama-ndjson":
        st_models, obj = _http_get_json(models_url, headers, min(timeout, 15.0))
        if st_models == 200 and isinstance(obj, dict) and isinstance(obj.get("data"), list):
            ids = [str(item["id"]) for item in obj["data"] if isinstance(item, dict) and isinstance(item.get("id"), str) and item["id"]]
            picked = _pick_preferred_model(ids)
            if picked:
                return chat_url, responses_url, dialect, _clean_display(picked, known_secrets, 128)

    st_tags, obj_ol = _http_get_json(tags_url, headers, min(timeout, 15.0))
    if st_tags == 200 and isinstance(obj_ol, dict) and isinstance(obj_ol.get("models"), list):
        ids = [str(item["name"]) for item in obj_ol["models"] if isinstance(item, dict) and isinstance(item.get("name"), str) and item["name"]]
        picked = _pick_preferred_model(ids)
        if picked:
            ol_prefix = base_path[: -len("/api")] if path_low.endswith("/api") else (base_path[: -len("/v1")] if path_low.endswith("/v1") else base_path)
            return _build_url(parsed, f"{ol_prefix}/api/chat"), None, "ollama-ndjson", _clean_display(picked, known_secrets, 128)

    auth_hint = " and --api-key <KEY>" if (st_models in (401, 403) or st_tags in (401, 403)) else ""
    raise RecorderError(
        f"Could not auto-discover model from {sanitize_url_for_error(models_url)} (HTTP {st_models}) "
        f"or {sanitize_url_for_error(tags_url)} (HTTP {st_tags}); specify --model <MODEL_ID>{auth_hint}."
    )


def _doc_tokens(doc: TraceDocument) -> Optional[int]:
    u = doc.summary.assembled.get("reported_usage") or {}
    pt = u.get("prompt_tokens")
    ct = u.get("completion_tokens")
    if is_strict_int(pt) and is_strict_int(ct):
        return pt + ct
    if is_strict_int(ct):
        return ct
    return None


def _has_inband_error(doc: TraceDocument) -> bool:
    return any((f.norm or {}).get("phase") == "ERROR" or (f.norm or {}).get("inband_error") for f in doc.frames)


def _build_chat_body(
    dialect: str,
    model: str,
    messages: List[Dict[str, Any]],
    *,
    max_tokens: int,
    temperature: float = 0.0,
    seed: Optional[int] = None,
    tools: Optional[List[Dict[str, Any]]] = None,
    tool_choice: Any = None,
    parallel_tool_calls: Optional[bool] = None,
    include_usage: bool = False,
    ignore_eos: Optional[bool] = None,
    stop: Optional[List[str]] = None,
) -> Dict[str, Any]:
    if dialect == "ollama-ndjson":
        opts: Dict[str, Any] = {"temperature": temperature, "num_predict": max_tokens}
        if seed is not None:
            opts["seed"] = seed
        if ignore_eos is not None:
            opts["ignore_eos"] = ignore_eos
        if stop is not None:
            opts["stop"] = stop
        body: Dict[str, Any] = {"model": model, "stream": True, "messages": messages, "options": opts}
        if tools is not None:
            body["tools"] = tools
        return body

    body = {
        "model": model,
        "stream": True,
        "messages": messages,
        "max_tokens": max_tokens,
        "temperature": temperature,
    }
    if seed is not None:
        body["seed"] = seed
    if tools is not None:
        body["tools"] = tools
    if tool_choice is not None:
        body["tool_choice"] = tool_choice
    if parallel_tool_calls is not None:
        body["parallel_tool_calls"] = parallel_tool_calls
    if include_usage:
        body["stream_options"] = {"include_usage": True}
    if ignore_eos is not None:
        body["ignore_eos"] = ignore_eos
    if stop is not None:
        body["stop"] = stop
    return body


def _c4_large_tool_schema() -> List[Dict[str, Any]]:
    """Standard multi-field function schema (~450-550 tokens) to detect tool-token omission in C4."""
    props: Dict[str, Any] = {}
    for idx in range(1, 13):
        props[f"cluster_storage_policy_field_{idx:02d}"] = {
            "type": "string",
            "description": (
                f"Deterministic configuration selector #{idx:02d} controlling tiered KV-cache placement, "
                "alignment granularity, eviction watermark threshold, and synchronous flush verification."
            ),
        }
    return [
        {
            "type": "function",
            "function": {
                "name": "configure_tiered_kv_storage_cluster",
                "description": (
                    "Validate and configure distributed KV-cache offloading policy across DRAM L1, "
                    "local NVMe O_DIRECT L2, and shared storage tiers with strict quota telemetry."
                ),
                "parameters": {
                    "type": "object",
                    "properties": props,
                    "required": ["cluster_storage_policy_field_01"],
                },
            },
        }
    ]


def _iter_frame_json_objects(doc: TraceDocument) -> List[Dict[str, Any]]:
    objs: List[Dict[str, Any]] = []
    for f in doc.frames:
        for line in f.raw_wire.splitlines():
            s = line.strip()
            if s.startswith("data:"):
                s = s[5:].strip()
            if not s or s == "[DONE]" or not s.startswith("{"):
                continue
            try:
                obj = strict_json_loads(s)
            except Exception:
                continue
            if isinstance(obj, dict):
                objs.append(obj)
    return objs


def _extract_wire_metadata(doc: TraceDocument) -> Tuple[Optional[str], Optional[str], Optional[int], bool]:
    """Return (model, system_fingerprint, total_tokens, has_empty_choices_usage_tail)."""
    rep_model: Optional[str] = None
    rep_fp: Optional[str] = None
    rep_total: Optional[int] = None
    has_empty_choices_usage = False
    for obj in _iter_frame_json_objects(doc):
        if isinstance(obj.get("model"), str) and obj["model"]:
            rep_model = obj["model"]
        if isinstance(obj.get("system_fingerprint"), str) and obj["system_fingerprint"]:
            rep_fp = obj["system_fingerprint"]
        u = obj.get("usage")
        if isinstance(u, dict):
            if is_strict_int(u.get("total_tokens")):
                rep_total = u["total_tokens"]
            choices = obj.get("choices")
            if isinstance(choices, list) and len(choices) == 0:
                if is_strict_int(u.get("prompt_tokens")) and is_strict_int(u.get("completion_tokens")):
                    has_empty_choices_usage = True
    return rep_model, rep_fp, rep_total, has_empty_choices_usage


def _inspect_raw_c5_wire(doc: TraceDocument) -> Tuple[bool, List[Any], bool]:
    """Inspect raw wire frames BEFORE dialect fallback normalization.

    Returns (has_initial_role, raw_explicit_indices_seen, any_omitted_index).
    """
    has_role = doc.header.dialect == "ollama-ndjson"
    saw_first_choice = False
    raw_indices: List[Any] = []
    any_omitted = False

    for obj in _iter_frame_json_objects(doc):
        choices = obj.get("choices")
        if not isinstance(choices, list) or not choices or not isinstance(choices[0], dict):
            continue
        delta = choices[0].get("delta")
        if not isinstance(delta, dict):
            continue
        if not saw_first_choice:
            if delta.get("role") == "assistant":
                has_role = True
                saw_first_choice = True
            elif delta.get("content") or delta.get("tool_calls") or delta.get("reasoning_content"):
                saw_first_choice = True
        tcalls = delta.get("tool_calls")
        if isinstance(tcalls, list):
            for tc in tcalls:
                if not isinstance(tc, dict):
                    continue
                if "index" not in tc or tc["index"] is None:
                    any_omitted = True
                else:
                    raw_indices.append(tc["index"])
    return has_role, raw_indices, any_omitted


def _save_path(save_dir: Optional[Path], name: str) -> Optional[Path]:
    return (save_dir / name) if save_dir is not None else None


def _run_c1(
    chat_url: str,
    responses_url: Optional[str],
    dialect: str,
    model: str,
    headers: Dict[str, str],
    timeout: float,
    save_dir: Optional[Path],
    profile: str,
    secrets_list: Sequence[str],
) -> ProbeResult:
    code, sev, ref = PROBE_CATALOG["C1"]
    tools = [
        {
            "type": "function",
            "function": {
                "name": "write_config",
                "description": "Write detailed service configuration JSON.",
                "parameters": {
                    "type": "object",
                    "properties": {
                        "service_name": {"type": "string"},
                        "description": {"type": "string"},
                        "endpoints": {"type": "array", "items": {"type": "string"}},
                    },
                    "required": ["service_name", "description", "endpoints"],
                },
            },
        }
    ]
    msgs = [
        {
            "role": "user",
            "content": "Call write_config with a 150-character description and 4 endpoint URLs.",
        }
    ]
    body = _build_chat_body(
        dialect,
        model,
        msgs,
        max_tokens=28,
        temperature=0.0,
        seed=42,
        tools=tools,
        tool_choice={"type": "function", "function": {"name": "write_config"}} if dialect != "ollama-ndjson" else None,
    )
    out_p = _save_path(save_dir, "c1_tool_call_budget_clip.trace.jsonl")
    t0 = time.monotonic()
    try:
        doc = record_stream(url=chat_url, request_body=body, out_path=out_p, headers=headers, dialect=dialect, label="doctor-C1", timeout=timeout)
    except RecorderError as exc:
        if "HTTP 400" in str(exc) or "HTTP 422" in str(exc):
            body["tool_choice"] = "auto"
            if dialect == "ollama-ndjson":
                body.pop("tool_choice", None)
            try:
                doc = record_stream(url=chat_url, request_body=body, out_path=out_p, headers=headers, dialect=dialect, label="doctor-C1", timeout=timeout)
            except RecorderError as exc2:
                return ProbeResult("C1", code, sev, "SKIP", _clean_display(f"tool calling rejected by endpoint ({exc2})", secrets_list), (time.monotonic() - t0) * 1000, 0, None, ref)
        else:
            return ProbeResult("C1", code, sev, "ERROR", _clean_display(f"transport/HTTP error: {exc}", secrets_list), (time.monotonic() - t0) * 1000, 0, None, ref)

    dur = doc.summary.timing.get("total_ms") or ((time.monotonic() - t0) * 1000)
    findings = audit_trace(doc)
    d_ids = {f.detector_id for f in findings}
    asm = doc.summary.assembled
    tpaths = [str(out_p)] if out_p else []
    docs = [doc]
    total_frames = doc.summary.total_frames
    tot_tok = _doc_tokens(doc)

    if _has_inband_error(doc):
        return ProbeResult("C1", code, "P0", "FAIL", "HTTP 200 returned an in-band error event", dur, total_frames, tot_tok, ref, tpaths, findings, docs)

    if D1 in d_ids or D4 in d_ids:
        return ProbeResult("C1", code, "P0", "FAIL", _clean_display(findings[0].message, secrets_list), dur, total_frames, tot_tok, ref, tpaths, findings, docs)

    # Optional /v1/responses cross-check in `full` profile (non-fatal if 404/405/501)
    if profile == "full" and responses_url and dialect == "openai-chat":
        resp_body = {
            "model": model,
            "stream": True,
            "temperature": 0.0,
            "seed": 42,
            "max_output_tokens": 28,
            "tools": [
                {
                    "type": "function",
                    "name": "write_config",
                    "description": "Write detailed service configuration JSON.",
                    "parameters": tools[0]["function"]["parameters"],
                }
            ],
            "input": msgs[0]["content"],
        }
        out_r = _save_path(save_dir, "c1_responses_tool_clip.trace.jsonl")
        try:
            doc_r = record_stream(url=responses_url, request_body=resp_body, out_path=out_r, headers=headers, dialect="openai-responses", label="doctor-C1-responses", timeout=timeout)
            docs.append(doc_r)
            if out_r:
                tpaths.append(str(out_r))
            dur += doc_r.summary.timing.get("total_ms") or 0.0
            total_frames += doc_r.summary.total_frames
            rt = _doc_tokens(doc_r)
            if rt is not None:
                tot_tok = (tot_tok or 0) + rt
            r_findings = audit_trace(doc_r)
            findings.extend(r_findings)
            r_ids = {f.detector_id for f in r_findings}
            if _has_inband_error(doc_r) or D1 in r_ids or D4 in r_ids:
                msg = r_findings[0].message if r_findings else "HTTP 200 /v1/responses returned in-band error"
                return ProbeResult("C1", code, "P0", "FAIL", _clean_display(f"/v1/responses breach: {msg}", secrets_list), dur, total_frames, tot_tok, ref, tpaths, findings, docs)
        except RecorderError:
            pass  # 404/405/501 or unsupported /v1/responses is expected on Chat-only servers

    tcalls = asm.get("tool_calls") or []
    if not tcalls:
        return ProbeResult(
            "C1",
            code,
            sev,
            "SKIP",
            "inconclusive: model returned plain text with 0 tool calls",
            dur,
            total_frames,
            tot_tok,
            ref,
            tpaths,
            findings,
            docs,
        )

    fr = asm.get("finish_reason", "unknown")
    st = asm.get("terminal_status", "unknown")
    if fr == "length" or st == "incomplete":
        return ProbeResult("C1", code, sev, "PASS", f'finish_reason="{fr}" honored on 28-tok tool cutoff (status={st})', dur, total_frames, tot_tok, ref, tpaths, findings, docs)
    if all(tc.get("json_valid") is True for tc in tcalls):
        return ProbeResult("C1", code, sev, "PASS", f'valid complete tool JSON within 28-tok cap (finish_reason="{fr}")', dur, total_frames, tot_tok, ref, tpaths, findings, docs)
    return ProbeResult("C1", code, "P0", "FAIL", f'incomplete tool JSON with unexpected terminal "{fr}/{st}"', dur, total_frames, tot_tok, ref, tpaths, findings, docs)


def _run_c2(
    chat_url: str,
    responses_url: Optional[str],
    dialect: str,
    model: str,
    headers: Dict[str, str],
    timeout: float,
    save_dir: Optional[Path],
    profile: str,
    secrets_list: Sequence[str],
) -> ProbeResult:
    code, sev, ref = PROBE_CATALOG["C2"]
    body = _build_chat_body(
        dialect,
        model,
        [{"role": "user", "content": "Reply with digits 42 only."}],
        max_tokens=32,
        temperature=0.0,
        seed=42,
        include_usage=(dialect != "ollama-ndjson"),
    )
    out_p = _save_path(save_dir, "c2_reasoning_starvation.trace.jsonl")
    t0 = time.monotonic()
    try:
        doc = record_stream(url=chat_url, request_body=body, out_path=out_p, headers=headers, dialect=dialect, label="doctor-C2", timeout=timeout)
    except RecorderError as exc:
        if ("HTTP 400" in str(exc) or "HTTP 422" in str(exc)) and "stream_options" in body:
            body.pop("stream_options", None)
            try:
                doc = record_stream(url=chat_url, request_body=body, out_path=out_p, headers=headers, dialect=dialect, label="doctor-C2", timeout=timeout)
            except RecorderError as exc2:
                return ProbeResult("C2", code, sev, "ERROR", _clean_display(f"transport/HTTP error: {exc2}", secrets_list), (time.monotonic() - t0) * 1000, 0, None, ref)
        else:
            return ProbeResult("C2", code, sev, "ERROR", _clean_display(f"transport/HTTP error: {exc}", secrets_list), (time.monotonic() - t0) * 1000, 0, None, ref)

    dur = doc.summary.timing.get("total_ms") or ((time.monotonic() - t0) * 1000)
    findings = audit_trace(doc)
    d_ids = {f.detector_id for f in findings}
    asm = doc.summary.assembled
    tpaths = [str(out_p)] if out_p else []

    if _has_inband_error(doc):
        return ProbeResult("C2", code, "P0", "FAIL", "HTTP 200 returned an in-band error event", dur, doc.summary.total_frames, _doc_tokens(doc), ref, tpaths, findings, [doc])

    if D4 in d_ids:
        return ProbeResult("C2", code, "P0", "FAIL", _clean_display(findings[0].message, secrets_list), dur, doc.summary.total_frames, _doc_tokens(doc), ref, tpaths, findings, [doc])

    content = (asm.get("content_text") or "").strip()
    reas = asm.get("reasoning_text") or ""
    comp = (asm.get("reported_usage") or {}).get("completion_tokens")
    fr = asm.get("finish_reason", "unknown")

    if D2 in d_ids:
        # Honest finish_reason="length" is PASS only when credible reasoning/token cap exhaustion occurred
        credible_length = fr == "length" and (bool(reas) or bool(asm.get("has_unclosed_think")) or (is_strict_int(comp) and comp >= 16))
        if credible_length:
            return ProbeResult("C2", code, sev, "PASS", 'reasoning hit 32-tok cap honestly (finish_reason="length")', dur, doc.summary.total_frames, _doc_tokens(doc), ref, tpaths, findings, [doc])
        return ProbeResult("C2", code, "P0", "FAIL", _clean_display(findings[0].message, secrets_list), dur, doc.summary.total_frames, _doc_tokens(doc), ref, tpaths, findings, [doc])

    if not content:
        return ProbeResult("C2", code, "P1", "WARN", f'empty content without credible length cutoff (finish_reason="{fr}")', dur, doc.summary.total_frames, _doc_tokens(doc), ref, tpaths, findings, [doc])

    return ProbeResult(
        "C2",
        code,
        sev,
        "PASS",
        f'non-empty content ({len(content)} chars), no ghost budget leak',
        dur,
        doc.summary.total_frames,
        _doc_tokens(doc),
        ref,
        tpaths,
        findings,
        [doc],
    )


def _run_c3(
    chat_url: str,
    responses_url: Optional[str],
    dialect: str,
    model: str,
    headers: Dict[str, str],
    timeout: float,
    save_dir: Optional[Path],
    profile: str,
    secrets_list: Sequence[str],
) -> ProbeResult:
    code, sev, ref = PROBE_CATALOG["C3"]
    body = _build_chat_body(
        dialect,
        model,
        [{"role": "user", "content": "Count upwards from 1 separated by spaces."}],
        max_tokens=96,
        temperature=0.0,
        seed=42,
        ignore_eos=True,
        stop=[],
        include_usage=(dialect != "ollama-ndjson"),
    )
    out_p = _save_path(save_dir, "c3_fixed_budget_honor.trace.jsonl")
    t0 = time.monotonic()
    try:
        doc = record_stream(url=chat_url, request_body=body, out_path=out_p, headers=headers, dialect=dialect, label="doctor-C3", timeout=timeout)
    except RecorderError as exc:
        if "HTTP 400" in str(exc) or "HTTP 422" in str(exc):
            return ProbeResult("C3", code, sev, "SKIP", "endpoint rejected ignore_eos (HTTP 400/422)", (time.monotonic() - t0) * 1000, 0, None, ref)
        return ProbeResult("C3", code, sev, "ERROR", _clean_display(f"transport/HTTP error: {exc}", secrets_list), (time.monotonic() - t0) * 1000, 0, None, ref)

    dur = doc.summary.timing.get("total_ms") or ((time.monotonic() - t0) * 1000)
    findings = audit_trace(doc)
    d_ids = {f.detector_id for f in findings}
    tpaths = [str(out_p)] if out_p else []

    if _has_inband_error(doc) or D4 in d_ids:
        msg = findings[0].message if findings else "HTTP 200 returned an in-band error event"
        return ProbeResult("C3", code, "P0", "FAIL", _clean_display(msg, secrets_list), dur, doc.summary.total_frames, _doc_tokens(doc), ref, tpaths, findings, [doc])

    comp = (doc.summary.assembled.get("reported_usage") or {}).get("completion_tokens")
    if not is_strict_int(comp):
        return ProbeResult("C3", code, "P1", "WARN", "server omitted completion_tokens on fixed-budget stream (evidence missing)", dur, doc.summary.total_frames, _doc_tokens(doc), ref, tpaths, findings, [doc])
    if D3 in d_ids or comp < 96:
        return ProbeResult("C3", code, "P1", "WARN", f"ignore_eos=true clipped to {comp}/96 tokens (D3)", dur, doc.summary.total_frames, _doc_tokens(doc), ref, tpaths, findings, [doc])
    if comp > 96:
        return ProbeResult("C3", code, "P1", "WARN", f"fixed budget exceeded ({comp}/96 completion_tokens)", dur, doc.summary.total_frames, _doc_tokens(doc), ref, tpaths, findings, [doc])
    return ProbeResult("C3", code, sev, "PASS", "fixed budget honored (96/96 completion_tokens)", dur, doc.summary.total_frames, _doc_tokens(doc), ref, tpaths, findings, [doc])


def _run_c4(
    chat_url: str,
    responses_url: Optional[str],
    dialect: str,
    model: str,
    headers: Dict[str, str],
    timeout: float,
    save_dir: Optional[Path],
    profile: str,
    secrets_list: Sequence[str],
) -> ProbeResult:
    code, sev, ref = PROBE_CATALOG["C4"]
    msgs = [{"role": "user", "content": "Reply OK."}]
    body_a = _build_chat_body(dialect, model, msgs, max_tokens=16, temperature=0.0, include_usage=(dialect != "ollama-ndjson"))
    body_b = _build_chat_body(dialect, model, msgs, max_tokens=16, temperature=0.0, tools=_c4_large_tool_schema(), include_usage=(dialect != "ollama-ndjson"))

    out_a = _save_path(save_dir, "c4a_usage_no_tools.trace.jsonl")
    out_b = _save_path(save_dir, "c4b_usage_with_tools.trace.jsonl")
    t0 = time.monotonic()
    try:
        doc_a = record_stream(url=chat_url, request_body=body_a, out_path=out_a, headers=headers, dialect=dialect, label="doctor-C4a", timeout=timeout)
        doc_b = record_stream(url=chat_url, request_body=body_b, out_path=out_b, headers=headers, dialect=dialect, label="doctor-C4b", timeout=timeout)
    except RecorderError as exc:
        if "HTTP 400" in str(exc) or "HTTP 422" in str(exc):
            return ProbeResult("C4", code, "P1", "WARN", _clean_display(f"stream_options.include_usage or tools rejected ({exc})", secrets_list), (time.monotonic() - t0) * 1000, 0, None, ref)
        return ProbeResult("C4", code, sev, "ERROR", _clean_display(f"transport/HTTP error: {exc}", secrets_list), (time.monotonic() - t0) * 1000, 0, None, ref)

    dur = (doc_a.summary.timing.get("total_ms") or 0) + (doc_b.summary.timing.get("total_ms") or 0)
    frames = doc_a.summary.total_frames + doc_b.summary.total_frames
    tpaths = [str(p) for p in (out_a, out_b) if p]
    findings = audit_trace(doc_a) + audit_trace(doc_b)
    tok_a, tok_b = _doc_tokens(doc_a), _doc_tokens(doc_b)
    tot_tok = (tok_a or 0) + (tok_b or 0) if (tok_a is not None or tok_b is not None) else None

    if _has_inband_error(doc_a) or _has_inband_error(doc_b) or any(f.detector_id == D4 for f in findings):
        msg = findings[0].message if findings else "HTTP 200 returned an in-band error event"
        return ProbeResult("C4", code, "P0", "FAIL", _clean_display(msg, secrets_list), dur, frames, tot_tok, ref, tpaths, findings, [doc_a, doc_b])

    ua = doc_a.summary.assembled.get("reported_usage") or {}
    ub = doc_b.summary.assembled.get("reported_usage") or {}
    pa, ca = ua.get("prompt_tokens"), ua.get("completion_tokens")
    pb, cb = ub.get("prompt_tokens"), ub.get("completion_tokens")
    _, _, raw_tot_a, empty_tail_a = _extract_wire_metadata(doc_a)
    _, _, raw_tot_b, empty_tail_b = _extract_wire_metadata(doc_b)

    issues: List[str] = []
    if not (is_strict_int(pa) and is_strict_int(ca)):
        issues.append("trailing usage missing (no tools)")
    else:
        if dialect == "openai-chat" and not empty_tail_a:
            issues.append("usage not on trailing empty-choices chunk (no tools)")
        if raw_tot_a is not None and raw_tot_a != pa + ca:
            issues.append(f"total_tokens mismatch on Run A ({raw_tot_a} != {pa}+{ca})")

    if not (is_strict_int(pb) and is_strict_int(cb)):
        issues.append("trailing usage missing when tools present")
    else:
        if dialect == "openai-chat" and not empty_tail_b:
            issues.append("usage not on trailing empty-choices chunk (with tools)")
        if raw_tot_b is not None and raw_tot_b != pb + cb:
            issues.append(f"total_tokens mismatch on Run B ({raw_tot_b} != {pb}+{cb})")

    if is_strict_int(pa) and is_strict_int(pb):
        delta_p = pb - pa
        if delta_p < 250:
            issues.append(f"tool schema tokens under-counted (prompt_tokens +{delta_p}, expected >=250)")

    if issues:
        return ProbeResult("C4", code, "P1", "WARN", "; ".join(issues), dur, frames, tot_tok, ref, tpaths, findings, [doc_a, doc_b])
    return ProbeResult(
        "C4",
        code,
        sev,
        "PASS",
        f"include_usage trailing empty-choices intact (prompt_tokens {pa} -> {pb}, +{pb - pa})",
        dur,
        frames,
        tot_tok,
        ref,
        tpaths,
        findings,
        [doc_a, doc_b],
    )


def _run_c5(
    chat_url: str,
    responses_url: Optional[str],
    dialect: str,
    model: str,
    headers: Dict[str, str],
    timeout: float,
    save_dir: Optional[Path],
    profile: str,
    secrets_list: Sequence[str],
) -> ProbeResult:
    code, sev, ref = PROBE_CATALOG["C5"]
    tools = [
        {
            "type": "function",
            "function": {
                "name": "get_node_status",
                "description": "Fetch live health metrics for a single cluster node.",
                "parameters": {
                    "type": "object",
                    "properties": {"node": {"type": "string"}},
                    "required": ["node"],
                },
            },
        }
    ]
    body = _build_chat_body(
        dialect,
        model,
        [{"role": "user", "content": "Call get_node_status in parallel for both 'node-a' and 'node-b' in a single turn."}],
        max_tokens=128,
        temperature=0.0,
        seed=42,
        tools=tools,
        parallel_tool_calls=True if dialect != "ollama-ndjson" else None,
        include_usage=(dialect != "ollama-ndjson"),
    )
    out_p = _save_path(save_dir, "c5_role_and_parallel_tools.trace.jsonl")
    t0 = time.monotonic()
    try:
        doc = record_stream(url=chat_url, request_body=body, out_path=out_p, headers=headers, dialect=dialect, label="doctor-C5", timeout=timeout)
    except RecorderError as exc:
        if "HTTP 400" in str(exc) or "HTTP 422" in str(exc):
            return ProbeResult("C5", code, sev, "SKIP", _clean_display(f"parallel tool calling unsupported ({exc})", secrets_list), (time.monotonic() - t0) * 1000, 0, None, ref)
        return ProbeResult("C5", code, sev, "ERROR", _clean_display(f"transport/HTTP error: {exc}", secrets_list), (time.monotonic() - t0) * 1000, 0, None, ref)

    dur = doc.summary.timing.get("total_ms") or ((time.monotonic() - t0) * 1000)
    findings = audit_trace(doc)
    d_ids = {f.detector_id for f in findings}
    tpaths = [str(out_p)] if out_p else []

    if _has_inband_error(doc):
        return ProbeResult("C5", code, "P0", "FAIL", "HTTP 200 returned an in-band error event", dur, doc.summary.total_frames, _doc_tokens(doc), ref, tpaths, findings, [doc])

    role_ok, raw_indices, any_omitted_idx = _inspect_raw_c5_wire(doc)
    tcalls = doc.summary.assembled.get("tool_calls") or []
    merged_bad_json = any(
        (tc.get("json_valid") is False) and ("}{" in (tc.get("raw_arguments") or "").replace(" ", ""))
        for tc in tcalls
    )

    if D1 in d_ids or D4 in d_ids or merged_bad_json:
        parts = []
        if not role_ok:
            parts.append("delta.role stripped")
        if merged_bad_json:
            parts.append("parallel tools merged onto colliding idx=0")
        elif findings:
            parts.append(_clean_display(findings[0].message, secrets_list))
        return ProbeResult("C5", code, "P0", "FAIL", " + ".join(parts), dur, doc.summary.total_frames, _doc_tokens(doc), ref, tpaths, findings, [doc])

    # Validate raw indices strictly BEFORE dialect fallback normalization
    invalid_raw_idx = any((not is_strict_int(ix)) or ix < 0 for ix in raw_indices)
    distinct_raw = sorted({ix for ix in raw_indices if is_strict_int(ix)})
    expected_seq = list(range(len(distinct_raw)))

    warns: List[str] = []
    if not role_ok:
        warns.append("initial delta.role='assistant' stripped")
    if dialect == "openai-chat" and tcalls:
        if any_omitted_idx:
            warns.append("tool_calls delta omitted raw index field")
        if invalid_raw_idx or (distinct_raw and distinct_raw != expected_seq):
            warns.append(f"non-contiguous/invalid raw tool indices {raw_indices}")

    if warns:
        return ProbeResult("C5", code, "P1", "WARN", "; ".join(warns), dur, doc.summary.total_frames, _doc_tokens(doc), ref, tpaths, findings, [doc])

    if len(tcalls) < 2:
        return ProbeResult(
            "C5",
            code,
            sev,
            "SKIP",
            f"inconclusive: model emitted only {len(tcalls)} tool call(s) (expected 2 parallel calls)",
            dur,
            doc.summary.total_frames,
            _doc_tokens(doc),
            ref,
            tpaths,
            findings,
            [doc],
        )

    return ProbeResult(
        "C5",
        code,
        sev,
        "PASS",
        f"initial role present, {len(tcalls)} parallel calls with contiguous raw indices {distinct_raw}",
        dur,
        doc.summary.total_frames,
        _doc_tokens(doc),
        ref,
        tpaths,
        findings,
        [doc],
    )


def _run_c6(
    chat_url: str,
    responses_url: Optional[str],
    dialect: str,
    model: str,
    headers: Dict[str, str],
    timeout: float,
    save_dir: Optional[Path],
    profile: str,
    secrets_list: Sequence[str],
) -> ProbeResult:
    code, sev, ref = PROBE_CATALOG["C6"]
    body = _build_chat_body(
        dialect,
        model,
        [{"role": "user", "content": f"原样逐字复述，不要解释：{C6_TARGET_TEXT}"}],
        max_tokens=48,
        temperature=0.0,
        seed=42,
    )
    out_p = _save_path(save_dir, "c6_utf8_multibyte_integrity.trace.jsonl")
    t0 = time.monotonic()
    try:
        doc = record_stream(url=chat_url, request_body=body, out_path=out_p, headers=headers, dialect=dialect, label="doctor-C6", timeout=timeout)
    except RecorderError as exc:
        return ProbeResult("C6", code, sev, "ERROR", _clean_display(f"transport/HTTP error: {exc}", secrets_list), (time.monotonic() - t0) * 1000, 0, None, ref)

    dur = doc.summary.timing.get("total_ms") or ((time.monotonic() - t0) * 1000)
    findings = audit_trace(doc)
    d_ids = {f.detector_id for f in findings}
    tpaths = [str(out_p)] if out_p else []

    if _has_inband_error(doc):
        return ProbeResult("C6", code, "P0", "FAIL", "HTTP 200 returned an in-band error event", dur, doc.summary.total_frames, _doc_tokens(doc), ref, tpaths, findings, [doc])

    content = doc.summary.assembled.get("content_text") or ""
    has_fffd_frame = any("\ufffd" in ((f.norm or {}).get("text_delta") or "") for f in doc.frames)
    has_bad_utf8 = any(f.parse_error == "invalid_utf8" for f in doc.frames)
    has_fffd_text = "\ufffd" in content
    swallowed_tail = (
        ("🔥" in content or "🚀" in content)
        and (C6_TRAILING_EMOJI not in content)
        and (doc.summary.assembled.get("finish_reason") == "stop")
    )

    if D4 in d_ids or has_fffd_frame or has_fffd_text or has_bad_utf8 or swallowed_tail:
        reasons = []
        if has_fffd_frame or has_fffd_text:
            reasons.append("U+FFFD replacement char detected in UTF-8 stream")
        if has_bad_utf8:
            reasons.append("invalid UTF-8 wire bytes")
        if swallowed_tail:
            reasons.append("trailing 4-byte emoji swallowed before finish_reason=stop")
        if D4 in d_ids and not reasons:
            reasons.append(_clean_display(findings[0].message, secrets_list))
        return ProbeResult("C6", code, "P0", "FAIL", "; ".join(reasons), dur, doc.summary.total_frames, _doc_tokens(doc), ref, tpaths, findings, [doc])

    # Require actual multilingual + 4-byte emoji echo to claim PASS (ASCII-only output is inconclusive)
    has_multibyte = ("吞吐量" in content or "Δ" in content) and (C6_TRAILING_EMOJI in content)
    if not has_multibyte:
        return ProbeResult(
            "C6",
            code,
            sev,
            "SKIP",
            "inconclusive: output did not echo CJK + trailing 4-byte emoji target",
            dur,
            doc.summary.total_frames,
            _doc_tokens(doc),
            ref,
            tpaths,
            findings,
            [doc],
        )

    return ProbeResult(
        "C6",
        code,
        sev,
        "PASS",
        f"0 U+FFFD across {doc.summary.total_frames} frames, CJK & trailing 4-byte emoji intact",
        dur,
        doc.summary.total_frames,
        _doc_tokens(doc),
        ref,
        tpaths,
        findings,
        [doc],
    )


def _run_c7(
    chat_url: str,
    responses_url: Optional[str],
    dialect: str,
    model: str,
    headers: Dict[str, str],
    timeout: float,
    save_dir: Optional[Path],
    profile: str,
    secrets_list: Sequence[str],
) -> ProbeResult:
    code, sev, ref = PROBE_CATALOG["C7"]
    body = _build_chat_body(
        dialect,
        model,
        [{"role": "user", "content": "Output integers 01 through 25 separated by commas on one line, nothing else."}],
        max_tokens=90,
        temperature=0.0,
        seed=42,
    )
    out_p = _save_path(save_dir, "c7_fake_streaming_buffer.trace.jsonl")
    t0 = time.monotonic()
    try:
        doc = record_stream(url=chat_url, request_body=body, out_path=out_p, headers=headers, dialect=dialect, label="doctor-C7", timeout=timeout)
    except RecorderError as exc:
        return ProbeResult("C7", code, sev, "ERROR", _clean_display(f"transport/HTTP error: {exc}", secrets_list), (time.monotonic() - t0) * 1000, 0, None, ref)

    dur = doc.summary.timing.get("total_ms") or ((time.monotonic() - t0) * 1000)
    findings = audit_trace(doc)
    d_ids = {f.detector_id for f in findings}
    tpaths = [str(out_p)] if out_p else []

    if _has_inband_error(doc) or D4 in d_ids:
        msg = findings[0].message if findings else "HTTP 200 returned an in-band error event"
        return ProbeResult("C7", code, "P0", "FAIL", _clean_display(msg, secrets_list), dur, doc.summary.total_frames, _doc_tokens(doc), ref, tpaths, findings, [doc])

    ttft_eff = doc.summary.timing.get("ttft_effective_ms") or 0.0
    total_ms = doc.summary.timing.get("total_ms") or 0.0
    eff_frames = [f for f in doc.frames if (f.norm or {}).get("text_delta")]
    eff_count = len(eff_frames)
    content_bytes = doc.summary.assembled.get("content_utf8_bytes") or 0

    ratio = (ttft_eff / total_ms) if total_ms > 0 else 0.0
    content_span_ms = (eff_frames[-1].t_rel_ms - eff_frames[0].t_rel_ms) if eff_count >= 2 else 0.0

    # Buffered fake streaming: >=40B payload, >=250ms total latency, >96% spent waiting for first content,
    # AND all content delivered in a single burst (<5ms arrival span).
    is_buffered = (
        content_bytes >= 40
        and total_ms >= 250.0
        and ratio > 0.96
        and content_span_ms < 5.0
    )
    if is_buffered:
        return ProbeResult(
            "C7",
            code,
            "P1",
            "WARN",
            f"{ratio * 100:.1f}% latency in TTFT ({ttft_eff:.0f}/{total_ms:.0f} ms), {eff_count}-frame burst ({content_span_ms:.1f} ms span)",
            dur,
            doc.summary.total_frames,
            _doc_tokens(doc),
            ref,
            tpaths,
            findings,
            [doc],
        )

    # Insufficient frames on a fast stream: mark inconclusive instead of claiming incremental delivery
    if eff_count < 4:
        return ProbeResult(
            "C7",
            code,
            sev,
            "SKIP",
            f"inconclusive: only {eff_count} content frame(s) over {total_ms:.1f} ms (span {content_span_ms:.1f} ms)",
            dur,
            doc.summary.total_frames,
            _doc_tokens(doc),
            ref,
            tpaths,
            findings,
            [doc],
        )

    return ProbeResult(
        "C7",
        code,
        sev,
        "PASS",
        f"incremental stream ({eff_count} content frames, content span {content_span_ms:.1f} ms)",
        dur,
        doc.summary.total_frames,
        _doc_tokens(doc),
        ref,
        tpaths,
        findings,
        [doc],
    )


def _run_c8(
    chat_url: str,
    responses_url: Optional[str],
    dialect: str,
    model: str,
    headers: Dict[str, str],
    timeout: float,
    save_dir: Optional[Path],
    profile: str,
    secrets_list: Sequence[str],
) -> ProbeResult:
    code, sev, ref = PROBE_CATALOG["C8"]
    n1 = secrets.token_hex(4)
    n2 = secrets.token_hex(4)
    body_1 = _build_chat_body(
        dialect,
        model,
        [{"role": "user", "content": f"[nonce:{n1}] Reply with the single word READY."}],
        max_tokens=32,
        temperature=0.0,
        seed=42,
        include_usage=(dialect != "ollama-ndjson"),
    )
    body_2 = _build_chat_body(
        dialect,
        model,
        [{"role": "user", "content": f"[nonce:{n2}] Reply with the single word READY."}],
        max_tokens=32,
        temperature=0.0,
        seed=42,
        include_usage=(dialect != "ollama-ndjson"),
    )
    out_1 = _save_path(save_dir, "c8a_relay_drift_1.trace.jsonl")
    out_2 = _save_path(save_dir, "c8b_relay_drift_2.trace.jsonl")
    t0 = time.monotonic()
    try:
        d1 = record_stream(url=chat_url, request_body=body_1, out_path=out_1, headers=headers, dialect=dialect, label="doctor-C8a", timeout=timeout)
        d2 = record_stream(url=chat_url, request_body=body_2, out_path=out_2, headers=headers, dialect=dialect, label="doctor-C8b", timeout=timeout)
    except RecorderError as exc:
        return ProbeResult("C8", code, sev, "ERROR", _clean_display(f"transport/HTTP error: {exc}", secrets_list), (time.monotonic() - t0) * 1000, 0, None, ref)

    dur = (d1.summary.timing.get("total_ms") or 0) + (d2.summary.timing.get("total_ms") or 0)
    frames = d1.summary.total_frames + d2.summary.total_frames
    tpaths = [str(p) for p in (out_1, out_2) if p]
    findings = audit_trace(d1) + audit_trace(d2)
    t1, t2 = _doc_tokens(d1), _doc_tokens(d2)
    tot_tok = (t1 or 0) + (t2 or 0) if (t1 is not None or t2 is not None) else None

    if _has_inband_error(d1) or _has_inband_error(d2) or any(f.detector_id == D4 for f in findings):
        msg = findings[0].message if findings else "HTTP 200 returned an in-band error event"
        return ProbeResult("C8", code, "P0", "FAIL", _clean_display(msg, secrets_list), dur, frames, tot_tok, ref, tpaths, findings, [d1, d2])

    m1, fp1, _, _ = _extract_wire_metadata(d1)
    m2, fp2, _, _ = _extract_wire_metadata(d2)
    p1 = (d1.summary.assembled.get("reported_usage") or {}).get("prompt_tokens")
    p2 = (d2.summary.assembled.get("reported_usage") or {}).get("prompt_tokens")
    txt1 = (d1.summary.assembled.get("content_text") or "").strip()
    txt2 = (d2.summary.assembled.get("content_text") or "").strip()
    tail1 = (d1.summary.assembled.get("saw_textless_usage_frame"), d1.summary.assembled.get("finish_reason"))
    tail2 = (d2.summary.assembled.get("saw_textless_usage_frame"), d2.summary.assembled.get("finish_reason"))

    drifts: List[str] = []
    if m1 and m2 and m1 != m2:
        drifts.append(f"model drifted ({_clean_display(m1, secrets_list, 48)} -> {_clean_display(m2, secrets_list, 48)})")
    if fp1 and fp2 and fp1 != fp2:
        drifts.append(f"system_fingerprint drifted ({_clean_display(fp1, secrets_list, 32)} -> {_clean_display(fp2, secrets_list, 32)})")
    if is_strict_int(p1) and is_strict_int(p2) and abs(p1 - p2) >= 3:
        drifts.append(f"prompt_tokens shifted ({p1} -> {p2}) on identical template")
    if tail1 != tail2:
        drifts.append(f"protocol tail mutated ({tail1} -> {tail2})")
    if txt1 != txt2:
        drifts.append("output text drifted across seed=42 runs")

    if drifts:
        return ProbeResult("C8", code, "P2", "WARN", "; ".join(drifts), dur, frames, tot_tok, ref, tpaths, findings, [d1, d2])

    # Require reported telemetry (usage or fingerprint/model) to claim full backend consistency
    has_telemetry = (is_strict_int(p1) and is_strict_int(p2)) or bool(fp1 and fp2)
    if not has_telemetry:
        return ProbeResult(
            "C8",
            code,
            sev,
            "SKIP",
            "inconclusive: output matched, but server omitted prompt_tokens and system_fingerprint",
            dur,
            frames,
            tot_tok,
            ref,
            tpaths,
            findings,
            [d1, d2],
        )

    return ProbeResult(
        "C8",
        code,
        sev,
        "PASS",
        f"consistent backend identity, tokenization (prompt_tokens={p1}/{p2}), and output",
        dur,
        frames,
        tot_tok,
        ref,
        tpaths,
        findings,
        [d1, d2],
    )


_PROBE_RUNNERS = {
    "C1": _run_c1,
    "C2": _run_c2,
    "C3": _run_c3,
    "C4": _run_c4,
    "C5": _run_c5,
    "C6": _run_c6,
    "C7": _run_c7,
    "C8": _run_c8,
}


def compute_wire_grade(results: List[ProbeResult], *, strict: bool = False) -> Tuple[str, int, int, int, int]:
    """Return (grade, exit_code, p0_count, warning_count, error_count)."""
    p0_fails = [r for r in results if r.status == "FAIL"]
    errors = [r for r in results if r.status == "ERROR"]
    p1_warns = [r for r in results if r.status == "WARN" and r.severity == "P1"]
    p2_warns = [r for r in results if r.status == "WARN" and r.severity == "P2"]
    skips = [r for r in results if r.status == "SKIP"]
    warn_total = len(p1_warns) + len(p2_warns)

    if p0_fails:
        return "F", EXIT_SILENT_PROTOCOL_BREACH, len(p0_fails), warn_total, len(errors)
    if errors:
        return "F", EXIT_USAGE_OR_IO_ERROR, 0, warn_total, len(errors)
    if len(p1_warns) >= 2:
        grade = "C"
    elif len(p1_warns) == 1:
        grade = "B"
    elif len(p2_warns) >= 1 or len(skips) >= 1:
        # Inconclusive/skipped checks or P2 advisory warnings cannot earn A+
        grade = "A"
    else:
        grade = "A+"

    rc = EXIT_SEMANTIC_REGRESSION if (strict and len(p1_warns) >= 1) else EXIT_OK
    return grade, rc, 0, warn_total, 0


def run_doctor(
    *,
    base_url: str,
    model: Optional[str] = None,
    api_key: Optional[str] = None,
    headers: Optional[Mapping[str, str]] = None,
    profile: str = "quick",
    timeout: float = 60.0,
    save_dir: Optional[str] = None,
    strict: bool = False,
) -> DoctorReport:
    """Execute the C1..C8 canary suite against a live LLM endpoint or relay."""
    if profile not in PROFILE_PROBES:
        raise ValueError(f"Unknown doctor profile: {profile!r} (valid: quick, full, relay)")

    # Auth precedence: explicit --api-key -> -H Authorization:... -> OPENAI_API_KEY -> none
    req_headers: Dict[str, str] = validate_and_merge_headers({}, headers) if headers else {}
    has_hdr_auth = any(k.lower() == "authorization" for k in req_headers)
    if api_key is not None:
        resolved_key = resolve_api_key(api_key)
        if resolved_key:
            req_headers = validate_and_merge_headers(req_headers, {"Authorization": f"Bearer {resolved_key}"})
    elif not has_hdr_auth:
        env_key = (os.environ.get("OPENAI_API_KEY") or "").strip()
        if env_key:
            req_headers = validate_and_merge_headers(req_headers, {"Authorization": f"Bearer {env_key}"})

    known_secrets = extract_header_secret_values(req_headers)

    chat_url, responses_url, dialect, resolved_model = resolve_endpoints_and_model(
        base_url,
        model=model,
        headers=req_headers,
        timeout=timeout,
        known_secrets=known_secrets,
    )

    if save_dir == "":
        ts = datetime.datetime.now(datetime.timezone.utc).strftime("%Y%m%dT%H%M%SZ")
        out_dir: Optional[Path] = Path(".inferdiff-doctor") / ts
    elif save_dir is None:
        out_dir = None
    else:
        out_dir = Path(save_dir)

    if out_dir is not None:
        out_dir.mkdir(parents=True, exist_ok=True)

    results: List[ProbeResult] = []
    for pid in PROFILE_PROBES[profile]:
        runner = _PROBE_RUNNERS[pid]
        res = runner(chat_url, responses_url, dialect, resolved_model, req_headers, timeout, out_dir, profile, known_secrets)
        results.append(res)

    grade, rc, p0_count, warn_count, err_count = compute_wire_grade(results, strict=strict)
    known_toks = [r.tokens_used for r in results if r.tokens_used is not None]
    total_tokens = sum(known_toks) if known_toks else None

    report = DoctorReport(
        target_url=sanitize_url_for_export(base_url),
        chat_url=sanitize_url_for_export(chat_url),
        dialect=dialect,
        model=_clean_display(resolved_model, known_secrets, 128),
        profile=profile,
        grade=grade,
        exit_code=rc,
        p0_count=p0_count,
        warning_count=warn_count,
        error_count=err_count,
        total_tokens=total_tokens,
        save_dir=str(out_dir) if out_dir is not None else None,
        results=results,
    )
    if out_dir is not None:
        (out_dir / "doctor_summary.json").write_text(
            json.dumps(report.to_dict(), ensure_ascii=True, indent=2) + "\n",
            encoding="utf-8",
            newline="\n",
        )
    return report


def render_doctor_terminal(report: DoctorReport, *, no_color: bool = False) -> str:
    """Render the compact terminal Wire Health Scorecard."""
    import sys

    use_color = False
    if not no_color:
        try:
            use_color = sys.stdout.isatty()
        except Exception:
            use_color = False

    def _c(txt: str, code: str) -> str:
        return f"\033[{code}m{txt}\033[0m" if use_color else txt

    sep = "-" * 102
    lines = [
        _c(
            f"inferdiff doctor v{__version__} | target: {_clean_display(report.target_url)} | model: {_clean_display(report.model)} | profile: {report.profile}",
            "1",
        ),
        sep,
    ]
    badge_color = {"PASS": "32", "WARN": "33", "FAIL": "31", "ERROR": "31", "SKIP": "36"}
    for r in report.results:
        b = _c(f"[{r.status}]", badge_color.get(r.status, "0"))
        label = f"{r.probe_id} {r.code}".ljust(34)
        lines.append(f"{b} {label} {_clean_display(r.summary)} ({r.duration_ms:.0f} ms)")
    lines.append(sep)

    tok_str = f"{report.total_tokens:,} tokens" if report.total_tokens is not None else "unknown tokens"
    grade_col = "31" if report.grade == "F" else ("33" if report.warning_count > 0 else "32")
    lines.append(
        _c(
            f"Wire Health Grade: {report.grade} ({report.p0_count} P0 Breaches, {report.error_count} Errors, {report.warning_count} P1/P2 Warnings) | Cost: {tok_str} | Exit: {report.exit_code}",
            grade_col,
        )
    )
    if report.save_dir:
        saved_count = sum(len(r.trace_paths) for r in report.results)
        lines.append(
            f"Saved {saved_count} sanitized traces to {report.save_dir} (run `inferdiff export <trace>` for <=25-line Issue)"
        )
    return "\n".join(lines) + "\n"
