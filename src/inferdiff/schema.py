"""inferdiff.trace.v1 dataclasses, strict JSON/schema validation, effective_params, and JSONL I/O."""

from __future__ import annotations

import hashlib
import json
import math
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Dict, Iterable, List, Optional, Tuple, Union

from ._probe_data import NUMBER, PROBE_FIELDS

SCHEMA_VERSION = "inferdiff.trace.v1"

EXIT_OK = 0
EXIT_USAGE_OR_IO_ERROR = 1
EXIT_SILENT_PROTOCOL_BREACH = 2
EXIT_SEMANTIC_REGRESSION = 3

VALID_DIALECTS = (
    "openai-chat",
    "openai-responses",
    "sglang-native",
    "ollama-ndjson",
    "anthropic-messages",
    "gemini-sse",
)

UsageValue = Union[int, str]


class TraceSchemaError(ValueError):
    """Raised when a .trace.jsonl file violates inferdiff.trace.v1."""


def is_strict_int(val: Any) -> bool:
    return isinstance(val, int) and not isinstance(val, bool)


def is_finite_number(val: Any) -> bool:
    if not isinstance(val, (int, float)) or isinstance(val, bool):
        return False
    try:
        return math.isfinite(float(val))
    except (OverflowError, ValueError):
        return False


def _reject_json_constant(token: str) -> Any:
    raise ValueError(f"Non-standard JSON constant not allowed: {token!r}")


def strict_json_loads(text: str) -> Any:
    """Parse RFC 8259 JSON, rejecting NaN, Infinity, -Infinity, and oversized integers."""
    return json.loads(text, parse_constant=_reject_json_constant)


def has_lone_surrogate(obj: Any) -> bool:
    """Return True if any string inside a parsed JSON object contains UTF-16 surrogates."""
    if isinstance(obj, str):
        for ch in obj:
            code = ord(ch)
            if 0xD800 <= code <= 0xDFFF:
                return True
        return False
    if isinstance(obj, list):
        return any(has_lone_surrogate(item) for item in obj)
    if isinstance(obj, dict):
        return any(has_lone_surrogate(k) or has_lone_surrogate(v) for k, v in obj.items())
    return False


def safe_utf8_len(text: str) -> int:
    """Compute UTF-8 byte length safely without crashing on escaped lone surrogates."""
    return len(text.encode("utf-8", errors="surrogatepass"))


def canonical_json_bytes(obj: Any) -> bytes:
    return json.dumps(obj, ensure_ascii=True, sort_keys=True, separators=(",", ":"), allow_nan=False).encode("utf-8")


def canonical_json_line(obj: Any) -> str:
    return json.dumps(obj, ensure_ascii=True, separators=(",", ":"), allow_nan=False)


def body_sha256(body: Dict[str, Any]) -> str:
    return hashlib.sha256(canonical_json_bytes(body)).hexdigest()


def empty_usage() -> Dict[str, UsageValue]:
    return {
        "prompt_tokens": "unknown",
        "completion_tokens": "unknown",
        "reasoning_tokens": "unknown",
        "cached_tokens": "unknown",
    }


def frame_has_effective_payload(norm: Dict[str, Any]) -> bool:
    """True iff frame carries actual content, reasoning, or tool arguments payload (not initial snapshot)."""
    if norm.get("text_delta") or norm.get("reasoning_delta"):
        return True
    for td in norm.get("tool_deltas") or []:
        if not isinstance(td, dict):
            continue
        if td.get("arguments_delta") or td.get("args_delta"):
            return True
        if td.get("arguments_snapshot") and td.get("is_args_done"):
            return True
    return False


def _pick_first_present(
    containers: List[Dict[str, Any]],
    keys: Tuple[str, ...],
    *,
    allow_null_override: bool = False,
) -> Tuple[bool, Any]:
    """Return (found, value) for the highest-precedence container that explicitly defines a key."""
    for container in containers:
        for key in keys:
            if key in container:
                if allow_null_override or container[key] is not None:
                    return True, container[key]
    return False, None


def _normalize_str_stop_value(val: Any) -> List[str]:
    out: List[str] = []
    if isinstance(val, str):
        if val != "":
            out.append(val)
    elif isinstance(val, list):
        for item in val:
            if isinstance(item, str) and item != "" and item not in out:
                out.append(item)
    return out


def _normalize_int_stop_value(val: Any) -> List[int]:
    out: List[int] = []
    if is_strict_int(val):
        out.append(val)
    elif isinstance(val, list):
        for item in val:
            if is_strict_int(item) and item not in out:
                out.append(item)
    return out


def extract_effective_params(body: Dict[str, Any], dialect: str) -> Dict[str, Any]:
    """Extract effective budget, ignore_eos, stop conditions, and tool flags with dialect precedence."""
    sp = body.get("sampling_params") if isinstance(body.get("sampling_params"), dict) else {}
    extra = body.get("extra_request_body") if isinstance(body.get("extra_request_body"), dict) else {}
    opts = body.get("options") if isinstance(body.get("options"), dict) else {}

    if dialect == "sglang-native":
        containers = [sp, extra, body]
        budget_keys = ("max_new_tokens", "max_tokens", "max_completion_tokens", "max_output_tokens")
    elif dialect == "ollama-ndjson":
        containers = [opts, body]
        budget_keys = ("num_predict", "max_tokens")
    elif dialect == "openai-responses":
        # Nested engine override containers take precedence over top-level body when present
        containers = [extra, sp, body]
        budget_keys = ("max_output_tokens", "max_completion_tokens", "max_tokens", "max_new_tokens")
    elif dialect == "gemini-sse":
        config = body.get("generationConfig")
        containers = [config] if isinstance(config, dict) else []
        budget_keys = ("maxOutputTokens",)
    else:  # openai-chat
        containers = [extra, sp, body]
        budget_keys = ("max_completion_tokens", "max_output_tokens", "max_tokens", "max_new_tokens")

    _, raw_budget = _pick_first_present(containers, budget_keys)
    _, raw_ignore = _pick_first_present(containers, ("ignore_eos",))
    _, raw_temp = _pick_first_present(containers, ("temperature",))
    _, raw_seed = _pick_first_present(containers, ("seed",))

    # Validate the winning value only (never fall back past an explicit override like 0 or -1)
    max_budget = raw_budget if (is_strict_int(raw_budget) and raw_budget > 0) else None
    ignore_eos = raw_ignore if isinstance(raw_ignore, bool) else False
    temperature = float(raw_temp) if is_finite_number(raw_temp) else None
    seed = raw_seed if is_strict_int(raw_seed) else None

    # Resolve each stop type independently using container precedence so explicit empty or null overrides win
    stop_key = "stopSequences" if dialect == "gemini-sse" else "stop"
    found_stop, raw_stop = _pick_first_present(containers, (stop_key,), allow_null_override=True)
    stop_sequences = _normalize_str_stop_value(raw_stop) if (found_stop and raw_stop is not None) else []

    found_stop_ids, raw_stop_ids = _pick_first_present(containers, ("stop_token_ids",), allow_null_override=True)
    stop_token_ids = _normalize_int_stop_value(raw_stop_ids) if (found_stop_ids and raw_stop_ids is not None) else []

    found_stop_re, raw_stop_re = _pick_first_present(containers, ("stop_regex",), allow_null_override=True)
    stop_regex = _normalize_str_stop_value(raw_stop_re) if (found_stop_re and raw_stop_re is not None) else []

    # Flattened list of effective (non-empty) stop conditions for v0.1 schema compatibility
    stops: List[Any] = []
    for item in (*stop_sequences, *stop_token_ids, *stop_regex):
        if item not in stops:
            stops.append(item)

    tools = body.get("tools")
    has_tools = isinstance(tools, list) and len(tools) > 0

    model = body.get("model") if isinstance(body.get("model"), str) else None
    stream = body.get("stream") if isinstance(body.get("stream"), bool) else True

    return {
        "model": model,
        "stream": stream,
        "max_budget_tokens": max_budget,
        "ignore_eos": ignore_eos,
        "temperature": temperature,
        "seed": seed,
        "has_tools": has_tools,
        "stop_sequences": stop_sequences,
        "stop_token_ids": stop_token_ids,
        "stop_regex": stop_regex,
        "stop_conditions": stops,
    }


@dataclass
class NormalizedDelta:
    phase: str = "CONTENT"  # HANDSHAKE | REASONING | CONTENT | TOOL | TERMINAL | USAGE | ERROR | UNKNOWN
    text_delta: str = ""
    reasoning_delta: str = ""
    tool_deltas: List[Dict[str, Any]] = field(default_factory=list)
    closed_events: List[str] = field(default_factory=list)
    finish_reason: Optional[str] = None
    terminal_status: Optional[str] = None
    matched_stop: Optional[Any] = None
    usage: Dict[str, UsageValue] = field(default_factory=empty_usage)
    is_done_sentinel: bool = False
    is_cumulative_text: bool = False
    inband_error: Optional[str] = None
    protocol_error: Optional[str] = None


@dataclass
class TraceHeader:
    trace_id: str
    label: str
    recorded_at_utc: str
    dialect: str
    request: Dict[str, Any]
    response_meta: Dict[str, Any]
    backend_probe: Optional[Dict[str, Any]] = None
    schema_version: str = SCHEMA_VERSION
    type: str = "header"

    def to_dict(self) -> Dict[str, Any]:
        return {
            "type": "header",
            "schema_version": self.schema_version,
            "trace_id": self.trace_id,
            "label": self.label,
            "recorded_at_utc": self.recorded_at_utc,
            "dialect": self.dialect,
            "request": self.request,
            "response_meta": self.response_meta,
            "backend_probe": self.backend_probe,
        }


@dataclass
class TraceFrame:
    seq: int
    t_rel_ms: float
    dt_ms: float
    sse_event: Optional[str]
    raw_wire: str
    is_done_sentinel: bool
    parse_error: Optional[str]
    norm: Dict[str, Any]
    type: str = "frame"

    def to_dict(self) -> Dict[str, Any]:
        return {
            "type": "frame",
            "seq": self.seq,
            "t_rel_ms": self.t_rel_ms,
            "dt_ms": self.dt_ms,
            "sse_event": self.sse_event,
            "raw_wire": self.raw_wire,
            "is_done_sentinel": self.is_done_sentinel,
            "parse_error": self.parse_error,
            "norm": self.norm,
        }


@dataclass
class TraceSummary:
    eof_clean: bool
    total_frames: int
    timing: Dict[str, Optional[float]]
    assembled: Dict[str, Any]
    backend_probe: Optional[Dict[str, Any]] = None
    type: str = "summary"

    def to_dict(self) -> Dict[str, Any]:
        out: Dict[str, Any] = {
            "type": "summary",
            "eof_clean": self.eof_clean,
            "total_frames": self.total_frames,
            "timing": self.timing,
            "assembled": self.assembled,
        }
        if self.backend_probe is not None:
            out["backend_probe"] = self.backend_probe
        return out


@dataclass
class TraceDocument:
    header: TraceHeader
    frames: List[TraceFrame]
    summary: TraceSummary


def scan_think_tags(text: str) -> Tuple[str, str, bool]:
    """Strip <think>...</think> spans into reasoning; return (visible, reasoning, has_unclosed_think)."""
    depth = 0
    vis: List[str] = []
    reas: List[str] = []
    i = 0
    n = len(text)
    while i < n:
        if text.startswith("<think>", i):
            depth += 1
            i += 7
            continue
        if text.startswith("</think>", i):
            if depth > 0:
                depth -= 1
                i += 8
                continue
            vis.append("</think>")
            i += 8
            continue
        ch = text[i]
        if depth > 0:
            reas.append(ch)
        else:
            vis.append(ch)
        i += 1
    return "".join(vis), "".join(reas), depth > 0


def _merge_tool_records(primary: Dict[str, Any], secondary: Dict[str, Any]) -> None:
    """Merge secondary provisional tool record into primary while preserving chronological order."""
    if not primary["id"] and secondary["id"]:
        primary["id"] = secondary["id"]
    if not primary["item_id"] and secondary["item_id"]:
        primary["item_id"] = secondary["item_id"]
    if primary["explicit_index"] is None and secondary["explicit_index"] is not None:
        primary["explicit_index"] = secondary["explicit_index"]
        primary["index"] = secondary["explicit_index"]
    if not primary["name"] and secondary["name"]:
        primary["name"] = secondary["name"]
        primary["name_seq"] = secondary["name_seq"]

    primary["delta_entries"].extend(secondary["delta_entries"])
    primary["delta_entries"].sort(key=lambda pair: (pair[0], pair[1]))

    if secondary["done_snapshot"] is not None:
        primary["done_snapshot"] = secondary["done_snapshot"]
        primary["done_seq"] = secondary["done_seq"]
    if secondary["item_snapshot"] is not None:
        primary["item_snapshot"] = secondary["item_snapshot"]
        primary["snapshot_seq"] = secondary["snapshot_seq"]
    primary["saw_args_delta"] = primary["saw_args_delta"] or secondary["saw_args_delta"]
    primary["saw_args_done_event"] = primary["saw_args_done_event"] or secondary["saw_args_done_event"]
    primary["identity_conflict"] = primary["identity_conflict"] or secondary["identity_conflict"]
    primary["first_seq"] = min(primary["first_seq"], secondary["first_seq"])
    primary["last_seq"] = max(primary["last_seq"], secondary["last_seq"])


def assemble_summary(
    header: TraceHeader,
    frames: List[TraceFrame],
    *,
    total_ms: float,
    socket_eof_clean: bool = True,
    backend_probe_summary: Optional[Dict[str, Any]] = None,
    ndjson: bool = False,
) -> TraceSummary:
    """Build deterministic TraceSummary from recorded frames with strict protocol ordering."""
    dialect = header.dialect
    t_headers_ms = header.response_meta.get("t_headers_ms")
    ttff_ms: Optional[float] = None
    ttft_effective_ms: Optional[float] = None

    raw_text_parts: List[str] = []
    reasoning_parts: List[str] = []
    observed_delta_frames = 0
    finish_reason: str = "unknown"
    terminal_status: str = "unknown"
    matched_stop: Optional[Any] = None
    usage = empty_usage()
    if dialect == "gemini-sse":
        usage["total_tokens"] = "unknown"

    saw_done_sentinel = False
    saw_typed_responses_terminal = False
    saw_raw_sse_done = False
    saw_finish_reason = False
    saw_textless_usage_frame = False
    protocol_violations: List[str] = []

    # Tool accumulation with alias reconciliation & identity conflict detection
    tools_by_key: Dict[str, Dict[str, Any]] = {}
    tool_order: List[str] = []
    alias_item_to_key: Dict[str, str] = {}
    alias_call_to_key: Dict[str, str] = {}
    alias_idx_to_key: Dict[int, str] = {}
    event_counter = 0

    def _repoint_aliases(old_key: str, new_key: str) -> None:
        for mp in (alias_item_to_key, alias_call_to_key):
            for ak, kv in list(mp.items()):
                if kv == old_key:
                    mp[ak] = new_key
        for ik, kv in list(alias_idx_to_key.items()):
            if kv == old_key:
                alias_idx_to_key[ik] = new_key

    def _new_tool_record(
        key: str,
        *,
        idx: Optional[int],
        call_id: Optional[str],
        item_id: Optional[str],
        name: str,
        seq: int,
        conflict: bool = False,
    ) -> Dict[str, Any]:
        rec = {
            "index": idx if is_strict_int(idx) else len(tool_order),
            "explicit_index": idx if is_strict_int(idx) else None,
            "id": call_id,
            "item_id": item_id,
            "name": name,
            "name_seq": seq if name else None,
            "first_seq": seq,
            "last_seq": seq,
            "done_seq": None,
            "snapshot_seq": None,
            "delta_entries": [],  # List[Tuple[seq, order, str]]
            "done_snapshot": None,
            "item_snapshot": None,
            "saw_args_delta": False,
            "saw_args_done_event": False,
            "identity_conflict": conflict,
        }
        tools_by_key[key] = rec
        tool_order.append(key)
        return rec

    def _compatible(rec: Dict[str, Any], item_id: Optional[str], call_id: Optional[str]) -> bool:
        if item_id and rec["item_id"] and rec["item_id"] != item_id:
            return False
        if call_id and rec["id"] and rec["id"] != call_id:
            return False
        return True

    def _resolve_tool(td: Dict[str, Any], seq: int) -> Dict[str, Any]:
        item_id = td.get("item_id") if isinstance(td.get("item_id"), str) and td.get("item_id") else None
        call_id = td.get("id") if isinstance(td.get("id"), str) and td.get("id") else None
        idx = td.get("index") if is_strict_int(td.get("index")) else None
        name = td.get("name") if isinstance(td.get("name"), str) else ""

        # Ollama streaming emits complete tool calls per chunk with frame-local positions.
        if td.get("tool_accumulate_mode") == "append":
            key = f"append:{len(tool_order)}"
            return _new_tool_record(
                key,
                idx=len(tool_order),
                call_id=call_id,
                item_id=item_id,
                name=name,
                seq=seq,
            )

        cand_keys: List[str] = []
        if item_id and item_id in alias_item_to_key:
            cand_keys.append(alias_item_to_key[item_id])
        if call_id and call_id in alias_call_to_key:
            k = alias_call_to_key[call_id]
            if k not in cand_keys:
                cand_keys.append(k)
        if idx is not None and idx in alias_idx_to_key:
            k = alias_idx_to_key[idx]
            if k not in cand_keys:
                cand_keys.append(k)

        # Partition candidates into compatible vs conflicting
        compat = [k for k in cand_keys if _compatible(tools_by_key[k], item_id, call_id)]
        conflicts = [k for k in cand_keys if k not in compat]

        if not compat:
            had_conflict = bool(conflicts)
            if had_conflict:
                for ck in conflicts:
                    tools_by_key[ck]["identity_conflict"] = True
            key = f"conflict:{len(tool_order)}" if had_conflict else (
                f"item:{item_id}" if item_id else (f"call:{call_id}" if call_id else (f"idx:{idx}" if idx is not None else f"ord:{len(tool_order)}"))
            )
            if key in tools_by_key:
                key = f"{key}#{len(tool_order)}"
            rec = _new_tool_record(
                key,
                idx=idx,
                call_id=call_id,
                item_id=item_id,
                name=name,
                seq=seq,
                conflict=had_conflict,
            )
            if item_id:
                alias_item_to_key[item_id] = key
            if call_id:
                alias_call_to_key[call_id] = key
            if idx is not None and not had_conflict:
                alias_idx_to_key[idx] = key
            return rec

        # Reconcile multiple compatible provisional records (pick earliest in tool_order)
        compat.sort(key=lambda k: tool_order.index(k))
        primary_key = compat[0]
        rec = tools_by_key[primary_key]
        if conflicts:
            # Known item reused an index already owned by a different call -> flag conflict on both!
            rec["identity_conflict"] = True
            for ck in conflicts:
                tools_by_key[ck]["identity_conflict"] = True
        for other_key in compat[1:]:
            other_rec = tools_by_key[other_key]
            # Verify pairwise compatibility between primary and secondary
            if _compatible(rec, other_rec["item_id"], other_rec["id"]):
                _merge_tool_records(rec, other_rec)
                _repoint_aliases(other_key, primary_key)
                del tools_by_key[other_key]
                tool_order.remove(other_key)
            else:
                rec["identity_conflict"] = True
                other_rec["identity_conflict"] = True

        if item_id:
            rec["item_id"] = item_id
            alias_item_to_key[item_id] = primary_key
        if call_id:
            rec["id"] = call_id
            alias_call_to_key[call_id] = primary_key
        if idx is not None and not conflicts:
            if rec["explicit_index"] is None:
                rec["explicit_index"] = idx
                rec["index"] = idx
            alias_idx_to_key[idx] = primary_key
        if name and not rec["name"]:
            rec["name"] = name
            rec["name_seq"] = seq
        rec["last_seq"] = max(rec["last_seq"], seq)
        return rec

    for frame in frames:
        if ttff_ms is None and frame.parse_error != "incomplete_event":
            ttff_ms = frame.t_rel_ms

        norm = frame.norm or {}
        closed_events = norm.get("closed_events") or []
        is_sse_done = "[DONE]" in closed_events or (frame.is_done_sentinel and frame.raw_wire.strip().endswith("[DONE]"))
        is_typed_resp_term = any(
            ev in ("response.completed", "response.incomplete", "response.failed") for ev in closed_events
        ) and not norm.get("protocol_error")
        is_ollama_done = "ollama.done" in closed_events or "done:true" in closed_events
        is_anthropic_stop = dialect == "anthropic-messages" and "message_stop" in closed_events

        # Detect protocol violations from dialect normalizers
        if norm.get("protocol_error"):
            protocol_violations.append(f"frame#{frame.seq}: {norm['protocol_error']}")

        # Detect payload arriving AFTER an EOF sentinel (e.g., [DONE] placed before content/finish!)
        if saw_raw_sse_done:
            protocol_violations.append(f"frame#{frame.seq}: frame_after_done_sentinel")
        elif dialect == "openai-responses" and saw_typed_responses_terminal and not is_sse_done:
            protocol_violations.append(f"frame#{frame.seq}: payload_after_responses_terminal")
        elif dialect == "ollama-ndjson" and saw_done_sentinel:
            protocol_violations.append(f"frame#{frame.seq}: frame_after_ollama_done")

        if is_sse_done:
            saw_raw_sse_done = True
            if dialect != "openai-responses":
                saw_done_sentinel = True
        if is_typed_resp_term:
            saw_typed_responses_terminal = True
            saw_done_sentinel = True
        if is_ollama_done or is_anthropic_stop:
            saw_done_sentinel = True

        text_delta = norm.get("text_delta") or ""
        reas_delta = norm.get("reasoning_delta") or ""
        tool_deltas = norm.get("tool_deltas") or []

        # Gemini, Chat, and SGLang may send usage after the candidate finishes.
        if (
            dialect in ("openai-chat", "sglang-native", "gemini-sse")
            and saw_finish_reason
            and not is_sse_done
            and (text_delta or reas_delta or tool_deltas)
        ):
            protocol_violations.append(f"frame#{frame.seq}: payload_after_finish_reason")

        if frame_has_effective_payload(norm):
            observed_delta_frames += 1
            if ttft_effective_ms is None:
                ttft_effective_ms = frame.t_rel_ms

        if text_delta:
            raw_text_parts.append(text_delta)
        if reas_delta:
            reasoning_parts.append(reas_delta)

        for td in tool_deltas:
            if not isinstance(td, dict):
                continue
            rec = _resolve_tool(td, frame.seq)
            arg_d = td.get("arguments_delta") if td.get("arguments_delta") is not None else td.get("args_delta")
            if td.get("is_args_delta_event") or (isinstance(arg_d, str) and arg_d != ""):
                rec["saw_args_delta"] = True
            if isinstance(arg_d, str) and arg_d != "":
                event_counter += 1
                rec["delta_entries"].append((frame.seq, event_counter, arg_d))
            arg_s = td.get("arguments_snapshot")
            if td.get("is_args_done"):
                rec["saw_args_done_event"] = True
                rec["done_seq"] = frame.seq
                if isinstance(arg_s, str):
                    rec["done_snapshot"] = arg_s
            elif isinstance(arg_s, str) and td.get("is_item_done_snapshot") is not False:
                rec["item_snapshot"] = arg_s
                rec["snapshot_seq"] = frame.seq

        fr = norm.get("finish_reason")
        if isinstance(fr, str) and fr and fr != "unknown":
            finish_reason = fr
            saw_finish_reason = True

        ts = norm.get("terminal_status")
        if isinstance(ts, str) and ts and ts != "unknown":
            terminal_status = ts

        if norm.get("matched_stop") is not None:
            matched_stop = norm["matched_stop"]

        f_usage = norm.get("usage")
        if isinstance(f_usage, dict):
            updated_usage = False
            for k in usage:
                v = f_usage.get(k)
                if is_strict_int(v) and v >= 0:
                    usage[k] = v
                    updated_usage = True
            if updated_usage and not text_delta and not tool_deltas:
                saw_textless_usage_frame = True

    joined_raw_text = "".join(raw_text_parts)
    visible_text, think_text, has_unclosed_think = scan_think_tags(joined_raw_text)
    full_reasoning = "".join(reasoning_parts) + think_text

    assembled_tools: List[Dict[str, Any]] = []
    for key in tool_order:
        rec = tools_by_key[key]
        streamed_args = "".join(chunk for _, _, chunk in rec["delta_entries"])
        done_snap = rec["done_snapshot"]
        item_snap = rec["item_snapshot"]

        args_mismatch = False
        args_mismatch_detail: Optional[str] = None
        if rec["delta_entries"] and done_snap is not None and streamed_args != done_snap:
            args_mismatch = True
            args_mismatch_detail = "streamed arguments.delta differs from arguments.done snapshot"
        # Anthropic sends the initial input object before any JSON fragments.
        elif (rec["delta_entries"] and item_snap is not None and streamed_args != item_snap
              and dialect != "anthropic-messages"):
            args_mismatch = True
            args_mismatch_detail = "streamed arguments.delta differs from final item snapshot"
        elif done_snap is not None and item_snap is not None and done_snap != item_snap:
            args_mismatch = True
            args_mismatch_detail = "arguments.done snapshot differs from final item snapshot"

        # Empty Responses delta without arguments.done must NOT be hidden by final item snapshot
        if rec["delta_entries"]:
            raw_args = streamed_args
        elif dialect == "openai-responses" and rec["saw_args_delta"] and not rec["saw_args_done_event"]:
            raw_args = ""
        elif done_snap is not None:
            raw_args = done_snap
        else:
            raw_args = item_snap or ""

        json_valid = False
        json_error: Optional[str] = None
        if not raw_args or not raw_args.strip():
            json_valid = False
            json_error = "Empty arguments string"
        else:
            try:
                parsed_args = strict_json_loads(raw_args)
                if has_lone_surrogate(parsed_args):
                    json_valid = False
                    json_error = "Arguments contain invalid lone UTF-16 surrogate"
                elif dialect in ("anthropic-messages", "gemini-sse") and not isinstance(parsed_args, dict):
                    vendor = "Anthropic" if dialect == "anthropic-messages" else "Gemini"
                    json_error = f"{vendor} tool input must be a JSON object"
                else:
                    json_valid = True
            except (json.JSONDecodeError, ValueError, RecursionError) as exc:
                json_valid = False
                json_error = str(exc)

        assembled_tools.append(
            {
                "index": rec["index"],
                "id": rec["id"] or rec["item_id"] or f"call_{rec['index']}",
                "item_id": rec["item_id"],
                "name": rec["name"],
                "raw_arguments": raw_args,
                "json_valid": json_valid,
                "json_error": json_error,
                "saw_args_delta": rec["saw_args_delta"],
                "saw_args_done_event": rec["saw_args_done_event"],
                "args_mismatch": args_mismatch,
                "args_mismatch_detail": args_mismatch_detail,
                "identity_conflict": rec["identity_conflict"],
                "first_seq": rec["first_seq"],
                "name_seq": rec["name_seq"],
                "last_seq": rec["last_seq"],
                "done_seq": rec["done_seq"],
                "snapshot_seq": rec["snapshot_seq"],
            }
        )

    # Strict dialect-specific clean EOF
    if not socket_eof_clean or protocol_violations:
        eof_clean = False
    elif dialect == "sglang-native" and ndjson:
        eof_clean = saw_finish_reason
    elif dialect in ("openai-chat", "sglang-native"):
        eof_clean = saw_done_sentinel
    elif dialect == "openai-responses":
        eof_clean = saw_typed_responses_terminal
    elif dialect == "gemini-sse":
        eof_clean = saw_finish_reason
    elif dialect == "ollama-ndjson":
        eof_clean = saw_done_sentinel
    else:
        eof_clean = saw_done_sentinel

    assembled = {
        "content_text": visible_text,
        "content_utf8_bytes": safe_utf8_len(visible_text),
        "reasoning_text": full_reasoning,
        "has_unclosed_think": has_unclosed_think,
        "tool_calls": assembled_tools,
        "finish_reason": finish_reason,
        "terminal_status": terminal_status,
        "matched_stop": matched_stop,
        "protocol_violations": protocol_violations,
        "observed_delta_frames": observed_delta_frames,
        "saw_textless_usage_frame": saw_textless_usage_frame,
        "reported_usage": usage,
    }
    timing = {
        "t_headers_ms": round(float(t_headers_ms), 3) if is_finite_number(t_headers_ms) else None,
        "ttff_ms": round(ttff_ms, 3) if ttff_ms is not None else None,
        "ttft_effective_ms": round(ttft_effective_ms, 3) if ttft_effective_ms is not None else None,
        "total_ms": round(total_ms, 3),
    }
    return TraceSummary(
        eof_clean=eof_clean,
        total_frames=len(frames),
        timing=timing,
        assembled=assembled,
        backend_probe=backend_probe_summary,
    )


def write_trace(path: Union[str, Path], doc: TraceDocument) -> None:
    """Write a complete TraceDocument atomically as UTF-8 LF JSONL."""
    target = Path(path)
    target.parent.mkdir(parents=True, exist_ok=True)
    tmp = target.with_name(f".{target.name}.tmp")
    try:
        with tmp.open("w", encoding="utf-8", newline="\n") as fh:
            fh.write(canonical_json_line(doc.header.to_dict()) + "\n")
            for frame in doc.frames:
                fh.write(canonical_json_line(frame.to_dict()) + "\n")
            fh.write(canonical_json_line(doc.summary.to_dict()) + "\n")
            fh.flush()
        tmp.replace(target)
    except Exception:
        if tmp.exists():
            tmp.unlink(missing_ok=True)
        raise


def _require_type(obj: Dict[str, Any], key: str, expected_type: Any, ctx: str) -> Any:
    if key not in obj:
        raise TraceSchemaError(f"{ctx}: missing required field {key!r}")
    val = obj[key]
    if expected_type is bool:
        if not isinstance(val, bool):
            raise TraceSchemaError(f"{ctx}: field {key!r} must be boolean, got {type(val).__name__}")
    elif expected_type is int:
        if not is_strict_int(val):
            raise TraceSchemaError(f"{ctx}: field {key!r} must be integer, got {type(val).__name__}")
    elif expected_type is float:
        if not is_finite_number(val):
            raise TraceSchemaError(f"{ctx}: field {key!r} must be finite number, got {type(val).__name__}")
    elif not isinstance(val, expected_type):
        raise TraceSchemaError(f"{ctx}: field {key!r} must be {expected_type.__name__}, got {type(val).__name__}")
    return val


def validate_backend_probe(value: Any, ctx: str) -> None:
    """Validate known fields and bound the size and nesting of extension data."""
    if value is None:
        return
    nodes_left = 2048
    chars_left = 65536

    def visit(item: Any, expected: Any, depth: int) -> None:
        nonlocal nodes_left, chars_left
        nodes_left -= 1
        if depth > 8 or nodes_left < 0:
            raise TraceSchemaError(f"{ctx}: backend_probe exceeds size or depth limits")
        if isinstance(item, str):
            chars_left -= len(item)
            if chars_left < 0 or len(item) > 4096 or has_lone_surrogate(item):
                raise TraceSchemaError(f"{ctx}: invalid backend_probe text")
        if expected is NUMBER:
            valid = is_finite_number(item)
        elif expected is int:
            valid = is_strict_int(item) and is_finite_number(item)
        elif isinstance(expected, dict):
            valid = isinstance(item, dict)
        else:
            valid = expected is None or isinstance(item, expected)
        if not valid:
            raise TraceSchemaError(f"{ctx}: invalid backend_probe field type")
        if isinstance(item, dict):
            fields = expected if isinstance(expected, dict) else {}
            for key, child in item.items():
                visit(key, str, depth + 1)
                visit(child, fields.get(key, fields.get(None)), depth + 1)
        elif isinstance(item, list):
            for child in item:
                visit(child, str if expected is list else None, depth + 1)
        elif item is not None and not isinstance(item, (str, bool)) and not is_finite_number(item):
            raise TraceSchemaError(f"{ctx}: backend_probe must contain finite JSON values")

    visit(value, PROBE_FIELDS, 0)


def load_trace(path: Union[str, Path], *, source: str | None = None) -> TraceDocument:
    """Load and strictly validate an inferdiff.trace.v1 JSONL file."""
    trace_file = Path(path)
    src = str(trace_file) if source is None else source
    try:
        # JSONL uses LF or CRLF. Other Unicode separators can appear inside a valid string.
        with trace_file.open(encoding="utf-8", newline="\n") as fh:
            return parse_trace(fh, source=src)
    except FileNotFoundError as exc:
        raise TraceSchemaError(f"Trace file not found: {src}") from exc
    except OSError as exc:
        raise TraceSchemaError(f"{src}: failed to read trace ({exc.strerror or type(exc).__name__})") from exc
    except UnicodeDecodeError as exc:
        raise TraceSchemaError(f"{src}: trace is not valid UTF-8") from exc


def parse_trace(lines: Iterable[str], *, source: str) -> TraceDocument:
    """Validate trace records from a file or an in-memory capture."""
    src = source
    records: List[Dict[str, Any]] = []
    for lineno, line in enumerate(lines, start=1):
        if not line.strip():
            continue
        try:
            obj = strict_json_loads(line)
        except (json.JSONDecodeError, ValueError, RecursionError) as exc:
            raise TraceSchemaError(f"{src}:{lineno}: invalid JSON: {exc}") from exc
        if not isinstance(obj, dict):
            raise TraceSchemaError(f"{src}:{lineno}: JSON record must be an object")
        records.append(obj)

    if len(records) < 2:
        raise TraceSchemaError(f"{src}: trace file too short (expected header + summary)")

    hdr_obj = records[0]
    if hdr_obj.get("type") != "header":
        raise TraceSchemaError(f"{src}: first record must have type='header'")
    if hdr_obj.get("schema_version") != SCHEMA_VERSION:
        raise TraceSchemaError(f"{src}: unsupported schema_version")
    dialect = _require_type(hdr_obj, "dialect", str, f"{src}:header")
    if dialect not in VALID_DIALECTS:
        raise TraceSchemaError(f"{src}: unsupported trace dialect")
    trace_id = _require_type(hdr_obj, "trace_id", str, f"{src}:header")
    recorded_at = _require_type(hdr_obj, "recorded_at_utc", str, f"{src}:header")
    label = hdr_obj.get("label", "")
    if not isinstance(label, str):
        raise TraceSchemaError(f"{src}:header: field 'label' must be str")
    req_obj = _require_type(hdr_obj, "request", dict, f"{src}:header")
    resp_meta = _require_type(hdr_obj, "response_meta", dict, f"{src}:header")
    _require_type(resp_meta, "status_code", int, f"{src}:header.response_meta")

    req_copy = dict(req_obj)
    if "url" in req_copy and not isinstance(req_copy["url"], str):
        raise TraceSchemaError(f"{src}:header.request: field 'url' must be str")
    if "body" in req_copy and req_copy["body"] is not None and not isinstance(req_copy["body"], dict):
        raise TraceSchemaError(f"{src}:header.request: field 'body' must be dict or null")
    if "effective_params" in req_copy and req_copy["effective_params"] is not None and not isinstance(req_copy["effective_params"], dict):
        raise TraceSchemaError(f"{src}:header.request: field 'effective_params' must be dict or null")
    # Recover effective_params using the same dialect precedence rules if absent
    if not req_copy.get("effective_params") and isinstance(req_copy.get("body"), dict):
        req_copy["effective_params"] = extract_effective_params(req_copy["body"], dialect)
    effective = req_copy.get("effective_params") or {}
    if effective.get("stop_conditions") is not None:
        _require_type(effective, "stop_conditions", list, f"{src}:header.request.effective_params")

    bp_hdr = hdr_obj.get("backend_probe")
    validate_backend_probe(bp_hdr, f"{src}:header")

    sum_obj = records[-1]
    if sum_obj.get("type") != "summary":
        raise TraceSchemaError(f"{src}: last record must have type='summary'")
    eof_clean = _require_type(sum_obj, "eof_clean", bool, f"{src}:summary")
    total_frames = _require_type(sum_obj, "total_frames", int, f"{src}:summary")
    timing = _require_type(sum_obj, "timing", dict, f"{src}:summary")
    if any(value is not None and not is_finite_number(value) for value in timing.values()):
        raise TraceSchemaError(f"{src}:summary.timing: values must be finite numbers or null")
    assembled = _require_type(sum_obj, "assembled", dict, f"{src}:summary")
    assembly_location = f"{src}:summary.assembled"
    if assembled.get("protocol_violations") is not None:
        _require_type(assembled, "protocol_violations", list, assembly_location)
    for key in ("content_utf8_bytes", "observed_delta_frames"):
        value = assembled.get(key)
        if value is not None and (not is_strict_int(value) or not is_finite_number(value) or value < 0):
            raise TraceSchemaError(f"{assembly_location}: field {key!r} must be a nonnegative integer or null")
    for s_key in ("content_text", "reasoning_text", "finish_reason", "terminal_status"):
        if s_key in assembled and assembled[s_key] is not None and not isinstance(assembled[s_key], str):
            raise TraceSchemaError(f"{assembly_location}: field {s_key!r} must be str")
    if "tool_calls" in assembled and assembled["tool_calls"] is not None:
        if not isinstance(assembled["tool_calls"], list):
            raise TraceSchemaError(f"{assembly_location}: field 'tool_calls' must be list")
        for ti, tc in enumerate(assembled["tool_calls"]):
            if not isinstance(tc, dict):
                raise TraceSchemaError(f"{assembly_location}.tool_calls[{ti}] must be object")
            if "raw_arguments" in tc and tc["raw_arguments"] is not None and not isinstance(tc["raw_arguments"], str):
                raise TraceSchemaError(f"{assembly_location}.tool_calls[{ti}].raw_arguments must be str")
            if "name" in tc and tc["name"] is not None and not isinstance(tc["name"], str):
                raise TraceSchemaError(f"{assembly_location}.tool_calls[{ti}].name must be str")
            if "json_valid" in tc and tc["json_valid"] is not None and not isinstance(tc["json_valid"], bool):
                raise TraceSchemaError(f"{assembly_location}.tool_calls[{ti}].json_valid must be bool")
    if "reported_usage" in assembled and assembled["reported_usage"] is not None and not isinstance(assembled["reported_usage"], dict):
        raise TraceSchemaError(f"{assembly_location}: field 'reported_usage' must be object")
    bp_sum = sum_obj.get("backend_probe")
    validate_backend_probe(bp_sum, f"{src}:summary")

    frames: List[TraceFrame] = []
    for idx, rec in enumerate(records[1:-1]):
        ctx = f"{src}:frame[{idx}]"
        if rec.get("type") != "frame":
            raise TraceSchemaError(f"{ctx}: record must have type='frame'")
        seq = _require_type(rec, "seq", int, ctx)
        if seq != idx:
            raise TraceSchemaError(f"{ctx}: non-contiguous frame seq={seq} expected {idx}")
        t_rel = float(_require_type(rec, "t_rel_ms", float, ctx))
        dt = float(_require_type(rec, "dt_ms", float, ctx))
        raw_wire = _require_type(rec, "raw_wire", str, ctx)
        is_done = _require_type(rec, "is_done_sentinel", bool, ctx)
        sse_ev = rec.get("sse_event")
        if sse_ev is not None and not isinstance(sse_ev, str):
            raise TraceSchemaError(f"{ctx}: field 'sse_event' must be str or null")
        parse_err = rec.get("parse_error")
        if parse_err is not None and not isinstance(parse_err, str):
            raise TraceSchemaError(f"{ctx}: field 'parse_error' must be str or null")
        norm = _require_type(rec, "norm", dict, ctx)
        if "tool_deltas" in norm and norm["tool_deltas"] is not None:
            if not isinstance(norm["tool_deltas"], list) or not all(isinstance(td, dict) for td in norm["tool_deltas"]):
                raise TraceSchemaError(f"{ctx}: field 'norm.tool_deltas' must be list of objects")
        if "usage" in norm and norm["usage"] is not None and not isinstance(norm["usage"], dict):
            raise TraceSchemaError(f"{ctx}: field 'norm.usage' must be object or null")
        frames.append(
            TraceFrame(
                seq=seq,
                t_rel_ms=t_rel,
                dt_ms=dt,
                sse_event=sse_ev,
                raw_wire=raw_wire,
                is_done_sentinel=is_done,
                parse_error=parse_err,
                norm=norm,
            )
        )

    if total_frames != len(frames):
        raise TraceSchemaError(
            f"{src}: summary.total_frames={total_frames} != actual frames={len(frames)}"
        )

    header = TraceHeader(
        trace_id=trace_id,
        label=label,
        recorded_at_utc=recorded_at,
        dialect=dialect,
        request=req_copy,
        response_meta=dict(resp_meta),
        backend_probe=bp_hdr,
        schema_version=SCHEMA_VERSION,
    )
    summary = TraceSummary(
        eof_clean=eof_clean,
        total_frames=total_frames,
        timing=dict(timing),
        assembled=dict(assembled),
        backend_probe=bp_sum,
    )
    return TraceDocument(header=header, frames=frames, summary=summary)
