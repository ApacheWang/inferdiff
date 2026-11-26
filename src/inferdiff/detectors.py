"""Deterministic silent-failure and storage/inference detectors (D1..D8)."""

from __future__ import annotations

from dataclasses import dataclass, field
from decimal import Decimal
from typing import Any, Dict, List, Optional, Set

from ._probe_data import MOONCAKE_STORAGE_READ_COUNTERS
from .schema import TraceDocument, frame_has_effective_payload, is_finite_number, is_strict_int, safe_utf8_len

D1 = "D1"
D2 = "D2"
D3 = "D3"
D4 = "D4"
D5 = "D5"
D6 = "D6"
D7 = "D7"
D8 = "D8"

DETECTOR_NAMES = {
    D1: "UNCLOSED_TOOL_CALL_SUCCESS",
    D2: "GHOST_BUDGET_EMPTY_OUTPUT",
    D3: "SILENT_SHORT_GENERATION",
    D4: "STREAM_PREMATURE_EOF",
    D5: "BENCHMARK_ILLUSION_ALERT",
    D6: "PAGE_CACHE_WARM_ILLUSION",
    D7: "LOOKUP_HIT_PREFETCH_DROP",
    D8: "OFFLOAD_SLOWER_THAN_RECOMPUTE",
}

VALID_AUDIT_DETECTORS = frozenset(DETECTOR_NAMES) - {D5}
AUDIT_RULE_LIST = ", ".join(sorted(VALID_AUDIT_DETECTORS))
_MIB = 1024 * 1024


@dataclass
class Finding:
    detector_id: str
    code: str
    severity: str  # "P0" | "P1" | "P2"
    message: str
    frame_seq: Optional[int] = None
    evidence: Dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "detector_id": self.detector_id,
            "code": self.code,
            "severity": self.severity,
            "message": self.message,
            "frame_seq": self.frame_seq,
            "evidence": self.evidence,
        }


def _last_terminal_seq(doc: TraceDocument) -> Optional[int]:
    for frame in reversed(doc.frames):
        norm = frame.norm or {}
        if norm.get("finish_reason") or norm.get("terminal_status"):
            return frame.seq
    for frame in reversed(doc.frames):
        norm = frame.norm or {}
        if norm.get("phase") == "TERMINAL":
            return frame.seq
    return doc.frames[-1].seq if doc.frames else None


def _has_inband_error(doc: TraceDocument) -> bool:
    return any((f.norm or {}).get("phase") == "ERROR" or (f.norm or {}).get("inband_error") for f in doc.frames)


def detect_d1(doc: TraceDocument) -> List[Finding]:
    """D1 (P0): Tool call JSON unclosed/invalid, conflicting, mismatched, or missing Responses .done while claiming success."""
    if doc.header.response_meta.get("status_code") != 200:
        return []
    asm = doc.summary.assembled
    tool_calls = asm.get("tool_calls") or []
    if not tool_calls:
        return []

    finish_reason = asm.get("finish_reason", "unknown")
    terminal_status = asm.get("terminal_status", "unknown")
    claims_success = (finish_reason in ("stop", "tool_calls")) or (terminal_status == "completed")
    if not claims_success:
        return []

    findings: List[Finding] = []
    dialect = doc.header.dialect
    term_seq = _last_terminal_seq(doc)

    for tc in tool_calls:
        invalid_json = tc.get("json_valid") is False
        saw_delta = tc.get("saw_args_delta")
        if saw_delta is None:
            saw_delta = tc.get("saw_args_done_event") is False
        missing_done = (
            dialect == "openai-responses"
            and bool(saw_delta)
            and tc.get("saw_args_done_event") is False
        )
        args_mismatch = bool(tc.get("args_mismatch"))
        identity_conflict = bool(tc.get("identity_conflict"))

        if invalid_json or missing_done or args_mismatch or identity_conflict:
            reasons: List[str] = []
            if invalid_json:
                reasons.append(f"json_valid=false ({tc.get('json_error')})")
            if missing_done:
                reasons.append("missing response.function_call_arguments.done")
            if args_mismatch:
                reasons.append(str(tc.get("args_mismatch_detail") or "streamed arguments mismatch final snapshot"))
            if identity_conflict:
                reasons.append("conflicting tool call identity on shared index")

            cite_seq = tc.get("last_seq") if is_strict_int(tc.get("last_seq")) else term_seq
            if missing_done and term_seq is not None:
                cite_seq = term_seq
            findings.append(
                Finding(
                    detector_id=D1,
                    code=DETECTOR_NAMES[D1],
                    severity="P0",
                    message=(
                        f"Tool call #{tc.get('index')} ({tc.get('name') or 'unnamed'}) reported terminal "
                        f"'{terminal_status if terminal_status != 'unknown' else finish_reason}' with "
                        + " and ".join(reasons)
                    ),
                    frame_seq=cite_seq,
                    evidence={
                        "tool_index": tc.get("index"),
                        "tool_name": tc.get("name"),
                        "raw_args_bytes": safe_utf8_len(tc.get("raw_arguments") or ""),
                        "json_valid": tc.get("json_valid"),
                        "json_error": tc.get("json_error"),
                        "saw_args_delta": tc.get("saw_args_delta"),
                        "saw_args_done_event": tc.get("saw_args_done_event"),
                        "args_mismatch": args_mismatch,
                        "identity_conflict": identity_conflict,
                        "finish_reason": finish_reason,
                        "terminal_status": terminal_status,
                    },
                )
            )
    return findings


def detect_d2(doc: TraceDocument) -> List[Finding]:
    """D2 (P0): HTTP 200 with empty visible content and no tools despite consumed budget / reasoning / stop."""
    if doc.header.response_meta.get("status_code") != 200:
        return []
    if _has_inband_error(doc):
        return []
    asm = doc.summary.assembled
    content_text = asm.get("content_text") or ""
    tool_calls = asm.get("tool_calls") or []
    if content_text.strip() != "" or len(tool_calls) > 0:
        return []

    finish_reason = asm.get("finish_reason", "unknown")
    matched_stop = asm.get("matched_stop")
    eff = doc.header.request.get("effective_params") or {}
    stop_conditions = eff.get("stop_conditions") or []
    usage = asm.get("reported_usage") or {}
    comp_tokens = usage.get("completion_tokens")
    reasoning_text = asm.get("reasoning_text") or ""
    has_unclosed_think = bool(asm.get("has_unclosed_think"))

    # Spec §4.2: nonempty reasoning predicate (any reasoning characters or unclosed <think>)
    has_reasoning = (reasoning_text != "") or has_unclosed_think

    if doc.header.dialect == "gemini-sse" and doc.summary.eof_clean and finish_reason == "MAX_TOKENS":
        thought_tokens = usage.get("reasoning_tokens")
        if has_reasoning or (is_strict_int(thought_tokens) and thought_tokens > 0):
            return []  # Gemini can use the entire budget for thinking.

    # Observed stop-match guard: only suppress D2 when the reported matched_stop actually
    # corresponds to one of the request's configured stop conditions (strict type match).
    matched_configured_stop = (
        matched_stop is not None
        and any(
            (type(matched_stop) is type(sc)) and (matched_stop == sc)
            for sc in stop_conditions
        )
    )
    if matched_configured_stop and not has_reasoning:
        return []

    has_tokens = is_strict_int(comp_tokens) and comp_tokens >= 1
    stopped_empty = finish_reason == "stop" or (doc.header.dialect == "gemini-sse" and finish_reason == "STOP")

    if has_tokens or has_reasoning or stopped_empty:
        return [
            Finding(
                detector_id=D2,
                code=DETECTOR_NAMES[D2],
                severity="P0",
                message=(
                    f"HTTP 200 returned empty visible content and 0 tool calls "
                    f"(completion_tokens={comp_tokens}, reasoning_chars={len(reasoning_text)}, "
                    f"unclosed_think={has_unclosed_think}, finish_reason={finish_reason})"
                ),
                frame_seq=_last_terminal_seq(doc),
                evidence={
                    "completion_tokens": comp_tokens,
                    "reasoning_chars": len(reasoning_text),
                    "has_unclosed_think": has_unclosed_think,
                    "finish_reason": finish_reason,
                    "terminal_status": asm.get("terminal_status"),
                    "matched_stop": matched_stop,
                },
            )
        ]
    return []


def detect_d3(doc: TraceDocument) -> List[Finding]:
    """D3 (P1): Fixed-length benchmark (ignore_eos=true, no effective stop) generated fewer tokens than budget."""
    if doc.header.response_meta.get("status_code") != 200:
        return []
    eff = doc.header.request.get("effective_params") or {}
    if eff.get("ignore_eos") is not True:
        return []
    budget = eff.get("max_budget_tokens")
    if not (is_strict_int(budget) and budget > 0):
        return []
    if eff.get("stop_conditions"):
        return []

    asm = doc.summary.assembled
    usage = asm.get("reported_usage") or {}
    comp = usage.get("completion_tokens")
    if not is_strict_int(comp):
        return []
    if comp < budget:
        return [
            Finding(
                detector_id=D3,
                code=DETECTOR_NAMES[D3],
                severity="P1",
                message=(
                    f"Fixed-length request (ignore_eos=true, budget={budget}) produced only "
                    f"{comp}/{budget} completion tokens (finish_reason={asm.get('finish_reason')})"
                ),
                frame_seq=_last_terminal_seq(doc),
                evidence={
                    "requested_budget": budget,
                    "completion_tokens": comp,
                    "finish_reason": asm.get("finish_reason"),
                    "saw_textless_usage_frame": bool(asm.get("saw_textless_usage_frame")),
                },
            )
        ]
    return []


def detect_d4(doc: TraceDocument) -> List[Finding]:
    """D4 (P0): HTTP 2xx stream ended prematurely, violated terminal order, or used unsupported 2xx status (e.g. 204)."""
    status_code = doc.header.response_meta.get("status_code")
    if not is_strict_int(status_code) or status_code < 200 or status_code >= 300:
        return []

    reasons: List[str] = []
    if status_code != 200:
        reasons.append(f"unexpected_2xx_status={status_code}")

    parse_errors = [(f.seq, f.parse_error) for f in doc.frames if f.parse_error]
    asm = doc.summary.assembled
    protocol_violations = asm.get("protocol_violations") or []
    no_terminal_state = (
        not _has_inband_error(doc)
        and asm.get("finish_reason", "unknown") == "unknown"
        and asm.get("terminal_status", "unknown") == "unknown"
    )
    if not doc.summary.eof_clean:
        reasons.append("eof_clean=false (missing terminal sentinel, framing error, or socket dropped)")
    if parse_errors:
        reasons.append(f"parse_errors={parse_errors[:3]}")
    if protocol_violations:
        reasons.append(f"protocol_violations={protocol_violations[:3]}")
    if no_terminal_state:
        reasons.append("missing finish_reason and terminal_status")

    if reasons:
        first_err_seq = parse_errors[0][0] if parse_errors else (doc.frames[-1].seq if doc.frames else None)
        return [
            Finding(
                detector_id=D4,
                code=DETECTOR_NAMES[D4],
                severity="P0",
                message=f"HTTP {status_code} stream terminated uncleanly: " + "; ".join(reasons),
                frame_seq=first_err_seq,
                evidence={
                    "status_code": status_code,
                    "eof_clean": doc.summary.eof_clean,
                    "total_frames": doc.summary.total_frames,
                    "parse_errors": parse_errors,
                    "protocol_violations": protocol_violations,
                    "finish_reason": asm.get("finish_reason"),
                    "terminal_status": asm.get("terminal_status"),
                },
            )
        ]
    return []


def _max_consecutive_burst_run(doc: TraceDocument) -> int:
    """Return length of longest contiguous run of sub-0.5ms elapsed intervals between text delta frames."""
    max_run = 0
    cur_run = 0
    prev_delta_t_ms: Optional[float] = None
    for f in doc.frames:
        has_text = bool((f.norm or {}).get("text_delta"))
        if not has_text:
            continue
        if prev_delta_t_ms is not None and (f.t_rel_ms - prev_delta_t_ms) < 0.5:
            cur_run += 1
            if cur_run > max_run:
                max_run = cur_run
        else:
            cur_run = 0
        prev_delta_t_ms = f.t_rel_ms
    return max_run


def detect_d5(
    before: TraceDocument,
    after: TraceDocument,
    *,
    ignore_timing: bool = False,
    min_delta_ms: float = 0.0,
) -> List[Finding]:
    """D5 (P1): Benchmark illusion alert when after latency drops >50%."""
    if ignore_timing:
        return []
    b_time = before.summary.timing
    a_time = after.summary.timing
    b_total = b_time.get("total_ms")
    a_total = a_time.get("total_ms")
    b_ttft = b_time.get("ttft_effective_ms")
    a_ttft = a_time.get("ttft_effective_ms")

    total_drop = (
        isinstance(b_total, (int, float))
        and isinstance(a_total, (int, float))
        and b_total > 0
        and (b_total - a_total) >= min_delta_ms
        and a_total < 0.5 * b_total
    )
    ttft_drop = (
        isinstance(b_ttft, (int, float))
        and isinstance(a_ttft, (int, float))
        and b_ttft > 0
        and (b_ttft - a_ttft) >= min_delta_ms
        and a_ttft < 0.5 * b_ttft
    )
    if not (total_drop or ttft_drop):
        return []

    sub_reasons: List[str] = []
    evidence: Dict[str, Any] = {
        "before_total_ms": b_total,
        "after_total_ms": a_total,
        "before_ttft_effective_ms": b_ttft,
        "after_ttft_effective_ms": a_ttft,
    }

    # (a) Asymmetric cached_tokens jump (requires reported cache evidence — never fabricate from unknown)
    b_usage = before.summary.assembled.get("reported_usage") or {}
    a_usage = after.summary.assembled.get("reported_usage") or {}
    b_cached = b_usage.get("cached_tokens", "unknown")
    a_cached = a_usage.get("cached_tokens", "unknown")
    evidence["before_cached_tokens"] = b_cached
    evidence["after_cached_tokens"] = a_cached
    if is_strict_int(a_cached) and a_cached > 0 and (not is_strict_int(b_cached) or a_cached > b_cached):
        sub_reasons.append(f"D5a asymmetric cached_tokens jump ({b_cached} -> {a_cached})")

    # (b) After output volume collapsed below 50% of before
    b_comp = b_usage.get("completion_tokens")
    a_comp = a_usage.get("completion_tokens")
    b_bytes = before.summary.assembled.get("content_utf8_bytes", 0)
    a_bytes = after.summary.assembled.get("content_utf8_bytes", 0)
    if is_strict_int(b_comp) and is_strict_int(a_comp) and b_comp > 0 and a_comp < 0.5 * b_comp:
        sub_reasons.append(f"D5b output token collapse ({a_comp}/{b_comp} tokens)")
    elif b_bytes > 0 and a_bytes < 0.5 * b_bytes:
        sub_reasons.append(f"D5b output byte collapse ({a_bytes}/{b_bytes} bytes)")

    # (c) Burst-pulse distortion (avg bytes/frame doubled + consecutive sub-0.5ms burst cluster)
    b_df = max(1, int(before.summary.assembled.get("observed_delta_frames") or 0))
    a_df = max(1, int(after.summary.assembled.get("observed_delta_frames") or 0))
    b_avg = b_bytes / b_df if b_bytes > 0 else 0.0
    a_avg = a_bytes / a_df if a_bytes > 0 else 0.0
    burst_run = _max_consecutive_burst_run(after)
    if b_avg > 0 and a_avg >= 2.0 * b_avg and burst_run >= 2:
        sub_reasons.append(
            f"D5c bursty multi-token frames (avg {b_avg:.1f}B -> {a_avg:.1f}B, {burst_run} consecutive intervals dt<0.5ms)"
        )
        evidence["max_consecutive_burst_intervals"] = burst_run

    if not sub_reasons:
        return []

    return [
        Finding(
            detector_id=D5,
            code=DETECTOR_NAMES[D5],
            severity="P1",
            message="Benchmark speedup >50% flagged as potential illusion: " + "; ".join(sub_reasons),
            frame_seq=None,
            evidence={**evidence, "sub_reasons": sub_reasons},
        )
    ]


def _section(parent: Dict[str, Any], key: str) -> Dict[str, Any]:
    value = parent.get(key)
    return value if isinstance(value, dict) else {}


def _count(section: Dict[str, Any], key: str, default: Any = None) -> int | None:
    value = section.get(key)
    return value if is_strict_int(value) and is_finite_number(value) and value >= 0 else default


def _number(section: Dict[str, Any], key: str, default: Any = None) -> int | float | None:
    value = section.get(key)
    return value if is_finite_number(value) and value >= 0 else default


def _usable_prefill(backend: Dict[str, Any]) -> Dict[str, Any]:
    proc = _section(backend, "proc_io")
    prefill = _section(proc, "prefill_window")
    if proc.get("status") == "process_changed" or prefill.get("status", "ok") != "ok":
        return {}
    return prefill


def _l2_hit(lmcache: Dict[str, Any]) -> bool:
    return any(_count(lmcache, key, 0) > 0 for key in ("delta_hit_l2_tokens", "delta_hit_l2_keys"))


def _storage_load_seen(backend: Dict[str, Any]) -> bool:
    lmcache = _section(backend, "lmcache_mp")
    client = _section(_section(backend, "mooncake"), "client_deltas")
    return _l2_hit(lmcache) or _count(lmcache, "delta_l2_load_completed", 0) > 0 or any(
        _count(client, name, 0) > 0 for name in MOONCAKE_STORAGE_READ_COUNTERS
    )


def _first_effective_seq(doc: TraceDocument) -> Optional[int]:
    return next((f.seq for f in doc.frames if frame_has_effective_payload(f.norm)), None)


def detect_d6(doc: TraceDocument) -> List[Finding]:
    """D6 (P1): large logical reads with no evidence of physical reads during prefill."""
    backend = doc.summary.backend_probe or {}
    prefill = _usable_prefill(backend)
    rchar = _count(prefill, "delta_rchar_bytes", 0)
    if rchar < 32 * _MIB or _count(prefill, "delta_read_bytes") != 0:
        return []

    l2_active = _storage_load_seen(backend)
    if not l2_active and rchar < 64 * _MIB:
        return []
    message = (
        "Backend cache activity coincided with large process-wide logical reads and zero physical reads "
        "during prefill, consistent with a warm page cache or buffered I/O fallback."
        if l2_active else
        "Process-wide correlation during prefill: large logical reads and zero physical reads. "
        "The source of the reads is unverified."
    )
    return [Finding(
        D6, DETECTOR_NAMES[D6], "P1" if l2_active else "P2", message + " See LMCache#4364.",
        frame_seq=_first_effective_seq(doc),
        evidence={"delta_rchar_bytes": rchar, "delta_read_bytes": 0, "l2_active": l2_active,
                  "reference": "https://github.com/LMCache/LMCache/issues/4364"},
    )]


def detect_d7(doc: TraceDocument) -> List[Finding]:
    """D7 (P1): direct delivery failures or indirect failures with L2 hit evidence."""
    backend = doc.summary.backend_probe or {}
    lmcache = _section(backend, "lmcache_mp")
    tokens = _count(lmcache, "delta_hit_l2_tokens", 0)
    keys = _count(lmcache, "delta_hit_l2_keys", 0)

    failures = _section(lmcache, "delta_l2_prefetch_failures")
    prefetch_failed = any(_count(failures, reason, 0) > 0 for reason in failures)
    l1 = _count(lmcache, "delta_l1_read_failures", 0)
    quota = _count(_section(backend, "mooncake"), "delta_quota_rejects", 0)
    dropped = max(_count(lmcache, "delta_event_bus_dropped", 0), _count(lmcache, "event_bus_dropped", 0))
    if not (prefetch_failed or l1 or ((tokens or keys) and (quota or dropped))):
        return []
    message = (
        "Backend counters recorded failures in the cache delivery path."
        if prefetch_failed or l1 else "L2 hits coincided with backend quota rejects or event bus drops."
    )
    return [Finding(
        D7, DETECTOR_NAMES[D7], "P1",
        message,
        evidence={"delta_hit_l2_tokens": tokens, "delta_hit_l2_keys": keys, "l2_prefetch_failed": prefetch_failed,
                  "delta_l1_read_failures": l1, "delta_quota_rejects": quota, "delta_event_bus_dropped": dropped},
    )]


def _small_reads(prefill: Dict[str, Any], min_syscalls: int) -> bool:
    return _number(prefill, "avg_syscall_read_kb", float("inf")) <= 8.0 and (
        _count(prefill, "delta_syscr", 0) >= min_syscalls
    )


def detect_d8(doc: TraceDocument) -> List[Finding]:
    """D8 (P1): severe fragmented physical reads during a single prefill."""
    backend = doc.summary.backend_probe or {}
    prefill = _usable_prefill(backend)
    if (_count(prefill, "delta_read_bytes", 0) < 16 * _MIB
            or not _small_reads(prefill, 2048) or not _storage_load_seen(backend)):
        return []
    return [Finding(
        D8, DETECTOR_NAMES[D8], "P1",
        "Backend cache activity coincided with at least 16 MiB of process-wide physical reads "
        "and thousands of small read syscalls during prefill, consistent with fragmented offload I/O.",
        frame_seq=_first_effective_seq(doc),
        evidence={key: prefill[key] for key in ("delta_read_bytes", "delta_syscr", "avg_syscall_read_kb")},
    )]


def detect_d8_pair(
    before: TraceDocument,
    after: TraceDocument,
    *,
    ignore_timing: bool = False,
    min_delta_ms: float = 0.0,
) -> List[Finding]:
    """D8 (P1): a >=30% effective TTFT regression with target storage evidence."""
    backend = after.summary.backend_probe
    if ignore_timing or not backend:
        return []
    before_ttft = _number(before.summary.timing, "ttft_effective_ms", 0)
    after_ttft = _number(after.summary.timing, "ttft_effective_ms", 0)
    if before_ttft <= 0 or not is_finite_number(min_delta_ms):
        return []
    start, end = Decimal(str(before_ttft)), Decimal(str(after_ttft))
    if end - start < Decimal(str(min_delta_ms)) or end < start * Decimal("1.30"):
        return []

    if not _storage_load_seen(backend):
        return []
    prefill = _usable_prefill(backend)
    rchar = _count(prefill, "delta_rchar_bytes", 0)
    reads = _count(prefill, "delta_read_bytes", 0)
    writes = _count(prefill, "delta_write_bytes_net", 0)
    reasons = []
    if reads >= _MIB and _small_reads(prefill, 1024):
        reasons.append("many small read syscalls and at least 1 MiB of physical reads")
    if writes >= 64 * _MIB:
        reasons.append("heavy writes consistent with disk contention")
    if rchar >= _MIB and reads >= 2 * rchar:
        reasons.append("physical read amplification of at least 2x")
    if not reasons:
        return []
    return [Finding(
        D8, DETECTOR_NAMES[D8], "P1",
        "Effective TTFT regressed by at least 30% with backend cache activity and "
        "process-wide prefill I/O: " + ", ".join(reasons) + ".",
        frame_seq=_first_effective_seq(after),
        evidence={"before_ttft_effective_ms": before_ttft, "after_ttft_effective_ms": after_ttft,
                  "delta_rchar_bytes": _count(prefill, "delta_rchar_bytes"),
                  "delta_read_bytes": _count(prefill, "delta_read_bytes"),
                  "delta_write_bytes_net": _count(prefill, "delta_write_bytes_net"),
                  "delta_syscr": _count(prefill, "delta_syscr"),
                  "avg_syscall_read_kb": _number(prefill, "avg_syscall_read_kb"), "sub_reasons": reasons},
    )]


_SINGLE_TRACE_DETECTORS = {
    D1: detect_d1, D2: detect_d2, D3: detect_d3, D4: detect_d4,
    D6: detect_d6, D7: detect_d7, D8: detect_d8,
}


def audit_trace(doc: TraceDocument, *, only: Optional[Set[str]] = None) -> List[Finding]:
    """Run single-trace detectors."""
    if only is not None:
        normalized = {d.strip().upper() for d in only if d.strip()}
        unknown = sorted(normalized - VALID_AUDIT_DETECTORS)
        if not normalized or unknown:
            raise ValueError(
                f"Invalid --only detector selection: {sorted(only)!r} (valid for audit: {AUDIT_RULE_LIST})"
            )
        active = normalized
    else:
        active = set(VALID_AUDIT_DETECTORS)

    findings: List[Finding] = []
    for detector_id, detect in _SINGLE_TRACE_DETECTORS.items():
        if detector_id in active:
            findings.extend(detect(doc))
    findings.sort(key=lambda f: (f.severity, f.detector_id))
    return findings
