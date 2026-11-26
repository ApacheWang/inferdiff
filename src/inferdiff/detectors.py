"""Pure deterministic silent-failure detectors (D1..D5) with zero-false-positive guards."""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional, Set

from .schema import TraceDocument, is_strict_int, safe_utf8_len

D1 = "D1"
D2 = "D2"
D3 = "D3"
D4 = "D4"
D5 = "D5"

VALID_AUDIT_DETECTORS = frozenset({D1, D2, D3, D4})

DETECTOR_NAMES = {
    D1: "UNCLOSED_TOOL_CALL_SUCCESS",
    D2: "GHOST_BUDGET_EMPTY_OUTPUT",
    D3: "SILENT_SHORT_GENERATION",
    D4: "STREAM_PREMATURE_EOF",
    D5: "BENCHMARK_ILLUSION_ALERT",
}


@dataclass
class Finding:
    detector_id: str
    code: str
    severity: str  # "P0" | "P1"
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
    stopped_empty = finish_reason == "stop"

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


def audit_trace(doc: TraceDocument, *, only: Optional[Set[str]] = None) -> List[Finding]:
    """Run D1..D4 (or validated subset via `only`) on a single TraceDocument."""
    if only is not None:
        normalized = {d.strip().upper() for d in only if d.strip()}
        unknown = sorted(normalized - VALID_AUDIT_DETECTORS)
        if not normalized or unknown:
            raise ValueError(
                f"Invalid --only detector selection: {sorted(only)!r} (valid for audit: D1, D2, D3, D4)"
            )
        active = normalized
    else:
        active = set(VALID_AUDIT_DETECTORS)

    findings: List[Finding] = []
    if D1 in active:
        findings.extend(detect_d1(doc))
    if D2 in active:
        findings.extend(detect_d2(doc))
    if D3 in active:
        findings.extend(detect_d3(doc))
    if D4 in active:
        findings.extend(detect_d4(doc))
    findings.sort(key=lambda f: (0 if f.severity == "P0" else 1, f.detector_id))
    return findings
