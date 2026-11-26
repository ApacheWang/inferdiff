"""Anti-chunk-jitter two-layer semantic alignment and exact physical frame back-mapping."""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional, Tuple

from .detectors import Finding, audit_trace, detect_d5, detect_d8_pair
from .schema import (
    EXIT_OK,
    EXIT_SEMANTIC_REGRESSION,
    EXIT_SILENT_PROTOCOL_BREACH,
    TraceDocument,
    TraceFrame,
    is_strict_int,
    strict_json_loads,
)


@dataclass
class DivergencePoint:
    category: str  # "CONTENT" | "REASONING" | "TOOL_CALL" | "TERMINAL" | "EOF" | "USAGE"
    detail: str
    before_seq: Optional[int]
    before_t_rel_ms: Optional[float]
    before_raw_wire: Optional[str]
    after_seq: Optional[int]
    after_t_rel_ms: Optional[float]
    after_raw_wire: Optional[str]

    def to_dict(self, *, include_wire: bool = True) -> Dict[str, Any]:
        return {
            "category": self.category,
            "detail": self.detail,
            "before_seq": self.before_seq,
            "before_t_rel_ms": self.before_t_rel_ms,
            "before_raw_wire": self.before_raw_wire if include_wire else None,
            "after_seq": self.after_seq,
            "after_t_rel_ms": self.after_t_rel_ms,
            "after_raw_wire": self.after_raw_wire if include_wire else None,
        }


@dataclass
class DiffReport:
    before_label: str
    after_label: str
    before_dialect: str
    after_dialect: str
    before_findings: List[Finding]
    after_findings: List[Finding]
    pair_findings: List[Finding]
    new_findings: List[Finding]
    semantic_equal: bool
    terminal_drifted: bool
    ttft_regressed: bool
    ttft_delta_pct: Optional[float]
    first_divergence: Optional[DivergencePoint]
    exit_code: int
    summary_table: Dict[str, Any] = field(default_factory=dict)

    def to_dict(self, *, include_wire: bool = True) -> Dict[str, Any]:
        return {
            "before_label": self.before_label,
            "after_label": self.after_label,
            "before_dialect": self.before_dialect,
            "after_dialect": self.after_dialect,
            "semantic_equal": self.semantic_equal,
            "terminal_drifted": self.terminal_drifted,
            "ttft_regressed": self.ttft_regressed,
            "ttft_delta_pct": self.ttft_delta_pct,
            "first_divergence": self.first_divergence.to_dict(include_wire=include_wire) if self.first_divergence else None,
            "before_findings": [f.to_dict() for f in self.before_findings],
            "after_findings": [f.to_dict() for f in self.after_findings],
            "pair_findings": [f.to_dict() for f in self.pair_findings],
            "new_findings": [f.to_dict() for f in self.new_findings],
            "summary_table": self.summary_table,
            "exit_code": self.exit_code,
        }


def _extract_semantic_text_streams(
    doc: TraceDocument,
) -> Tuple[str, List[Tuple[int, int, int]], str, List[Tuple[int, int, int]]]:
    """Extract normalized (visible_text, visible_spans, reasoning_text, reasoning_spans).

    Chronologically interleaves dedicated reasoning_delta and inline <think>...</think> spans
    frame-by-frame (handling tags split across frame boundaries) so mixed inline + dedicated
    reasoning produces identical normalized streams.
    """
    vis_chars: List[str] = []
    vis_seqs: List[int] = []
    reas_chars: List[str] = []
    reas_seqs: List[int] = []

    depth = 0
    # Pending character buffer for potential "<think>" (7) or "</think>" (8) split across frames
    pending_chars: List[str] = []
    pending_seqs: List[int] = []

    def _emit_char(ch: str, seq: int) -> None:
        if depth > 0:
            reas_chars.append(ch)
            reas_seqs.append(seq)
        else:
            vis_chars.append(ch)
            vis_seqs.append(seq)

    def _drain_pending(*, flush_all: bool) -> None:
        nonlocal depth, pending_chars, pending_seqs
        while pending_chars:
            s = "".join(pending_chars)
            if s.startswith("<think>"):
                depth += 1
                del pending_chars[:7]
                del pending_seqs[:7]
                continue
            if s.startswith("</think>"):
                if depth > 0:
                    depth -= 1
                else:
                    for ch, sq in zip(pending_chars[:8], pending_seqs[:8]):
                        vis_chars.append(ch)
                        vis_seqs.append(sq)
                del pending_chars[:8]
                del pending_seqs[:8]
                continue
            if not flush_all and ("<think>".startswith(s) or "</think>".startswith(s)):
                break
            _emit_char(pending_chars.pop(0), pending_seqs.pop(0))

    for f in doc.frames:
        norm = f.norm or {}
        rd = norm.get("reasoning_delta") or ""
        if rd:
            for ch in rd:
                reas_chars.append(ch)
                reas_seqs.append(f.seq)
        td = norm.get("text_delta") or ""
        if td:
            for ch in td:
                pending_chars.append(ch)
                pending_seqs.append(f.seq)
                _drain_pending(flush_all=False)

    _drain_pending(flush_all=True)

    def _compress_spans(seqs: List[int]) -> List[Tuple[int, int, int]]:
        if not seqs:
            return []
        spans: List[Tuple[int, int, int]] = []
        start = 0
        cur_seq = seqs[0]
        for idx in range(1, len(seqs)):
            if seqs[idx] != cur_seq:
                spans.append((start, idx, cur_seq))
                start = idx
                cur_seq = seqs[idx]
        spans.append((start, len(seqs), cur_seq))
        return spans

    return (
        "".join(vis_chars),
        _compress_spans(vis_seqs),
        "".join(reas_chars),
        _compress_spans(reas_seqs),
    )


def _build_tool_arg_offset_map(doc: TraceDocument, tc: Dict[str, Any], k: int) -> Tuple[str, List[Tuple[int, int, int]]]:
    """Build argument char-offset -> physical frame map for logical tool call `tc`."""
    tool_idx = tc.get("index", k)
    tool_id = tc.get("id")
    tool_item_id = tc.get("item_id")

    def _matches(td: Dict[str, Any]) -> bool:
        if tool_item_id and td.get("item_id") == tool_item_id:
            return True
        if tool_id and td.get("id") == tool_id:
            return True
        if td.get("index") == tool_idx:
            return True
        if td.get("index") is None and tool_idx == 0 and not td.get("item_id") and not td.get("id"):
            return True
        return False

    parts: List[str] = []
    spans: List[Tuple[int, int, int]] = []
    cursor = 0
    for f in doc.frames:
        for td in (f.norm or {}).get("tool_deltas") or []:
            if not isinstance(td, dict):
                continue
            if _matches(td):
                ad = td.get("arguments_delta") or td.get("args_delta") or ""
                if ad:
                    end = cursor + len(ad)
                    parts.append(ad)
                    spans.append((cursor, end, f.seq))
                    cursor = end
    if parts:
        return "".join(parts), spans

    # Fallback to recorded snapshot_seq / raw_arguments
    raw_args = tc.get("raw_arguments") or ""
    snap_seq = tc.get("done_seq") if is_strict_int(tc.get("done_seq")) else tc.get("snapshot_seq")
    if snap_seq is None:
        snap_seq = tc.get("first_seq")
    if raw_args and is_strict_int(snap_seq):
        return raw_args, [(0, len(raw_args), snap_seq)]
    return raw_args, []


def _lookup_frame_for_offset(spans: List[Tuple[int, int, int]], offset: int, fallback_seq: Optional[int]) -> Optional[int]:
    for start, end, seq in spans:
        if start <= offset < end:
            return seq
    if spans:
        return spans[-1][2]
    return fallback_seq


def _terminal_frame(doc: TraceDocument) -> Optional[TraceFrame]:
    for f in reversed(doc.frames):
        norm = f.norm or {}
        if norm.get("finish_reason") or norm.get("terminal_status"):
            return f
    for f in reversed(doc.frames):
        norm = f.norm or {}
        if norm.get("phase") == "TERMINAL":
            return f
    return doc.frames[-1] if doc.frames else None


def _usage_frame_seq(doc: TraceDocument, fallback: Optional[int]) -> Optional[int]:
    for f in reversed(doc.frames):
        u = (f.norm or {}).get("usage")
        if isinstance(u, dict) and is_strict_int(u.get("completion_tokens")):
            return f.seq
    return fallback


def _eof_violation_seq(doc: TraceDocument, fallback: Optional[int]) -> Optional[int]:
    for f in doc.frames:
        if f.parse_error or (f.norm or {}).get("protocol_error"):
            return f.seq
    if doc.frames:
        return doc.frames[-1].seq
    return fallback


def _frame_by_seq(doc: TraceDocument, seq: Optional[int]) -> Optional[TraceFrame]:
    if seq is None or seq < 0 or seq >= len(doc.frames):
        return None
    return doc.frames[seq]


def _make_div(
    category: str,
    detail: str,
    before: TraceDocument,
    b_seq: Optional[int],
    after: TraceDocument,
    a_seq: Optional[int],
) -> DivergencePoint:
    bf = _frame_by_seq(before, b_seq)
    af = _frame_by_seq(after, a_seq)
    return DivergencePoint(
        category=category,
        detail=detail,
        before_seq=bf.seq if bf else None,
        before_t_rel_ms=bf.t_rel_ms if bf else None,
        before_raw_wire=bf.raw_wire if bf else None,
        after_seq=af.seq if af else None,
        after_t_rel_ms=af.t_rel_ms if af else None,
        after_raw_wire=af.raw_wire if af else None,
    )


def _first_char_diff(a: str, b: str) -> Optional[int]:
    lim = min(len(a), len(b))
    for i in range(lim):
        if a[i] != b[i]:
            return i
    if len(a) != len(b):
        return lim
    return None


def _tool_is_closed(tc: Dict[str, Any], dialect: str) -> bool:
    if tc.get("json_valid") is not True:
        return False
    if tc.get("args_mismatch") or tc.get("identity_conflict"):
        return False
    saw_delta = tc.get("saw_args_delta")
    if saw_delta is None:
        saw_delta = tc.get("saw_args_done_event") is False
    if dialect == "openai-responses" and bool(saw_delta) and tc.get("saw_args_done_event") is False:
        return False
    return True


def _json_strict_equal(a: Any, b: Any) -> bool:
    """Strict JSON value equality (prevents Python bool True == 1 / False == 0 collapse)."""
    if isinstance(a, bool) or isinstance(b, bool):
        return isinstance(a, bool) and isinstance(b, bool) and a is b
    if isinstance(a, dict) and isinstance(b, dict):
        if len(a) != len(b) or set(a.keys()) != set(b.keys()):
            return False
        return all(_json_strict_equal(a[k], b[k]) for k in a)
    if isinstance(a, list) and isinstance(b, list):
        if len(a) != len(b):
            return False
        return all(_json_strict_equal(x, y) for x, y in zip(a, b))
    return type(a) is type(b) and a == b if not isinstance(a, (int, float)) else (isinstance(b, (int, float)) and not isinstance(b, bool) and a == b)


def _compare_tool_args_structurally(bt: Dict[str, Any], at: Dict[str, Any]) -> bool:
    """Return True if both tool calls have strict-valid JSON representing equal values (key-order invariant, strict types)."""
    if bt.get("json_valid") is not True or at.get("json_valid") is not True:
        return False
    try:
        return _json_strict_equal(
            strict_json_loads(bt.get("raw_arguments") or ""),
            strict_json_loads(at.get("raw_arguments") or ""),
        )
    except Exception:
        return False


def _terminal_drifted(before: TraceDocument, after: TraceDocument) -> bool:
    b_asm = before.summary.assembled
    a_asm = after.summary.assembled
    b_sig = (b_asm.get("finish_reason", "unknown"), b_asm.get("terminal_status", "unknown"))
    a_sig = (a_asm.get("finish_reason", "unknown"), a_asm.get("terminal_status", "unknown"))

    # Within the same dialect, preserve distinct terminal reasons (e.g. stop -> tool_calls)
    if before.header.dialect == after.header.dialect:
        return b_sig != a_sig

    # Cross-dialect equivalence (e.g. chat finish_reason="stop"/"tool_calls" ~ responses status="completed")
    def _canon_term(sig: Tuple[str, str], has_tools: bool) -> str:
        fr, st = sig
        if st == "failed" or fr == "error":
            return "failed"
        if fr in ("length", "max_output_tokens") or st == "incomplete":
            return "incomplete"
        if fr == "tool_calls" or (st == "completed" and has_tools):
            return "completed_tools"
        if fr == "stop" or (st == "completed" and not has_tools):
            return "completed"
        return f"{fr}/{st}"

    b_has_tools = bool(b_asm.get("tool_calls"))
    a_has_tools = bool(a_asm.get("tool_calls"))
    return _canon_term(b_sig, b_has_tools) != _canon_term(a_sig, a_has_tools)


def _find_first_divergence(before: TraceDocument, after: TraceDocument) -> Tuple[Optional[DivergencePoint], bool]:
    """Perform jitter-proof semantic alignment across content, reasoning, tools, EOF, terminal, and usage.

    Collects candidate divergences with their exact causal physical frame sequences and selects
    the earliest chronological divergence.
    """
    b_asm = before.summary.assembled
    a_asm = after.summary.assembled

    b_term = _terminal_frame(before)
    a_term = _terminal_frame(after)
    b_term_seq = b_term.seq if b_term else None
    a_term_seq = a_term.seq if a_term else None

    term_drifted = _terminal_drifted(before, after)
    candidates: List[Tuple[Tuple[int, int, int], DivergencePoint]] = []

    def _add_candidate(priority: int, div: DivergencePoint) -> None:
        a_ord = div.after_seq if div.after_seq is not None else 10**9
        b_ord = div.before_seq if div.before_seq is not None else 10**9
        # Order chronologically by earliest causal frame, then category priority
        key = (min(a_ord, b_ord), a_ord, priority)
        candidates.append((key, div))

    # 1. Normalized visible content & reasoning streams (inline <think> == dedicated reasoning_delta!)
    b_vis, b_vspans, b_reas, b_rspans = _extract_semantic_text_streams(before)
    a_vis, a_vspans, a_reas, a_rspans = _extract_semantic_text_streams(after)

    r_idx = _first_char_diff(b_reas, a_reas)
    if r_idx is not None:
        b_seq = _lookup_frame_for_offset(b_rspans, r_idx, b_term_seq)
        a_seq = _lookup_frame_for_offset(a_rspans, r_idx, a_term_seq)
        _add_candidate(
            1,
            _make_div(
                "REASONING",
                f"Reasoning stream diverged at char offset {r_idx} (before={len(b_reas)} chars, after={len(a_reas)} chars)",
                before,
                b_seq,
                after,
                a_seq,
            ),
        )

    t_idx = _first_char_diff(b_vis, a_vis)
    if t_idx is not None:
        b_seq = _lookup_frame_for_offset(b_vspans, t_idx, b_term_seq)
        a_seq = _lookup_frame_for_offset(a_vspans, t_idx, a_term_seq)
        _add_candidate(
            2,
            _make_div(
                "CONTENT",
                f"Content stream diverged at char offset {t_idx} (before={len(b_vis)} chars, after={len(a_vis)} chars)",
                before,
                b_seq,
                after,
                a_seq,
            ),
        )

    # 2. Tool calls (count, name, structural JSON args, dialect-aware closure)
    b_tools = b_asm.get("tool_calls") or []
    a_tools = a_asm.get("tool_calls") or []
    max_tc = max(len(b_tools), len(a_tools))
    for k in range(max_tc):
        if k >= len(b_tools) or k >= len(a_tools):
            b_cite = b_tools[k].get("first_seq") if k < len(b_tools) else b_term_seq
            a_cite = a_tools[k].get("first_seq") if k < len(a_tools) else a_term_seq
            _add_candidate(
                3,
                _make_div(
                    "TOOL_CALL",
                    f"Tool call count diverged (before={len(b_tools)}, after={len(a_tools)})",
                    before,
                    b_cite if is_strict_int(b_cite) else b_term_seq,
                    after,
                    a_cite if is_strict_int(a_cite) else a_term_seq,
                ),
            )
            break

        bt, at = b_tools[k], a_tools[k]
        if bt.get("name") != at.get("name"):
            b_nseq = bt.get("name_seq") if is_strict_int(bt.get("name_seq")) else bt.get("first_seq")
            a_nseq = at.get("name_seq") if is_strict_int(at.get("name_seq")) else at.get("first_seq")
            _add_candidate(
                3,
                _make_div(
                    "TOOL_CALL",
                    f"Tool #{k} name changed ({bt.get('name')!r} -> {at.get('name')!r})",
                    before,
                    b_nseq if is_strict_int(b_nseq) else b_term_seq,
                    after,
                    a_nseq if is_strict_int(a_nseq) else a_term_seq,
                ),
            )
            break

        b_closed = _tool_is_closed(bt, before.header.dialect)
        a_closed = _tool_is_closed(at, after.header.dialect)

        if not _compare_tool_args_structurally(bt, at):
            b_args, b_aspans = _build_tool_arg_offset_map(before, bt, k)
            a_args, a_aspans = _build_tool_arg_offset_map(after, at, k)
            a_idx = _first_char_diff(b_args, a_args)
            if a_idx is not None:
                b_seq = _lookup_frame_for_offset(b_aspans, a_idx, bt.get("last_seq") or b_term_seq)
                a_seq = _lookup_frame_for_offset(a_aspans, a_idx, at.get("last_seq") or a_term_seq)
                _add_candidate(
                    3,
                    _make_div(
                        "TOOL_CALL",
                        f"Tool #{k} ({at.get('name')}) arguments diverged at char offset {a_idx} "
                        f"(before json_valid={bt.get('json_valid')}, after json_valid={at.get('json_valid')})",
                        before,
                        b_seq,
                        after,
                        a_seq,
                    ),
                )
                break

        if b_closed != a_closed:
            b_cseq = bt.get("done_seq") if is_strict_int(bt.get("done_seq")) else b_term_seq
            a_cseq = at.get("done_seq") if is_strict_int(at.get("done_seq")) else a_term_seq
            _add_candidate(
                4,
                _make_div(
                    "TOOL_CALL",
                    f"Tool #{k} ({at.get('name')}) closure diverged "
                    f"(before closed={b_closed}, after closed={a_closed}, "
                    f"after json_valid={at.get('json_valid')}, args_done={at.get('saw_args_done_event')})",
                    before,
                    b_cseq,
                    after,
                    a_cseq,
                ),
            )
            break

    # 3. EOF cleanliness & protocol-order violations
    b_viol = b_asm.get("protocol_violations") or []
    a_viol = a_asm.get("protocol_violations") or []
    if before.summary.eof_clean != after.summary.eof_clean or b_viol != a_viol:
        _add_candidate(
            5,
            _make_div(
                "EOF",
                f"Stream EOF/protocol cleanliness changed (eof_clean {before.summary.eof_clean} -> {after.summary.eof_clean})",
                before,
                _eof_violation_seq(before, b_term_seq),
                after,
                _eof_violation_seq(after, a_term_seq),
            ),
        )

    # 4. Terminal status drift
    if term_drifted:
        b_sig = (b_asm.get("finish_reason", "unknown"), b_asm.get("terminal_status", "unknown"))
        a_sig = (a_asm.get("finish_reason", "unknown"), a_asm.get("terminal_status", "unknown"))
        _add_candidate(
            6,
            _make_div(
                "TERMINAL",
                f"Terminal signal drifted ({b_sig[0]}/{b_sig[1]} -> {a_sig[0]}/{a_sig[1]})",
                before,
                b_term_seq,
                after,
                a_term_seq,
            ),
        )

    # 5. Completion token mismatch when both are reported integers
    b_comp = (b_asm.get("reported_usage") or {}).get("completion_tokens")
    a_comp = (a_asm.get("reported_usage") or {}).get("completion_tokens")
    if is_strict_int(b_comp) and is_strict_int(a_comp) and b_comp != a_comp:
        _add_candidate(
            7,
            _make_div(
                "USAGE",
                f"Reported completion_tokens changed ({b_comp} -> {a_comp})",
                before,
                _usage_frame_seq(before, b_term_seq),
                after,
                _usage_frame_seq(after, a_term_seq),
            ),
        )

    if not candidates:
        return None, term_drifted
    candidates.sort(key=lambda item: item[0])
    return candidates[0][1], term_drifted


def diff_traces(
    before: TraceDocument,
    after: TraceDocument,
    *,
    ignore_timing: bool = False,
    ttft_regress_pct: float = 50.0,
    min_ttft_delta_ms: float = 0.0,
    fail_on: str = "p0",
) -> DiffReport:
    """Compare two TraceDocuments with chunk-jitter-proof semantic alignment and D1..D8."""
    before_findings = audit_trace(before)
    after_findings = audit_trace(after)
    pair_findings = detect_d5(
        before,
        after,
        ignore_timing=ignore_timing,
        min_delta_ms=min_ttft_delta_ms,
    )
    pair_findings.extend(detect_d8_pair(
        before, after, ignore_timing=ignore_timing, min_delta_ms=min_ttft_delta_ms,
    ))

    before_severity = {(f.detector_id, f.code): f.severity for f in before_findings}
    new_after = [
        f for f in after_findings
        if (f.detector_id, f.code) not in before_severity or f.severity < before_severity[(f.detector_id, f.code)]
    ]
    new_findings = new_after + pair_findings

    first_div, terminal_drifted = _find_first_divergence(before, after)

    b_ttft = before.summary.timing.get("ttft_effective_ms")
    a_ttft = after.summary.timing.get("ttft_effective_ms")
    ttft_delta_pct: Optional[float] = None
    ttft_regressed = False
    if (
        not ignore_timing
        and isinstance(b_ttft, (int, float))
        and isinstance(a_ttft, (int, float))
        and b_ttft > 0
    ):
        ttft_delta_pct = round(((a_ttft - b_ttft) / b_ttft) * 100.0, 2)
        if ttft_delta_pct >= ttft_regress_pct and (a_ttft - b_ttft) >= min_ttft_delta_ms:
            ttft_regressed = True

    semantic_equal = (first_div is None) and not terminal_drifted

    # Exit code per Spec §2.1 & §2.2 (--fail-on gates CI return code cleanly):
    # - P0 finding always exits 2 (EXIT_SILENT_PROTOCOL_BREACH)
    # - Under --fail-on p0: only P0 fails (exits 0 otherwise)
    # - Under --fail-on p1: P1 findings, terminal drift, or TTFT regression exit 3
    # - Under --fail-on any-diff: any P1 or semantic divergence (incl. content/reasoning/tool/usage) exits 3
    all_target_findings = after_findings + pair_findings
    has_p0 = any(f.severity == "P0" for f in all_target_findings)
    has_p1 = any(f.severity == "P1" for f in all_target_findings) or terminal_drifted or ttft_regressed

    if has_p0:
        exit_code = EXIT_SILENT_PROTOCOL_BREACH
    elif fail_on == "p0":
        exit_code = EXIT_OK
    elif fail_on == "p1":
        exit_code = EXIT_SEMANTIC_REGRESSION if has_p1 else EXIT_OK
    else:  # any-diff
        exit_code = EXIT_SEMANTIC_REGRESSION if (has_p1 or not semantic_equal) else EXIT_OK

    summary_table = {
        "before_status": before.header.response_meta.get("status_code"),
        "after_status": after.header.response_meta.get("status_code"),
        "before_eof_clean": before.summary.eof_clean,
        "after_eof_clean": after.summary.eof_clean,
        "before_frames": before.summary.total_frames,
        "after_frames": after.summary.total_frames,
        "before_ttff_ms": before.summary.timing.get("ttff_ms"),
        "after_ttff_ms": after.summary.timing.get("ttff_ms"),
        "before_ttft_effective_ms": b_ttft,
        "after_ttft_effective_ms": a_ttft,
        "before_total_ms": before.summary.timing.get("total_ms"),
        "after_total_ms": after.summary.timing.get("total_ms"),
        "before_completion_tokens": (before.summary.assembled.get("reported_usage") or {}).get("completion_tokens"),
        "after_completion_tokens": (after.summary.assembled.get("reported_usage") or {}).get("completion_tokens"),
        "before_finish_reason": before.summary.assembled.get("finish_reason"),
        "after_finish_reason": after.summary.assembled.get("finish_reason"),
        "before_terminal_status": before.summary.assembled.get("terminal_status"),
        "after_terminal_status": after.summary.assembled.get("terminal_status"),
    }

    return DiffReport(
        before_label=before.header.label or before.header.dialect,
        after_label=after.header.label or after.header.dialect,
        before_dialect=before.header.dialect,
        after_dialect=after.header.dialect,
        before_findings=before_findings,
        after_findings=after_findings,
        pair_findings=pair_findings,
        new_findings=new_findings,
        semantic_equal=semantic_equal,
        terminal_drifted=terminal_drifted,
        ttft_regressed=ttft_regressed,
        ttft_delta_pct=ttft_delta_pct,
        first_divergence=first_div,
        exit_code=exit_code,
        summary_table=summary_table,
    )
