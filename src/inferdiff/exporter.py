"""Terminal ANSI renderer and strict <=25-line sanitized GitHub Issue Markdown exporter."""

from __future__ import annotations

import json
import shlex
import sys
from typing import Any, Dict, List, Optional

from . import __version__
from .detectors import Finding
from .differ import DiffReport
from .redact import (
    extract_safe_repro_body,
    redact_headers,
    redact_secret_text,
    sanitize_body_for_export,
    sanitize_url_for_export,
)
from .schema import TraceDocument

MAX_ISSUE_LINES = 25


def _supports_color(no_color: bool) -> bool:
    if no_color:
        return False
    try:
        return sys.stdout.isatty()
    except Exception:
        return False


def _c(text: str, code: str, use_color: bool) -> str:
    return f"\033[{code}m{text}\033[0m" if use_color else text


def _strip_controls_and_newlines(text: Any) -> str:
    """Flatten control characters and Unicode line separators so no field can inject extra lines."""
    s = str(text)
    out: List[str] = []
    for ch in s:
        code = ord(ch)
        if ch in ("\r", "\n", "\u0085", "\u2028", "\u2029"):
            out.append(" ")
        elif code < 32 or code == 127:
            out.append(f"\\x{code:02x}")
        else:
            out.append(ch)
    return "".join(out)


def _esc_md(text: Any, max_chars: int = 160) -> str:
    flat = _strip_controls_and_newlines(text).replace("|", "\\|").replace("`", "'").strip()
    if len(flat) > max_chars:
        return flat[: max_chars - 3] + "..."
    return flat


def _one_line_wire(raw_wire: Optional[str], max_chars: int = 125) -> str:
    if raw_wire is None:
        return "null"
    scrubbed = redact_secret_text(raw_wire)
    compact = scrubbed.replace("\r\n", " | ").replace("\n", " | ").replace("\r", " | ")
    compact = _strip_controls_and_newlines(compact).strip(" |")
    if len(compact) > max_chars:
        return compact[: max_chars - 3] + "..."
    return compact


def _safe_shell_url(doc: TraceDocument) -> str:
    raw_url = str(doc.header.request.get("url") or "http://127.0.0.1:8080/v1/chat/completions")
    try:
        clean = sanitize_url_for_export(raw_url)
    except ValueError:
        clean = "http://invalid-url.redacted/"
    return shlex.quote(clean)


def _sanitized_curl_lines(doc: TraceDocument, *, include_body: bool = False) -> List[str]:
    """Build a POSIX-safe curl reproducer with --globoff --url and strict credential separation."""
    quoted_url = _safe_shell_url(doc)
    body = doc.header.request.get("body")
    body_hash8 = str(doc.header.request.get("body_sha256") or "unknown")[:8]

    if not isinstance(body, dict):
        return [
            f"# Attach sanitized request.json (body_sha256={body_hash8})",
            f"curl -sS -N --globoff --url {quoted_url} -H 'Content-Type: application/json' --data-binary @request.json",
        ]

    if include_body:
        payload = sanitize_body_for_export(body)
        compact_body = _strip_controls_and_newlines(json.dumps(payload, ensure_ascii=True, separators=(",", ":")))
        if len(compact_body) <= 420:
            return [
                f"curl -sS -N --globoff --url {quoted_url} -H 'Content-Type: application/json' -d {shlex.quote(compact_body)}"
            ]
        return [
            f"# Body >420 chars: save sanitized request payload (sha256:{body_hash8}) to request.json",
            f"curl -sS -N --globoff --url {quoted_url} -H 'Content-Type: application/json' --data-binary @request.json",
        ]

    # Default shareable mode: never echo arbitrary user prompts or custom body fields
    safe_proto, omitted_arbitrary = extract_safe_repro_body(body)
    if not omitted_arbitrary:
        compact_body = _strip_controls_and_newlines(json.dumps(safe_proto, ensure_ascii=True, separators=(",", ":")))
        if len(compact_body) <= 420:
            return [
                f"curl -sS -N --globoff --url {quoted_url} -H 'Content-Type: application/json' -d {shlex.quote(compact_body)}"
            ]

    proto_hint = _strip_controls_and_newlines(
        json.dumps(
            {k: safe_proto[k] for k in ("model", "stream", "temperature", "seed") if k in safe_proto},
            ensure_ascii=True,
            separators=(",", ":"),
        )
    )
    return [
        f"# Arbitrary prompt/body omitted by default (sha256:{body_hash8}, params={proto_hint}); save to request.json or re-export with --include-body",
        f"curl -sS -N --globoff --url {quoted_url} -H 'Content-Type: application/json' --data-binary @request.json",
    ]


def _md_code_span(text: str) -> str:
    """Wrap exact command text in a Markdown code span without mangling or truncating characters."""
    # Choose a backtick fence longer than any consecutive backtick run inside text
    max_run = 0
    cur = 0
    for ch in text:
        if ch == "`":
            cur += 1
            if cur > max_run:
                max_run = cur
        else:
            cur = 0
    fence = "`" * (max_run + 1)
    pad = " " if (text.startswith("`") or text.endswith("`")) else ""
    return f"{fence}{pad}{text}{pad}{fence}"


def sanitize_trace_for_json_export(
    doc: TraceDocument,
    *,
    include_body: bool = False,
    include_wire: bool = False,
) -> Dict[str, Any]:
    """Build a strictly allowlisted, credential-safe trace header + summary dict for JSON export."""
    raw_req = doc.header.request if isinstance(doc.header.request, dict) else {}
    raw_url = raw_req.get("url")
    if isinstance(raw_url, str):
        try:
            safe_url = sanitize_url_for_export(raw_url)
        except ValueError:
            safe_url = "http://invalid-url.redacted/"
    else:
        safe_url = "http://invalid-url.redacted/"

    # Re-redact imported headers so a tampered or third-party trace cannot smuggle raw secrets
    raw_hdrs = raw_req.get("headers_redacted")
    safe_hdrs = redact_headers(
        {str(k): str(v) for k, v in raw_hdrs.items()} if isinstance(raw_hdrs, dict) else {}
    )

    eff = raw_req.get("effective_params") if isinstance(raw_req.get("effective_params"), dict) else {}
    safe_eff = {
        "model": redact_secret_text(str(eff["model"])) if isinstance(eff.get("model"), str) else None,
        "stream": eff.get("stream") if isinstance(eff.get("stream"), bool) else True,
        "max_budget_tokens": eff.get("max_budget_tokens"),
        "ignore_eos": eff.get("ignore_eos") if isinstance(eff.get("ignore_eos"), bool) else False,
        "temperature": eff.get("temperature"),
        "seed": eff.get("seed"),
        "has_tools": eff.get("has_tools") if isinstance(eff.get("has_tools"), bool) else False,
        "stop_conditions_count": len(eff.get("stop_conditions") or []),
    }

    safe_req: Dict[str, Any] = {
        "method": str(raw_req.get("method") or "POST"),
        "url": safe_url,
        "headers_redacted": safe_hdrs,
        "body_sha256": str(raw_req.get("body_sha256") or ""),
        "effective_params": safe_eff,
    }
    if include_body and isinstance(raw_req.get("body"), dict):
        safe_req["body"] = sanitize_body_for_export(raw_req["body"])

    rm = doc.header.response_meta if isinstance(doc.header.response_meta, dict) else {}
    safe_rm = {
        "status_code": rm.get("status_code"),
        "content_type": redact_secret_text(str(rm.get("content_type") or "")),
        "t_headers_ms": rm.get("t_headers_ms"),
    }

    hdr = {
        "type": "header",
        "schema_version": doc.header.schema_version,
        "trace_id": doc.header.trace_id,
        "label": redact_secret_text(doc.header.label),
        "recorded_at_utc": doc.header.recorded_at_utc,
        "dialect": doc.header.dialect,
        "request": safe_req,
        "response_meta": safe_rm,
        "backend_probe": sanitize_body_for_export(doc.header.backend_probe) if doc.header.backend_probe is not None else None,
    }

    raw_asm = doc.summary.assembled if isinstance(doc.summary.assembled, dict) else {}
    safe_tools: List[Dict[str, Any]] = []
    for tc in raw_asm.get("tool_calls") or []:
        if not isinstance(tc, dict):
            continue
        item: Dict[str, Any] = {
            "index": tc.get("index"),
            "id": tc.get("id"),
            "name": tc.get("name"),
            "json_valid": tc.get("json_valid"),
            "json_error": tc.get("json_error"),
            "saw_args_delta": tc.get("saw_args_delta"),
            "saw_args_done_event": tc.get("saw_args_done_event"),
            "args_mismatch": tc.get("args_mismatch"),
            "identity_conflict": tc.get("identity_conflict"),
        }
        if include_wire and isinstance(tc.get("raw_arguments"), str):
            item["raw_arguments"] = redact_secret_text(tc["raw_arguments"])
        safe_tools.append(item)

    safe_asm: Dict[str, Any] = {
        "content_utf8_bytes": raw_asm.get("content_utf8_bytes"),
        "has_unclosed_think": raw_asm.get("has_unclosed_think"),
        "tool_calls": safe_tools,
        "finish_reason": raw_asm.get("finish_reason"),
        "terminal_status": raw_asm.get("terminal_status"),
        "protocol_violations": raw_asm.get("protocol_violations") or [],
        "observed_delta_frames": raw_asm.get("observed_delta_frames"),
        "saw_textless_usage_frame": raw_asm.get("saw_textless_usage_frame"),
        "reported_usage": raw_asm.get("reported_usage") if isinstance(raw_asm.get("reported_usage"), dict) else {},
    }
    if include_wire:
        safe_asm["content_text"] = redact_secret_text(str(raw_asm.get("content_text") or ""))
        safe_asm["reasoning_text"] = redact_secret_text(str(raw_asm.get("reasoning_text") or ""))

    summary: Dict[str, Any] = {
        "type": "summary",
        "eof_clean": doc.summary.eof_clean,
        "total_frames": doc.summary.total_frames,
        "timing": dict(doc.summary.timing),
        "assembled": safe_asm,
    }
    if doc.summary.backend_probe is not None:
        summary["backend_probe"] = sanitize_body_for_export(doc.summary.backend_probe)
    return {"header": hdr, "summary": summary}


def _safe_frame_summary(doc: TraceDocument, seq: Optional[int]) -> str:
    if seq is None or seq < 0 or seq >= len(doc.frames):
        return "none"
    f = doc.frames[seq]
    norm = f.norm or {}
    parts = [f"phase={_esc_md(norm.get('phase', 'UNKNOWN'), 24)}"]
    if f.sse_event:
        parts.append(f"event={_esc_md(f.sse_event, 40)}")
    if norm.get("finish_reason"):
        parts.append(f"finish_reason={_esc_md(norm['finish_reason'], 24)}")
    if norm.get("terminal_status"):
        parts.append(f"status={_esc_md(norm['terminal_status'], 24)}")
    if norm.get("text_delta"):
        parts.append(f"text_delta_chars={len(norm['text_delta'])}")
    if norm.get("reasoning_delta"):
        parts.append(f"reasoning_delta_chars={len(norm['reasoning_delta'])}")
    if norm.get("tool_deltas"):
        parts.append(f"tool_deltas={len(norm['tool_deltas'])}")
    if f.parse_error:
        parts.append(f"parse_error={_esc_md(f.parse_error, 48)}")
    return ", ".join(parts)


def render_audit_terminal(doc: TraceDocument, findings: List[Finding], *, no_color: bool = False) -> str:
    use_color = _supports_color(no_color)
    label = _strip_controls_and_newlines(doc.header.label or doc.header.dialect)
    asm = doc.summary.assembled
    t = doc.summary.timing
    usage = asm.get("reported_usage") or {}

    lines = [
        _c(f"inferdiff v{__version__} audit :: {label} ({doc.header.dialect})", "1", use_color),
        f"  HTTP {doc.header.response_meta.get('status_code')} | eof_clean={doc.summary.eof_clean} | frames={doc.summary.total_frames}",
        f"  timing: ttff={t.get('ttff_ms')} ms | ttft_effective={t.get('ttft_effective_ms')} ms | total={t.get('total_ms')} ms",
        f"  output: content={asm.get('content_utf8_bytes')} B | tools={len(asm.get('tool_calls') or [])} | finish={asm.get('finish_reason')}/{asm.get('terminal_status')} | completion_tokens={usage.get('completion_tokens')}",
    ]
    if not findings:
        lines.append(_c("  PASS: 0 silent failures detected (D1-D4)", "32", use_color))
    else:
        for f in findings:
            col = "31" if f.severity == "P0" else "33"
            seq_s = f" @frame#{f.frame_seq}" if f.frame_seq is not None else ""
            lines.append(_c(f"  [{f.severity}] {f.detector_id} {f.code}{seq_s}: {_strip_controls_and_newlines(f.message)}", col, use_color))
    return "\n".join(lines) + "\n"


def render_diff_terminal(report: DiffReport, *, no_color: bool = False) -> str:
    use_color = _supports_color(no_color)
    st = report.summary_table
    lines = [
        _c(
            f"inferdiff v{__version__} diff :: {_strip_controls_and_newlines(report.before_label)} -> {_strip_controls_and_newlines(report.after_label)}",
            "1",
            use_color,
        ),
        f"  HTTP/EOF  : {st['before_status']} (clean={st['before_eof_clean']}, {st['before_frames']}f) -> {st['after_status']} (clean={st['after_eof_clean']}, {st['after_frames']}f)",
        f"  Terminal  : {_strip_controls_and_newlines(st['before_finish_reason'])}/{_strip_controls_and_newlines(st['before_terminal_status'])} -> {_strip_controls_and_newlines(st['after_finish_reason'])}/{_strip_controls_and_newlines(st['after_terminal_status'])}",
        f"  Timing    : ttft_eff {st['before_ttft_effective_ms']} -> {st['after_ttft_effective_ms']} ms | total {st['before_total_ms']} -> {st['after_total_ms']} ms",
        f"  Tokens    : completion {st['before_completion_tokens']} -> {st['after_completion_tokens']} | semantic_equal={report.semantic_equal}",
    ]
    if report.first_divergence:
        d = report.first_divergence
        lines.append(_c(f"  First Divergence [{d.category}]: {_strip_controls_and_newlines(d.detail)}", "33", use_color))
        lines.append(_c(f"    - before #{d.before_seq} (+{d.before_t_rel_ms} ms): {_one_line_wire(d.before_raw_wire)}", "36", use_color))
        lines.append(_c(f"    + after  #{d.after_seq} (+{d.after_t_rel_ms} ms): {_one_line_wire(d.after_raw_wire)}", "31", use_color))

    all_findings = report.after_findings + report.pair_findings
    for f in all_findings:
        col = "31" if f.severity == "P0" else "33"
        lines.append(_c(f"  [{f.severity}] {f.detector_id} {f.code}: {_strip_controls_and_newlines(f.message)}", col, use_color))
    if report.ttft_regressed:
        lines.append(_c(f"  [P1] TTFT_REGRESSION: ttft_effective increased by +{report.ttft_delta_pct}%", "33", use_color))

    # Gate banner strictly reflects report.exit_code (never prints PASS while returning non-zero)
    if report.exit_code == 0:
        if not report.semantic_equal or all_findings or report.ttft_regressed:
            lines.append(_c("  PASS (exit 0; gate passed, non-blocking diff/warning shown above)", "32", use_color))
        else:
            lines.append(_c("  PASS (exit 0): no silent protocol breach or semantic regression", "32", use_color))
    elif report.exit_code == 2:
        lines.append(_c("  FAIL (exit 2): P0 silent protocol breach detected", "31", use_color))
    else:
        lines.append(_c(f"  FAIL (exit {report.exit_code}): semantic or benchmark regression exceeded gate", "33", use_color))

    return "\n".join(lines) + "\n"


def _enforce_line_budget(lines: List[str], max_lines: int = MAX_ISSUE_LINES) -> str:
    """Guarantee rendered output has strictly <= max_lines physical lines and balanced code fences."""
    # Flatten every entry through splitlines() so embedded newlines can never bypass the budget
    physical: List[str] = []
    for entry in lines:
        parts = entry.splitlines() if entry != "" else [""]
        physical.extend(parts)

    if len(physical) <= max_lines:
        return "\n".join(physical) + "\n"

    footer = physical[-1]
    body = physical[: max_lines - 1]
    # Ensure any open triple-backtick fence in body is closed cleanly within the budget
    fence_count = sum(1 for ln in body if ln.lstrip().startswith("```"))
    if fence_count % 2 == 1:
        body = body[: max_lines - 2] + ["```"]
    final = body + [footer]
    assert len(final) <= max_lines
    return "\n".join(final) + "\n"


def render_github_issue(
    before: TraceDocument,
    after: Optional[TraceDocument] = None,
    *,
    diff_report: Optional[DiffReport] = None,
    audit_findings: Optional[List[Finding]] = None,
    before_path: str = "before.trace.jsonl",
    after_path: str = "after.trace.jsonl",
    include_body: bool = False,
    include_wire: bool = False,
) -> str:
    """Render a strictly <=25-line sanitized, zero-fluff GitHub Issue Markdown report."""
    lines: List[str] = []
    # Preserve exact POSIX shell-quoted filenames (never truncate or rewrite after shlex.quote!)
    q_before = shlex.quote(_strip_controls_and_newlines(before_path))
    q_after = shlex.quote(_strip_controls_and_newlines(after_path))

    if after is not None and diff_report is not None:
        all_f = diff_report.after_findings + diff_report.pair_findings
        primary = f"{all_f[0].detector_id}: {all_f[0].code}" if all_f else ("SEMANTIC_DRIFT" if not diff_report.semantic_equal else "NO_REGRESSION")
        st = diff_report.summary_table
        b_lbl = _esc_md(diff_report.before_label, 48)
        a_lbl = _esc_md(diff_report.after_label, 48)
        lines.append(f"### Wire-Level Regression Report (`inferdiff v{__version__}` - `{_esc_md(primary, 60)}`)")
        lines.append(f"| Metric | Baseline (`{b_lbl}`) | Target (`{a_lbl}`) |")
        lines.append("| :--- | :--- | :--- |")
        lines.append(
            f"| HTTP / Clean EOF | `{_esc_md(st['before_status'], 16)}` / `{str(st['before_eof_clean']).lower()}` (`{st['before_frames']}` frames) "
            f"| `{_esc_md(st['after_status'], 16)}` / `{str(st['after_eof_clean']).lower()}` (`{st['after_frames']}` frames) |"
        )
        lines.append(
            f"| Terminal Signal | `{_esc_md(st['before_finish_reason'], 24)}` / `{_esc_md(st['before_terminal_status'], 24)}` "
            f"| `{_esc_md(st['after_finish_reason'], 24)}` / `{_esc_md(st['after_terminal_status'], 24)}` |"
        )
        lines.append(
            f"| Timing (`ttft_eff` / `total`) | `{st['before_ttft_effective_ms']}` / `{st['before_total_ms']} ms` "
            f"| `{st['after_ttft_effective_ms']}` / `{st['after_total_ms']} ms` |"
        )
        lines.append(
            f"| Completion Tokens | `{_esc_md(st['before_completion_tokens'], 16)}` | `{_esc_md(st['after_completion_tokens'], 16)}` |"
        )
        if diff_report.first_divergence:
            d = diff_report.first_divergence
            lines.append(f"| First Divergence | Frame `#{d.before_seq}` (`+{d.before_t_rel_ms} ms`) | Frame `#{d.after_seq}` (`+{d.after_t_rel_ms} ms`) |")
        lines.append("")
        lines.append("**Minimal Reproducer (auth & secrets redacted):**")
        lines.append("```bash")
        lines.extend(_sanitized_curl_lines(after, include_body=include_body))
        lines.append("```")
        if all_f:
            f0 = all_f[0]
            lines.append(f"**Finding (`[{f0.severity}] {f0.detector_id}:{f0.code}`):** {_esc_md(f0.message, 240)}")
        if diff_report.first_divergence:
            d = diff_report.first_divergence
            lines.append(f"**First Divergent Frame (`Target #{d.after_seq}` vs `Baseline #{d.before_seq}`):**")
            lines.append("```diff")
            if include_wire:
                lines.append(f"- Baseline #{d.before_seq}: {_one_line_wire(d.before_raw_wire)}")
                lines.append(f"+ Target   #{d.after_seq}: {_one_line_wire(d.after_raw_wire)}")
            else:
                lines.append(f"- Baseline #{d.before_seq}: {_safe_frame_summary(before, d.before_seq)}")
                lines.append(f"+ Target   #{d.after_seq}: {_safe_frame_summary(after, d.after_seq)}")
            lines.append("```")
        offline_cmd = _md_code_span(f"uvx inferdiff diff {q_before} {q_after} --fail-on p1")
        lines.append(f"Reproduce offline: {offline_cmd} (exits `{diff_report.exit_code}`).")
    else:
        findings = audit_findings or []
        primary = f"{findings[0].detector_id}: {findings[0].code}" if findings else "CLEAN"
        lbl = _esc_md(before.header.label or before.header.dialect, 48)
        asm = before.summary.assembled
        t = before.summary.timing
        usage = asm.get("reported_usage") or {}
        lines.append(f"### Wire-Level Audit Report (`inferdiff v{__version__}` - `{_esc_md(primary, 60)}`)")
        lines.append(f"| Metric | Target (`{lbl}`) |")
        lines.append("| :--- | :--- |")
        lines.append(f"| HTTP / Clean EOF | `{_esc_md(before.header.response_meta.get('status_code'), 16)}` / `{str(before.summary.eof_clean).lower()}` (`{before.summary.total_frames}` frames) |")
        lines.append(f"| Terminal Signal | `{_esc_md(asm.get('finish_reason'), 24)}` / `{_esc_md(asm.get('terminal_status'), 24)}` |")
        lines.append(f"| Timing (`ttft_eff` / `total`) | `{t.get('ttft_effective_ms')}` / `{t.get('total_ms')} ms` |")
        lines.append(f"| Output / Tokens | `{asm.get('content_utf8_bytes')} B`, `{len(asm.get('tool_calls') or [])}` tools / `{_esc_md(usage.get('completion_tokens'), 16)}` tokens |")
        lines.append("")
        lines.append("**Minimal Reproducer (auth & secrets redacted):**")
        lines.append("```bash")
        lines.extend(_sanitized_curl_lines(before, include_body=include_body))
        lines.append("```")
        if findings:
            f0 = findings[0]
            lines.append(f"**Triggering Finding (`[{f0.severity}] {f0.detector_id}:{f0.code}`):**")
            lines.append("```text")
            lines.append(_esc_md(f0.message, 240))
            if f0.frame_seq is not None and 0 <= f0.frame_seq < len(before.frames):
                if include_wire:
                    lines.append(f"Frame #{f0.frame_seq}: {_one_line_wire(before.frames[f0.frame_seq].raw_wire)}")
                else:
                    lines.append(f"Frame #{f0.frame_seq}: {_safe_frame_summary(before, f0.frame_seq)}")
            lines.append("```")
        offline_cmd = _md_code_span(f"uvx inferdiff audit {q_before} --strict")
        lines.append(f"Reproduce offline: {offline_cmd}.")

    return _enforce_line_budget(lines, MAX_ISSUE_LINES)


def render_ci_summary(
    before: TraceDocument,
    after: Optional[TraceDocument] = None,
    *,
    diff_report: Optional[DiffReport] = None,
    audit_findings: Optional[List[Finding]] = None,
) -> str:
    if after is not None and diff_report is not None:
        all_f = diff_report.after_findings + diff_report.pair_findings
        status = "PASS" if diff_report.exit_code == 0 else "FAIL"
        codes = ",".join(f"{f.detector_id}:{f.code}" for f in all_f) or "none"
        return (
            f"inferdiff ci-summary: {status} | {_strip_controls_and_newlines(diff_report.before_label)} -> {_strip_controls_and_newlines(diff_report.after_label)} | "
            f"semantic_equal={diff_report.semantic_equal} | findings={codes} | exit={diff_report.exit_code}\n"
        )
    findings = audit_findings or []
    status = "PASS" if not findings else "FAIL"
    codes = ",".join(f"{f.detector_id}:{f.code}" for f in findings) or "none"
    return f"inferdiff ci-summary: {status} | {_strip_controls_and_newlines(before.header.label or before.header.dialect)} | findings={codes}\n"
