"""Zero-external-dependency single-file HTML5 + inline SVG frame waterfall renderer (<80 KiB)."""

from __future__ import annotations

import base64
import hashlib
import html
import urllib.parse
from typing import Any, Callable, Dict, List, Optional, Tuple

from . import __version__
from .canary import DoctorReport
from .detectors import D6, D7, D8, Finding
from .differ import DiffReport
from .exporter import _safe_frame_summary, _sanitized_curl_lines, _strip_controls_and_newlines
from .redact import redact_secret_text
from .schema import TraceDocument, TraceFrame, frame_has_effective_payload, is_finite_number

MAX_HTML_BYTES = 81_920
STALL_GAP_MS = 250.0
FOLD_THRESHOLD_FRAMES = 500
MAX_FINDING_ROWS = 20

APPROVED_ANCHOR_HOSTS = frozenset(
    {
        "github.com",
        "docs.vllm.ai",
        "docs.ollama.com",
        "docs.lmcache.ai",
        "developers.openai.com",
    }
)

# Colorblind-friendly semantic phase palette
COLOR_HANDSHAKE = "#64748b"  # Slate gray
COLOR_REASONING = "#f59e0b"  # Amber
COLOR_CONTENT = "#10b981"    # Emerald
COLOR_TOOL = "#6366f1"       # Indigo
COLOR_STALL = "#f97316"      # Orange dashed bridge
COLOR_ALERT = "#ef4444"      # Crimson crosshair & breach highlight
COLOR_TERMINAL = "#38bdf8"   # Sky blue (healthy terminal)

_STATIC_JS = (
    "(function(){"
    "var a=document.getElementById('svg-abs'),n=document.getElementById('svg-norm'),"
    "ba=document.getElementById('btn-abs'),bn=document.getElementById('btn-norm');"
    "if(ba&&bn&&a&&n){"
    "ba.onclick=function(){a.classList.remove('hid');n.classList.add('hid');ba.classList.add('on');bn.classList.remove('on');};"
    "bn.onclick=function(){n.classList.remove('hid');a.classList.add('hid');bn.classList.add('on');ba.classList.remove('on');};"
    "}"
    "var box=document.getElementById('click-wire');"
    "document.querySelectorAll('.wf-bar').forEach(function(el){"
    "el.addEventListener('click',function(){"
    "if(!box)return;"
    "var w=el.getAttribute('data-wire')||'';"
    "box.textContent='['+el.getAttribute('data-lane')+'] '+el.getAttribute('data-info')+(w?'\\n'+w:'');"
    "});"
    "});"
    "var cp=document.getElementById('btn-copy'),cu=document.getElementById('curl-box');"
    "if(cp&&cu&&navigator.clipboard){"
    "cp.onclick=function(){navigator.clipboard.writeText(cu.textContent).then(function(){cp.textContent='Copied';});};"
    "}"
    "})();"
)
_SCRIPT_SHA256_B64 = base64.b64encode(hashlib.sha256(_STATIC_JS.encode("utf-8")).digest()).decode("ascii")


def _safe_utf8_str(val: Any) -> str:
    """Replace any lone UTF-16 surrogates so UTF-8 encoding never raises UnicodeEncodeError."""
    return str(val).encode("utf-8", errors="replace").decode("utf-8")


def _esc(val: Any, max_chars: Optional[int] = None) -> str:
    s = _safe_utf8_str(val)
    if max_chars is not None and len(s) > max_chars:
        s = s[: max(0, max_chars - 3)] + "..."
    return html.escape(s, quote=True)


def _safe_anchor(url: str, label: str = "anchor") -> str:
    try:
        p = urllib.parse.urlsplit(url)
        if p.scheme == "https" and (p.hostname or "").lower() in APPROVED_ANCHOR_HOSTS:
            return f'<a href="{_esc(url, 200)}" style="color:#93c5fd" rel="noreferrer noopener">{_esc(label)}</a>'
    except ValueError:
        pass
    return _esc(label)


def _frame_category(f: TraceFrame) -> str:
    norm = f.norm or {}
    if f.parse_error or norm.get("phase") == "ERROR":
        return "ERROR"
    if norm.get("phase") == "TOOL" or norm.get("tool_deltas"):
        return "TOOL"
    if norm.get("phase") == "REASONING" or (norm.get("reasoning_delta") and not norm.get("text_delta")):
        return "REASONING"
    if norm.get("text_delta"):
        return "CONTENT"
    if norm.get("phase") in ("TERMINAL", "EOF") or f.is_done_sentinel or norm.get("finish_reason") or norm.get("terminal_status"):
        return "TERMINAL"
    return "HANDSHAKE"


def _frame_color(cat: str, is_alert: bool = False) -> str:
    if is_alert or cat == "ERROR":
        return COLOR_ALERT
    return {
        "HANDSHAKE": COLOR_HANDSHAKE,
        "REASONING": COLOR_REASONING,
        "CONTENT": COLOR_CONTENT,
        "TOOL": COLOR_TOOL,
        "TERMINAL": COLOR_TERMINAL,
    }.get(cat, COLOR_HANDSHAKE)


def _bucket_segments(segments: List[Dict[str, Any]], max_segments: int) -> List[Dict[str, Any]]:
    """Hard-cap segment count per lane (even on 1,200+ stall frames) while keeping critical markers."""
    if max_segments <= 0 or len(segments) <= max_segments:
        return segments
    # Always retain first, last, and divergence segments; bucket interior uniformly
    first = segments[0]
    last = segments[-1]
    div_indices = {i for i, s in enumerate(segments) if s.get("is_div")}
    interior = segments[1:-1]
    budget = max(1, max_segments - 2)
    step = max(1, (len(interior) + budget - 1) // budget)

    out: List[Dict[str, Any]] = [first]
    i = 0
    while i < len(interior):
        orig_idx = i + 1
        if orig_idx in div_indices:
            out.append(interior[i])
            i += 1
            continue
        chunk = interior[i : i + step]
        # Split chunk if it contains a divergence marker
        split_at = next((k for k in range(len(chunk)) if (orig_idx + k) in div_indices), None)
        if split_at is not None and split_at > 0:
            chunk = chunk[:split_at]
        if len(chunk) == 1:
            out.append(chunk[0])
        else:
            s0, s1 = chunk[0], chunk[-1]
            cnt = sum(c.get("count", 1) for c in chunk)
            out.append(
                {
                    "folded": True,
                    "seq": s0["seq"],
                    "end_seq": s1["end_seq"],
                    "count": cnt,
                    "start_ms": s0["start_ms"],
                    "end_ms": s1["end_ms"],
                    "dt_ms": round(max(0.0, s1["end_ms"] - s0["start_ms"]), 2),
                    "cat": s0["cat"],
                    "has_fffd": any(c.get("has_fffd") for c in chunk),
                    "is_stall": any(c.get("is_stall") for c in chunk),
                    "is_div": False,
                    "detail": f"Collapsed {cnt} frames #{s0['seq']}..#{s1['end_seq']}",
                }
            )
        i += len(chunk)
    out.append(last)
    return out


def _fold_frames_for_svg(
    doc: TraceDocument,
    *,
    divergence_seq: Optional[int] = None,
    threshold: int = FOLD_THRESHOLD_FRAMES,
    max_segments: int = 240,
    include_wire: bool = False,
) -> List[Dict[str, Any]]:
    """Build renderable SVG segment descriptors with adaptive folding and hard per-lane cap."""
    frames = doc.frames
    if not frames:
        return []

    first_eff_seq: Optional[int] = None
    for f in frames:
        if frame_has_effective_payload(f.norm or {}):
            first_eff_seq = f.seq
            break

    keep_all = len(frames) <= threshold
    must_keep: set[int] = set()
    if not keep_all:
        must_keep.add(0)
        if first_eff_seq is not None:
            must_keep.add(first_eff_seq)
        for s in range(max(0, len(frames) - 3), len(frames)):
            must_keep.add(s)
        if divergence_seq is not None:
            for s in range(max(0, divergence_seq - 10), min(len(frames), divergence_seq + 11)):
                must_keep.add(s)
        for f in frames:
            cat = _frame_category(f)
            if cat in ("TOOL", "ERROR", "TERMINAL") or f.dt_ms > STALL_GAP_MS or "\ufffd" in ((f.norm or {}).get("text_delta") or ""):
                must_keep.add(f.seq)

    segments: List[Dict[str, Any]] = []
    i = 0
    n = len(frames)
    while i < n:
        f = frames[i]
        cat = _frame_category(f)
        if keep_all or f.seq in must_keep or cat not in ("CONTENT", "REASONING"):
            start_ms = max(0.0, f.t_rel_ms - f.dt_ms)
            has_fffd = "\ufffd" in ((f.norm or {}).get("text_delta") or "")
            detail = (
                redact_secret_text(f.raw_wire)
                if include_wire
                else _safe_frame_summary(doc, f.seq)
            )
            segments.append(
                {
                    "folded": False,
                    "seq": f.seq,
                    "end_seq": f.seq,
                    "count": 1,
                    "start_ms": start_ms,
                    "end_ms": f.t_rel_ms,
                    "dt_ms": f.dt_ms,
                    "cat": cat,
                    "has_fffd": has_fffd,
                    "is_stall": f.dt_ms > STALL_GAP_MS,
                    "is_div": (divergence_seq is not None and f.seq == divergence_seq),
                    "detail": detail,
                }
            )
            i += 1
        else:
            j = i + 1
            while j < n and frames[j].seq not in must_keep and _frame_category(frames[j]) == cat:
                j += 1
            f_start = frames[i]
            f_end = frames[j - 1]
            span_ms = round(max(0.0, f_end.t_rel_ms - max(0.0, f_start.t_rel_ms - f_start.dt_ms)), 2)
            segments.append(
                {
                    "folded": True,
                    "seq": f_start.seq,
                    "end_seq": f_end.seq,
                    "count": j - i,
                    "start_ms": max(0.0, f_start.t_rel_ms - f_start.dt_ms),
                    "end_ms": f_end.t_rel_ms,
                    "dt_ms": span_ms,
                    "cat": cat,
                    "has_fffd": False,
                    "is_stall": False,
                    "is_div": False,
                    "detail": f"Collapsed {j - i} healthy {cat} frames #{f_start.seq}..#{f_end.seq} (+{span_ms} ms)",
                }
            )
            i = j

    return _bucket_segments(segments, max_segments)


def _render_lane_svg_elements(
    lane_id: str,
    label: str,
    doc: TraceDocument,
    y_top: int,
    *,
    max_ms: float,
    normalized: bool,
    divergence_seq: Optional[int],
    lane_alert: bool,
    fold_threshold: int = FOLD_THRESHOLD_FRAMES,
    max_segments: int = 240,
    wire_cap: int = 160,
    include_wire: bool = False,
    svg_w: int = 1120,
    left_pad: int = 190,
    right_pad: int = 24,
    bar_h: int = 24,
) -> Tuple[str, Optional[float]]:
    plot_w = svg_w - left_pad - right_pad
    denom = (doc.summary.timing.get("total_ms") or max_ms) if normalized else max_ms
    if denom <= 0:
        denom = 1.0

    segs = _fold_frames_for_svg(
        doc,
        divergence_seq=divergence_seq,
        threshold=fold_threshold,
        max_segments=max_segments,
        include_wire=include_wire,
    )
    parts: List[str] = []
    parts.append(
        f'<text x="8" y="{y_top + 16}" fill="#cbd5e1" font-size="11" font-family="ui-monospace,Consolas,monospace">'
        f'{_esc(_strip_controls_and_newlines(redact_secret_text(label)), 24)}</text>'
    )
    parts.append(
        f'<rect x="{left_pad}" y="{y_top}" width="{plot_w}" height="{bar_h}" rx="4" fill="#1e293b" stroke="#334155" stroke-width="1"/>'
    )

    div_x: Optional[float] = None
    for s in segs:
        x0 = left_pad + (s["start_ms"] / denom) * plot_w
        x1 = left_pad + (s["end_ms"] / denom) * plot_w
        x0 = max(left_pad, min(left_pad + plot_w - 3, x0))
        w = max(3.0, min(left_pad + plot_w - x0, x1 - x0))

        if s["is_stall"] and w > 6:
            mid_y = y_top + bar_h / 2
            parts.append(
                f'<line x1="{x0:.1f}" y1="{mid_y:.1f}" x2="{x0 + w - 3:.1f}" y2="{mid_y:.1f}" '
                f'stroke="{COLOR_STALL}" stroke-width="2" stroke-dasharray="4,3"/>'
            )

        is_err_frame = s["is_div"] or (lane_alert and s["cat"] == "TERMINAL")
        fill = _frame_color(s["cat"], is_alert=is_err_frame)
        fill_attr = f'url(#fold-{s["cat"]})' if (s["folded"] and s["cat"] in ("CONTENT", "REASONING")) else fill
        stroke = f' stroke="{COLOR_ALERT}" stroke-width="2"' if s["is_div"] else ""
        title_txt = (
            f'Collapsed {s["count"]} {s["cat"]} frames #{s["seq"]}..#{s["end_seq"]} ({s["start_ms"]:.1f}->{s["end_ms"]:.1f}ms)'
            if s["folded"]
            else f'#{s["seq"]} | {s["cat"]} | t={s["end_ms"]:.2f}ms | dt={s["dt_ms"]:.2f}ms'
        )
        detail_preview = _strip_controls_and_newlines(s["detail"])[:wire_cap] if wire_cap > 0 else ""
        wire_attr = f' data-wire="{_esc(detail_preview)}"' if detail_preview else ""
        parts.append(
            f'<rect class="wf-bar" data-lane="{_esc(lane_id, 24)}" data-seq="{s["seq"]}" '
            f'data-info="{_esc(title_txt, 120)}"{wire_attr} '
            f'x="{x0:.1f}" y="{y_top + 2}" width="{w:.1f}" height="{bar_h - 4}" rx="2" fill="{fill_attr}"{stroke}>'
            f'<title>{_esc(title_txt, 120)}</title></rect>'
        )

        if s["has_fffd"]:
            cx = x0 + w / 2
            cy = y_top + bar_h / 2
            parts.append(
                f'<polygon points="{cx:.1f},{cy - 5:.1f} {cx + 5:.1f},{cy:.1f} {cx:.1f},{cy + 5:.1f} {cx - 5:.1f},{cy:.1f}" '
                f'fill="{COLOR_ALERT}" stroke="#fff" stroke-width="1"><title>U+FFFD UTF-8 corruption at #{s["seq"]}</title></polygon>'
            )

        if s["is_div"]:
            div_x = x0 + w / 2

    return "\n".join(parts), div_x


def _svg_defs() -> str:
    return (
        "<defs>"
        f'<pattern id="fold-CONTENT" width="6" height="6" patternUnits="userSpaceOnUse" patternTransform="rotate(45)">'
        f'<rect width="6" height="6" fill="{COLOR_CONTENT}" fill-opacity="0.35"/>'
        f'<line x1="0" y1="0" x2="0" y2="6" stroke="{COLOR_CONTENT}" stroke-width="2"/></pattern>'
        f'<pattern id="fold-REASONING" width="6" height="6" patternUnits="userSpaceOnUse" patternTransform="rotate(45)">'
        f'<rect width="6" height="6" fill="{COLOR_REASONING}" fill-opacity="0.35"/>'
        f'<line x1="0" y1="0" x2="0" y2="6" stroke="{COLOR_REASONING}" stroke-width="2"/></pattern>'
        "</defs>"
    )


def _highlight_diff_text(a: str, b: str) -> Tuple[str, str]:
    sa = _strip_controls_and_newlines(redact_secret_text(a))[:280]
    sb = _strip_controls_and_newlines(redact_secret_text(b))[:280]
    lim = min(len(sa), len(sb))
    k = 0
    while k < lim and sa[k] == sb[k]:
        k += 1
    if k == len(sa) and k == len(sb):
        return _esc(sa), _esc(sb)
    ha = f"{_esc(sa[:k])}<mark>{_esc(sa[k:])}</mark>" if k < len(sa) else f"{_esc(sa)}<mark>[EOF]</mark>"
    hb = f"{_esc(sb[:k])}<mark>{_esc(sb[k:])}</mark>" if k < len(sb) else f"{_esc(sb)}<mark>[EOF]</mark>"
    return ha, hb


def _kpi_card(title: str, value: str, sub: str, accent: str = "") -> str:
    cls = f"kpi {accent}".strip()
    return (
        f'<div class="{cls}"><div class="kpi-t">{_esc(title, 48)}</div>'
        f'<div class="kpi-v">{_esc(value, 64)}</div>'
        f'<div class="kpi-s">{_esc(sub, 80)}</div></div>'
    )


def _probe_metric(value: Any, *, size: bool = False) -> str:
    if not is_finite_number(value) or value < 0:
        return "n/a"
    if size:
        if value >= 1024 * 1024:
            return f"{value / (1024 * 1024):.3g} MiB"
        if value >= 1024:
            return f"{value / 1024:.3g} KiB"
        return f"{value:.3g} B"
    return f"{value:.4g}"


def _backend_probe_kpi(doc: TraceDocument, findings: List[Finding]) -> str:
    bp = doc.summary.backend_probe
    if not isinstance(bp, dict):
        return _kpi_card("Backend Probe (v0.2)", "idle", "slot ready (LMCache/Mooncake/io)")
    pio = bp.get("proc_io") if isinstance(bp.get("proc_io"), dict) else {}
    pref = pio.get("prefill_window") if isinstance(pio.get("prefill_window"), dict) else {}
    lmc = bp.get("lmcache_mp") if isinstance(bp.get("lmcache_mp"), dict) else {}
    moon = bp.get("mooncake") if isinstance(bp.get("mooncake"), dict) else {}
    active_ids = sorted({f.detector_id for f in findings if f.detector_id in (D6, D7, D8)})
    status = ", ".join(active_ids) if active_ids else "no D6–D8 findings"
    metrics = []
    keys = _probe_metric(lmc.get("delta_hit_l2_keys"))
    tokens = _probe_metric(lmc.get("delta_hit_l2_tokens"))
    if keys != "n/a" or tokens != "n/a":
        metrics.append(f"L2 hits {keys} keys" if keys != "n/a" else f"L2 hits {tokens} tok")
    rchar = _probe_metric(pref.get("delta_rchar_bytes"), size=True)
    physical = _probe_metric(pref.get("delta_read_bytes"), size=True)
    if rchar != "n/a" or physical != "n/a":
        metrics.append(f"rchar {rchar} / read_bytes {physical}")
    if not metrics and (quota := _probe_metric(moon.get("delta_quota_rejects"))) != "n/a":
        metrics.append(f"Quota rejects {quota}")
    return _kpi_card("Backend Probe (v0.2)", f"active · {status}",
                     " · ".join(metrics) or "No counters available", "kpi-lit")


def _wrap_html_document(title: str, body_html: str) -> str:
    """Wrap body in a 100% airgap-safe HTML5 shell with hash-locked CSP and zero external assets."""
    css = (
        ":root{--bg:#0b1120;--card:#111827;--bd:#1f2937;--fg:#e5e7eb;--mut:#94a3b8}"
        "*{box-sizing:border-box}body{margin:0;background:var(--bg);color:var(--fg);font:13px/1.45 ui-sans-serif,system-ui,sans-serif;padding:14px}"
        ".wrap{max-width:1200px;margin:0 auto}.hero{background:var(--card);border:1px solid var(--bd);border-radius:10px;padding:12px 16px;margin-bottom:10px}"
        ".top{display:flex;justify-content:space-between;align-items:center;gap:10px;flex-wrap:wrap;margin-bottom:10px}"
        ".badge{padding:4px 10px;border-radius:6px;font:700 12px ui-monospace,Consolas,monospace;color:#fff}"
        ".b-red{background:#dc2626}.b-amb{background:#d97706}.b-grn{background:#059669}"
        ".pill{padding:2px 8px;border-radius:999px;background:#1e293b;color:#cbd5e1;font:11px ui-monospace,Consolas,monospace;border:1px solid #334155}"
        ".kpis{display:grid;grid-template-columns:repeat(5,1fr);gap:8px}"
        ".kpi{background:#0f172a;border:1px solid var(--bd);border-radius:8px;padding:8px 10px}"
        ".kpi-lit{border-color:#6366f1}.kpi-t{font-size:11px;color:var(--mut)}.kpi-v{font:700 14px ui-monospace,Consolas,monospace;margin-top:2px}.kpi-s{font-size:11px;color:#94a3b8;white-space:nowrap;overflow:hidden;text-overflow:ellipsis}"
        ".sec{background:var(--card);border:1px solid var(--bd);border-radius:10px;padding:12px 14px;margin-bottom:10px}"
        ".sec-h{display:flex;justify-content:space-between;align-items:center;margin-bottom:8px;gap:8px;flex-wrap:wrap}"
        ".sec-h h2{margin:0;font-size:13px;letter-spacing:.02em;color:#f8fafc}"
        ".legend{display:flex;gap:10px;flex-wrap:wrap;font-size:11px;color:var(--mut)}.dot{display:inline-block;width:9px;height:9px;border-radius:2px;margin-right:4px;vertical-align:-1px}"
        ".btn{background:#1e293b;color:#e2e8f0;border:1px solid #334155;border-radius:6px;padding:3px 9px;font:11px ui-monospace,Consolas,monospace;cursor:pointer}"
        ".btn.on{background:#312e81;border-color:#6366f1}"
        "svg{width:100%;height:auto;display:block}.wf-bar{cursor:pointer}.wf-bar:hover{opacity:.85}"
        ".split{display:grid;grid-template-columns:1fr 1fr;gap:10px}.code{background:#020617;border:1px solid var(--bd);border-radius:6px;padding:8px 10px;font:11.5px/1.4 ui-monospace,Consolas,monospace;overflow-x:auto;white-space:pre-wrap;word-break:break-all;margin:4px 0 0}"
        "mark{background:rgba(239,68,68,.35);color:#fecaca;border-radius:2px;padding:0 2px}"
        "table{width:100%;border-collapse:collapse;font-size:12px}th,td{text-align:left;padding:6px 8px;border-bottom:1px solid var(--bd)}th{color:var(--mut);font-weight:600}"
        "details summary{cursor:pointer;color:#93c5fd;font-size:12px}"
        ".foot{display:flex;justify-content:space-between;align-items:center;color:#64748b;font:11px ui-monospace,Consolas,monospace;padding:4px 2px}"
        ".hid{display:none}"
        "@media print{body{background:#fff;color:#111}.hero,.sec,.kpi,.code{background:#fff;border-color:#cbd5e1;color:#111}}"
        "@media(max-width:860px){.kpis{grid-template-columns:repeat(2,1fr)}.split{grid-template-columns:1fr}}"
    )
    csp = f"default-src 'none'; style-src 'unsafe-inline'; script-src 'sha256-{_SCRIPT_SHA256_B64}'; img-src data:;"
    doc_html = (
        "<!DOCTYPE html><html lang=\"en\"><head><meta charset=\"utf-8\">"
        "<meta name=\"viewport\" content=\"width=device-width,initial-scale=1\">"
        f"<meta http-equiv=\"Content-Security-Policy\" content=\"{csp}\">"
        f"<title>{_esc(title, 90)}</title><style>{css}</style></head><body>"
        f"<div class=\"wrap\">{_safe_utf8_str(body_html)}"
        f"<div class=\"foot\"><span>100% offline self-contained report (zero external CDN/fonts)</span>"
        f"<span>Generated by inferdiff v{__version__} &middot; Wire-Level LLM Regression &amp; Relay Forensics</span></div>"
        f"</div><script>{_STATIC_JS}</script></body></html>\n"
    )
    return _safe_utf8_str(doc_html)


def _fit_within_budget(
    title: str,
    summary_line: str,
    builder: Callable[[int, int, int], str],
    *,
    fallback_kpi: str = "",
) -> str:
    """Adaptively tighten folding and per-lane segment caps; fallback guarantees <80 KiB strictly."""
    tiers = (
        (FOLD_THRESHOLD_FRAMES, 200, 140),
        (120, 80, 80),
        (40, 32, 0),
        (12, 16, 0),
        (0, 8, 0),
    )
    for thresh, max_segs, wcap in tiers:
        candidate = builder(thresh, max_segs, wcap)
        if len(candidate.encode("utf-8")) < MAX_HTML_BYTES:
            return candidate
    # Guaranteed compact fallback (< 6 KiB) for extreme pathological traces
    fallback_body = (
        f'<div class="hero"><div class="top"><span class="badge b-amb">{_esc(title, 80)}</span></div>'
        f'<pre class="code">{_esc(summary_line, 600)}</pre></div>{fallback_kpi}'
    )
    return _wrap_html_document(title, fallback_body)


def _legend_html() -> str:
    items = [
        (COLOR_HANDSHAKE, "Handshake/Empty"),
        (COLOR_REASONING, "Reasoning"),
        (COLOR_CONTENT, "Content"),
        (COLOR_TOOL, "Tool Call"),
        (COLOR_STALL, "Stall >250ms"),
        (COLOR_ALERT, "Divergence/Breach"),
    ]
    return '<div class="legend">' + "".join(
        f'<span><i class="dot" style="background:{c}"></i>{lbl}</span>' for c, lbl in items
    ) + "</div>"


def _safe_model_label(doc: TraceDocument) -> str:
    raw = (doc.header.request.get("effective_params") or {}).get("model")
    if not isinstance(raw, str) or not raw.strip():
        return "unknown"
    return _strip_controls_and_newlines(redact_secret_text(raw))[:48]


def render_diff_html(
    before: TraceDocument,
    after: TraceDocument,
    report: DiffReport,
    *,
    include_body: bool = False,
    include_wire: bool = False,
) -> str:
    """Render a dual-lane single-file HTML5 + SVG frame waterfall report for `diff` / `compare`."""
    all_f = report.after_findings + report.pair_findings
    if report.exit_code == 2:
        b_cls = "b-red"
        verdict = f"EXIT 2 · {all_f[0].detector_id}: {all_f[0].code}" if all_f else "EXIT 2 · P0 PROTOCOL BREACH"
    elif report.exit_code == 3:
        b_cls = "b-amb"
        verdict = f"EXIT 3 · {all_f[0].detector_id}: {all_f[0].code}" if all_f else "EXIT 3 · SEMANTIC REGRESSION"
    else:
        b_cls = "b-grn"
        verdict = "EXIT 0 · PASS"

    st = report.summary_table
    model = _safe_model_label(after)
    a_asm = after.summary.assembled
    tools = a_asm.get("tool_calls") or []
    json_ok = all(tc.get("json_valid") is True for tc in tools) if tools else True
    has_fffd = "\ufffd" in (a_asm.get("content_text") or "")
    probe_kpi = _backend_probe_kpi(after, all_f)

    kpis = "".join(
        [
            _kpi_card(
                "TTFF / Effective TTFT",
                f"{st['before_ttft_effective_ms']} -> {st['after_ttft_effective_ms']} ms",
                f"handshake ttff: {st['before_ttff_ms']} -> {st['after_ttff_ms']} ms",
            ),
            _kpi_card(
                "Total / Clean EOF",
                f"{st['before_total_ms']} -> {st['after_total_ms']} ms",
                f"eof_clean: {st['before_eof_clean']} -> {st['after_eof_clean']}",
            ),
            _kpi_card(
                "Tokens vs Frames",
                f"{st['before_completion_tokens']} -> {st['after_completion_tokens']} tok",
                f"frames: {st['before_frames']} -> {st['after_frames']}",
            ),
            _kpi_card(
                "JSON / UTF-8 Integrity",
                "FAIL" if (not json_ok or has_fffd) else "OK",
                f"tools={len(tools)} json_valid={json_ok} fffd={has_fffd}",
            ),
            probe_kpi,
        ]
    )

    max_ms = max(before.summary.timing.get("total_ms") or 1.0, after.summary.timing.get("total_ms") or 1.0, 1.0)
    b_div_seq = report.first_divergence.before_seq if report.first_divergence else None
    a_div_seq = report.first_divergence.after_seq if report.first_divergence else None

    if report.first_divergence:
        d = report.first_divergence
        if include_wire:
            b_txt = d.before_raw_wire or "null"
            a_txt = d.after_raw_wire or "null"
        else:
            b_txt = _safe_frame_summary(before, d.before_seq)
            a_txt = _safe_frame_summary(after, d.after_seq)
        hl_b, hl_a = _highlight_diff_text(b_txt, a_txt)
        mode_note = "Raw wire (redacted)" if include_wire else "Structured frame summary (pass --include-wire for raw wire)"
        insp = (
            f'<div class="sec"><div class="sec-h"><h2>First-Divergence Inspector [{_esc(d.category, 24)}]</h2>'
            f'<span class="pill">{_esc(_strip_controls_and_newlines(d.detail), 120)}</span></div>'
            f'<div class="split">'
            f'<div><div class="kpi-t">Baseline Frame #{d.before_seq} (+{d.before_t_rel_ms} ms) · {_esc(mode_note, 64)}</div><pre class="code">{hl_b}</pre></div>'
            f'<div><div class="kpi-t">Target Frame #{d.after_seq} (+{d.after_t_rel_ms} ms) · {_esc(mode_note, 64)}</div><pre class="code">{hl_a}</pre></div>'
            f"</div>"
            f'<details style="margin-top:8px"><summary>Inspect clicked frame &amp; minimal sanitized curl reproducer</summary>'
            f'<pre id="click-wire" class="code">Click any frame bar in the waterfall above to inspect its frame summary.</pre>'
            f'<div style="display:flex;justify-content:space-between;align-items:center;margin-top:6px"><span class="kpi-t">Sanitized curl reproducer</span>'
            f'<button id="btn-copy" class="btn" type="button">Copy curl</button></div>'
            f'<pre id="curl-box" class="code">{_esc(chr(10).join(_sanitized_curl_lines(after, include_body=include_body)), 600)}</pre>'
            f"</details></div>"
        )
    else:
        insp = (
            '<div class="sec"><div class="sec-h"><h2>Frame Inspector</h2></div>'
            '<pre id="click-wire" class="code">No semantic divergence detected. Click any frame bar above to inspect its summary.</pre></div>'
        )

    title = f"inferdiff diff · {_strip_controls_and_newlines(report.before_label)[:32]} vs {_strip_controls_and_newlines(report.after_label)[:32]}"

    def _assemble(thresh: int, max_segs: int, wcap: int) -> str:
        def _dual_svg(svg_id: str, normalized: bool, hidden: bool, cap: int) -> str:
            l1, x1 = _render_lane_svg_elements(
                "Baseline", report.before_label, before, 14, max_ms=max_ms, normalized=normalized, divergence_seq=b_div_seq, lane_alert=False, fold_threshold=thresh, max_segments=max_segs, wire_cap=cap, include_wire=include_wire
            )
            l2, x2 = _render_lane_svg_elements(
                "Target", report.after_label, after, 54, max_ms=max_ms, normalized=normalized, divergence_seq=a_div_seq, lane_alert=(report.exit_code == 2), fold_threshold=thresh, max_segments=max_segs, wire_cap=cap, include_wire=include_wire
            )
            cross = ""
            if x1 is not None and x2 is not None:
                cross = (
                    f'<line x1="{x1:.1f}" y1="10" x2="{x2:.1f}" y2="82" '
                    f'stroke="{COLOR_ALERT}" stroke-width="1.6" stroke-dasharray="4,3"/>'
                )
            cls = ' class="hid"' if hidden else ""
            axis_lbl = "0% → 100% normalized progress" if normalized else f"0 ms → {max_ms:.1f} ms shared absolute clock"
            return (
                f'<svg id="{svg_id}"{cls} viewBox="0 0 1120 98" xmlns="http://www.w3.org/2000/svg">'
                f"{_svg_defs()}{l1}{l2}{cross}"
                f'<text x="190" y="94" fill="#64748b" font-size="10" font-family="ui-monospace,Consolas,monospace">{_esc(axis_lbl)}</text>'
                "</svg>"
            )

        svg_abs = _dual_svg("svg-abs", False, False, wcap)
        svg_norm = _dual_svg("svg-norm", True, True, 0)
        body = (
            f'<div class="hero"><div class="top"><div><span class="badge {b_cls}">{_esc(verdict, 80)}</span> '
            f'<span class="pill">{_esc(report.before_dialect)} → {_esc(report.after_dialect)}</span> '
            f'<span class="pill">model: {_esc(model, 48)}</span></div>'
            f'<div class="pill">{_esc(report.before_label, 36)} vs {_esc(report.after_label, 36)}</div></div>'
            f'<div class="kpis">{kpis}</div></div>'
            f'<div class="sec"><div class="sec-h"><h2>Dual-Lane Frame Waterfall (Hover for timing, click to inspect)</h2>'
            f'<div><button id="btn-abs" class="btn on" type="button">Absolute ms</button> '
            f'<button id="btn-norm" class="btn" type="button">Normalized %</button></div></div>'
            f"{_legend_html()}{svg_abs}{svg_norm}</div>"
            f"{insp}"
        )
        return _wrap_html_document(title, body)

    return _fit_within_budget(
        title, f"{verdict} | frames {st['before_frames']} -> {st['after_frames']}", _assemble,
        fallback_kpi=probe_kpi if after.summary.backend_probe is not None else "",
    )


def render_audit_html(
    doc: TraceDocument,
    findings: List[Finding],
    *,
    include_body: bool = False,
    include_wire: bool = False,
) -> str:
    """Render a single-lane airgap-safe HTML5 + SVG waterfall report for `audit`."""
    has_p0 = any(f.severity == "P0" for f in findings)
    has_p1 = any(f.severity == "P1" for f in findings)
    b_cls = "b-red" if has_p0 else ("b-amb" if has_p1 else "b-grn")
    verdict = f"{findings[0].severity} · {findings[0].detector_id}: {findings[0].code}" if findings else "PASS · 0 SILENT FAILURES"

    asm = doc.summary.assembled
    t = doc.summary.timing
    u = asm.get("reported_usage") or {}
    model = _safe_model_label(doc)
    tools = asm.get("tool_calls") or []
    json_ok = all(tc.get("json_valid") is True for tc in tools) if tools else True
    has_fffd = "\ufffd" in (asm.get("content_text") or "")
    probe_kpi = _backend_probe_kpi(doc, findings)

    kpis = "".join(
        [
            _kpi_card("TTFF / Effective TTFT", f"{t.get('ttff_ms')} / {t.get('ttft_effective_ms')} ms", f"headers: {t.get('t_headers_ms')} ms"),
            _kpi_card("Total / Clean EOF", f"{t.get('total_ms')} ms", f"eof_clean={doc.summary.eof_clean}"),
            _kpi_card("Tokens vs Frames", f"{u.get('completion_tokens')} tok", f"{doc.summary.total_frames} frames ({asm.get('content_utf8_bytes')} B)"),
            _kpi_card("JSON / UTF-8", "FAIL" if (not json_ok or has_fffd) else "OK", f"finish={_strip_controls_and_newlines(asm.get('finish_reason'))[:24]}/{_strip_controls_and_newlines(asm.get('terminal_status'))[:24]}"),
            probe_kpi,
        ]
    )

    max_ms = max(t.get("total_ms") or 1.0, 1.0)
    div_seq = findings[0].frame_seq if findings else None
    capped_findings = findings[:MAX_FINDING_ROWS]
    f_rows = "".join(
        f"<tr><td><span class='badge {'b-red' if f.severity == 'P0' else 'b-amb'}'>{_esc(f.severity, 8)}</span></td>"
        f"<td><code>{_esc(f.detector_id, 8)}</code></td><td>{_esc(f.code, 48)}</td><td>#{f.frame_seq}</td>"
        f"<td>{_esc(_strip_controls_and_newlines(redact_secret_text(f.message)), 160)}</td></tr>"
        for f in capped_findings
    ) or "<tr><td colspan='5'>No silent protocol breaches detected (D1-D4).</td></tr>"
    if len(findings) > MAX_FINDING_ROWS:
        f_rows += f"<tr><td colspan='5'>... {len(findings) - MAX_FINDING_ROWS} additional finding(s) omitted for 80 KiB budget.</td></tr>"

    title = f"inferdiff audit · {_strip_controls_and_newlines(doc.header.label or doc.header.dialect)[:48]}"

    def _assemble(thresh: int, max_segs: int, wcap: int) -> str:
        lane_svg, _ = _render_lane_svg_elements(
            "Target", doc.header.label or doc.header.dialect, doc, 14, max_ms=max_ms, normalized=False, divergence_seq=div_seq, lane_alert=has_p0, fold_threshold=thresh, max_segments=max_segs, wire_cap=wcap, include_wire=include_wire
        )
        svg = (
            f'<svg id="svg-abs" viewBox="0 0 1120 58" xmlns="http://www.w3.org/2000/svg">{_svg_defs()}{lane_svg}'
            f'<text x="190" y="54" fill="#64748b" font-size="10" font-family="ui-monospace,Consolas,monospace">0 ms → {max_ms:.1f} ms</text></svg>'
        )
        body = (
            f'<div class="hero"><div class="top"><div><span class="badge {b_cls}">{_esc(verdict, 80)}</span> '
            f'<span class="pill">{_esc(doc.header.dialect)}</span> <span class="pill">model: {_esc(model, 48)}</span></div></div>'
            f'<div class="kpis">{kpis}</div></div>'
            f'<div class="sec"><div class="sec-h"><h2>Single-Track Frame Waterfall</h2></div>{_legend_html()}{svg}</div>'
            f'<div class="sec"><div class="sec-h"><h2>Audit Findings &amp; Frame Inspector</h2></div>'
            f"<table><thead><tr><th>Sev</th><th>ID</th><th>Rule</th><th>Frame</th><th>Evidence</th></tr></thead><tbody>{f_rows}</tbody></table>"
            f'<pre id="click-wire" class="code" style="margin-top:8px">Click any frame bar above to inspect its summary.</pre>'
            f'<details style="margin-top:8px"><summary>Minimal sanitized curl reproducer</summary>'
            f'<pre id="curl-box" class="code">{_esc(chr(10).join(_sanitized_curl_lines(doc, include_body=include_body)), 600)}</pre></details></div>'
        )
        return _wrap_html_document(title, body)

    return _fit_within_budget(
        title, f"{verdict} | {doc.summary.total_frames} frames", _assemble,
        fallback_kpi=probe_kpi if doc.summary.backend_probe is not None else "",
    )


def render_doctor_html(report: DoctorReport, *, include_wire: bool = False) -> str:
    """Render the C1..C8 Doctor Health Scorecard + multi-lane SVG frame waterfalls."""
    b_cls = "b-red" if report.grade == "F" else ("b-amb" if report.warning_count > 0 else "b-grn")
    verdict = f"DOCTOR GRADE: {report.grade} · EXIT {report.exit_code}"
    tok_str = f"{report.total_tokens:,} tok" if report.total_tokens is not None else "unknown"
    passed = sum(1 for r in report.results if r.status == "PASS")
    tot_ms = sum(r.duration_ms for r in report.results)

    kpis = "".join(
        [
            _kpi_card("Wire Health Grade", report.grade, f"{passed}/{len(report.results)} probes passed"),
            _kpi_card("P0 Protocol Breaches", str(report.p0_count), f"{report.error_count} errors, {report.warning_count} warnings"),
            _kpi_card("Total Canary Cost", tok_str, f"profile: {report.profile}"),
            _kpi_card("Total Latency", f"{tot_ms:.0f} ms", f"dialect: {report.dialect}"),
            _kpi_card("Target Endpoint", redact_secret_text(report.model)[:22], redact_secret_text(report.target_url)[:36]),
        ]
    )

    traced_lanes: List[Tuple[str, TraceDocument, bool]] = []
    for r in report.results:
        if r.traces:
            traced_lanes.append((f"{r.probe_id} {r.status}", r.traces[-1], r.status in ("FAIL", "ERROR")))

    max_ms = max((doc.summary.timing.get("total_ms") or 1.0 for _, doc, _ in traced_lanes), default=1.0)
    svg_h = max(60, len(traced_lanes) * 34 + 26)
    st_badge = {"PASS": "b-grn", "WARN": "b-amb", "FAIL": "b-red", "ERROR": "b-red", "SKIP": "pill"}
    rows: List[str] = []
    for r in report.results:
        cls = st_badge.get(r.status, "pill")
        tok = str(r.tokens_used) if r.tokens_used is not None else "unknown"
        ref_html = _safe_anchor(r.reference_url, "anchor")
        wire_snippet = ""
        if r.traces and r.traces[-1].frames:
            doc_last = r.traces[-1]
            snip = (
                redact_secret_text(doc_last.frames[-1].raw_wire)[:180]
                if include_wire
                else _safe_frame_summary(doc_last, doc_last.frames[-1].seq)
            )
            wire_snippet = f'<details><summary>frame</summary><pre class="code">{_esc(_strip_controls_and_newlines(snip), 180)}</pre></details>'
        rows.append(
            f"<tr><td><span class='badge {cls}'>{_esc(r.status, 12)}</span></td>"
            f"<td><code>{_esc(r.probe_id, 8)}</code> {_esc(r.code, 40)}</td>"
            f"<td>{r.duration_ms:.0f} ms</td><td>{r.total_frames}</td><td>{_esc(tok, 16)}</td>"
            f"<td>{_esc(_strip_controls_and_newlines(redact_secret_text(r.summary)), 150)} {wire_snippet}</td><td>{ref_html}</td></tr>"
        )

    title = f"inferdiff doctor · {redact_secret_text(report.model)[:36]} (Grade {report.grade})"

    def _assemble(thresh: int, max_segs: int, wcap: int) -> str:
        per_lane_cap = max(8, max_segs // max(1, len(traced_lanes)))
        lanes_abs: List[str] = []
        lanes_norm: List[str] = []
        for idx, (lbl, doc, is_fail) in enumerate(traced_lanes):
            y = 12 + idx * 34
            s_a, _ = _render_lane_svg_elements(lbl, lbl, doc, y, max_ms=max_ms, normalized=False, divergence_seq=None, lane_alert=is_fail, fold_threshold=thresh, max_segments=per_lane_cap, wire_cap=wcap, include_wire=include_wire)
            s_n, _ = _render_lane_svg_elements(lbl, lbl, doc, y, max_ms=max_ms, normalized=True, divergence_seq=None, lane_alert=is_fail, fold_threshold=thresh, max_segments=per_lane_cap, wire_cap=0, include_wire=include_wire)
            lanes_abs.append(s_a)
            lanes_norm.append(s_n)

        svg_abs = (
            f'<svg id="svg-abs" viewBox="0 0 1120 {svg_h}" xmlns="http://www.w3.org/2000/svg">'
            f"{_svg_defs()}{''.join(lanes_abs)}"
            f'<text x="190" y="{svg_h - 6}" fill="#64748b" font-size="10" font-family="ui-monospace,Consolas,monospace">0 ms → {max_ms:.1f} ms shared absolute clock</text></svg>'
        )
        svg_norm = (
            f'<svg id="svg-norm" class="hid" viewBox="0 0 1120 {svg_h}" xmlns="http://www.w3.org/2000/svg">'
            f"{_svg_defs()}{''.join(lanes_norm)}"
            f'<text x="190" y="{svg_h - 6}" fill="#64748b" font-size="10" font-family="ui-monospace,Consolas,monospace">0% → 100% normalized per-probe progress</text></svg>'
        )
        body = (
            f'<div class="hero"><div class="top"><div><span class="badge {b_cls}">{_esc(verdict, 80)}</span> '
            f'<span class="pill">profile: {_esc(report.profile)}</span> <span class="pill">model: {_esc(redact_secret_text(report.model), 48)}</span></div>'
            f'<div class="pill">{_esc(redact_secret_text(report.target_url), 72)}</div></div>'
            f'<div class="kpis">{kpis}</div></div>'
            f'<div class="sec"><div class="sec-h"><h2>Canary Multi-Lane Frame Waterfall (C1-C8)</h2>'
            f'<div><button id="btn-abs" class="btn on" type="button">Absolute ms</button> '
            f'<button id="btn-norm" class="btn" type="button">Normalized %</button></div></div>'
            f"{_legend_html()}{svg_abs}{svg_norm}"
            f'<pre id="click-wire" class="code" style="margin-top:8px">Click any frame bar above to inspect its summary.</pre></div>'
            f'<div class="sec"><div class="sec-h"><h2>Endpoint &amp; Relay Canary Matrix (C1-C8)</h2></div>'
            f"<table><thead><tr><th>Status</th><th>Probe</th><th>Time</th><th>Frames</th><th>Tokens</th><th>Verdict &amp; Evidence</th><th>Ref</th></tr></thead>"
            f"<tbody>{''.join(rows)}</tbody></table></div>"
        )
        return _wrap_html_document(title, body)

    return _fit_within_budget(title, f"{verdict} | profile={report.profile}", _assemble)
