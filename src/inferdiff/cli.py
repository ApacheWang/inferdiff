"""Argparse CLI entrypoint for inferdiff (doctor, record, audit, diff, compare, export)."""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path
from typing import Any, Dict, List, Optional, Sequence

from . import __version__
from .canary import render_doctor_terminal, run_doctor
from .detectors import VALID_AUDIT_DETECTORS, audit_trace
from .differ import diff_traces
from .exporter import (
    render_audit_terminal,
    render_ci_summary,
    render_diff_terminal,
    render_github_issue,
    sanitize_trace_for_json_export,
)
from .recorder import RecorderError, record_stream, validate_and_merge_headers
from .schema import (
    EXIT_OK,
    EXIT_SEMANTIC_REGRESSION,
    EXIT_SILENT_PROTOCOL_BREACH,
    EXIT_USAGE_OR_IO_ERROR,
    TraceSchemaError,
    VALID_DIALECTS,
    load_trace,
    strict_json_loads,
)
from .waterfall import render_audit_html, render_diff_html, render_doctor_html


def _configure_stdio() -> None:
    for stream in (sys.stdout, sys.stderr):
        if hasattr(stream, "reconfigure"):
            try:
                stream.reconfigure(encoding="utf-8", errors="backslashreplace", newline="\n")
            except Exception:
                pass


def _norm_path_key(path: str | Path) -> str:
    resolved = str(Path(path).resolve())
    return resolved.lower() if sys.platform == "win32" else resolved


def _assert_distinct_output_path(out_path: str, protected_paths: Sequence[str | Path]) -> None:
    """Reject writing HTML/export output over an input trace, captured trace, or doctor_summary.json."""
    if not out_path:
        return
    out_key = _norm_path_key(out_path)
    for prot in protected_paths:
        if prot and _norm_path_key(prot) == out_key:
            raise ValueError(f"Output path {out_path!r} would overwrite trace/evidence file {str(prot)!r}.")


def _write_text_file(path: str, content: str) -> None:
    p = Path(path)
    p.parent.mkdir(parents=True, exist_ok=True)
    p.write_text(content, encoding="utf-8", newline="\n")


def _parse_headers(raw_headers: Optional[Sequence[str]]) -> Dict[str, str]:
    parsed: Dict[str, str] = {}
    if not raw_headers:
        return parsed
    for item in raw_headers:
        if ":" not in item:
            raise ValueError("Invalid --header format (expected 'Name: value').")
        name, val = item.split(":", 1)
        parsed[name.strip()] = val.strip()
    return validate_and_merge_headers({}, parsed)


def _load_request_bodies(source: str, *, allow_jsonl: bool = False) -> List[Dict[str, Any]]:
    """Load a single JSON request object (or multi-line JSONL request suite when allow_jsonl=True)."""
    if source in ("-", "@-"):
        text = sys.stdin.read()
    else:
        p = Path(source)
        if not p.exists():
            raise ValueError(f"Request file not found: {source}")
        text = p.read_text(encoding="utf-8")

    stripped = text.strip()
    if not stripped:
        raise ValueError("Request input is empty.")

    try:
        obj = strict_json_loads(stripped)
    except json.JSONDecodeError:
        if not allow_jsonl:
            raise
        bodies: List[Dict[str, Any]] = []
        for lineno, line in enumerate(text.splitlines(), start=1):
            if not line.strip():
                continue
            item = strict_json_loads(line)
            if not isinstance(item, dict):
                raise ValueError(f"Request JSONL line {lineno} must be a JSON object.")
            bodies.append(item)
        if not bodies:
            raise ValueError("Request JSONL input contains no objects.")
        return bodies

    if not isinstance(obj, dict):
        raise ValueError("Request JSON must be an object.")
    return [obj]


def _derive_suite_out_path(base_out: str, idx: int) -> Path:
    p = Path(base_out)
    if base_out.endswith(("/", "\\")) or p.is_dir():
        return p / f"req_{idx:03d}.trace.jsonl"
    name = p.name
    if name.endswith(".trace.jsonl"):
        stem = name[: -len(".trace.jsonl")]
        return p.with_name(f"{stem}_{idx:03d}.trace.jsonl")
    return p.with_name(f"{p.stem}_{idx:03d}{p.suffix or '.trace.jsonl'}")


def _audit_exit_code(findings: List[Any], *, strict: bool) -> int:
    if any(f.severity == "P0" for f in findings):
        return EXIT_SILENT_PROTOCOL_BREACH
    if strict and any(f.severity == "P1" for f in findings):
        return EXIT_SEMANTIC_REGRESSION
    return EXIT_OK


def _aggregate_exit_code(current: int, new_rc: int) -> int:
    if current == EXIT_SILENT_PROTOCOL_BREACH or new_rc == EXIT_SILENT_PROTOCOL_BREACH:
        return EXIT_SILENT_PROTOCOL_BREACH
    if current == EXIT_SEMANTIC_REGRESSION or new_rc == EXIT_SEMANTIC_REGRESSION:
        return EXIT_SEMANTIC_REGRESSION
    return EXIT_OK


def _cmd_doctor(args: argparse.Namespace) -> int:
    headers = _parse_headers(args.header)
    if args.html and args.save_dir:
        _assert_distinct_output_path(args.html, [Path(args.save_dir) / "doctor_summary.json"])
    report = run_doctor(
        base_url=args.base_url,
        model=args.model or None,
        api_key=args.api_key,
        headers=headers,
        profile=args.profile,
        timeout=args.timeout,
        save_dir=args.save_dir,
        strict=args.strict,
    )
    if args.html:
        protected: List[str | Path] = []
        if report.save_dir:
            protected.append(Path(report.save_dir) / "doctor_summary.json")
        for r in report.results:
            protected.extend(r.trace_paths)
        _assert_distinct_output_path(args.html, protected)
        _write_text_file(args.html, render_doctor_html(report))
    if args.json:
        sys.stdout.write(json.dumps(report.to_dict(), ensure_ascii=True, separators=(",", ":")) + "\n")
    else:
        sys.stdout.write(render_doctor_terminal(report, no_color=args.no_color))
        if args.html:
            sys.stdout.write(f"Saved HTML waterfall report: {args.html}\n")
    return report.exit_code


def _cmd_record(args: argparse.Namespace) -> int:
    headers = _parse_headers(args.header)
    bodies = _load_request_bodies(args.request, allow_jsonl=True)
    agg_rc = EXIT_OK

    for idx, body in enumerate(bodies, start=1):
        out_target = Path(args.out) if len(bodies) == 1 else _derive_suite_out_path(args.out, idx)
        lbl = args.label or ""
        if len(bodies) > 1:
            lbl = f"{lbl}#{idx}" if lbl else f"req#{idx}"
        doc = record_stream(
            url=args.url,
            request_body=body,
            out_path=out_target,
            headers=headers,
            dialect=args.dialect,
            label=lbl,
            timeout=args.timeout,
        )
        findings = audit_trace(doc)
        sys.stdout.write(render_audit_terminal(doc, findings, no_color=args.no_color))
        sys.stdout.write(f"Saved trace: {out_target}\n")
        agg_rc = _aggregate_exit_code(agg_rc, _audit_exit_code(findings, strict=True))
    return agg_rc


def _parse_only_detectors(raw_only: Optional[str]) -> Optional[set[str]]:
    if raw_only is None:
        return None
    tokens = [tok.strip().upper() for tok in raw_only.split(",") if tok.strip()]
    if not tokens:
        raise ValueError("Invalid --only value: must specify one or more of D1, D2, D3, D4.")
    unknown = sorted(set(tokens) - VALID_AUDIT_DETECTORS)
    if unknown:
        raise ValueError(
            f"Unknown detector(s) in --only: {', '.join(unknown)} (valid for audit: D1, D2, D3, D4)."
        )
    return set(tokens)


def _cmd_audit(args: argparse.Namespace) -> int:
    only = _parse_only_detectors(args.only)
    if args.html:
        _assert_distinct_output_path(args.html, [args.trace_path])
    doc = load_trace(args.trace_path)
    findings = audit_trace(doc, only=only)
    rc = _audit_exit_code(findings, strict=args.strict)
    if args.html:
        _write_text_file(args.html, render_audit_html(doc, findings))
    if args.json:
        safe = sanitize_trace_for_json_export(doc, include_body=False, include_wire=False)
        payload = {
            **safe,
            "findings": [f.to_dict() for f in findings],
            "exit_code": rc,
        }
        sys.stdout.write(json.dumps(payload, ensure_ascii=True, separators=(",", ":")) + "\n")
    else:
        sys.stdout.write(render_audit_terminal(doc, findings, no_color=args.no_color))
        if args.html:
            sys.stdout.write(f"Saved HTML waterfall report: {args.html}\n")
    return rc


def _cmd_diff(args: argparse.Namespace) -> int:
    if args.html:
        _assert_distinct_output_path(args.html, [args.before_trace, args.after_trace])
    before = load_trace(args.before_trace)
    after = load_trace(args.after_trace)
    report = diff_traces(
        before,
        after,
        ignore_timing=args.ignore_timing,
        ttft_regress_pct=args.ttft_regress_pct,
        fail_on=args.fail_on,
    )
    if args.html:
        _write_text_file(args.html, render_diff_html(before, after, report))
    if args.json:
        sys.stdout.write(json.dumps(report.to_dict(include_wire=False), ensure_ascii=True, separators=(",", ":")) + "\n")
    else:
        sys.stdout.write(render_diff_terminal(report, no_color=args.no_color))
        if args.html:
            sys.stdout.write(f"Saved HTML waterfall report: {args.html}\n")
    return report.exit_code


def _cmd_compare(args: argparse.Namespace) -> int:
    shared_headers = _parse_headers(args.header)
    before_headers = validate_and_merge_headers(shared_headers, _parse_headers(args.before_header))
    after_headers = validate_and_merge_headers(shared_headers, _parse_headers(args.after_header))

    bodies = _load_request_bodies(args.request, allow_jsonl=False)
    body = bodies[0]
    save_dir = Path(args.save_dir) if args.save_dir else None
    b_out = (save_dir / "before.trace.jsonl") if save_dir else None
    a_out = (save_dir / "after.trace.jsonl") if save_dir else None
    if args.html:
        protected = [p for p in (b_out, a_out) if p is not None]
        if args.request not in ("-", "@-"):
            protected.append(args.request)
        _assert_distinct_output_path(args.html, protected)

    before = record_stream(
        url=args.before_url,
        request_body=body,
        out_path=b_out,
        headers=before_headers,
        dialect=args.dialect,
        label=args.before_label or "before",
        timeout=args.timeout,
    )
    after = record_stream(
        url=args.after_url,
        request_body=body,
        out_path=a_out,
        headers=after_headers,
        dialect=args.dialect,
        label=args.after_label or "after",
        timeout=args.timeout,
    )
    report = diff_traces(
        before,
        after,
        ignore_timing=args.ignore_timing,
        ttft_regress_pct=args.ttft_regress_pct,
        fail_on=args.fail_on,
    )
    if args.html:
        _write_text_file(args.html, render_diff_html(before, after, report))
    if args.json:
        sys.stdout.write(json.dumps(report.to_dict(include_wire=False), ensure_ascii=True, separators=(",", ":")) + "\n")
    else:
        sys.stdout.write(render_diff_terminal(report, no_color=args.no_color))
        if args.html:
            sys.stdout.write(f"Saved HTML waterfall report: {args.html}\n")
    return report.exit_code


def _cmd_export(args: argparse.Namespace) -> int:
    if args.out:
        _assert_distinct_output_path(args.out, [p for p in (args.before, args.after) if p])
    before = load_trace(args.before)
    after = load_trace(args.after) if args.after else None

    if after is not None:
        report = diff_traces(before, after, fail_on="p1")
        rc = report.exit_code
        if args.format == "github-issue":
            rendered = render_github_issue(
                before,
                after,
                diff_report=report,
                before_path=Path(args.before).name,
                after_path=Path(args.after).name,
                include_body=args.include_body,
                include_wire=args.include_wire,
            )
        elif args.format == "ci-summary":
            rendered = render_ci_summary(before, after, diff_report=report)
        elif args.format == "html":
            rendered = render_diff_html(before, after, report, include_body=args.include_body, include_wire=args.include_wire)
        else:
            rendered = json.dumps(report.to_dict(include_wire=args.include_wire), ensure_ascii=True, indent=2) + "\n"
    else:
        findings = audit_trace(before)
        rc = _audit_exit_code(findings, strict=True)
        if args.format == "github-issue":
            rendered = render_github_issue(
                before,
                None,
                audit_findings=findings,
                before_path=Path(args.before).name,
                include_body=args.include_body,
                include_wire=args.include_wire,
            )
        elif args.format == "ci-summary":
            rendered = render_ci_summary(before, None, audit_findings=findings)
        elif args.format == "html":
            rendered = render_audit_html(before, findings, include_body=args.include_body, include_wire=args.include_wire)
        else:
            safe = sanitize_trace_for_json_export(
                before,
                include_body=args.include_body,
                include_wire=args.include_wire,
            )
            rendered = (
                json.dumps(
                    {
                        **safe,
                        "findings": [f.to_dict() for f in findings],
                        "exit_code": rc,
                    },
                    ensure_ascii=True,
                    indent=2,
                )
                + "\n"
            )

    if args.out:
        _write_text_file(args.out, rendered)
    else:
        sys.stdout.write(rendered)
    return rc


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="inferdiff",
        description="Wire-level canary doctor, regression diff, and silent-failure forensics for LLM serving & API relays.",
    )
    parser.add_argument("--version", action="version", version=f"inferdiff {__version__}")
    sub = parser.add_subparsers(dest="command", required=True)

    # doctor (primary zero-setup entry point per Spec §2.1)
    p_doc = sub.add_parser("doctor", help="Zero-setup C1..C8 canary health check for local engines or API relays")
    p_doc.add_argument("base_url", help="Target base URL (e.g. http://127.0.0.1:8080/v1 or https://api.example.com/v1)")
    p_doc.add_argument("--model", "-m", default="", help="Model ID (auto-discovers /models or /api/tags if omitted)")
    p_doc.add_argument("--api-key", default=None, help="API key or $ENV_VAR (defaults to OPENAI_API_KEY, always redacted)")
    p_doc.add_argument("--header", "-H", action="append", default=[], help="Extra HTTP header 'Name: value' (repeatable)")
    p_doc.add_argument("--profile", choices=("quick", "full", "relay"), default="quick", help="Canary profile (quick/full/relay)")
    p_doc.add_argument("--timeout", type=float, default=60.0, help="Per-probe socket timeout in seconds")
    p_doc.add_argument("--save-dir", default="", help="Directory to save canary .trace.jsonl files (default ./.inferdiff-doctor/<ts>/)")
    p_doc.add_argument("--html", default="", help="Write single-file airgap-safe HTML scorecard & SVG waterfall")
    p_doc.add_argument("--strict", action="store_true", help="Exit 3 on P1 warnings (P0 breaches always exit 2)")
    p_doc.add_argument("--json", action="store_true", help="Emit JSON canary matrix report")
    p_doc.add_argument("--no-color", action="store_true")
    p_doc.set_defaults(func=_cmd_doctor)

    # record
    p_rec = sub.add_parser("record", help="Record live streaming LLM request (or JSONL suite) to .trace.jsonl")
    p_rec.add_argument("--url", required=True, help="Target endpoint URL")
    p_rec.add_argument("--request", "-d", required=True, help="JSON request file, multi-line .jsonl suite, or '-' / '@-' for stdin")
    p_rec.add_argument("--header", "-H", action="append", default=[], help="Extra HTTP header 'Name: value' (repeatable)")
    p_rec.add_argument("--dialect", choices=("auto", *VALID_DIALECTS), default="auto")
    p_rec.add_argument("--label", default="", help="Version label (e.g. llama-server-v1.1.0)")
    p_rec.add_argument("--timeout", type=float, default=120.0, help="Socket timeout in seconds")
    p_rec.add_argument("--out", "-o", required=True, help="Output .trace.jsonl path (or prefix/dir for JSONL suites)")
    p_rec.add_argument("--no-color", action="store_true")
    p_rec.set_defaults(func=_cmd_record)

    # audit
    p_aud = sub.add_parser("audit", help="Audit a single .trace.jsonl for D1..D4 silent failures")
    p_aud.add_argument("trace_path", help="Path to .trace.jsonl")
    p_aud.add_argument("--only", default=None, help="Comma-separated detector subset from D1,D2,D3,D4")
    p_aud.add_argument("--html", default="", help="Write single-file airgap-safe HTML frame waterfall")
    p_aud.add_argument("--json", action="store_true", help="Emit sanitized JSON audit report")
    p_aud.add_argument("--strict", action="store_true", help="Treat P1 warnings as non-zero exit code 3")
    p_aud.add_argument("--no-color", action="store_true")
    p_aud.set_defaults(func=_cmd_audit)

    # diff
    p_diff = sub.add_parser("diff", help="Diff baseline and target .trace.jsonl with chunk-jitter-proof alignment")
    p_diff.add_argument("before_trace", help="Baseline .trace.jsonl")
    p_diff.add_argument("after_trace", help="Target .trace.jsonl")
    p_diff.add_argument(
        "--ignore-timing",
        action="store_true",
        help="Ignore TTFT latency regression and D5 timing/benchmark-illusion alerts",
    )
    p_diff.add_argument("--ttft-regress-pct", type=float, default=50.0)
    p_diff.add_argument("--fail-on", choices=("p0", "p1", "any-diff"), default="p0")
    p_diff.add_argument("--html", default="", help="Write dual-lane single-file HTML frame waterfall")
    p_diff.add_argument("--json", action="store_true")
    p_diff.add_argument("--no-color", action="store_true")
    p_diff.set_defaults(func=_cmd_diff)

    # compare
    p_cmp = sub.add_parser("compare", help="Record two live endpoints sequentially and diff immediately")
    p_cmp.add_argument("--before-url", required=True)
    p_cmp.add_argument("--after-url", required=True)
    p_cmp.add_argument("--request", "-d", required=True)
    p_cmp.add_argument("--header", "-H", action="append", default=[], help="Shared HTTP header for both targets")
    p_cmp.add_argument("--before-header", action="append", default=[], help="HTTP header scoped only to --before-url")
    p_cmp.add_argument("--after-header", action="append", default=[], help="HTTP header scoped only to --after-url")
    p_cmp.add_argument("--dialect", choices=("auto", *VALID_DIALECTS), default="auto")
    p_cmp.add_argument("--before-label", default="before")
    p_cmp.add_argument("--after-label", default="after")
    p_cmp.add_argument("--timeout", type=float, default=120.0)
    p_cmp.add_argument("--save-dir", default="", help="Optional directory to save before/after traces")
    p_cmp.add_argument(
        "--ignore-timing",
        action="store_true",
        help="Ignore TTFT latency regression and D5 timing/benchmark-illusion alerts",
    )
    p_cmp.add_argument("--ttft-regress-pct", type=float, default=50.0)
    p_cmp.add_argument("--fail-on", choices=("p0", "p1", "any-diff"), default="p0")
    p_cmp.add_argument("--html", default="", help="Write dual-lane single-file HTML frame waterfall")
    p_cmp.add_argument("--json", action="store_true")
    p_cmp.add_argument("--no-color", action="store_true")
    p_cmp.set_defaults(func=_cmd_compare)

    # export
    p_exp = sub.add_parser("export", help="Export compact <=25-line sanitized GitHub Issue, HTML waterfall, or CI summary")
    p_exp.add_argument("before", help="Single trace (audit) or baseline trace (diff)")
    p_exp.add_argument("after", nargs="?", default=None, help="Optional target trace for diff export")
    p_exp.add_argument("--format", choices=("github-issue", "ci-summary", "html", "json"), default="github-issue")
    p_exp.add_argument("--include-body", action="store_true", help="Include sanitized request body in export")
    p_exp.add_argument("--include-wire", action="store_true", help="Include sanitized raw wire frame excerpts in export")
    p_exp.add_argument("--out", "-o", default="", help="Output file path (defaults to stdout)")
    p_exp.set_defaults(func=_cmd_export)

    return parser


def main(argv: Optional[Sequence[str]] = None) -> int:
    _configure_stdio()
    parser = build_parser()
    try:
        args = parser.parse_args(argv)
    except SystemExit as exc:
        code = exc.code if isinstance(exc.code, int) else EXIT_USAGE_OR_IO_ERROR
        return EXIT_OK if code == 0 else EXIT_USAGE_OR_IO_ERROR

    try:
        return int(args.func(args))
    except (RecorderError, TraceSchemaError, ValueError, OSError, json.JSONDecodeError) as exc:
        sys.stderr.write(f"inferdiff error: {exc}\n")
        return EXIT_USAGE_OR_IO_ERROR
