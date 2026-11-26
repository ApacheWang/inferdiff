"""Argparse CLI entrypoint for inferdiff (record, audit, diff, compare, export)."""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path
from typing import Any, Dict, List, Optional, Sequence

from . import __version__
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


def _configure_stdio() -> None:
    for stream in (sys.stdout, sys.stderr):
        if hasattr(stream, "reconfigure"):
            try:
                stream.reconfigure(encoding="utf-8", errors="backslashreplace", newline="\n")
            except Exception:
                pass


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

    # Try single JSON document first
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
    """Derive a distinct .trace.jsonl filename for request `idx` (1-based) in a JSONL suite."""
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
    """Combine exit codes across a recorded suite: P0 (2) > P1 (3) > OK (0)."""
    if current == EXIT_SILENT_PROTOCOL_BREACH or new_rc == EXIT_SILENT_PROTOCOL_BREACH:
        return EXIT_SILENT_PROTOCOL_BREACH
    if current == EXIT_SEMANTIC_REGRESSION or new_rc == EXIT_SEMANTIC_REGRESSION:
        return EXIT_SEMANTIC_REGRESSION
    return EXIT_OK


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
    doc = load_trace(args.trace_path)
    findings = audit_trace(doc, only=only)
    rc = _audit_exit_code(findings, strict=args.strict)
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
    return rc


def _cmd_diff(args: argparse.Namespace) -> int:
    before = load_trace(args.before_trace)
    after = load_trace(args.after_trace)
    report = diff_traces(
        before,
        after,
        ignore_timing=args.ignore_timing,
        ttft_regress_pct=args.ttft_regress_pct,
        fail_on=args.fail_on,
    )
    if args.json:
        sys.stdout.write(json.dumps(report.to_dict(include_wire=False), ensure_ascii=True, separators=(",", ":")) + "\n")
    else:
        sys.stdout.write(render_diff_terminal(report, no_color=args.no_color))
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
    if args.json:
        sys.stdout.write(json.dumps(report.to_dict(include_wire=False), ensure_ascii=True, separators=(",", ":")) + "\n")
    else:
        sys.stdout.write(render_diff_terminal(report, no_color=args.no_color))
    return report.exit_code


def _cmd_export(args: argparse.Namespace) -> int:
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
        out_p = Path(args.out)
        out_p.parent.mkdir(parents=True, exist_ok=True)
        out_p.write_text(rendered, encoding="utf-8", newline="\n")
    else:
        sys.stdout.write(rendered)
    return rc


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="inferdiff",
        description="Wire-level regression diff and silent-failure forensics for LLM serving upgrades.",
    )
    parser.add_argument("--version", action="version", version=f"inferdiff {__version__}")
    sub = parser.add_subparsers(dest="command", required=True)

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
    p_cmp.add_argument("--json", action="store_true")
    p_cmp.add_argument("--no-color", action="store_true")
    p_cmp.set_defaults(func=_cmd_compare)

    # export
    p_exp = sub.add_parser("export", help="Export compact <=25-line sanitized GitHub Issue or CI summary")
    p_exp.add_argument("before", help="Single trace (audit) or baseline trace (diff)")
    p_exp.add_argument("after", nargs="?", default=None, help="Optional target trace for diff export")
    p_exp.add_argument("--format", choices=("github-issue", "ci-summary", "json"), default="github-issue")
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
