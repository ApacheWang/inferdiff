"""Argparse CLI entrypoint for inferdiff."""

from __future__ import annotations

import argparse
import json
import math
import os
import sys
from pathlib import Path
from typing import Any, Dict, List, Mapping, Optional, Sequence

from . import __version__
from .canary import (
    PROBE_CATALOG,
    DoctorReport,
    ProbeResult,
    render_doctor_terminal,
    resolve_api_key,
    run_doctor,
    select_doctor_probes,
)
from .comparison import (
    compare_reports,
    render_comparison_html,
    render_comparison_markdown,
    render_comparison_terminal,
)
from .detectors import AUDIT_RULE_LIST, VALID_AUDIT_DETECTORS, audit_trace
from .differ import DiffReport, diff_traces
from .exporter import (
    render_audit_terminal,
    render_ci_summary,
    render_diff_terminal,
    render_github_issue,
    sanitize_trace_for_json_export,
)
from .exporters import (
    _ReportCase, audit_cases, canary_cases, comparison_cases, diff_cases, render_junit, render_sarif, replay_cases,
)
from .probes import CompositeBackendProbe, LinuxProcIoProbe, LmcacheMpProbe, MooncakeStoreProbe
from .recorder import RecorderError, record_stream, validate_and_merge_headers, validate_url
from .redact import (
    extract_body_secret_values,
    extract_header_secret_values,
    extract_url_secret_values,
    sanitize_url_for_export,
    scrub_report_data,
    scrub_report_text,
)
from .replay import render_replay_terminal, run_replay
from .schema import (
    EXIT_OK,
    EXIT_SEMANTIC_REGRESSION,
    EXIT_SILENT_PROTOCOL_BREACH,
    EXIT_USAGE_OR_IO_ERROR,
    TraceDocument,
    TraceSchemaError,
    VALID_DIALECTS,
    load_trace,
    strict_json_loads,
)
from .watch import run_watch
from .waterfall import render_audit_html, render_diff_html, render_doctor_html, render_replay_html


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


def _validate_output_paths(paths: Sequence[str | None], protected: Sequence[str | Path] = ()) -> None:
    seen = set()
    for path in paths:
        if path:
            _assert_distinct_output_path(path, protected)
            key = _norm_path_key(path)
            if key in seen:
                raise ValueError("Use a distinct file for each report output.")
            seen.add(key)


def _render_json(payload: Any, known_secrets: Sequence[str], *, indent: int | None = None) -> str:
    separators = (",", ":") if indent is None else None
    return json.dumps(scrub_report_data(payload, known_secrets), ensure_ascii=True, indent=indent,
                      separators=separators, allow_nan=False) + "\n"


def _trace_report_secrets(doc: TraceDocument) -> list[str]:
    request = doc.header.request
    secrets = extract_url_secret_values(request.get("url") or "")
    for metadata in (request, doc.header.response_meta):
        for name in ("headers", "headers_redacted"):
            headers = metadata.get(name)
            if isinstance(headers, dict):
                secrets.extend(extract_header_secret_values(headers, min_length=1))
    return secrets + extract_body_secret_values(request.get("body"))


def _live_report_secrets(url: str, headers: Mapping[str, str], api_key: str | None = None) -> list[str]:
    secrets = extract_url_secret_values(url) + extract_header_secret_values(headers, min_length=1)
    key = resolve_api_key(api_key)
    if key:
        secrets.append(key)
    for name in ("OPENAI_API_KEY", "ANTHROPIC_API_KEY", "GEMINI_API_KEY", "GOOGLE_API_KEY"):
        if value := os.environ.get(name, "").strip():
            secrets.append(value)
    return secrets


def _write_ci_reports(args: argparse.Namespace, cases: Sequence[_ReportCase], known_secrets: Sequence[str]) -> None:
    sarif_path = getattr(args, "out_sarif", None)
    if sarif_path:
        _write_text_file(sarif_path, render_sarif(cases, known_secrets=known_secrets))
    if args.out_junit:
        _write_text_file(args.out_junit, render_junit(cases, known_secrets=known_secrets))


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


def _canary_selection(args: argparse.Namespace) -> Dict[str, Any]:
    return {
        "profile": args.profile or "quick",
        "only": args.only.split(",") if args.only is not None else None,
        "protocol": args.protocol,
        "anthropic_version": args.anthropic_version,
    }


def _cmd_doctor(args: argparse.Namespace) -> int:
    base_url = args.base_url if args.base_url_option is None else args.base_url_option
    headers = _parse_headers(args.header)
    paths = (args.html, args.out_sarif, args.out_junit)
    protected = [Path(args.save_dir) / "doctor_summary.json"] if args.save_dir else []
    _validate_output_paths(paths, protected)
    known_secrets = _live_report_secrets(base_url, headers, args.api_key)
    report = run_doctor(
        base_url=base_url,
        model=args.model or None,
        api_key=args.api_key,
        headers=headers,
        timeout=args.timeout,
        save_dir=args.save_dir,
        strict=args.strict,
        **_canary_selection(args),
    )
    evidence: list[str | Path] = [Path(report.save_dir) / "doctor_summary.json"] if report.save_dir else []
    evidence.extend(path for result in report.results for path in result.trace_paths)
    _validate_output_paths(paths, evidence)
    if args.html:
        _write_text_file(args.html, render_doctor_html(report))
    if args.out_sarif or args.out_junit:
        _write_ci_reports(args, canary_cases(report), known_secrets)
    if args.json:
        sys.stdout.write(_render_json(report.to_dict(), known_secrets))
    else:
        sys.stdout.write(render_doctor_terminal(report, no_color=args.no_color))
        if args.html:
            sys.stdout.write(f"Saved HTML waterfall report: {args.html}\n")
    return report.exit_code


def _cmd_watch(args: argparse.Namespace) -> int:
    try:
        headers = _parse_headers(args.header)
    except (RecorderError, ValueError):
        raise ValueError("Invalid --header for watch. Use 'Name: value'.") from None
    try:
        return run_watch(
            base_url=args.base_url, model=args.model or None, api_key=args.api_key, headers=headers,
            timeout=args.timeout, interval=args.interval, max_runs=args.max_runs, cooldown=args.cooldown,
            webhook_url=args.webhook_url, out_jsonl=args.out_jsonl, fail_on_breach=args.fail_on_breach,
            **_canary_selection(args),
        )
    except OSError:
        raise ValueError("Watch could not read or write local data.") from None


_PROBE_OPTIONS = {
    "pid": (int, "Linux process ID for /proc/PID/io sampling"),
    "lmcache": (str, "LMCache MP metrics URL (defaults to /metrics on an origin)"),
    "mooncake-master": (str, "Mooncake Store master HTTP origin"),
    "mooncake-client": (str, "Mooncake Store client HTTP origin"),
}


def _probe_config(args: argparse.Namespace, prefix: str = "") -> dict[str, Any]:
    config = {}
    for flag in _PROBE_OPTIONS:
        name = flag.replace("-", "_")
        value = getattr(args, f"{prefix}probe_{name}")
        if value is not None:
            config[name] = value
    return config


def _backend_probe(
    *, lmcache: str | None = None, mooncake_master: str | None = None,
    mooncake_client: str | None = None, pid: int | None = None,
) -> Optional[CompositeBackendProbe]:
    if all(value is None for value in (lmcache, mooncake_master, mooncake_client, pid)):
        return None
    return CompositeBackendProbe(
        lmcache_mp=LmcacheMpProbe(lmcache) if lmcache is not None else None,
        mooncake=MooncakeStoreProbe(mooncake_master, mooncake_client)
        if mooncake_master is not None or mooncake_client is not None else None,
        proc_io=LinuxProcIoProbe(pid) if pid is not None else None,
    )


def _cmd_record(args: argparse.Namespace) -> int:
    headers = _parse_headers(args.header)
    bodies = _load_request_bodies(args.request, allow_jsonl=True)
    probe_config = _probe_config(args)
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
            probe=_backend_probe(**probe_config),
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
        raise ValueError(f"Invalid --only value. Valid audit rules are {AUDIT_RULE_LIST}.")
    unknown = sorted(set(tokens) - VALID_AUDIT_DETECTORS)
    if unknown:
        raise ValueError(
            f"Invalid detector selection for audit: {', '.join(unknown)}. Valid audit rules are {AUDIT_RULE_LIST}."
        )
    return set(tokens)


def _cmd_audit(args: argparse.Namespace) -> int:
    only = _parse_only_detectors(args.only)
    _validate_output_paths((args.html, args.out_sarif, args.out_junit), [args.trace_path])
    doc = load_trace(args.trace_path)
    findings = audit_trace(doc, only=only)
    rc = _audit_exit_code(findings, strict=args.strict)
    known_secrets = _trace_report_secrets(doc)
    if args.html:
        _write_text_file(args.html, render_audit_html(doc, findings))
    if args.out_sarif or args.out_junit:
        _write_ci_reports(args, audit_cases(doc, findings, only=only), known_secrets)
    if args.json:
        safe = sanitize_trace_for_json_export(doc, include_body=False, include_wire=False)
        payload = {
            **safe,
            "findings": [f.to_dict() for f in findings],
            "exit_code": rc,
        }
        sys.stdout.write(_render_json(payload, known_secrets))
    else:
        sys.stdout.write(render_audit_terminal(doc, findings, no_color=args.no_color))
        if args.html:
            sys.stdout.write(f"Saved HTML waterfall report: {args.html}\n")
    return rc


def _cmd_replay(args: argparse.Namespace) -> int:
    json_path = args.out_json if args.out_json != "-" else None
    outputs = (json_path, args.out_sarif, args.out_junit, args.out_html)
    report = run_replay(args.path, baseline=args.baseline, strict=args.strict)
    known_secrets = [secret for trace in (*report.traces, *report.baseline_traces)
                     for secret in _trace_report_secrets(trace.doc)]
    try:
        _validate_output_paths(outputs, report.input_paths)
        if json_path or args.out_json == "-":
            payload = _render_json(report.to_dict(), known_secrets, indent=2)
            if json_path:
                _write_text_file(json_path, payload)
            else:
                sys.stdout.write(payload)
        if args.out_sarif or args.out_junit:
            _write_ci_reports(args, replay_cases(report), known_secrets)
        if args.out_html:
            _write_text_file(args.out_html, render_replay_html(report, known_secrets=known_secrets))
    except (ValueError, OSError) as exc:
        raise ValueError(scrub_report_text(str(exc), known_secrets)) from None
    if args.out_json != "-":
        sys.stdout.write(render_replay_terminal(report, known_secrets=known_secrets))
    return report.exit_code


def _cmd_diff(args: argparse.Namespace) -> int:
    _validate_output_paths((args.html, args.out_sarif, args.out_junit), [args.before_trace, args.after_trace])
    before = load_trace(args.before_trace)
    after = load_trace(args.after_trace)
    report = diff_traces(
        before,
        after,
        ignore_timing=args.ignore_timing,
        ttft_regress_pct=args.ttft_regress_pct,
        fail_on=args.fail_on,
    )
    return _write_diff_outputs(args, before, after, report)


def _write_diff_outputs(
    args: argparse.Namespace, before: TraceDocument, after: TraceDocument, report: DiffReport,
    known_secrets: Sequence[str] = (),
) -> int:
    secrets = [*known_secrets, *_trace_report_secrets(before), *_trace_report_secrets(after)]
    if args.html:
        _write_text_file(args.html, render_diff_html(before, after, report))
    if getattr(args, "out_sarif", None) or args.out_junit:
        _write_ci_reports(args, diff_cases(after, report, ignore_timing=args.ignore_timing), secrets)
    if args.json:
        sys.stdout.write(_render_json(report.to_dict(include_wire=False), secrets))
    else:
        sys.stdout.write(render_diff_terminal(report, no_color=args.no_color))
        if args.html:
            sys.stdout.write(f"Saved HTML waterfall report: {args.html}\n")
    return report.exit_code


def _cmd_compare(args: argparse.Namespace) -> int:
    if (any(getattr(args, f"{side}_{field}") is not None for side in ("a", "b")
            for field in ("url", "key", "model", "label"))
            or any(value is not None for value in (args.only, args.protocol, args.anthropic_version, args.profile))
            or args.out_json or args.out_md or args.out_html or args.markdown):
        return _cmd_compare_canaries(args)
    return _cmd_compare_replay(args)


def _run_compare_target(
    url: str, model: Optional[str], api_key: Optional[str], *, headers: Dict[str, str],
    timeout: float, selection: Dict[str, Any], probes: Sequence[str],
) -> DoctorReport:
    try:
        return run_doctor(base_url=url, model=model, api_key=api_key, headers=headers, timeout=timeout, **selection)
    except RecorderError as exc:
        results = []
        for probe in probes:
            code, severity, reference = PROBE_CATALOG[probe]
            results.append(ProbeResult(probe, code, severity, "ERROR", str(exc), 0.0, 0, None, reference))
        return DoctorReport(
            target_url=sanitize_url_for_export(url), chat_url="", dialect="unknown", model=model or "",
            profile=selection["profile"], grade="F", exit_code=EXIT_USAGE_OR_IO_ERROR, p0_count=0,
            warning_count=0, error_count=len(results), total_tokens=None, save_dir=None, results=results,
        )


def _cmd_compare_canaries(args: argparse.Namespace) -> int:
    if not args.a_url or not args.b_url:
        raise ValueError("Canary compare requires --a-url and --b-url.")
    if (args.before_url or args.after_url or args.request or args.before_header or args.after_header or args.save_dir
            or args.before_label or args.after_label or args.dialect != "auto" or args.fail_on
            or any(_probe_config(args, prefix) for prefix in ("", "before_", "after_"))):
        raise ValueError("Canary compare uses --a-* and --b-*; request replay uses --before-url, --after-url and --request.")
    if args.out_html and args.html:
        raise ValueError("Use only one of --out-html and --html.")
    stdout_json = args.json or args.out_json == "-"
    stdout_markdown = args.markdown or args.out_md == "-"
    if stdout_json and stdout_markdown:
        raise ValueError("Choose JSON or Markdown for stdout.")

    out_html = args.out_html or args.html
    paths = [out_html, args.out_junit, *(path for path in (args.out_json, args.out_md) if path != "-")]
    _validate_output_paths(paths)
    if not math.isfinite(args.ttft_regress_pct) or args.ttft_regress_pct < 0:
        raise ValueError("--ttft-regress-pct must be a finite nonnegative number.")
    validate_url(args.a_url)
    validate_url(args.b_url)
    selection = _canary_selection(args)
    probes = select_doctor_probes(**selection)
    headers = _parse_headers(args.header)
    known_secrets = _live_report_secrets(args.a_url, headers, args.a_key)
    known_secrets.extend(_live_report_secrets(args.b_url, headers, args.b_key))

    a = _run_compare_target(args.a_url, args.a_model, args.a_key, headers=headers, timeout=args.timeout,
                            selection=selection, probes=probes)
    b = _run_compare_target(args.b_url, args.b_model, args.b_key, headers=headers, timeout=args.timeout,
                            selection=selection, probes=probes)
    report = compare_reports(a, b, a_label=args.a_label or "A", b_label=args.b_label or "B",
                             known_secrets=known_secrets, ignore_timing=args.ignore_timing,
                             ttft_regress_pct=args.ttft_regress_pct)

    if out_html:
        _write_text_file(out_html, render_comparison_html(report))
    if args.out_junit:
        _write_ci_reports(args, comparison_cases(report), known_secrets)
    if args.out_json or stdout_json:
        payload = _render_json(report.to_dict(), known_secrets, indent=2)
        if args.out_json and args.out_json != "-":
            _write_text_file(args.out_json, payload)
        if stdout_json:
            sys.stdout.write(payload)
    if args.out_md or stdout_markdown:
        markdown = render_comparison_markdown(report)
        if args.out_md and args.out_md != "-":
            _write_text_file(args.out_md, markdown)
        if stdout_markdown:
            sys.stdout.write(markdown)
    if not (stdout_json or stdout_markdown):
        sys.stdout.write(render_comparison_terminal(report, no_color=args.no_color))
    return report.exit_code


def _cmd_compare_replay(args: argparse.Namespace) -> int:
    if not (args.before_url and args.after_url and args.request):
        raise ValueError("Request replay compare requires --before-url, --after-url and --request.")
    shared_headers = _parse_headers(args.header)
    before_headers = validate_and_merge_headers(shared_headers, _parse_headers(args.before_header))
    after_headers = validate_and_merge_headers(shared_headers, _parse_headers(args.after_header))

    bodies = _load_request_bodies(args.request, allow_jsonl=False)
    body = bodies[0]
    save_dir = Path(args.save_dir) if args.save_dir else None
    b_out = (save_dir / "before.trace.jsonl") if save_dir else None
    a_out = (save_dir / "after.trace.jsonl") if save_dir else None
    protected = [p for p in (b_out, a_out) if p is not None]
    if args.request not in ("-", "@-"):
        protected.append(args.request)
    _validate_output_paths((args.html, args.out_junit), protected)

    shared_probe = _probe_config(args)
    before_config, after_config = _probe_config(args, "before_"), _probe_config(args, "after_")
    if shared_probe and (
        args.before_url != args.after_url or before_headers != after_headers or before_config or after_config
    ):
        raise ValueError("Shared --probe-* flags require identical inference URLs and headers. "
                         "Use --before-probe-* and --after-probe-* to scope probes independently.")
    before_probe = _backend_probe(**(before_config or shared_probe))
    after_probe = _backend_probe(**(after_config or shared_probe))
    before = record_stream(
        url=args.before_url,
        request_body=body,
        out_path=b_out,
        headers=before_headers,
        dialect=args.dialect,
        label=args.before_label or "before",
        timeout=args.timeout,
        probe=before_probe,
    )
    after = record_stream(
        url=args.after_url,
        request_body=body,
        out_path=a_out,
        headers=after_headers,
        dialect=args.dialect,
        label=args.after_label or "after",
        timeout=args.timeout,
        probe=after_probe,
    )
    report = diff_traces(
        before,
        after,
        ignore_timing=args.ignore_timing,
        ttft_regress_pct=args.ttft_regress_pct,
        fail_on=args.fail_on or "p0",
    )
    known_secrets = _live_report_secrets(args.before_url, before_headers)
    known_secrets.extend(_live_report_secrets(args.after_url, after_headers))
    return _write_diff_outputs(args, before, after, report, known_secrets)


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
            secrets = _trace_report_secrets(before) + _trace_report_secrets(after)
            rendered = _render_json(report.to_dict(include_wire=args.include_wire), secrets, indent=2)
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
            rendered = _render_json({**safe, "findings": [f.to_dict() for f in findings], "exit_code": rc},
                                    _trace_report_secrets(before), indent=2)

    if args.out:
        _write_text_file(args.out, rendered)
    else:
        sys.stdout.write(rendered)
    return rc


def _add_probe_options(parser: argparse.ArgumentParser, side: str = "") -> None:
    prefix = f"{side}-" if side else ""
    scope = f" for the {side} request" if side else ""
    for name, (value_type, help_text) in _PROBE_OPTIONS.items():
        parser.add_argument(f"--{prefix}probe-{name}", type=value_type, help=help_text + scope)


def _add_canary_options(parser: argparse.ArgumentParser | argparse._ArgumentGroup) -> None:
    parser.add_argument("--profile", choices=("quick", "full", "relay"), help="Canary profile (default: quick)")
    parser.add_argument("--only", help="Comma-separated checks (C1 through C10)")
    parser.add_argument("--protocol", choices=("openai", "anthropic", "gemini"),
                        help="Select OpenAI canaries, Anthropic Messages (C9), or Gemini SSE (C10)")
    parser.add_argument("--anthropic-version", metavar="DATE", help="Anthropic version header (opts into C9 by default)")


def _add_ci_report_options(parser: argparse.ArgumentParser, *, sarif: bool = True) -> None:
    if sarif:
        parser.add_argument("--out-sarif", metavar="PATH", help="Write a SARIF 2.1.0 report")
    parser.add_argument("--out-junit", metavar="PATH", help="Write a JUnit XML report")


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="inferdiff",
        description="Wire-level canary doctor, regression diff, and silent-failure forensics for LLM serving & API relays.",
    )
    parser.add_argument("--version", action="version", version=f"inferdiff {__version__}")
    sub = parser.add_subparsers(dest="command", required=True)

    # doctor (primary zero-setup entry point per Spec §2.1)
    p_doc = sub.add_parser("doctor", aliases=["canary"],
                           help="Live C1..C10 streaming contract checks for engines and API relays")
    target = p_doc.add_mutually_exclusive_group(required=True)
    target.add_argument("base_url", nargs="?", help="Target base URL (e.g. http://127.0.0.1:8080/v1)")
    target.add_argument("--base-url", dest="base_url_option", help="Target base URL")
    p_doc.add_argument("--model", "-m", default="", help="Model ID (auto-discovers /models or /api/tags if omitted)")
    p_doc.add_argument("--api-key", default=None, help="API key or $ENV_VAR (defaults to the selected protocol's environment key)")
    p_doc.add_argument("--header", "-H", action="append", default=[], help="Extra HTTP header 'Name: value' (repeatable)")
    _add_canary_options(p_doc)
    p_doc.add_argument("--timeout", type=float, default=60.0, help="Per-probe socket timeout in seconds")
    p_doc.add_argument("--save-dir", default="", help="Directory to save canary .trace.jsonl files (default ./.inferdiff-doctor/<ts>/)")
    p_doc.add_argument("--html", default="", help="Write single-file airgap-safe HTML scorecard & SVG waterfall")
    p_doc.add_argument("--strict", action="store_true", help="Exit 3 on P1 warnings (P0 breaches always exit 2)")
    p_doc.add_argument("--json", action="store_true", help="Emit JSON canary matrix report")
    p_doc.add_argument("--no-color", action="store_true")
    _add_ci_report_options(p_doc)
    p_doc.set_defaults(func=_cmd_doctor)

    p_watch = sub.add_parser("watch", help="Run canaries continuously and alert on health transitions")
    p_watch.add_argument("--base-url", required=True, help="Inference endpoint base URL")
    p_watch.add_argument("--model", "-m", help="Model ID (auto-discovers if omitted)")
    p_watch.add_argument("--api-key", help="API key or $ENV_VAR (defaults to the selected protocol's environment key)")
    p_watch.add_argument("--header", "-H", action="append", default=[], help="Extra inference HTTP header (repeatable)")
    _add_canary_options(p_watch)
    p_watch.add_argument("--timeout", type=float, default=60.0, help="Per-probe socket timeout in seconds")
    p_watch.add_argument("--interval", type=float, default=60.0, help="Seconds between cycle starts (default: 60)")
    p_watch.add_argument("--max-runs", type=int, default=0, help="Stop after this many cycles (default: 0, unlimited)")
    p_watch.add_argument("--cooldown", type=float, default=300.0, help="Seconds between repeated failure alerts (default: 300)")
    p_watch.add_argument("--webhook-url", help="Optional generic JSON, Feishu, or Lark webhook URL")
    p_watch.add_argument("--out-jsonl", metavar="PATH", help="Append a redacted summary for each cycle")
    p_watch.add_argument("--fail-on-breach", action="store_true", help="Exit 2 if any cycle failed, even after recovery")
    p_watch.set_defaults(func=_cmd_watch)

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
    _add_probe_options(p_rec)
    p_rec.set_defaults(func=_cmd_record)

    # audit
    p_aud = sub.add_parser("audit", help="Audit a single .trace.jsonl for silent failures and storage symptoms")
    p_aud.add_argument("trace_path", help="Path to .trace.jsonl")
    p_aud.add_argument("--only", default=None, help=f"Comma-separated subset of {AUDIT_RULE_LIST}")
    p_aud.add_argument("--html", default="", help="Write single-file airgap-safe HTML frame waterfall")
    p_aud.add_argument("--json", action="store_true", help="Emit sanitized JSON audit report")
    p_aud.add_argument("--strict", action="store_true", help="Treat P1 warnings as non-zero exit code 3")
    p_aud.add_argument("--no-color", action="store_true")
    _add_ci_report_options(p_aud)
    p_aud.set_defaults(func=_cmd_audit)

    p_replay = sub.add_parser("replay", help="Audit saved traces offline and gate new protocol breaches")
    p_replay.add_argument("path", help="A .trace.jsonl file or directory of .trace.jsonl files")
    p_replay.add_argument("--baseline", metavar="DIR", help="Compare against saved traces matched by relative path")
    p_replay.add_argument("--out-json", metavar="PATH", help="Write replay JSON (use - for stdout)")
    p_replay.add_argument("--out-html", metavar="PATH", help="Write a self-contained replay report")
    p_replay.add_argument("--strict", action="store_true", help="Exit 3 on P1 warnings (P0 breaches exit 2)")
    _add_ci_report_options(p_replay)
    p_replay.set_defaults(func=_cmd_replay)

    # diff
    p_diff = sub.add_parser("diff", help="Diff baseline and target .trace.jsonl with chunk-jitter-proof alignment")
    p_diff.add_argument("before_trace", help="Baseline .trace.jsonl")
    p_diff.add_argument("after_trace", help="Target .trace.jsonl")
    p_diff.add_argument(
        "--ignore-timing",
        action="store_true",
        help="Ignore TTFT regressions and pair-level D5 and D8 alerts",
    )
    p_diff.add_argument("--ttft-regress-pct", type=float, default=50.0)
    p_diff.add_argument("--fail-on", choices=("p0", "p1", "any-diff"), default="p0")
    p_diff.add_argument("--html", default="", help="Write dual-lane single-file HTML frame waterfall")
    p_diff.add_argument("--json", action="store_true")
    p_diff.add_argument("--no-color", action="store_true")
    _add_ci_report_options(p_diff)
    p_diff.set_defaults(func=_cmd_diff)

    # compare
    p_cmp = sub.add_parser(
        "compare", help="Compare two live canary targets or replay a request against two endpoints",
        description="Run canaries with --a-url and --b-url, or replay --request with --before-url and --after-url. "
                    "Both modes contact targets sequentially.",
    )
    canaries = p_cmp.add_argument_group("A/B canary comparison")
    for side in ("a", "b"):
        canaries.add_argument(f"--{side}-url", help=f"Target {side.upper()} base URL")
        canaries.add_argument(f"--{side}-key", help=f"Target {side.upper()} API key or $ENV_VAR")
        canaries.add_argument(f"--{side}-model", help=f"Target {side.upper()} model ID (auto-discovers if omitted)")
        canaries.add_argument(f"--{side}-label", help=f"Display label for target {side.upper()}")
    _add_canary_options(canaries)
    canaries.add_argument("--out-html", help="Write a self-contained A/B waterfall")
    canaries.add_argument("--out-json", help="Write comparison JSON (use - for stdout)")
    canaries.add_argument("--out-md", help="Write a Markdown comparison table (use - for stdout)")
    canaries.add_argument("--markdown", "--md", action="store_true", help="Print the Markdown comparison table")
    p_cmp.add_argument("--before-url", help="Baseline endpoint for request replay")
    p_cmp.add_argument("--after-url", help="Target endpoint for request replay")
    p_cmp.add_argument("--request", "-d", help="Request JSON for request replay")
    p_cmp.add_argument("--header", "-H", action="append", default=[], help="Shared HTTP header for both targets")
    p_cmp.add_argument("--before-header", action="append", default=[], help="HTTP header scoped only to --before-url")
    p_cmp.add_argument("--after-header", action="append", default=[], help="HTTP header scoped only to --after-url")
    p_cmp.add_argument("--dialect", choices=("auto", *VALID_DIALECTS), default="auto")
    p_cmp.add_argument("--before-label")
    p_cmp.add_argument("--after-label")
    p_cmp.add_argument("--timeout", type=float, default=120.0)
    p_cmp.add_argument("--save-dir", default="", help="Optional directory to save before/after traces")
    p_cmp.add_argument(
        "--ignore-timing",
        action="store_true",
        help="Ignore timing regressions and pair-level D5 and D8 alerts",
    )
    p_cmp.add_argument("--ttft-regress-pct", type=float, default=50.0)
    p_cmp.add_argument("--fail-on", choices=("p0", "p1", "any-diff"), help="Request replay failure threshold (default: p0)")
    p_cmp.add_argument("--html", default="", help="Write dual-lane single-file HTML frame waterfall")
    p_cmp.add_argument("--json", action="store_true")
    p_cmp.add_argument("--no-color", action="store_true")
    _add_ci_report_options(p_cmp, sarif=False)
    _add_probe_options(p_cmp)
    _add_probe_options(p_cmp, "before")
    _add_probe_options(p_cmp, "after")
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
        sys.stderr.write(f"inferdiff error: {scrub_report_text(str(exc))}\n")
        return EXIT_USAGE_OR_IO_ERROR
