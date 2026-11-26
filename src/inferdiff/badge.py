"""Render an offline SVG from a doctor summary's public status fields."""

from __future__ import annotations

import os
import re
from html import escape, unescape
from unicodedata import east_asian_width
from urllib.parse import unquote, urlsplit

from .redact import extract_header_secret_values, extract_url_secret_values, scrub_report_text
from .schema import is_strict_int

_GRADES = ("A+", "A", "B", "C", "F")
_STATUSES = ("PASS", "WARN", "FAIL", "SKIP", "ERROR")
_DEFAULT_LABEL = "inferdiff"
_SENSITIVE_LABEL = re.compile(
    r"(?i)//|\\|\b[a-z]:/|\b(?:https?|ftp|file):|\b(?:bearer|basic)\s+\S|"
    r"\b(?:api[ _-]?key|authorization|password|secret|access[ _-]?token)\s*[:=]|"
    r"\b(?:sk|rk|pk)-[\w-]+|\bgithub_pat_\w+|"
    r"\b(?:[\w-]+\.)+(?:corp|internal|lan|local|localhost|test)\b"
)
_AUTH_VALUE = re.compile(r"(?i)\b(?:bearer|basic)\s+([\w.~+/=-]+)")


def _label_secrets(summary: dict) -> tuple[list[str], list[str]]:
    key_names = ("OPENAI_API_KEY", "ANTHROPIC_API_KEY", "GEMINI_API_KEY", "GOOGLE_API_KEY")
    secrets = [os.environ.get(name, "").strip() for name in key_names]
    hosts = []
    for field in ("target_url", "chat_url"):
        url = summary.get(field)
        if isinstance(url, str):
            secrets.extend(extract_url_secret_values(url))
            try:
                host = urlsplit(url).hostname
            except ValueError:
                continue
            if host:
                hosts.append(host.casefold())

    pending = [summary]
    while pending:
        value = pending.pop()
        if isinstance(value, dict):
            headers = {key.replace("_", "-"): child for key, child in value.items()}
            secrets.extend(extract_header_secret_values(headers, min_length=1))
            pending.extend(value.values())
        elif isinstance(value, list):
            pending.extend(value)
        elif isinstance(value, str):
            secrets.extend(_AUTH_VALUE.findall(value))
    return secrets, hosts


def _safe_label(label: str, summary: dict) -> str:
    label = label.strip()
    if label == _DEFAULT_LABEL or not label or not label.isprintable():
        return _DEFAULT_LABEL
    checked = label
    for _ in range(3):
        decoded = unescape(unquote(checked))
        if decoded == checked:
            break
        checked = decoded
    else:
        return _DEFAULT_LABEL

    secrets, hosts = _label_secrets(summary)
    for candidate in (label, checked):
        if (_SENSITIVE_LABEL.search(candidate) or any(host in candidate.casefold() for host in hosts)
                or scrub_report_text(candidate, secrets) != candidate):
            return _DEFAULT_LABEL
    return label[:48]


def _badge_status(summary: dict) -> tuple[str, str]:
    grade = summary.get("grade")
    results = summary.get("results")
    counts = [summary.get(key, 0) for key in ("p0_count", "warning_count", "error_count")]
    if grade not in _GRADES or not isinstance(results, list) or any(
        not is_strict_int(count) or count < 0 for count in counts
    ):
        raise ValueError("Invalid doctor summary grade, results, or counts.")
    if any(not isinstance(result, dict) or result.get("status") not in _STATUSES for result in results):
        raise ValueError("Invalid probe result status in the doctor summary.")

    statuses = [result["status"] for result in results]
    p0, warnings, errors = counts
    if p0 or "FAIL" in statuses:
        return "Grade F · P0 BREACH", "#be123c"
    if errors or "ERROR" in statuses or grade == "F":
        return "Grade F · ERROR", "#be123c"
    if warnings or "WARN" in statuses or grade in ("B", "C"):
        return f"Grade {grade} · WARN", "#b45309"
    return f"Grade {grade} · {statuses.count('PASS')}/{len(statuses)} PASS", "#047857"


def render_badge_svg(summary: object, *, label: str = _DEFAULT_LABEL) -> str:
    """Return a self-contained shield with no provider-supplied text."""
    if not isinstance(summary, dict):
        raise ValueError("Badge input must be a doctor summary JSON object.")
    status, color = _badge_status(summary)
    label = _safe_label(label, summary)
    label_width = 14 + sum(14 if east_asian_width(char) in {"W", "F"} else 7 for char in label)
    status_width = 14 + 7 * len(status)
    width = label_width + status_width
    title = escape(f"{label} | {status}")
    return (
        f'<svg xmlns="http://www.w3.org/2000/svg" width="{width}" height="20" '
        f'viewBox="0 0 {width} 20" role="img" aria-label="{title}">\n'
        f'  <title>{title}</title>\n'
        f'  <clipPath id="shield"><rect width="{width}" height="20" rx="3"/></clipPath>\n'
        '  <g clip-path="url(#shield)">\n'
        f'    <rect width="{label_width}" height="20" fill="#374151"/>\n'
        f'    <rect x="{label_width}" width="{status_width}" height="20" fill="{color}"/>\n'
        '  </g>\n'
        '  <g fill="#fff" font-family="Consolas,monospace" font-size="11" text-anchor="middle">\n'
        f'    <text x="{label_width / 2:g}" y="14">{escape(label)}</text>\n'
        f'    <text x="{label_width + status_width / 2:g}" y="14">{escape(status)}</text>\n'
        '  </g>\n'
        '</svg>\n'
    )
