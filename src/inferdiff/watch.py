"""Run canaries on a local schedule and report health transitions."""

from __future__ import annotations

import datetime
import http.client
import json
import math
import os
import sys
import time
import urllib.error
import urllib.request
from contextlib import nullcontext
from pathlib import Path
from typing import BinaryIO, ContextManager, Mapping, Sequence

from .canary import resolve_api_key, run_doctor, select_doctor_probes
from .recorder import RecorderError, validate_and_merge_headers, validate_url
from .schema import EXIT_OK, EXIT_SILENT_PROTOCOL_BREACH, strict_json_loads

_CHECK_STATUSES = frozenset({"PASS", "FAIL", "WARN", "SKIP", "ERROR"})
_UNHEALTHY = frozenset({"FAIL", "ERROR"})


class _NoWebhookRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        return None


def _is_feishu(host: str) -> bool:
    host = host.rstrip(".").lower()
    return host in {"open.feishu.cn", "larksuite.com"} or host.endswith(".larksuite.com")


def _json_line(record: dict[str, object]) -> str:
    return json.dumps(record, ensure_ascii=True, separators=(",", ":"), allow_nan=False) + "\n"


def _send_webhook(
    opener: urllib.request.OpenerDirector, url: str, *, feishu: bool, text: str, line: str, timeout: float,
) -> bool:
    body = _json_line({"msg_type": "text", "content": {"text": text}}) if feishu else line
    try:
        request = urllib.request.Request(url, data=body.encode("utf-8"), headers={"Content-Type": "application/json"})
        with opener.open(request, timeout=timeout) as response:
            if not 200 <= response.status < 300:
                return False
            if not feishu:
                return True
            raw = response.read(4097)
            if len(raw) > 4096:
                return False
            result = strict_json_loads(raw.decode("utf-8"))
            code = result.get("code", result.get("StatusCode")) if isinstance(result, dict) else None
            return type(code) is int and code == 0
    except urllib.error.HTTPError as exc:
        exc.close()
    except (OSError, ValueError, OverflowError, RecursionError, http.client.HTTPException):
        return False
    return False


def _open_log(path: str | Path | None) -> ContextManager[BinaryIO | None]:
    if path is None:
        return nullcontext()
    try:
        log = Path(path)
        log.parent.mkdir(parents=True, exist_ok=True)
        return log.open("a+b")
    except (OSError, ValueError):
        raise OSError("Could not open --out-jsonl.") from None


def _wait_until(deadline: float) -> None:
    delay = deadline - time.monotonic()
    while delay > 0:
        time.sleep(min(delay, 3600.0))
        delay = deadline - time.monotonic()


def run_watch(
    *,
    base_url: str,
    model: str | None,
    api_key: str | None,
    headers: Mapping[str, str],
    timeout: float,
    interval: float = 60.0,
    max_runs: int = 0,
    cooldown: float = 300.0,
    webhook_url: str | None = None,
    out_jsonl: str | Path | None = None,
    fail_on_breach: bool = False,
    profile: str = "quick",
    only: Sequence[str] | None = None,
    protocol: str | None = None,
    anthropic_version: str | None = None,
) -> int:
    """Watch indefinitely when max_runs is zero, keeping report fields independent of wire data."""
    if not math.isfinite(interval) or interval < 0:
        raise ValueError("--interval must be a finite nonnegative number.")
    if not math.isfinite(cooldown) or cooldown < 0:
        raise ValueError("--cooldown must be a finite nonnegative number.")
    if not math.isfinite(timeout) or timeout <= 0:
        raise ValueError("--timeout must be a finite number greater than zero.")
    if max_runs < 0:
        raise ValueError("--max-runs must be a nonnegative integer.")
    validate_url(base_url)
    try:
        resolve_api_key(api_key)
    except ValueError:
        raise ValueError("Could not resolve --api-key.") from None
    headers = validate_and_merge_headers({}, headers)
    probes = select_doctor_probes(profile, only, protocol=protocol, anthropic_version=anthropic_version)
    opener = None
    feishu = False
    if webhook_url is not None:
        try:
            webhook_host = validate_url(webhook_url).hostname or ""
        except RecorderError:
            raise ValueError("--webhook-url must be a valid HTTP(S) URL without userinfo.") from None
        feishu = _is_feishu(webhook_host)
        opener = urllib.request.build_opener(_NoWebhookRedirect())

    unhealthy = ever_unhealthy = False
    last_alert = None
    run = 0
    try:
        with _open_log(out_jsonl) as log:
            prefix = b""
            if log is not None and log.seek(0, os.SEEK_END):
                log.seek(-1, os.SEEK_END)
                if log.read(1) != b"\n":
                    prefix = b"\n"
            deadline = time.monotonic()
            while max_runs == 0 or run < max_runs:
                if interval:
                    _wait_until(deadline)
                run += 1
                try:
                    report = run_doctor(base_url=base_url, model=model, api_key=api_key, headers=headers, timeout=timeout,
                                        profile=profile, only=probes, protocol=protocol, anthropic_version=anthropic_version)
                    observed = {result.probe_id: result.status for result in report.results if result.status in _CHECK_STATUSES}
                except RecorderError:
                    observed = {}
                except OverflowError:
                    raise ValueError("--timeout exceeds the platform socket timeout range.") from None

                checks = {probe: observed.get(probe, "ERROR") for probe in probes}
                failed = [f"{probe} {status}" for probe, status in checks.items() if status in _UNHEALTHY]
                now = time.monotonic()
                event = None
                if failed and (last_alert is None or now - last_alert >= cooldown):
                    event = "FAIL"
                    last_alert = now
                elif unhealthy and not failed:
                    event = "RECOVERED"
                    last_alert = None
                unhealthy = bool(failed)
                ever_unhealthy = ever_unhealthy or unhealthy
                status = "FAIL" if unhealthy else "PASS"
                line = _json_line({
                    "run": run,
                    "timestamp": datetime.datetime.now(datetime.timezone.utc).isoformat(timespec="seconds"),
                    "status": status,
                    "event": event,
                    "checks": checks,
                })
                if log is not None:
                    try:
                        log.write(prefix + line.encode("utf-8"))
                        log.flush()
                    except OSError:
                        raise OSError("Could not write --out-jsonl.") from None
                    prefix = b""
                details = f" ({', '.join(failed)})" if failed else ""
                text = f"inferdiff watch run {run} {event or status}{details}"
                print(text, flush=True)
                if event and opener is not None and webhook_url is not None:
                    if not _send_webhook(opener, webhook_url, feishu=feishu, text=text, line=line, timeout=timeout):
                        print("inferdiff watch: Webhook delivery failed", file=sys.stderr, flush=True)

                if interval:
                    deadline += interval
                    now = time.monotonic()
                    if deadline < now:
                        deadline = now + (interval - (now - deadline) % interval)
    except KeyboardInterrupt:
        print("Stopped inferdiff watch.", flush=True)

    breached = ever_unhealthy if fail_on_breach else unhealthy
    return EXIT_SILENT_PROTOCOL_BREACH if breached else EXIT_OK
