"""Shared validation for inference and telemetry targets."""

from urllib.parse import SplitResult, unquote_plus, urlsplit

from .redact import has_control_chars


class RecorderError(RuntimeError):
    """Raised when a target, HTTP request, or streaming response is invalid."""


def validate_url(url: str) -> SplitResult:
    """Validate an HTTP(S) target without exposing parser input in errors."""
    if not isinstance(url, str) or not url or has_control_chars(url):
        raise RecorderError("Invalid URL: empty or contains control characters.")
    try:
        parsed = urlsplit(url)
    except ValueError:
        raise RecorderError("Invalid URL syntax.") from None
    if parsed.username is not None or parsed.password is not None:
        raise RecorderError("URL must not contain embedded credentials; use --header instead.")
    if parsed.scheme not in ("http", "https") or not parsed.hostname:
        raise RecorderError("Unsupported or invalid URL scheme/host.")
    try:
        port = parsed.port
    except ValueError:
        raise RecorderError("Invalid URL port.") from None
    if port == 0:
        raise RecorderError("Invalid URL port.")
    return parsed


def gemini_request_url(url: str) -> tuple[str, str | None]:
    """Separate query credentials from a Gemini URL for header-only authentication."""
    parsed = validate_url(url)
    params = []
    key = None
    for field in parsed.query.split("&"):
        name, _, value = field.partition("=")
        if unquote_plus(name).lower() in {"key", "x-goog-api-key"}:
            key = key or unquote_plus(value) or None
        elif field:
            params.append(field)
    return parsed._replace(query="&".join(params), fragment="").geturl(), key
