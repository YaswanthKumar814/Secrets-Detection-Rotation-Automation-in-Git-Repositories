"""Lightweight LocalStack health checks (no boto3 required for ping)."""

from __future__ import annotations

import json
import re
import socket
from typing import Optional
from urllib.error import URLError
from urllib.parse import urlparse
from urllib.request import Request, urlopen

DEFAULT_TIMEOUT_SEC = 2.0
STARTUP_HINT = (
    "LocalStack may still be starting. Wait ~15-30 seconds after `docker run`, "
    "then run `python main.py aws-check` again."
)

# error_kind values returned by classify_endpoint_failure / check_localstack_health
KIND_MALFORMED = "malformed_url"
KIND_INVALID_HOST = "invalid_hostname"
KIND_STARTUP = "startup"
KIND_TIMEOUT = "timeout"
KIND_UNREACHABLE = "unreachable"


def _is_localhost(host: Optional[str]) -> bool:
    if not host:
        return False
    h = host.lower().strip("[]")
    return h in ("localhost", "127.0.0.1", "::1")


def parse_endpoint(endpoint_url: str) -> dict:
    """Validate and parse a LocalStack endpoint URL."""
    raw = (endpoint_url or "").strip()
    if not raw:
        return {
            "valid": False,
            "error_kind": KIND_MALFORMED,
            "detail": "No endpoint URL configured",
            "hint": None,
        }

    candidate = raw if "://" in raw else f"http://{raw}"
    try:
        parsed = urlparse(candidate)
    except ValueError:
        return {
            "valid": False,
            "error_kind": KIND_MALFORMED,
            "detail": "Invalid LocalStack endpoint URL.",
            "hint": "Use a URL like http://localhost:4566",
        }

    if parsed.scheme not in ("http", "https") or not parsed.netloc:
        return {
            "valid": False,
            "error_kind": KIND_MALFORMED,
            "detail": "Invalid LocalStack endpoint URL.",
            "hint": "Use a URL like http://localhost:4566",
        }

    host = parsed.hostname
    if not host:
        return {
            "valid": False,
            "error_kind": KIND_MALFORMED,
            "detail": "Invalid LocalStack endpoint URL.",
            "hint": "Use a URL like http://localhost:4566",
        }

    # reject obvious garbage hostnames
    if not re.match(r"^[a-zA-Z0-9.\-:\[\]]+$", parsed.netloc.split("@")[-1]):
        return {
            "valid": False,
            "error_kind": KIND_MALFORMED,
            "detail": "Invalid LocalStack endpoint URL.",
            "hint": "Use a URL like http://localhost:4566",
        }

    base = f"{parsed.scheme}://{parsed.netloc}".rstrip("/")
    return {
        "valid": True,
        "base": base,
        "host": host,
        "is_localhost": _is_localhost(host),
        "error_kind": None,
        "detail": "",
        "hint": None,
    }


def _failure(
    error_kind: str,
    detail: str,
    *,
    endpoint_url: str = "",
    is_localhost: bool = False,
    hint: Optional[str] = None,
) -> dict:
    if hint is None:
        if error_kind == KIND_STARTUP:
            hint = STARTUP_HINT
        elif error_kind == KIND_INVALID_HOST:
            hint = "Check GITGUARD_AWS_ENDPOINT_URL for typos in the hostname."
        elif error_kind == KIND_MALFORMED:
            hint = "Use a URL like http://localhost:4566"
        elif error_kind == KIND_TIMEOUT and is_localhost:
            hint = STARTUP_HINT
        else:
            hint = "Check GITGUARD_AWS_ENDPOINT_URL and network connectivity."
    return {
        "reachable": False,
        "error_kind": error_kind,
        "detail": detail,
        "hint": hint,
        "is_localhost": is_localhost,
    }


def _classify_connection_error(endpoint_url: str, host: str, is_localhost: bool, exc: BaseException) -> dict:
    err = str(exc).lower()
    winerr = getattr(exc, "winerror", None)
    errno = getattr(exc, "errno", None)

    dns_markers = ("getaddrinfo", "name or service not known", "nodename nor servname", "11001", "11002")
    is_dns = any(m in err for m in dns_markers) or winerr in (11001, 11002) or errno in (11001, 11002)

    if is_dns:
        return _failure(
            KIND_INVALID_HOST,
            "Invalid LocalStack endpoint hostname or DNS resolution failure.",
            endpoint_url=endpoint_url,
            is_localhost=is_localhost,
        )

    if isinstance(exc, ConnectionRefusedError) or "connection refused" in err or "actively refused" in err:
        if is_localhost:
            return _failure(
                KIND_STARTUP,
                "Connection refused — is LocalStack running?",
                endpoint_url=endpoint_url,
                is_localhost=True,
            )
        return _failure(
            KIND_UNREACHABLE,
            f"Could not connect to LocalStack at {host}.",
            endpoint_url=endpoint_url,
            is_localhost=False,
        )

    if isinstance(exc, socket.timeout) or "timed out" in err:
        detail = "Connection timed out"
        kind = KIND_STARTUP if is_localhost else KIND_TIMEOUT
        return _failure(kind, detail, endpoint_url=endpoint_url, is_localhost=is_localhost)

    return _failure(
        KIND_UNREACHABLE,
        str(exc)[:200] or "Network error",
        endpoint_url=endpoint_url,
        is_localhost=is_localhost,
    )


def check_localstack_health(endpoint_url: str, timeout: float = DEFAULT_TIMEOUT_SEC) -> dict:
    """Ping LocalStack health endpoint. Never raises."""
    parsed = parse_endpoint(endpoint_url)
    if not parsed.get("valid"):
        return {
            "reachable": False,
            "error_kind": parsed["error_kind"],
            "detail": parsed["detail"],
            "hint": parsed.get("hint"),
            "is_localhost": False,
        }

    base = parsed["base"]
    host = parsed["host"]
    is_localhost = parsed["is_localhost"]
    health_url = f"{base}/_localstack/health"

    try:
        req = Request(health_url, headers={"Accept": "application/json"})
        with urlopen(req, timeout=timeout) as resp:
            body = resp.read().decode("utf-8", errors="replace")
            if resp.status >= 400:
                return _failure(
                    KIND_STARTUP if is_localhost else KIND_UNREACHABLE,
                    f"Health endpoint returned HTTP {resp.status}",
                    endpoint_url=endpoint_url,
                    is_localhost=is_localhost,
                )
            try:
                data = json.loads(body) if body else {}
            except json.JSONDecodeError:
                data = {}
            services = data.get("services") if isinstance(data, dict) else None
            if services:
                running = [k for k, v in services.items() if v in ("running", "available", "ready")]
                detail = f"LocalStack healthy ({len(running)} services running)"
            else:
                detail = "LocalStack health endpoint responded"
            return {"reachable": True, "detail": detail, "hint": None, "error_kind": None, "is_localhost": is_localhost}
    except URLError as exc:
        reason = getattr(exc, "reason", exc)
        return _classify_connection_error(endpoint_url, host, is_localhost, reason if isinstance(reason, BaseException) else exc)
    except (OSError, socket.timeout) as exc:
        return _classify_connection_error(endpoint_url, host, is_localhost, exc)
    except Exception as exc:
        return _classify_connection_error(endpoint_url, host, is_localhost, exc)


def localstack_guidance(endpoint_url: Optional[str] = None, error_kind: Optional[str] = None) -> str:
    """Beginner-friendly guidance when LocalStack is unreachable."""
    if error_kind == KIND_INVALID_HOST:
        lines = [
            "Invalid LocalStack endpoint hostname or DNS resolution failure.",
            "• Check GITGUARD_AWS_ENDPOINT_URL for typos.",
            "• Example: http://localhost:4566",
        ]
        if endpoint_url:
            lines.insert(1, f"• Current value: {endpoint_url}")
        return "\n".join(lines)

    if error_kind == KIND_MALFORMED:
        return "\n".join([
            "Invalid LocalStack endpoint URL.",
            "• Use format: http://localhost:4566",
            f"• Current value: {endpoint_url or '(empty)'}",
        ])

    lines = [
        "Could not connect to LocalStack.",
        "• Make sure Docker Desktop is running.",
        "• Start LocalStack: docker run -d -p 4566:4566 --name gitguard-localstack localstack/localstack",
    ]
    if endpoint_url:
        lines.insert(1, f"• Endpoint: {endpoint_url}")
    if error_kind in (KIND_STARTUP, KIND_TIMEOUT, None):
        lines.append(STARTUP_HINT)
    return "\n".join(lines)
