"""Safe AWS error detection and non-blocking operation helpers."""

from __future__ import annotations

import logging
import socket
from typing import Any, Callable, Optional, TypeVar

logger = logging.getLogger("gitguard.aws")

T = TypeVar("T")

# botocore / urllib3 connection-related exceptions
_AWS_ERROR_TYPES: tuple[type[BaseException], ...] = (
    ConnectionRefusedError,
    ConnectionResetError,
    TimeoutError,
    socket.timeout,
    OSError,
)

try:
    from botocore.exceptions import (
        BotoCoreError,
        ClientError,
        ConnectTimeoutError,
        ConnectionClosedError,
        EndpointConnectionError,
        ReadTimeoutError,
    )

    _AWS_ERROR_TYPES = _AWS_ERROR_TYPES + (
        BotoCoreError,
        ClientError,
        EndpointConnectionError,
        ConnectTimeoutError,
        ReadTimeoutError,
        ConnectionClosedError,
    )
except ImportError:
    BotoCoreError = Exception  # type: ignore
    ClientError = Exception  # type: ignore

try:
    from urllib3.exceptions import HTTPError, MaxRetryError, NewConnectionError

    _AWS_ERROR_TYPES = _AWS_ERROR_TYPES + (HTTPError, MaxRetryError, NewConnectionError)
except ImportError:
    pass


def is_aws_connection_error(exc: BaseException) -> bool:
    """Return True if the exception looks like a network/endpoint failure."""
    if ClientError is not Exception and isinstance(exc, ClientError):
        code = exc.response.get("Error", {}).get("Code", "") if hasattr(exc, "response") else ""
        if code in ("RequestTimeout", "ServiceUnavailable", "InternalError"):
            return True
        return False

    if isinstance(exc, _AWS_ERROR_TYPES):
        return True

    msg = str(exc).lower()
    connection_markers = (
        "could not connect",
        "connection refused",
        "failed to establish",
        "endpoint url",
        "max retries exceeded",
        "timed out",
        "timeout",
        "name or service not known",
        "actively refused",
        "connection aborted",
    )
    return any(m in msg for m in connection_markers)


def format_aws_warning(service: str, operation: str, exc: BaseException) -> str:
    """Short user-facing warning without traceback."""
    if is_aws_connection_error(exc):
        return f"Could not connect to {service} ({operation}). Skipping."
    return f"{service} {operation} failed: {exc.__class__.__name__}. Skipping."


def safe_aws_call(
    fn: Callable[[], T],
    *,
    default: T,
    service: str,
    operation: str,
    log_level: int = logging.WARNING,
) -> T:
    """Run an AWS operation; never raise — return default on any failure."""
    try:
        return fn()
    except Exception as exc:
        msg = format_aws_warning(service, operation, exc)
        logger.log(log_level, msg)
        if logger.isEnabledFor(logging.DEBUG):
            logger.debug("%s %s detail: %s", service, operation, exc, exc_info=True)
        return default
