"""Safe, scoped network primitives used by the tool and verification layers.

All access is funneled through :class:`TargetAllowlist` and bounded by
timeouts. Nothing here executes a shell command.
"""

from __future__ import annotations

import logging
import socket
import ssl
from urllib.error import URLError
from urllib.request import Request, urlopen

from tools.boundary import TargetAllowlist

logger = logging.getLogger(__name__)


class NetworkError(Exception):
    """Raised when a network operation fails or is out of scope."""


def tcp_connect(host: str, port: int, timeout: float) -> socket.socket:
    sock = socket.create_connection((host, port), timeout=timeout)
    sock.settimeout(timeout)
    return sock


def read_banner(
    host: str,
    port: int,
    timeout: float,
    probe: bytes = b"",
    scope: TargetAllowlist | None = None,
) -> str:
    """Open a TCP connection and read an initial banner. Non-destructive."""
    if scope is not None:
        scope.assert_allowed(host)
    try:
        sock = tcp_connect(host, port, timeout)
    except OSError as exc:
        raise NetworkError(f"connect failed for {host}:{port}: {exc}") from exc
    try:
        if probe:
            sock.sendall(probe)
        data = sock.recv(4096)
        return data.decode("utf-8", "replace").strip()
    except OSError as exc:
        raise NetworkError(f"read failed for {host}:{port}: {exc}") from exc
    finally:
        sock.close()


def http_get(
    host: str,
    port: int,
    path: str = "/",
    timeout: float = 5.0,
    headers: dict[str, str] | None = None,
    use_https: bool = False,
    scope: TargetAllowlist | None = None,
) -> dict:
    """Perform a single HTTP(S) GET and return status/headers/body.

    Returns a dict with ``ok``, ``status``, ``headers`` and ``body`` keys. A
    non-2xx status is still considered a completed request (``ok`` reflects
    transport success, not HTTP status).
    """
    if scope is not None:
        scope.assert_allowed(host)
    scheme = "https" if use_https else "http"
    url = f"{scheme}://{host}:{port}{path if path.startswith('/') else '/' + path}"
    req = Request(url, headers=headers or {"User-Agent": "llm-vuln-agent/0.1 (authorized test)"})
    try:
        context = ssl._create_unverified_context() if use_https else None
        with urlopen(req, timeout=timeout, context=context) as resp:
            body = resp.read(8192).decode("utf-8", "replace")
            return {
                "ok": True,
                "status": resp.status,
                "headers": {k.lower(): v for k, v in resp.headers.items()},
                "body": body,
            }
    except URLError as exc:
        # Try the other scheme once, since many lab services are plain HTTP.
        if not use_https:
            return http_get(host, port, path, timeout, headers, True, scope)
        return {"ok": False, "status": None, "headers": {}, "body": "", "error": str(exc)}
    except (OSError, ssl.SSLError) as exc:
        return {"ok": False, "status": None, "headers": {}, "body": "", "error": str(exc)}
