"""Port scanning tool (pure Python, allowlist-guarded)."""

from __future__ import annotations

import socket
from typing import Any

from tools.base import Tool
from tools.boundary import TargetAllowlist


class PortScanner(Tool):
    name = "port_scan"
    description = (
        "Probe a set of TCP ports on an authorized host and report which are open "
        "plus any banner returned. Non-destructive connect scan."
    )
    input_schema = {
        "type": "object",
        "properties": {
            "ip": {"type": "string"},
            "ports": {"type": "array", "items": {"type": "integer"}},
            "timeout": {"type": "number"},
        },
        "required": ["ip"],
    }
    output_schema = {
        "type": "object",
        "properties": {
            "ip": {"type": "string"},
            "open_ports": {"type": "array"},
        },
    }

    def __init__(self, scope: TargetAllowlist, default_ports: list[int] | None = None, timeout: float = 3.0) -> None:
        self.scope = scope
        self.default_ports = default_ports or [80, 443, 8080, 22, 21, 25]
        self.timeout = timeout

    def execute(self, **kwargs: Any) -> dict[str, Any]:
        ip = str(kwargs["ip"])
        self.scope.assert_allowed(ip)
        ports = kwargs.get("ports") or self.default_ports
        timeout = float(kwargs.get("timeout", self.timeout))
        open_ports: list[dict[str, Any]] = []
        for port in ports:
            try:
                with socket.create_connection((ip, int(port)), timeout=timeout) as sock:
                    sock.settimeout(timeout)
                    banner = ""
                    try:
                        banner = sock.recv(256).decode("utf-8", "replace").strip()
                    except OSError:
                        banner = ""
                open_ports.append({"port": int(port), "banner": banner})
            except OSError:
                continue
        return {"ip": ip, "open_ports": open_ports}
