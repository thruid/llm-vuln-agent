"""Target allowlist: the hard safety boundary for all network-capable tools.

Deny by default. A target may only be touched if it (or its resolved IP) is in
the allowlist and not in the denylist. This is what keeps the system confined
to authorized lab / CTF environments and prevents scanning arbitrary public
targets.
"""

from __future__ import annotations

import ipaddress
import logging
import socket
from typing import Iterable

logger = logging.getLogger(__name__)


class TargetAllowlist:
    def __init__(self, allowed: Iterable[str] | None = None, denied: Iterable[str] | None = None) -> None:
        self.allowed_hosts: set[str] = set()
        self.allowed_nets: list[ipaddress._BaseNetwork] = []
        self.denied_hosts: set[str] = set()
        self.denied_nets: list[ipaddress._BaseNetwork] = []
        self._register(self.allowed_hosts, self.allowed_nets, allowed)
        self._register(self.denied_hosts, self.denied_nets, denied)

    @staticmethod
    def _register(hosts: set[str], nets: list[ipaddress._BaseNetwork], entries: Iterable[str] | None) -> None:
        for entry in entries or []:
            entry = (entry or "").strip()
            if not entry:
                continue
            try:
                nets.append(ipaddress.ip_network(entry, strict=False))
            except ValueError:
                hosts.add(entry.lower())

    @staticmethod
    def _resolve(host: str) -> list[ipaddress._BaseAddress]:
        try:
            return [ipaddress.ip_address(host.strip())]
        except ValueError:
            pass
        try:
            return [ipaddress.ip_address(socket.gethostbyname(host.strip()))]
        except (OSError, ValueError):
            return []

    def is_allowed(self, host: str) -> bool:
        host = (host or "").strip()
        if not host:
            return False
        ips = self._resolve(host)

        # Denylist wins.
        for ip in ips:
            for net in self.denied_nets:
                if ip.version == net.version and ip in net:
                    return False
        if host.lower() in self.denied_hosts:
            return False

        if host.lower() in self.allowed_hosts:
            return True
        for ip in ips:
            for net in self.allowed_nets:
                if ip.version == net.version and ip in net:
                    return True
        return False

    def assert_allowed(self, host: str) -> None:
        if not self.is_allowed(host):
            raise PermissionError(
                f"target {host!r} is outside the authorized allowlist; refusing to proceed"
            )

    def __bool__(self) -> bool:
        return bool(self.allowed_hosts or self.allowed_nets)
