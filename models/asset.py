"""Asset model: a normalized description of a target discovered during probing."""

from __future__ import annotations

from dataclasses import dataclass, field, asdict
from typing import Any


@dataclass
class Asset:
    """A single network asset with the fields the system reasons over.

    All fields except ``ip`` are optional: the asset layer may receive only a
    partial description (e.g. just an IP and a port) and the agent is expected
    to enrich it with the probing tools.
    """

    ip: str
    port: int | None = None
    protocol: str = "tcp"
    service: str | None = None
    product: str | None = None
    vendor: str | None = None
    version: str | None = None
    banner: str | None = None
    extra: dict[str, Any] = field(default_factory=dict)

    @property
    def target(self) -> str:
        """Human-readable ``ip:port`` (or just the ip when no port is known)."""
        return f"{self.ip}:{self.port}" if self.port is not None else self.ip

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> "Asset":
        known = {f for f in cls.__dataclass_fields__}  # type: ignore[attr-defined]
        fields = {k: v for k, v in data.items() if k in known}
        fields.setdefault("extra", {})
        return cls(**fields)

    def __str__(self) -> str:  # pragma: no cover - convenience
        parts = [self.target]
        if self.service:
            parts.append(self.service)
        if self.product:
            parts.append(self.product)
        if self.version:
            parts.append(self.version)
        return " ".join(parts)
