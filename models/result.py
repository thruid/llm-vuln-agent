"""Result models: verification outcomes and the final structured report."""

from __future__ import annotations

from dataclasses import dataclass, field, asdict
from enum import Enum
from typing import Any


class FinalStatus(str, Enum):
    """The three verdicts the system is allowed to emit."""

    CONFIRMED = "CONFIRMED"
    NOT_VULNERABLE = "NOT_VULNERABLE"
    UNCERTAIN = "UNCERTAIN"


class VerificationStatus(str, Enum):
    """Execution status of a verification attempt (not the verdict itself)."""

    SUCCESS = "success"
    FAILED = "failed"
    ERROR = "error"


class VersionMatch(str, Enum):
    MATCH = "match"
    NO_MATCH = "no_match"
    UNCERTAIN = "uncertain"


@dataclass
class VerificationResult:
    """Structured outcome of a single vulnerability verification attempt."""

    cve_id: str = ""
    target: str = ""
    verification_id: str = ""
    status: VerificationStatus = VerificationStatus.ERROR
    result: FinalStatus = FinalStatus.UNCERTAIN
    evidence: str = ""
    raw_output: str = ""
    confidence: float = 0.0
    error: str = ""

    def to_dict(self) -> dict[str, Any]:
        data = asdict(self)
        data["status"] = self.status.value
        data["result"] = self.result.value
        return data

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> "VerificationResult":
        fields = {k: v for k, v in data.items() if k in cls.__dataclass_fields__}  # type: ignore[attr-defined]
        if "status" in fields:
            fields["status"] = VerificationStatus(fields["status"])
        if "result" in fields:
            fields["result"] = FinalStatus(fields["result"])
        return cls(**fields)


@dataclass
class ReportEntry:
    """One line of the final report, as specified in the requirements."""

    target: str = ""
    service: str = ""
    version: str = ""
    cve: str = ""
    description: str = ""
    verification_method: str = ""
    verification_result: str = ""
    evidence: str = ""
    confidence: float = 0.0
    final_status: str = FinalStatus.UNCERTAIN.value

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> "ReportEntry":
        fields = {k: v for k, v in data.items() if k in cls.__dataclass_fields__}  # type: ignore[attr-defined]
        return cls(**fields)


@dataclass
class Report:
    """Top-level report container."""

    target: str = ""
    generated_at: str = ""
    entries: list[ReportEntry] = field(default_factory=list)
    meta: dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        return {
            "target": self.target,
            "generated_at": self.generated_at,
            "meta": self.meta,
            "entries": [e.to_dict() for e in self.entries],
        }

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> "Report":
        return cls(
            target=data.get("target", ""),
            generated_at=data.get("generated_at", ""),
            meta=data.get("meta", {}),
            entries=[ReportEntry.from_dict(e) for e in data.get("entries", [])],
        )
