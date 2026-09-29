"""Document loading: turn vulnerability records into embeddable documents."""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any

from models.vulnerability import Vulnerability


@dataclass
class Document:
    id: str
    text: str
    metadata: dict[str, Any] = field(default_factory=dict)

    @property
    def cve_id(self) -> str:
        return str(self.metadata.get("cve_id", self.id))


def vulnerability_to_document(vuln: Vulnerability) -> Document:
    return Document(
        id=vuln.cve_id,
        text=vuln.to_document_text(),
        metadata={
            "cve_id": vuln.cve_id,
            "product": vuln.product,
            "vendor": vuln.vendor,
            "vulnerability_type": vuln.vulnerability_type,
            "severity": vuln.severity,
        },
    )


def documents_from_vulnerabilities(vulns: list[Vulnerability]) -> list[Document]:
    return [vulnerability_to_document(v) for v in vulns]
