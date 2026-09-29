"""Hybrid retriever.

Combines (1) semantic vector similarity, (2) product match, (3) vendor match
and (4) version match into a ranked candidate set. Vector similarity alone is
deliberately not the sole signal — the requirements ask for product / vendor /
version matching to be folded in.
"""

from __future__ import annotations

import logging
from dataclasses import dataclass
from typing import Any

from models.asset import Asset
from models.result import VersionMatch
from rag.knowledge_base import KnowledgeBase
from vulnerability.matcher import VulnerabilityMatcher

logger = logging.getLogger(__name__)


@dataclass
class RetrievalHit:
    cve_id: str
    product: str
    vendor: str
    vulnerability_type: str
    description: str
    verification_id: str
    semantic_score: float
    product_match: bool
    vendor_match: bool
    version_match: str  # VersionMatch value
    score: float

    def to_dict(self) -> dict[str, Any]:
        data = {k: getattr(self, k) for k in self.__dataclass_fields__}  # type: ignore[attr-defined]
        return data

    @property
    def is_version_candidate(self) -> bool:
        return self.product_match and self.version_match != VersionMatch.NO_MATCH.value


class Retriever:
    def __init__(
        self,
        knowledge_base: KnowledgeBase,
        matcher: VulnerabilityMatcher | None = None,
        top_k: int = 5,
        semantic_weight: float = 0.5,
        product_weight: float = 0.35,
        vendor_weight: float = 0.15,
    ) -> None:
        self.knowledge_base = knowledge_base
        self.matcher = matcher or VulnerabilityMatcher()
        self.top_k = top_k
        self.semantic_weight = semantic_weight
        self.product_weight = product_weight
        self.vendor_weight = vendor_weight

    def _query_text(self, asset: Asset) -> str:
        return " ".join(
            filter(
                None,
                [
                    asset.service,
                    asset.product,
                    asset.vendor,
                    asset.version,
                    asset.banner or "",
                ],
            )
        )

    def retrieve(self, asset: Asset, top_k: int | None = None) -> list[RetrievalHit]:
        top_k = top_k or self.top_k
        kb = self.knowledge_base
        if kb.size() == 0:
            return []

        query_vector = kb.embedder.embed(self._query_text(asset))
        # Oversample on the semantic pass so the structured filters can prune.
        semantic = kb.store.search(query_vector, top_k=max(top_k * 3, 10))

        hits: list[RetrievalHit] = []
        for s in semantic:
            vuln = kb.get(s.id)
            if vuln is None:
                continue
            outcome = self.matcher.match(asset, vuln)
            product_bonus = 1.0 if outcome.product_match else 0.0
            vendor_bonus = 1.0 if outcome.vendor_match else 0.0
            score = (
                self.semantic_weight * s.score
                + self.product_weight * product_bonus
                + self.vendor_weight * vendor_bonus
            )
            hits.append(
                RetrievalHit(
                    cve_id=vuln.cve_id,
                    product=vuln.product,
                    vendor=vuln.vendor,
                    vulnerability_type=vuln.vulnerability_type,
                    description=vuln.description,
                    verification_id=vuln.verification_id,
                    semantic_score=round(s.score, 4),
                    product_match=outcome.product_match,
                    vendor_match=outcome.vendor_match,
                    version_match=outcome.version_match.value,
                    score=round(score, 4),
                )
            )

        hits.sort(key=lambda h: h.score, reverse=True)
        return hits[:top_k]
