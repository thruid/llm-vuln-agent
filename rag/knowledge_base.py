"""Vector store + knowledge base.

:class:`InMemoryVectorStore` is the default (brute-force cosine search, fine
for a small demo). The ``VectorStore`` protocol mirrors a minimal Milvus-like
interface so a real vector database can be swapped in later without touching
the retriever.
"""

from __future__ import annotations

import logging
from abc import ABC, abstractmethod
from dataclasses import dataclass
from typing import Any, Protocol, runtime_checkable

from models.vulnerability import Vulnerability
from rag.document_loader import Document, documents_from_vulnerabilities
from rag.embedding import Embedder

logger = logging.getLogger(__name__)


@dataclass
class SearchResult:
    id: str
    score: float
    metadata: dict[str, Any]


@runtime_checkable
class VectorStore(Protocol):
    def add(self, ids: list[str], vectors: list[list[float]], metadatas: list[dict]) -> None: ...

    def search(self, query_vector: list[float], top_k: int) -> list[SearchResult]: ...

    def clear(self) -> None: ...

    def __len__(self) -> int: ...


def _cosine(a: list[float], b: list[float]) -> float:
    dot = sum(x * y for x, y in zip(a, b))
    return max(-1.0, min(1.0, dot))  # vectors are pre-normalized


class InMemoryVectorStore:
    """Pure-Python brute-force vector store (L2-normalized cosine similarity)."""

    def __init__(self) -> None:
        self._ids: list[str] = []
        self._vectors: list[list[float]] = []
        self._metadatas: list[dict[str, Any]] = []

    def add(self, ids: list[str], vectors: list[list[float]], metadatas: list[dict]) -> None:
        self._ids.extend(ids)
        self._vectors.extend(vectors)
        self._metadatas.extend(metadatas)

    def search(self, query_vector: list[float], top_k: int) -> list[SearchResult]:
        scored = [
            SearchResult(id=self._ids[i], score=_cosine(query_vector, self._vectors[i]), metadata=self._metadatas[i])
            for i in range(len(self._ids))
        ]
        scored.sort(key=lambda r: r.score, reverse=True)
        return scored[:top_k]

    def clear(self) -> None:
        self._ids.clear()
        self._vectors.clear()
        self._metadatas.clear()

    def __len__(self) -> int:
        return len(self._ids)


class KnowledgeBase:
    """Holds vulnerabilities, their documents and the vector index."""

    def __init__(self, embedder: Embedder, vector_store: VectorStore | None = None) -> None:
        self.embedder = embedder
        self.store: VectorStore = vector_store or InMemoryVectorStore()
        self._vulns: dict[str, Vulnerability] = {}
        self._documents: dict[str, Document] = {}

    def add_vulnerabilities(self, vulns: list[Vulnerability]) -> None:
        for vuln in vulns:
            if not vuln.cve_id:
                continue
            self._vulns[vuln.cve_id] = vuln
        self.rebuild_index()

    def rebuild_index(self) -> None:
        self.store.clear()
        documents = documents_from_vulnerabilities(list(self._vulns.values()))
        self._documents = {d.id: d for d in documents}
        ids = [d.id for d in documents]
        vectors = self.embedder.embed_batch([d.text for d in documents])
        metadatas = [d.metadata for d in documents]
        self.store.add(ids, vectors, metadatas)
        logger.info("indexed %d vulnerabilities", len(ids))

    def get(self, cve_id: str) -> Vulnerability | None:
        return self._vulns.get(cve_id)

    def all_vulnerabilities(self) -> list[Vulnerability]:
        return list(self._vulns.values())

    def size(self) -> int:
        return len(self._vulns)
