"""Embedding providers.

The default :class:`HashingEmbedder` is deterministic and dependency-free
(bag-of-words + character 3-grams hashed into a fixed-size signed vector,
L2-normalized). It gives a reasonable semantic-overlap signal for a small
offline demo. A real provider (OpenAI embeddings) can be plugged in behind the
same :class:`Embedder` interface.
"""

from __future__ import annotations

import hashlib
import math
import re
from abc import ABC, abstractmethod
from typing import Protocol, runtime_checkable

_WORD = re.compile(r"[a-z0-9]+")


@runtime_checkable
class Embedder(Protocol):
    def embed(self, text: str) -> list[float]: ...

    def embed_batch(self, texts: list[str]) -> list[list[float]]: ...


def _tokenize(text: str) -> list[str]:
    lowered = (text or "").lower()
    words = _WORD.findall(lowered)
    grams: set[str] = set()
    for word in words:
        if len(word) >= 3:
            for i in range(len(word) - 2):
                grams.add(word[i : i + 3])
    return words + sorted(grams)


class HashingEmbedder:
    """Deterministic feature-hashing embedder (offline, no dependencies)."""

    def __init__(self, dim: int = 256) -> None:
        self.dim = dim

    def embed(self, text: str) -> list[float]:
        vector = [0.0] * self.dim
        for token in _tokenize(text):
            digest = hashlib.md5(token.encode("utf-8")).digest()
            index = int.from_bytes(digest[:4], "big") % self.dim
            sign = 1.0 if (digest[4] & 1) else -1.0
            vector[index] += sign
        return self._normalize(vector)

    def embed_batch(self, texts: list[str]) -> list[list[float]]:
        return [self.embed(t) for t in texts]

    @staticmethod
    def _normalize(vector: list[float]) -> list[float]:
        norm = math.sqrt(sum(v * v for v in vector))
        if norm == 0.0:
            return vector
        return [v / norm for v in vector]


class OpenAIEmbedder:
    """Real embedding provider (requires the ``openai`` package + API key)."""

    def __init__(self, model: str = "text-embedding-3-small", api_key: str | None = None) -> None:
        self.model = model
        self._api_key = api_key

    def _client(self):
        try:
            from openai import OpenAI  # type: ignore
        except ImportError as exc:  # pragma: no cover - optional dependency
            raise RuntimeError("openai package is required for OpenAIEmbedder") from exc
        return OpenAI(api_key=self._api_key)

    def embed(self, text: str) -> list[float]:
        client = self._client()
        resp = client.embeddings.create(model=self.model, input=[text])
        return list(resp.data[0].embedding)

    def embed_batch(self, texts: list[str]) -> list[list[float]]:
        client = self._client()
        resp = client.embeddings.create(model=self.model, input=texts)
        return [list(item.embedding) for item in resp.data]


def build_embedder(provider: str, dim: int = 256, **kwargs) -> Embedder:
    if provider == "openai":
        return OpenAIEmbedder(**kwargs)
    return HashingEmbedder(dim=dim)
