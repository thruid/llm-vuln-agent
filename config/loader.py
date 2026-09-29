"""Configuration loading.

Reads ``config/config.yaml`` when available (and PyYAML is installed) and
falls back to safe built-in defaults otherwise. Environment variables are
applied on top so secrets (API keys) never live in the file.
"""

from __future__ import annotations

import os
from copy import deepcopy
from pathlib import Path
from typing import Any

DEFAULTS: dict[str, Any] = {
    "targets": {
        "allowlist": ["127.0.0.1", "::1", "localhost"],
        "denylist": [],
    },
    "network": {
        "timeout_seconds": 3.0,
        "max_ports": 100,
        "scan_ports": [80, 443, 8080, 8000, 22, 21, 25, 3306, 5432, 6379],
    },
    "llm": {
        "provider": "mock",
        "model": "gpt-4o-mini",
        "base_url": "",
        "api_key_env": "LLM_API_KEY",
        "temperature": 0.0,
        "max_tokens": 2000,
    },
    "embedding": {"provider": "hash", "dim": 256},
    "vector_store": {"provider": "memory", "collection": "cve_knowledge_base"},
    "database": {"provider": "sqlite", "path": "data/results.db"},
    "rag": {
        "top_k": 5,
        "semantic_weight": 0.5,
        "product_weight": 0.35,
        "vendor_weight": 0.15,
    },
    "verification": {"timeout_seconds": 5.0, "non_destructive_only": True},
    "logging": {"level": "INFO"},
}

# Environment variables that override a dotted config key.
_ENV_OVERRIDES: dict[str, str] = {
    "LLM_PROVIDER": "llm.provider",
    "LLM_MODEL": "llm.model",
    "LLM_BASE_URL": "llm.base_url",
    "LLM_API_KEY_ENV": "llm.api_key_env",
    "EMBEDDING_PROVIDER": "embedding.provider",
    "VECTOR_STORE_PROVIDER": "vector_store.provider",
    "DATABASE_PROVIDER": "database.provider",
    "LOG_LEVEL": "logging.level",
}


def _deep_merge(base: dict, override: dict) -> dict:
    """Recursively merge ``override`` into a copy of ``base``."""
    result = deepcopy(base)
    for key, value in override.items():
        if isinstance(value, dict) and isinstance(result.get(key), dict):
            result[key] = _deep_merge(result[key], value)
        else:
            result[key] = value
    return result


def _load_yaml(path: Path) -> dict[str, Any] | None:
    try:
        import yaml  # type: ignore
    except ImportError:
        return None
    try:
        with path.open("r", encoding="utf-8") as fh:
            data = yaml.safe_load(fh)
        return data if isinstance(data, dict) else None
    except (OSError, ValueError):
        return None


class Config:
    """Immutable-ish, nested configuration with dotted access."""

    def __init__(self, path: str | os.PathLike | None = None, data: dict[str, Any] | None = None) -> None:
        merged = dict(DEFAULTS)
        if data:
            merged = _deep_merge(merged, data)
        else:
            p = Path(path) if path else Path(__file__).resolve().parent / "config.yaml"
            loaded = _load_yaml(p)
            if loaded:
                merged = _deep_merge(merged, loaded)
        self._data = self._apply_env(merged)

    @staticmethod
    def _apply_env(data: dict[str, Any]) -> dict[str, Any]:
        result = deepcopy(data)

        def _set(dotted: str, value: str) -> None:
            node = result
            parts = dotted.split(".")
            for part in parts[:-1]:
                node = node.setdefault(part, {})
            node[parts[-1]] = value

        for env_name, dotted in _ENV_OVERRIDES.items():
            if env_name in os.environ:
                _set(dotted, os.environ[env_name])
        return result

    def get(self, dotted: str, default: Any = None) -> Any:
        node: Any = self._data
        for part in dotted.split("."):
            if not isinstance(node, dict) or part not in node:
                return default
            node = node[part]
        return node

    def section(self, name: str) -> dict[str, Any]:
        value = self._data.get(name, {})
        return value if isinstance(value, dict) else {}

    def as_dict(self) -> dict[str, Any]:
        return deepcopy(self._data)

    def __getitem__(self, key: str) -> Any:
        if key not in self._data:
            raise KeyError(key)
        return self._data[key]
