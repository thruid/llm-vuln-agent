"""Lightweight agent memory: bounded history of observations for context."""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any


@dataclass
class Memory:
    max_entries: int = 50
    entries: list[dict[str, Any]] = field(default_factory=list)

    def add(self, entry: dict[str, Any]) -> None:
        self.entries.append(entry)
        if len(self.entries) > self.max_entries:
            self.entries = self.entries[-self.max_entries :]

    def recent(self, n: int = 10) -> list[dict[str, Any]]:
        return self.entries[-n:]

    def clear(self) -> None:
        self.entries.clear()

    def context(self, n: int = 10) -> str:
        if not self.entries:
            return "(no history)"
        lines = []
        for e in self.recent(n):
            lines.append(f"- [{e.get('kind', '')}] {e.get('summary', '')}")
        return "\n".join(lines)
