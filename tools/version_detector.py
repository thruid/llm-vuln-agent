"""Version detection from banner text."""

from __future__ import annotations

import re
from typing import Any

from tools.base import Tool

_VERSION_RE = re.compile(
    r"\b(\d+\.\d+(?:\.\d+)?(?:[A-Za-z0-9.\-+_]*)?)\b"
)


class VersionDetector(Tool):
    name = "version_detect"
    description = "Extract a version string from a service banner."
    input_schema = {
        "type": "object",
        "properties": {
            "banner": {"type": "string"},
        },
        "required": ["banner"],
    }
    output_schema = {
        "type": "object",
        "properties": {
            "version": {"type": "string"},
            "found": {"type": "boolean"},
        },
    }

    def execute(self, **kwargs: Any) -> dict[str, Any]:
        banner = str(kwargs.get("banner") or "")
        m = _VERSION_RE.search(banner)
        if m:
            return {"found": True, "version": m.group(1)}
        return {"found": False, "version": None}

    @staticmethod
    def extract(banner: str) -> str | None:
        m = _VERSION_RE.search(banner or "")
        return m.group(1) if m else None
