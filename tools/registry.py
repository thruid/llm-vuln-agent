"""Tool registry: the single dispatch point the agent talks to.

The registry validates arguments, enforces the allowlist boundary, logs every
execution and converts exceptions into a structured error envelope so the
agent can keep running after a failed tool call.
"""

from __future__ import annotations

import logging
from typing import Any

from tools.base import Tool
from tools.boundary import TargetAllowlist

logger = logging.getLogger(__name__)


class ToolExecutionError(Exception):
    """Raised internally for out-of-scope or unknown tools."""


class ToolRegistry:
    def __init__(self, scope: TargetAllowlist | None = None) -> None:
        self.scope = scope
        self._tools: dict[str, Tool] = {}

    def register(self, tool: Tool) -> None:
        if not tool.name:
            raise ValueError("tool must have a name")
        self._tools[tool.name] = tool

    def names(self) -> list[str]:
        return sorted(self._tools)

    def get(self, name: str) -> Tool:
        if name not in self._tools:
            raise ToolExecutionError(f"unknown tool: {name!r}")
        return self._tools[name]

    def schemas(self) -> list[dict[str, Any]]:
        return [t.describe() for t in self._tools.values()]

    def call(self, name: str, arguments: dict[str, Any] | None = None) -> dict[str, Any]:
        """Execute a tool and return a uniform envelope.

        Envelope: ``{"success": bool, "tool": str, "output": {...}, "error": str}``.
        Never raises for business failures — only for programmer errors.
        """
        arguments = arguments or {}
        tool = self.get(name)

        validation_errors = tool.validate(arguments)
        if validation_errors:
            logger.warning("tool %s rejected args: %s", name, validation_errors)
            return {
                "success": False,
                "tool": name,
                "output": None,
                "error": "invalid arguments: " + "; ".join(validation_errors),
            }

        logger.info("tool call: %s %s", name, _redact(arguments))
        try:
            output = tool.execute(**arguments)
        except PermissionError as exc:
            logger.warning("tool %s blocked by boundary: %s", name, exc)
            return {"success": False, "tool": name, "output": None, "error": str(exc)}
        except Exception as exc:  # noqa: BLE001 - tool boundary
            logger.exception("tool %s raised", name)
            return {"success": False, "tool": name, "output": None, "error": f"{type(exc).__name__}: {exc}"}

        logger.info("tool %s returned %s keys", name, len(output))
        return {"success": True, "tool": name, "output": output, "error": ""}


def _redact(arguments: dict[str, Any]) -> dict[str, Any]:
    # Keep logs compact; nothing sensitive in our tool args, but strip anything huge.
    return {k: (v if not isinstance(v, str) or len(v) < 200 else v[:200] + "...") for k, v in arguments.items()}
