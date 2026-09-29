"""Unified Tool interface.

Every tool the agent may call implements this contract. The LLM never runs
arbitrary commands — it can only request one of these predefined tools, each
of which validates its input against an explicit JSON schema and carries a
permission / safety boundary.
"""

from __future__ import annotations

import logging
from abc import ABC, abstractmethod
from typing import Any

logger = logging.getLogger(__name__)


def validate_against_schema(arguments: dict[str, Any], schema: dict[str, Any]) -> list[str]:
    """Validate ``arguments`` against a small JSON-Schema subset.

    Supports ``object`` (with ``properties`` / ``required``) and the scalar
    types ``string``, ``integer``, ``number``, ``boolean``, ``array`` and
    ``object``. Returns a list of human-readable errors (empty == valid).
    """
    errors: list[str] = []
    if not isinstance(schema, dict) or schema.get("type") != "object":
        return errors
    if not isinstance(arguments, dict):
        return ["arguments must be an object"]

    required = schema.get("required", [])
    for key in required:
        if key not in arguments:
            errors.append(f"missing required field: {key}")

    properties = schema.get("properties", {})
    type_check = {
        "string": str,
        "integer": int,
        "number": (int, float),
        "boolean": bool,
        "array": list,
        "object": dict,
    }
    for key, value in arguments.items():
        if key not in properties:
            continue
        expected = properties[key].get("type")
        if expected not in type_check:
            continue
        if isinstance(value, bool) and expected == "integer":
            errors.append(f"field {key}: expected {expected}, got bool")
            continue
        if not isinstance(value, type_check[expected]):
            errors.append(f"field {key}: expected {expected}, got {type(value).__name__}")
        if expected == "integer" and isinstance(value, float) and not value.is_integer():
            errors.append(f"field {key}: expected integer, got float")
    return errors


class Tool(ABC):
    """Base class for all tools."""

    name: str = ""
    description: str = ""
    input_schema: dict[str, Any] = {}
    output_schema: dict[str, Any] = {}
    #: Whether the tool performs network I/O against the target.
    requires_network: bool = True
    #: Safety boundary: the tool only runs on targets within the allowlist.
    boundary: str = "target_allowlist"

    @abstractmethod
    def execute(self, **kwargs: Any) -> dict[str, Any]:
        """Run the tool. Must return a JSON-serializable dict."""
        raise NotImplementedError

    def validate(self, arguments: dict[str, Any]) -> list[str]:
        return validate_against_schema(arguments, self.input_schema)

    def describe(self) -> dict[str, Any]:
        return {
            "name": self.name,
            "description": self.description,
            "input_schema": self.input_schema,
            "output_schema": self.output_schema,
            "boundary": self.boundary,
        }
