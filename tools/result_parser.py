"""Result parser: turn raw tool output into a structured verification result."""

from __future__ import annotations

import re
from typing import Any

from models.result import FinalStatus, VerificationResult, VerificationStatus
from tools.base import Tool

_CONFIRM = re.compile(r"\b(confirmed|vulnerable|存在漏洞|affected)\b", re.IGNORECASE)
_NEGATE = re.compile(r"\b(not[ _-]?vulnerable|not affected|safe|不存在漏洞|patched)\b", re.IGNORECASE)


class ResultParserTool(Tool):
    name = "result_parser"
    description = "Parse raw tool output into a structured verification result with status and evidence."
    input_schema = {
        "type": "object",
        "properties": {
            "raw_output": {"type": "string"},
            "cve_id": {"type": "string"},
            "target": {"type": "string"},
        },
        "required": ["raw_output"],
    }
    output_schema = {
        "type": "object",
        "properties": {
            "status": {"type": "string"},
            "result": {"type": "string"},
            "evidence": {"type": "string"},
            "confidence": {"type": "number"},
        },
    }

    def execute(self, **kwargs: Any) -> dict[str, Any]:
        raw = str(kwargs.get("raw_output") or "")
        verdict = self._classify(raw)
        result = VerificationResult(
            cve_id=str(kwargs.get("cve_id") or ""),
            target=str(kwargs.get("target") or ""),
            status=VerificationStatus.SUCCESS,
            result=verdict,
            evidence=raw[:500],
            raw_output=raw,
            confidence=self._confidence(raw, verdict),
        )
        return {
            "status": result.status.value,
            "result": result.result.value,
            "evidence": result.evidence,
            "confidence": result.confidence,
        }

    @staticmethod
    def _classify(raw: str) -> FinalStatus:
        if _NEGATE.search(raw):
            return FinalStatus.NOT_VULNERABLE
        if _CONFIRM.search(raw):
            return FinalStatus.CONFIRMED
        return FinalStatus.UNCERTAIN

    @staticmethod
    def _confidence(raw: str, verdict: FinalStatus) -> float:
        if verdict == FinalStatus.UNCERTAIN:
            return 0.3
        if not raw.strip():
            return 0.2
        return 0.85
