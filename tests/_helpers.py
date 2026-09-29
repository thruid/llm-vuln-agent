"""Shared test helpers: build a configured system around a known CVE set."""

from __future__ import annotations

import json
import tempfile
from pathlib import Path
from typing import Any

from config.loader import Config
from pipeline.factory import System, build_system

DEFAULT_ALLOWED = ["127.0.0.1", "::1", "localhost"]


def build_system_with_cves(
    cve_dicts: list[dict[str, Any]],
    top_k: int = 10,
    allowed: list[str] | None = None,
) -> tuple[System, Path]:
    tmp = Path(tempfile.mkdtemp(prefix="llm-vuln-agent-test-"))
    (tmp / "vulns.json").write_text(json.dumps(cve_dicts), encoding="utf-8")
    config = Config(
        data={
            "rag": {"top_k": top_k},
            "targets": {"allowlist": allowed if allowed is not None else DEFAULT_ALLOWED},
        }
    )
    return build_system(config, cve_dir=tmp), tmp


# Minimal vulnerability factory for tests.
def cve(
    cve_id: str,
    product: str,
    affected: list[str] | None = None,
    vendor: str = "",
    verification_id: str = "mock",
    extra: dict[str, Any] | None = None,
    description: str = "test vulnerability",
) -> dict[str, Any]:
    return {
        "cve_id": cve_id,
        "product": product,
        "vendor": vendor,
        "affected_versions": affected or ["*"],
        "fixed_versions": [],
        "vulnerability_type": "test",
        "description": description,
        "prerequisites": "",
        "verification_method": "mock",
        "verification_id": verification_id,
        "references": [],
        "severity": "MEDIUM",
        "cvss_score": 5.0,
        "extra": extra or {},
    }
