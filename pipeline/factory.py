"""Component wiring: build a fully configured system from a Config object."""

from __future__ import annotations

import logging
from dataclasses import dataclass
from pathlib import Path

from agent.llm import LLMClient, build_llm
from config.loader import Config
from rag.embedding import build_embedder
from rag.knowledge_base import KnowledgeBase
from rag.retriever import Retriever
from tools.boundary import TargetAllowlist
from tools.port_scanner import PortScanner
from tools.registry import ToolRegistry
from tools.result_parser import ResultParserTool
from tools.service_detector import ServiceDetector
from tools.version_detector import VersionDetector
from tools.vulnerability_search import VulnerabilitySearchTool
from tools.vulnerability_verifier import VulnerabilityVerifierTool
from vulnerability.cve import CVEDataLoader
from vulnerability.matcher import VulnerabilityMatcher
from vulnerability.verifier import VerificationEngine

logger = logging.getLogger(__name__)

PROJECT_ROOT = Path(__file__).resolve().parent.parent
DEFAULT_CVE_DIR = PROJECT_ROOT / "data" / "vulnerabilities"


@dataclass
class System:
    config: Config
    scope: TargetAllowlist
    knowledge_base: KnowledgeBase
    retriever: Retriever
    matcher: VulnerabilityMatcher
    engine: VerificationEngine
    registry: ToolRegistry
    llm: LLMClient


def build_system(config: Config | None = None, cve_dir: str | Path | None = None) -> System:
    config = config or Config()

    scope = TargetAllowlist(
        allowed=config.get("targets.allowlist", []),
        denied=config.get("targets.denylist", []),
    )

    embedder = build_embedder(config.get("embedding.provider", "hash"), dim=int(config.get("embedding.dim", 256)))
    knowledge_base = KnowledgeBase(embedder)
    loader = CVEDataLoader(Path(cve_dir) if cve_dir else DEFAULT_CVE_DIR)
    vulnerabilities = loader.load()
    knowledge_base.add_vulnerabilities(vulnerabilities)
    logger.info("loaded %d vulnerability records into knowledge base", len(vulnerabilities))

    matcher = VulnerabilityMatcher()
    rag = config.section("rag")
    retriever = Retriever(
        knowledge_base,
        matcher,
        top_k=int(rag.get("top_k", 5)),
        semantic_weight=float(rag.get("semantic_weight", 0.5)),
        product_weight=float(rag.get("product_weight", 0.35)),
        vendor_weight=float(rag.get("vendor_weight", 0.15)),
    )

    engine = VerificationEngine(
        scope=scope,
        timeout=float(config.get("verification.timeout_seconds", 5.0)),
        non_destructive_only=bool(config.get("verification.non_destructive_only", True)),
    )

    network = config.section("network")
    registry = ToolRegistry(scope=scope)
    registry.register(PortScanner(scope, default_ports=network.get("scan_ports"), timeout=float(network.get("timeout_seconds", 3.0))))
    registry.register(ServiceDetector())
    registry.register(VersionDetector())
    registry.register(VulnerabilitySearchTool(retriever))
    registry.register(VulnerabilityVerifierTool(knowledge_base, engine))
    registry.register(ResultParserTool())

    llm = build_llm(config.section("llm"))

    return System(
        config=config,
        scope=scope,
        knowledge_base=knowledge_base,
        retriever=retriever,
        matcher=matcher,
        engine=engine,
        registry=registry,
        llm=llm,
    )
