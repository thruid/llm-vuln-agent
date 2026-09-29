import math
import unittest

from models.asset import Asset
from models.vulnerability import Vulnerability
from rag.embedding import HashingEmbedder
from rag.knowledge_base import KnowledgeBase
from rag.retriever import Retriever
from vulnerability.matcher import VulnerabilityMatcher


class TestEmbedding(unittest.TestCase):
    def test_deterministic_and_normalized(self):
        embedder = HashingEmbedder(dim=128)
        v1 = embedder.embed("Apache Tomcat 9.0.50")
        v2 = embedder.embed("Apache Tomcat 9.0.50")
        self.assertEqual(v1, v2)
        self.assertEqual(len(v1), 128)
        self.assertAlmostEqual(math.sqrt(sum(x * x for x in v1)), 1.0, places=5)


class TestKnowledgeBaseAndRetriever(unittest.TestCase):
    def setUp(self):
        self.kb = KnowledgeBase(HashingEmbedder(dim=128))
        self.kb.add_vulnerabilities(
            [
                Vulnerability(cve_id="CVE-A", product="apache tomcat", vendor="apache", affected_versions=["<9.0.54"], description="tomcat denial of service"),
                Vulnerability(cve_id="CVE-B", product="apache tomcat", vendor="apache", affected_versions=["<9.0.31"], description="tomcat ajp file read"),
                Vulnerability(cve_id="CVE-C", product="nginx", vendor="f5", affected_versions=["<1.20.1"], description="nginx resolver bug"),
            ]
        )
        self.retriever = Retriever(self.kb, VulnerabilityMatcher(), top_k=5)

    def test_index_size(self):
        self.assertEqual(self.kb.size(), 3)

    def test_retrieve_tomcat_classifies_versions(self):
        asset = Asset("127.0.0.1", 8080, product="Apache Tomcat", vendor="Apache", version="9.0.50")
        hits = self.retriever.retrieve(asset)
        self.assertTrue(hits)
        by_id = {h.cve_id: h for h in hits}
        self.assertEqual(by_id["CVE-A"].version_match, "match")
        self.assertEqual(by_id["CVE-B"].version_match, "no_match")
        self.assertTrue(by_id["CVE-A"].product_match)

    def test_empty_knowledge_base(self):
        retriever = Retriever(KnowledgeBase(HashingEmbedder(dim=128)), VulnerabilityMatcher())
        self.assertEqual(retriever.retrieve(Asset("127.0.0.1", 8080, product="x")), [])


if __name__ == "__main__":
    unittest.main()
