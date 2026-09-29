import unittest

from models.asset import Asset
from models.result import VersionMatch
from models.vulnerability import Vulnerability
from vulnerability.matcher import VulnerabilityMatcher


class TestMatcher(unittest.TestCase):
    def setUp(self):
        self.matcher = VulnerabilityMatcher()

    @staticmethod
    def _vuln(affected):
        return Vulnerability(cve_id="CVE-1", product="Apache Tomcat", vendor="apache", affected_versions=affected)

    def test_version_match(self):
        asset = Asset("127.0.0.1", 8080, product="Apache Tomcat", vendor="Apache", version="9.0.50")
        self.assertEqual(self.matcher.match(asset, self._vuln(["<9.0.54"])).version_match, VersionMatch.MATCH)

    def test_version_no_match(self):
        asset = Asset("127.0.0.1", 8080, product="Apache Tomcat", vendor="Apache", version="9.0.50")
        self.assertEqual(self.matcher.match(asset, self._vuln(["<9.0.31"])).version_match, VersionMatch.NO_MATCH)

    def test_version_uncertain(self):
        asset = Asset("127.0.0.1", 8080, product="Apache Tomcat", version=None)
        self.assertEqual(self.matcher.match(asset, self._vuln(["<9.0.54"])).version_match, VersionMatch.UNCERTAIN)

    def test_product_mismatch(self):
        asset = Asset("127.0.0.1", 8080, product="nginx", version="1.18.0")
        self.assertFalse(self.matcher.product_matches(asset, self._vuln(["<9.0.54"])))

    def test_product_match_via_service(self):
        asset = Asset("127.0.0.1", 8080, service="Apache Tomcat", version="9.0.50")
        self.assertTrue(self.matcher.product_matches(asset, self._vuln(["<9.0.54"])))


if __name__ == "__main__":
    unittest.main()
