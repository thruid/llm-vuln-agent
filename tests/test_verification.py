import unittest

from models.asset import Asset
from models.result import FinalStatus, VerificationStatus
from models.vulnerability import Vulnerability
from tools.boundary import TargetAllowlist
from vulnerability.verifier import VerificationEngine, VerificationTask


class TestVerificationEngine(unittest.TestCase):
    def setUp(self):
        self.engine = VerificationEngine(scope=TargetAllowlist(allowed=["127.0.0.1", "::1", "localhost"]))

    @staticmethod
    def _task(cve_id="CVE-1", ip="127.0.0.1", version=None, vuln=None):
        v = vuln or Vulnerability(cve_id=cve_id, product="tomcat", affected_versions=["<9.0.54"], verification_id="mock")
        asset = Asset(ip=ip, port=8080, version=version, product="tomcat")
        return VerificationTask(asset=asset, vulnerability=v)

    def test_mock_confirmed_explicit(self):
        vuln = Vulnerability(cve_id="CVE-1", product="tomcat", verification_id="mock", extra={"mock_result": "confirmed"})
        r = self.engine.verify(self._task(vuln=vuln))
        self.assertEqual(r.result, FinalStatus.CONFIRMED)

    def test_mock_version_match_fallback(self):
        self.assertEqual(self.engine.verify(self._task(version="9.0.50")).result, FinalStatus.CONFIRMED)

    def test_mock_version_no_match(self):
        self.assertEqual(self.engine.verify(self._task(version="9.1.0")).result, FinalStatus.NOT_VULNERABLE)

    def test_mock_uncertain_without_version(self):
        self.assertEqual(self.engine.verify(self._task(version=None)).result, FinalStatus.UNCERTAIN)

    def test_out_of_scope(self):
        r = self.engine.verify(self._task(ip="8.8.8.8"))
        self.assertEqual(r.status, VerificationStatus.FAILED)
        self.assertIn("allowlist", r.error)

    def test_unknown_verifier(self):
        vuln = Vulnerability(cve_id="CVE-1", product="tomcat", verification_id="does_not_exist")
        r = self.engine.verify(self._task(vuln=vuln))
        self.assertEqual(r.status, VerificationStatus.ERROR)
        self.assertEqual(r.result, FinalStatus.UNCERTAIN)


if __name__ == "__main__":
    unittest.main()
