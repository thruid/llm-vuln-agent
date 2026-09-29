import unittest

from models.asset import Asset
from models.result import FinalStatus, Report, ReportEntry, VerificationResult, VerificationStatus
from models.vulnerability import Vulnerability


class TestAsset(unittest.TestCase):
    def test_target_with_port(self):
        self.assertEqual(Asset("1.2.3.4", 8080).target, "1.2.3.4:8080")

    def test_target_without_port(self):
        self.assertEqual(Asset("1.2.3.4").target, "1.2.3.4")

    def test_roundtrip(self):
        asset = Asset("1.2.3.4", 8080, "tcp", "http", "Apache Tomcat", "Apache", "9.0.50", "banner", {"x": 1})
        self.assertEqual(Asset.from_dict(asset.to_dict()), asset)


class TestVulnerability(unittest.TestCase):
    def test_roundtrip(self):
        vuln = Vulnerability(cve_id="CVE-X", product="tomcat", affected_versions=["<9"], references=["http://x"])
        self.assertEqual(Vulnerability.from_dict(vuln.to_dict()), vuln)

    def test_document_text(self):
        vuln = Vulnerability(cve_id="CVE-1", product="tomcat", description="a description")
        text = vuln.to_document_text()
        self.assertIn("CVE-1", text)
        self.assertIn("a description", text)


class TestVerificationResult(unittest.TestCase):
    def test_enum_roundtrip(self):
        r = VerificationResult(cve_id="CVE-1", status=VerificationStatus.SUCCESS, result=FinalStatus.CONFIRMED)
        r2 = VerificationResult.from_dict(r.to_dict())
        self.assertEqual(r2.result, FinalStatus.CONFIRMED)
        self.assertEqual(r2.status, VerificationStatus.SUCCESS)


class TestReport(unittest.TestCase):
    def test_roundtrip(self):
        report = Report(target="t", entries=[ReportEntry(cve="CVE-1", final_status="CONFIRMED")])
        report2 = Report.from_dict(report.to_dict())
        self.assertEqual(report2.entries[0].cve, "CVE-1")
        self.assertEqual(report2.entries[0].final_status, "CONFIRMED")


if __name__ == "__main__":
    unittest.main()
