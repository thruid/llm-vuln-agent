import json
import tempfile
import unittest
from pathlib import Path

from models.asset import Asset
from models.result import FinalStatus
from pipeline.report import report_to_json, report_to_markdown
from pipeline.storage import ResultStore
from pipeline.workflow import run_workflow
from tests._helpers import build_system_with_cves, cve

TOMCAT = [
    cve("CVE-A", "Apache Tomcat", ["<9.0.54"], vendor="apache"),
    cve("CVE-B", "Apache Tomcat", ["<9.0.31"], vendor="apache"),
    cve("CVE-C", "nginx", ["<1.20.1"], vendor="f5"),
]


class TestPipeline(unittest.TestCase):
    def test_vulnerable_asset_confirmed(self):
        system, _ = build_system_with_cves(TOMCAT)
        asset = Asset("127.0.0.1", 8080, product="Apache Tomcat", vendor="Apache", version="9.0.50")
        report = run_workflow(asset, system)
        self.assertTrue(any(e.final_status == FinalStatus.CONFIRMED.value for e in report.entries))

    def test_patched_asset_not_vulnerable(self):
        system, _ = build_system_with_cves(TOMCAT)
        asset = Asset("127.0.0.1", 8080, product="Apache Tomcat", vendor="Apache", version="9.0.60")
        report = run_workflow(asset, system)
        self.assertTrue(any(e.final_status == FinalStatus.NOT_VULNERABLE.value for e in report.entries))
        self.assertFalse(any(e.final_status == FinalStatus.CONFIRMED.value for e in report.entries))

    def test_uncertain_when_version_unknown(self):
        system, _ = build_system_with_cves(TOMCAT)
        asset = Asset("127.0.0.1", 8080, product="Apache Tomcat", version=None)
        report = run_workflow(asset, system)
        self.assertTrue(any(e.final_status == FinalStatus.UNCERTAIN.value for e in report.entries))

    def test_report_formatting(self):
        system, _ = build_system_with_cves(TOMCAT)
        asset = Asset("127.0.0.1", 8080, product="Apache Tomcat", version="9.0.50")
        report = run_workflow(asset, system)
        md = report_to_markdown(report)
        self.assertIn("CONFIRMED", md)
        data = json.loads(report_to_json(report))
        self.assertIn("entries", data)


class TestStorage(unittest.TestCase):
    def test_save_and_load(self):
        system, _ = build_system_with_cves(TOMCAT)
        asset = Asset("127.0.0.1", 8080, product="Apache Tomcat", version="9.0.50")
        report = run_workflow(asset, system)

        tmp = Path(tempfile.mkdtemp()) / "results.db"
        store = ResultStore(tmp)
        report_id = store.save(report)
        loaded = store.load(report_id)
        self.assertIsNotNone(loaded)
        self.assertEqual(len(loaded.entries), len(report.entries))
        store.close()


if __name__ == "__main__":
    unittest.main()
