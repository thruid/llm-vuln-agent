import unittest

from tools.boundary import TargetAllowlist
from tools.port_scanner import PortScanner
from tools.registry import ToolExecutionError, ToolRegistry
from tools.result_parser import ResultParserTool
from tools.service_detector import ServiceDetector
from tools.version_detector import VersionDetector


class TestAllowlist(unittest.TestCase):
    def test_allows_localhost(self):
        scope = TargetAllowlist(allowed=["127.0.0.1", "::1", "localhost"])
        self.assertTrue(scope.is_allowed("127.0.0.1"))
        self.assertTrue(scope.is_allowed("localhost"))

    def test_denies_unknown(self):
        self.assertFalse(TargetAllowlist(allowed=["127.0.0.1"]).is_allowed("8.8.8.8"))

    def test_denylist_wins(self):
        scope = TargetAllowlist(allowed=["127.0.0.0/8"], denied=["127.0.0.1"])
        self.assertFalse(scope.is_allowed("127.0.0.1"))

    def test_cidr(self):
        scope = TargetAllowlist(allowed=["10.0.0.0/8"])
        self.assertTrue(scope.is_allowed("10.1.2.3"))


class TestRegistryAndTools(unittest.TestCase):
    def setUp(self):
        self.registry = ToolRegistry(scope=TargetAllowlist(allowed=["127.0.0.1"]))
        self.registry.register(ServiceDetector())
        self.registry.register(VersionDetector())
        self.registry.register(PortScanner(TargetAllowlist(allowed=["127.0.0.1"])))
        self.registry.register(ResultParserTool())

    def test_service_detect(self):
        r = self.registry.call("service_detect", {"port": 8080, "banner": "Apache Tomcat/9.0.50"})
        self.assertTrue(r["success"])
        self.assertEqual(r["output"]["product"], "Apache Tomcat")

    def test_version_detect(self):
        r = self.registry.call("version_detect", {"banner": "Apache/2.4.41 (Ubuntu)"})
        self.assertTrue(r["success"])
        self.assertEqual(r["output"]["version"], "2.4.41")

    def test_validation_error(self):
        r = self.registry.call("port_scan", {})
        self.assertFalse(r["success"])
        self.assertIn("missing required", r["error"])

    def test_out_of_scope_rejected(self):
        r = self.registry.call("port_scan", {"ip": "8.8.8.8", "ports": [80]})
        self.assertFalse(r["success"])
        self.assertIn("allowlist", r["error"])

    def test_unknown_tool_raises(self):
        with self.assertRaises(ToolExecutionError):
            self.registry.call("nope", {})

    def test_result_parser(self):
        r = self.registry.call("result_parser", {"raw_output": "confirmed vulnerable"})
        self.assertTrue(r["success"])
        self.assertEqual(r["output"]["result"], "CONFIRMED")


if __name__ == "__main__":
    unittest.main()
