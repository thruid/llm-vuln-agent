import unittest

from agent.agent import Agent
from agent.state import AgentState
from models.asset import Asset
from models.result import FinalStatus
from tests._helpers import build_system_with_cves, cve

TOMCAT = [
    cve("CVE-A", "Apache Tomcat", ["<9.0.54"], vendor="apache"),
    cve("CVE-B", "Apache Tomcat", ["<9.0.31"], vendor="apache"),
]


class TestAgent(unittest.TestCase):
    def test_multi_round_confirmed_and_not_vulnerable(self):
        system, _ = build_system_with_cves(TOMCAT)
        asset = Asset("127.0.0.1", 8080, product="Apache Tomcat", vendor="Apache", version="9.0.50")
        state = AgentState(asset=asset)
        report = Agent(system.llm, system.registry, state).run()
        statuses = [e.final_status for e in report.entries]
        self.assertIn(FinalStatus.CONFIRMED.value, statuses)
        self.assertIn(FinalStatus.NOT_VULNERABLE.value, statuses)
        # search -> verify -> final is at least 3 iterations (multi-round tool calling)
        self.assertGreaterEqual(state.step, 3)

    def test_insufficient_info(self):
        system, _ = build_system_with_cves(TOMCAT)
        asset = Asset("127.0.0.1")  # no product / service / version / banner
        state = AgentState(asset=asset)
        report = Agent(system.llm, system.registry, state).run()
        self.assertEqual(report.entries[0].final_status, FinalStatus.UNCERTAIN.value)

    def test_empty_knowledge_base_uncertain(self):
        system, _ = build_system_with_cves([])
        asset = Asset("127.0.0.1", 8080, product="Apache Tomcat", version="9.0.50")
        state = AgentState(asset=asset)
        report = Agent(system.llm, system.registry, state).run()
        self.assertEqual(report.entries[0].final_status, FinalStatus.UNCERTAIN.value)


if __name__ == "__main__":
    unittest.main()
