import os
import sys
import asyncio
import unittest

backend_dir = os.path.dirname(os.path.abspath(__file__))
if backend_dir not in sys.path:
    sys.path.insert(0, backend_dir)

from app.database import AsyncSessionLocal, engine, Base
from app.routers.dashboard import analyze_critical_alert, AlertAnalyzePayload

class TestCriticalAlertsAnalysis(unittest.IsolatedAsyncioTestCase):
    async def asyncSetUp(self):
        async with engine.begin() as conn:
            await conn.run_sync(Base.metadata.create_all)

    async def test_unseen_ip_unsw_nb15_alert_analysis(self):
        payload = AlertAnalyzePayload(
            dataset="UNSW-NB15",
            source_ip="198.51.100.99",
            destination_ip="10.0.0.2 (Auth Server)",
            source_port=54321,
            destination_port=443,
            protocol="TCP"
        )
        async with AsyncSessionLocal() as db:
            res = await analyze_critical_alert(payload=payload, db=db)
            self.assertEqual(res.get("status"), "success")
            alert = res.get("data", {})
            self.assertTrue(alert.get("alert_id", "").startswith("ALT-"), "Missing ALT- alert_id")
            self.assertIn("attack_type", alert, "Missing attack_type")
            self.assertIn("composite_risk_score", alert, "Missing composite_risk_score")
            self.assertIn(alert.get("severity"), ["Critical", "High", "Medium", "Low"])
            self.assertIn("mitre_tag", alert)
            self.assertIn("containment_playbook", alert)
            print("   --> PASS: Received dynamic alert outputs for unseen IP 198.51.100.99", flush=True)

    async def test_unseen_ip_cicids2017_alert_analysis(self):
        payload = AlertAnalyzePayload(
            dataset="CICIDS2017",
            source_ip="203.0.113.77",
            destination_ip="10.0.0.5 (DB Server)",
            source_port=49152,
            destination_port=80,
            protocol="UDP"
        )
        async with AsyncSessionLocal() as db:
            res = await analyze_critical_alert(payload=payload, db=db)
            self.assertEqual(res.get("status"), "success")
            alert = res.get("data", {})
            self.assertTrue(alert.get("alert_id", "").startswith("ALT-"))
            self.assertIn("attack_type", alert)
            self.assertIn("composite_risk_score", alert)
            print("   --> PASS: Received dynamic alert outputs for unseen IP 203.0.113.77", flush=True)

if __name__ == "__main__":
    print("=" * 60, flush=True)
    print("NETSHIELD-AI DYNAMIC CRITICAL ALERTS ANALYSIS TEST", flush=True)
    print("=" * 60, flush=True)
    unittest.main(verbosity=2)
