import os
import sys
import unittest
from fastapi.testclient import TestClient

backend_dir = os.path.dirname(os.path.abspath(__file__))
if backend_dir not in sys.path:
    sys.path.insert(0, backend_dir)

from app.main import app

client = TestClient(app)

class TestHelpQuery(unittest.TestCase):
    def test_source_ip_query(self):
        res = client.post("/api/help/query", json={"query": "what is source ip"})
        self.assertEqual(res.status_code, 200)
        data = res.json()
        print("\n1. Source IP query result:", data)
        self.assertEqual(data.get("category"), "Network Fundamentals")
        self.assertIn("originating IPv4 address", data.get("answer", ""))
        print("   --> PASS: Matched Network Fundamentals (Source IP)")

    def test_destination_ip_query(self):
        res = client.post("/api/help/query", json={"query": "what is destination ip"})
        self.assertEqual(res.status_code, 200)
        data = res.json()
        print("\n2. Destination IP query result:", data)
        self.assertEqual(data.get("category"), "Asset Protection")
        self.assertIn("internal infrastructure node", data.get("answer", ""))
        print("   --> PASS: Matched Asset Protection (Destination IP)")

    def test_triage_query(self):
        res = client.post("/api/help/query", json={"query": "what is triage"})
        self.assertEqual(res.status_code, 200)
        data = res.json()
        print("\n3. Triage query result:", data)
        self.assertEqual(data.get("category"), "Incident Response")
        self.assertIn("evaluation and prioritization", data.get("answer", "").lower())
        print("   --> PASS: Matched Incident Response (Triage)")

    def test_ml_analyzer_query(self):
        res = client.post("/api/help/query", json={"query": "Explain UNSW-NB15 dataset selection"})
        self.assertEqual(res.status_code, 200)
        data = res.json()
        print("\n4. ML Analyzer query result:", data)
        self.assertEqual(data.get("category"), "Machine Learning Analyzers")
        self.assertIn("unsw-nb15", data.get("answer", "").lower())
        print("   --> PASS: Matched Machine Learning Analyzers")

    def test_threat_score_query(self):
        res = client.post("/api/help/query", json={"query": "How is threat score calculated?"})
        self.assertEqual(res.status_code, 200)
        data = res.json()
        print("\n5. Threat Score query result:", data)
        self.assertEqual(data.get("category"), "Telemetry Analytics")
        self.assertIn("Threat scores (0–100)", data.get("answer", ""))
        print("   --> PASS: Matched Telemetry Analytics (Threat Score)")

    def test_fallback_query(self):
        res = client.post("/api/help/query", json={"query": "How do I setup custom Quantum encryption?"})
        self.assertEqual(res.status_code, 200)
        data = res.json()
        print("\n6. Fallback query result:", data)
        self.assertEqual(data.get("category"), "SOC Knowledge Base")
        self.assertIn("Information regarding 'How do I setup custom Quantum encryption?'", data.get("answer", ""))
        print("   --> PASS: Generated smart fallback for unrecognized topic")

    def test_security_analyst_responsibilities_query(self):
        res = client.post("/api/help/query", json={"query": "security analyst responsibilities"})
        self.assertEqual(res.status_code, 200)
        data = res.json()
        print("\n7. Security Analyst Responsibilities query result:", data)
        self.assertEqual(data.get("category"), "Security Analyst Role")
        self.assertIn("Security Analysts are responsible for real-time threat telemetry monitoring", data.get("answer", ""))
        print("   --> PASS: Matched dedicated Security Analyst Role intent")

    def test_security_administrator_query(self):
        res = client.post("/api/help/query", json={"query": "security administrator responsibilities"})
        self.assertEqual(res.status_code, 200)
        data = res.json()
        print("\n8. Security Administrator query result:", data)
        self.assertEqual(data.get("category"), "Security Administrator Role")
        self.assertIn("Security Administrators hold root administrative authority", data.get("answer", ""))
        print("   --> PASS: Matched dedicated Security Administrator Role intent")

    def test_threats_section_query(self):
        res = client.post("/api/help/query", json={"query": "threats section overview"})
        self.assertEqual(res.status_code, 200)
        data = res.json()
        print("\n9. Threats Section query result:", data)
        self.assertEqual(data.get("category"), "Threat Detection & Analysis")
        self.assertIn("continuously analyzes incoming network telemetry", data.get("answer", ""))
        self.assertEqual(data.get("query"), "threats section overview")
        print("   --> PASS: Exact query preserved & matched Threat Detection & Analysis")

    def test_audit_log_section_query(self):
        res = client.post("/api/help/query", json={"query": "what is the responsibilities of audit log section"})
        self.assertEqual(res.status_code, 200)
        data = res.json()
        print("\n10. Audit Log Section query result:", data)
        self.assertEqual(data.get("category"), "Audit Logs & Event Ledger")
        self.assertIn("immutable ledger of all system security events", data.get("answer", ""))
        self.assertEqual(data.get("query"), "what is the responsibilities of audit log section")
        print("   --> PASS: Matched Audit Logs & Event Ledger")

    def test_critical_alerts_query(self):
        res = client.post("/api/help/query", json={"query": "critical alerts"})
        self.assertEqual(res.status_code, 200)
        data = res.json()
        print("\n11. Critical Alerts query result:", data)
        self.assertEqual(data.get("category"), "Critical Threat Alerts")
        self.assertIn("monitors real-time composite threat anomalies", data.get("answer", ""))
        self.assertEqual(data.get("query"), "critical alerts")
        print("   --> PASS: Exact query preserved & matched Critical Threat Alerts")

    def test_activity_security_query(self):
        res = client.post("/api/help/query", json={"query": "activity security"})
        self.assertEqual(res.status_code, 200)
        data = res.json()
        print("\n12. Activity Security query result:", data)
        self.assertEqual(data.get("category"), "Activity Security & Threat Scans")
        self.assertIn("tracks real-time threat detection metrics", data.get("answer", ""))
        self.assertEqual(data.get("query"), "activity security")
        print("   --> PASS: Matched Activity Security & Threat Scans")

if __name__ == "__main__":
    print("=" * 60)
    print("NETSHIELD-AI INTERACTIVE SYSTEM HELP Q&A TEST")
    print("=" * 60)
    suite = unittest.TestLoader().loadTestsFromTestCase(TestHelpQuery)
    runner = unittest.TextTestRunner(verbosity=2)
    result = runner.run(suite)
    if result.wasSuccessful():
        print("=" * 60)
        print("ALL INTERACTIVE SYSTEM HELP Q&A TESTS PASSED 100%!")
        print("=" * 60)
        sys.exit(0)
    else:
        sys.exit(1)
