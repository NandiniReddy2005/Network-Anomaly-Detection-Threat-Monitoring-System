import sys
import os

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from fastapi.testclient import TestClient
from app.main import app

def run_threat_analysis_tests():
    print("============================================================")
    print("NETSHIELD-AI DYNAMIC THREAT VECTOR ANALYSIS TEST")
    print("============================================================")

    with TestClient(app) as client:
        # Test 1: UNSW-NB15 dataset with unseen IP
        payload_1 = {
            "dataset": "UNSW-NB15",
            "sourceIp": "203.0.113.195",
            "destinationIp": "10.0.0.5 (DB)",
            "sourcePort": "54321",
            "destinationPort": "443",
            "protocol": "TCP"
        }
        res1 = client.post("/api/threats/analyze", json=payload_1)
        print("1. POST /api/threats/analyze (UNSW-NB15 unseen IP):", res1.status_code)
        assert res1.status_code == 200, f"Expected 200, got {res1.status_code}: {res1.text}"
        data1 = res1.json()
        print("   Response payload:", data1)
        assert "data" in data1 or "threat_id" in data1
        res_data1 = data1.get("data", data1)
        assert "threat_id" in res_data1
        assert "predicted_threat" in res_data1
        assert "threat_score" in res_data1
        assert "severity" in res_data1
        assert "confidence_score" in res_data1
        assert res_data1["dataset"] in ["UNSW-NB15", "UNSW_NB15"]
        print("   --> PASS: Received required dynamic fields for unseen IP 203.0.113.195")

        # Test 2: CICIDS2017 dataset with another unseen IP
        payload_2 = {
            "dataset": "CICIDS2017",
            "sourceIp": "198.51.100.42",
            "destinationIp": "10.0.0.12 (Subnet)",
            "sourcePort": "41122",
            "destinationPort": "80",
            "protocol": "UDP"
        }
        res2 = client.post("/api/threats/analyze", json=payload_2)
        print("\n2. POST /api/threats/analyze (CICIDS2017 unseen IP):", res2.status_code)
        assert res2.status_code == 200, f"Expected 200, got {res2.status_code}: {res2.text}"
        data2 = res2.json()
        print("   Response payload:", data2)
        res_data2 = data2.get("data", data2)
        assert "threat_id" in res_data2
        assert "predicted_threat" in res_data2
        assert "threat_score" in res_data2
        assert "severity" in res_data2
        assert "confidence_score" in res_data2
        assert res_data2["dataset"] in ["CICIDS2017", "CICIDS_2017"]
        print("   --> PASS: Received required dynamic fields for unseen IP 198.51.100.42")

        # Test 3: /api/ml/analyze route compatibility
        res3 = client.post("/api/ml/analyze", json=payload_1)
        print("\n3. POST /api/ml/analyze route compatibility:", res3.status_code)
        assert res3.status_code == 200, f"Expected 200, got {res3.status_code}: {res3.text}"
        data3 = res3.json()
        res_data3 = data3.get("data", data3)
        assert "threat_id" in res_data3
        assert "predicted_threat" in res_data3
        assert "threat_score" in res_data3
        assert "severity" in res_data3
        print("   --> PASS: Route /api/ml/analyze correctly returns dynamic threat fields")

    print("\n============================================================")
    print("ALL DYNAMIC THREAT VECTOR ANALYSIS TESTS PASSED 100%!")
    print("============================================================")

if __name__ == "__main__":
    run_threat_analysis_tests()
