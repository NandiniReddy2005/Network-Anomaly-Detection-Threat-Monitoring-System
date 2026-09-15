import sys
import os

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
if hasattr(sys.stdout, "reconfigure"):
    sys.stdout.reconfigure(encoding="utf-8")

from fastapi.testclient import TestClient
from app.main import app

def test_dynamic_ml_predict():
    print("============================================================")
    print("NETSHIELD-AI DYNAMIC ML PREDICT ENDPOINT VERIFICATION")
    print("============================================================")

    with TestClient(app) as client:
        # Test Case 1: IP 192.168.1.222 with UDP
        payload1 = {
            "target_dataset": "UNSW-NB15",
            "source_ip": "192.168.1.222",
            "destination_ip": "10.0.9.47",
            "source_port": 49166,
            "destination_port": 45600,
            "protocol": "UDP"
        }
        res1 = client.post("/api/predict", json=payload1)
        assert res1.status_code == 200, f"Expected 200, got {res1.status_code}: {res1.text}"
        data1 = res1.json()
        print("1. Test 192.168.1.222 (UDP):")
        print("   Predicted Threat:", data1.get("predicted_threat"))
        print("   Threat Probability:", data1.get("threat_probability"))
        print("   Threat Level:", data1.get("threat_level"))
        print("   Anomaly Status:", data1.get("anomaly_status"))
        print("   Anomaly Score:", data1.get("anomaly_score"))
        print("   Risk Score:", data1.get("risk_score"))
        print("   Verdict:", data1.get("security_verdict"))

        # Test Case 2: IP 10.0.0.15 with TCP
        payload2 = {
            "target_dataset": "UNSW-NB15",
            "source_ip": "10.0.0.15",
            "destination_ip": "10.0.0.1",
            "source_port": 49152,
            "destination_port": 80,
            "protocol": "TCP"
        }
        res2 = client.post("/api/predict", json=payload2)
        assert res2.status_code == 200, f"Expected 200, got {res2.status_code}: {res2.text}"
        data2 = res2.json()
        print("\n2. Test 10.0.0.15 (TCP):")
        print("   Predicted Threat:", data2.get("predicted_threat"))
        print("   Threat Probability:", data2.get("threat_probability"))
        print("   Threat Level:", data2.get("threat_level"))
        print("   Anomaly Status:", data2.get("anomaly_status"))
        print("   Anomaly Score:", data2.get("anomaly_score"))
        print("   Risk Score:", data2.get("risk_score"))
        print("   Verdict:", data2.get("security_verdict"))

        # Assert dynamic values differ
        assert data1["predicted_threat"] != data2["predicted_threat"], "Predicted threat types should differ"
        assert data1["threat_probability"] != data2["threat_probability"], "Threat probabilities should differ"
        assert data1["anomaly_score"] != data2["anomaly_score"], "Anomaly scores should differ"
        assert data1["threat_level"] != data2["threat_level"], "Threat levels should differ"
        assert data1["security_verdict"] != data2["security_verdict"], "Verdicts should differ"

        # Test Case 3: Verify Audit Log persistence for Activity Security
        headers = {"X-User-Email": "sec_admin@gmail.com"}
        res_audit = client.post("/api/predict", json=payload1, headers=headers)
        assert res_audit.status_code == 200

        res_logs = client.get("/api/dashboard/audit-logs")
        assert res_logs.status_code == 200
        logs_data = res_logs.json()
        logs_list = logs_data.get("logs") or logs_data.get("data") or logs_data
        
        activity_sec_logs = [log for log in logs_list if log.get("module") == "Activity Security"]
        print("\n3. Audit Logs Verification:")
        print(f"   Found {len(activity_sec_logs)} audit log entries for 'Activity Security'")
        assert len(activity_sec_logs) > 0, "Expected at least 1 audit log with module='Activity Security'"
        top_log = activity_sec_logs[0]
        print(f"   Latest Audit Log -> Module: {top_log['module']} | Actor: {top_log['actor']} | Action: {top_log['action']}")
        assert "Executed ML Analysis on Target" in top_log["action"], f"Unexpected action: {top_log['action']}"
        assert top_log["module"] == "Activity Security"
        assert top_log["status"] == "Success"

        print("\n--> PASS: Audit event correctly logged with module='Activity Security' and performed action string!")

if __name__ == "__main__":
    test_dynamic_ml_predict()
