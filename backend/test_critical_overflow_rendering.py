from fastapi.testclient import TestClient
from app.main import app

def test_critical_overflow_and_rendering():
    client = TestClient(app)
    print("=" * 60)
    print("  TESTING CRITICAL FLOOD CLASSIFICATION & RESPONSE FIELDS")
    print("=" * 60)

    # 1. Test High Volume Flood with formatted numerical string (dpkts = "1,000,000")
    print("\n1. Testing high volume flood (dpkts='1,000,000')...")
    res = client.post(
        "/api/incidents/analyze-add",
        json={
            "source_ip": "185.220.101.55",
            "target_ip": "10.0.9.47",
            "dataset": "UNSW-NB15",
            "dur": "0.05",
            "spkts": "142",
            "dpkts": "1,000,000",
            "flow_duration": "1250",
            "total_fwd_packets": "450",
            "user_email": "soc_analyst@netshield.ai"
        }
    )
    assert res.status_code == 200
    data = res.json()
    assert data["status"] == "success"
    
    inc = data.get("data") or data.get("incident")
    assert inc is not None
    assert inc.get("alert_id") is not None and inc.get("alert_id").startswith("ALT-")
    assert inc.get("timestamp") is not None and len(inc.get("timestamp")) > 0
    assert inc.get("threat_vector") is not None and len(inc.get("threat_vector")) > 0
    assert inc.get("severity") == "CRITICAL"
    assert "Volumetric DoS" in inc.get("threat_vector")

    print(f"  [PASS] Successfully classified alert {inc['alert_id']}!")
    print(f"  Alert ID: {inc['alert_id']}")
    print(f"  Timestamp: {inc['timestamp']}")
    print(f"  Severity: {inc['severity']}")
    print(f"  Threat Vector: {inc['threat_vector']}")
    print(f"  Details: {inc['details']}")

    # 2. Test High Volume Flood with large integer (spkts = 50000)
    print("\n2. Testing high volume flood with large integer (spkts=50000)...")
    res2 = client.post(
        "/api/incidents/analyze-add",
        json={
            "source_ip": "198.51.100.88",
            "target_ip": "10.0.9.50",
            "dataset": "CICIDS2017",
            "spkts": "50000",
            "dpkts": "25000",
            "user_email": "soc_analyst@netshield.ai"
        }
    )
    assert res2.status_code == 200
    data2 = res2.json()
    inc2 = data2.get("data")
    assert inc2["severity"] == "CRITICAL"
    print(f"  [PASS] Alert {inc2['alert_id']} correctly assigned CRITICAL severity!")

    print("\n" + "=" * 60)
    print("  ALL CRITICAL FLOOD & RENDERING TESTS PASSED!")
    print("=" * 60)

if __name__ == "__main__":
    test_critical_overflow_and_rendering()
