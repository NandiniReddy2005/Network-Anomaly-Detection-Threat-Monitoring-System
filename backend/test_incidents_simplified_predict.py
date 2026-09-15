from fastapi.testclient import TestClient
from app.main import app

def test_simplified_threat_predictor():
    client = TestClient(app)
    print("=" * 60)
    print("  TESTING SIMPLIFIED THREAT PREDICTOR & PERSISTENCE")
    print("=" * 60)

    # 1. Test Invalid IP Address Validation
    print("\n1. Testing IP address regex validation failure...")
    res_bad = client.post(
        "/api/incidents/predict",
        json={"ip_address": "invalid_ip_string", "dataset_engine": "UNSW-NB15"}
    )
    assert res_bad.status_code == 400
    print("  [PASS] Blocked malformed IP with 400 HTTP status!")

    # 2. Test UNSW-NB15 Prediction
    print("\n2. Testing UNSW-NB15 threat prediction...")
    res_unsw = client.post(
        "/api/incidents/predict",
        json={
            "ip_address": "185.220.101.42",
            "dataset_engine": "UNSW-NB15",
            "user_email": "soc_analyst@netshield.ai"
        }
    )
    assert res_unsw.status_code == 200
    data_unsw = res_unsw.json()
    inc_unsw = data_unsw.get("data")
    assert inc_unsw is not None
    assert inc_unsw["severity"] == "CRITICAL"
    assert "UNSW-NB15 DoS" in inc_unsw["threat_vector"]
    print(f"  [PASS] Alert {inc_unsw['alert_id']}: {inc_unsw['severity']} - {inc_unsw['threat_vector']}")

    # 3. Test CICIDS2017 Prediction
    print("\n3. Testing CICIDS2017 threat prediction...")
    res_cic = client.post(
        "/api/incidents/predict",
        json={
            "ip_address": "198.51.100.22",
            "dataset_engine": "CICIDS2017",
            "user_email": "soc_analyst@netshield.ai"
        }
    )
    assert res_cic.status_code == 200
    data_cic = res_cic.json()
    inc_cic = data_cic.get("data")
    assert inc_cic["severity"] == "HIGH"
    assert "CICIDS2017 Web Attack" in inc_cic["threat_vector"]
    print(f"  [PASS] Alert {inc_cic['alert_id']}: {inc_cic['severity']} - {inc_cic['threat_vector']}")

    # 4. Test AbuseIPDB Threat Intel Prediction
    print("\n4. Testing AbuseIPDB Threat Intel prediction...")
    res_abuse = client.post(
        "/api/incidents/predict",
        json={
            "ip_address": "45.33.32.156",
            "dataset_engine": "AbuseIPDB Threat Intel",
            "user_email": "soc_analyst@netshield.ai"
        }
    )
    assert res_abuse.status_code == 200
    data_abuse = res_abuse.json()
    inc_abuse = data_abuse.get("data")
    assert inc_abuse["severity"] == "CRITICAL"
    assert "AbuseIPDB Known Malicious" in inc_abuse["threat_vector"]
    print(f"  [PASS] Alert {inc_abuse['alert_id']}: {inc_abuse['severity']} - {inc_abuse['threat_vector']}")

    # 5. Verify PostgreSQL Database Persistence & Session Restoration
    print("\n5. Testing PostgreSQL Session Restore (GET /api/incidents/queue)...")
    res_queue = client.get("/api/incidents/queue")
    assert res_queue.status_code == 200
    queue_incidents = res_queue.json().get("incidents", [])

    created_ids = [inc_unsw["alert_id"], inc_cic["alert_id"], inc_abuse["alert_id"]]
    for target_id in created_ids:
        found = next((i for i in queue_incidents if i["alert_id"] == target_id), None)
        assert found is not None, f"Incident {target_id} not found in database queue"
        assert len(found["action_history"]) >= 1
    print(f"  [PASS] All {len(created_ids)} incidents successfully persisted to PostgreSQL and restored in queue!")

    print("\n" + "=" * 60)
    print("  ALL SIMPLIFIED PREDICTOR TESTS PASSED!")
    print("=" * 60)

if __name__ == "__main__":
    test_simplified_threat_predictor()
