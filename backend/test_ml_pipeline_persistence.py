from fastapi.testclient import TestClient
from app.main import app

def test_ml_pipeline_and_persistence():
    client = TestClient(app)
    print("=" * 55)
    print("  TESTING ML PREDICTION PIPELINE & POSTGRES PERSISTENCE")
    print("=" * 55)

    # 1. Test Validation Failure (Negative Number)
    print("\n1. Testing validation failure for negative 'dpkts'...")
    res_bad = client.post(
        "/api/incidents/analyze-add",
        json={
            "source_ip": "185.220.101.42",
            "target_ip": "10.0.9.47",
            "dataset": "UNSW-NB15",
            "dur": "0.05",
            "spkts": "142",
            "dpkts": "-98"
        }
    )
    assert res_bad.status_code == 400
    print("  [PASS] Validation blocked negative dpkts with 400 HTTP status!")

    # 2. Test Validation Failure (Malformed IP)
    print("\n2. Testing validation failure for malformed Source IP...")
    res_bad_ip = client.post(
        "/api/incidents/analyze-add",
        json={
            "source_ip": "999.999.999.999",
            "target_ip": "10.0.9.47",
            "dataset": "UNSW-NB15"
        }
    )
    assert res_bad_ip.status_code == 400
    print("  [PASS] Validation blocked malformed IP with 400 HTTP status!")

    # 3. Test High Volume Volumetric Flood Prediction (dpkts=1000000)
    print("\n3. Testing ML Engine Prediction for high volume flood (dpkts=1,000,000)...")
    res_predict = client.post(
        "/api/incidents/analyze-add",
        json={
            "source_ip": "185.220.101.99",
            "target_ip": "10.0.9.47",
            "dataset": "UNSW-NB15",
            "user_email": "analyst_test@netshield.ai",
            "dur": "0.05",
            "spkts": "142",
            "dpkts": "1000000",
            "flow_duration": "1250",
            "total_fwd_packets": "450"
        }
    )
    assert res_predict.status_code == 200
    data = res_predict.json()
    assert data["status"] == "success"
    assert data["severity"] == "CRITICAL"
    assert "Volumetric DoS" in data["threat_vector"]
    alert_id = data["alert_id"]
    print(f"  [PASS] ML Engine classified alert {alert_id} as '{data['severity']}' ({data['threat_vector']})!")
    print(f"  Details: {data['data']['details']}")

    # 4. Verify PostgreSQL Session Restore via GET /api/incidents/queue
    print("\n4. Testing PostgreSQL Session Restore (GET /api/incidents/queue)...")
    res_queue = client.get("/api/incidents/queue")
    assert res_queue.status_code == 200
    queue_data = res_queue.json()
    incidents = queue_data.get("incidents", [])

    created_inc = next((i for i in incidents if i["alert_id"] == alert_id), None)
    assert created_inc is not None
    assert created_inc["source_ip"] == "185.220.101.99"
    assert created_inc["severity"] == "CRITICAL"
    assert len(created_inc["action_history"]) >= 1
    assert created_inc["action_history"][0]["action_type"] == "ANALYZED_AND_QUEUED"

    print(f"  [PASS] Incident {alert_id} successfully restored from PostgreSQL database!")
    print(f"  Action Log: {created_inc['action_history'][0]['analyst_email']} -> {created_inc['action_history'][0]['action_type']}")

    print("\n" + "=" * 55)
    print("  ALL ML PIPELINE & PERSISTENCE TESTS PASSED!")
    print("=" * 55)

if __name__ == "__main__":
    test_ml_pipeline_and_persistence()
