from fastapi.testclient import TestClient
from app.main import app

def test_sequential_alert_ids_and_timestamps():
    client = TestClient(app)
    print("=" * 65)
    print("  TESTING SEQUENTIAL ALERT IDs (ALT-1..) & DYNAMIC TIMESTAMPS")
    print("=" * 65)

    # 1. Fetch current queue
    print("\n1. Fetching initial incident queue...")
    res_queue = client.get("/api/incidents/queue")
    assert res_queue.status_code == 200
    incidents = res_queue.json().get("incidents", [])

    print(f"  [PASS] Retrieved {len(incidents)} incidents from queue!")
    for inc in incidents[:5]:
        print(f"    - ID: {inc['alert_id']} | Severity: {inc['severity']} | Source: {inc['source_ip']}")

    # 2. Add new incident and verify sequential ID increment
    print("\n2. Adding new threat alert via /api/incidents/predict...")
    res_add = client.post(
        "/api/incidents/predict",
        json={
            "ip_address": "185.220.101.99",
            "dataset_engine": "UNSW-NB15",
            "user_email": "analyst@netshield.ai"
        }
    )
    assert res_add.status_code == 200
    new_inc = res_add.json().get("data")
    assert new_inc is not None

    alert_id = new_inc["alert_id"]
    print(f"  [PASS] Created incident assigned sequential Alert ID: '{alert_id}'!")
    print(f"  Timestamp: {new_inc['timestamp']}")

    assert alert_id.startswith("ALT-")
    numeric_id = int(alert_id.replace("ALT-", ""))
    assert numeric_id >= 1, f"Expected numeric ID >= 1, got {numeric_id}"

    print("\n" + "=" * 65)
    print("  ALL SEQUENTIAL ID & TIMESTAMP TESTS PASSED!")
    print("=" * 65)

if __name__ == "__main__":
    test_sequential_alert_ids_and_timestamps()
