import asyncio
from fastapi.testclient import TestClient
from app.main import app

def test_audit_trail_actions():
    client = TestClient(app)
    print("=" * 50)
    print("  TESTING AUDIT TRAIL ENDPOINTS & ACTION PAYLOADS")
    print("=" * 50)

    # 1. Test POST /api/incidents/ALT-1083/actions with MARK_INVESTIGATING
    print("\n1. Testing POST /api/incidents/ALT-1083/actions [MARK_INVESTIGATING]...")
    res = client.post(
        "/api/incidents/ALT-1083/actions",
        json={
            "incident_id": "ALT-1083",
            "action_type": "MARK_INVESTIGATING",
            "user_email": "analyst_soc@netshield.ai",
            "timestamp": "2026-08-23T12:00:00Z"
        }
    )
    assert res.status_code == 200
    data = res.json()
    assert data["status"] == "success"
    assert data["new_status"] == "Investigating"
    assert data["action"]["action_type"] == "MARK_INVESTIGATING"
    assert data["action"]["user_email"] == "analyst_soc@netshield.ai"
    print(f"  [PASS] Successfully posted MARK_INVESTIGATING! Status: {data['new_status']}")

    # 2. Test POST /api/incidents/ALT-1083/actions with CONTAIN_IP
    print("\n2. Testing POST /api/incidents/ALT-1083/actions [CONTAIN_IP]...")
    res2 = client.post(
        "/api/incidents/ALT-1083/actions",
        json={
            "incident_id": "ALT-1083",
            "action_type": "CONTAIN_IP",
            "user_email": "analyst_soc@netshield.ai",
            "timestamp": "2026-08-23T12:01:00Z"
        }
    )
    assert res2.status_code == 200
    data2 = res2.json()
    assert data2["new_status"] == "Contained"
    print(f"  [PASS] Successfully posted CONTAIN_IP! Status: {data2['new_status']}")

    # 3. Test GET /api/incidents/ALT-1083/actions
    print("\n3. Testing GET /api/incidents/ALT-1083/actions...")
    res_get = client.get("/api/incidents/ALT-1083/actions")
    assert res_get.status_code == 200
    get_data = res_get.json()
    assert get_data["status"] == "success"
    assert len(get_data["actions"]) >= 2
    print(f"  [PASS] Successfully fetched {len(get_data['actions'])} historical actions for ALT-1083!")
    for act in get_data["actions"]:
        print(f"    - [{act['timestamp']}] {act['user_email']} -> {act['action_type']} ({act['old_value']} => {act['new_value']})")

    # 4. Test POST /api/incidents/ALT-1083/actions with RESOLVED
    print("\n4. Testing POST /api/incidents/ALT-1083/actions [RESOLVED]...")
    res3 = client.post(
        "/api/incidents/ALT-1083/actions",
        json={
            "incident_id": "ALT-1083",
            "action_type": "RESOLVED",
            "user_email": "lead_soc@netshield.ai",
            "timestamp": "2026-08-23T12:02:00Z"
        }
    )
    assert res3.status_code == 200
    data3 = res3.json()
    assert data3["new_status"] == "Resolved"
    print(f"  [PASS] Successfully posted RESOLVED! Status: {data3['new_status']}")

    print("\n" + "=" * 50)
    print("  ALL AUDIT TRAIL & ACTION PERSISTENCE TESTS PASSED!")
    print("=" * 50)

if __name__ == "__main__":
    test_audit_trail_actions()
