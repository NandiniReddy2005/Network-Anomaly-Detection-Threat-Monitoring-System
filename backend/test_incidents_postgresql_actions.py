import sys
import asyncio
from pathlib import Path
from fastapi.testclient import TestClient

backend_dir = Path(__file__).resolve().parent
if str(backend_dir) not in sys.path:
    sys.path.insert(0, str(backend_dir))

from app.main import app

def test_incident_actions():
    print("=" * 60)
    print("NETSHIELD-AI INCIDENT QUEUE POSTGRESQL ACTION LOGGING VERIFICATION")
    print("=" * 60)

    client = TestClient(app)

    # 1. Test GET /api/incidents/queue (Fetches incidents JOINED with action_history)
    print("\n1. Testing GET /api/incidents/queue...")
    response = client.get("/api/incidents/queue", headers={"X-User-Email": "security@gmail.com"})
    assert response.status_code == 200, f"Failed: {response.text}"
    data = response.json()
    assert data["status"] == "success"
    incidents = data["incidents"]
    assert len(incidents) >= 1
    print(f"  [PASS] Successfully fetched {len(incidents)} incidents with relational action history!")

    target_inc = incidents[0]
    target_id = target_inc["alert_id"]
    print(f"  [INFO] Target Incident ID for Action: {target_id}")

    # 2. Test Transactional POST /api/incidents/{incident_id}/action
    print(f"\n2. Testing Transactional POST /api/incidents/{target_id}/action...")
    action_payload = {
        "alert_id": target_id,
        "action_type": "STATUS_CHANGE",
        "old_value": target_inc["status"],
        "new_value": "Investigating",
        "notes": "Initiated deep payload analysis on target node.",
        "actor": "sec_analyst_test@netshield.ai"
    }

    act_res = client.post(
        f"/api/incidents/{target_id}/action",
        json=action_payload,
        headers={"X-User-Email": "sec_analyst_test@netshield.ai"}
    )
    assert act_res.status_code == 200, f"Failed: {act_res.text}"
    act_data = act_res.json()
    assert act_data["status"] == "success"
    assert act_data["new_status"] == "Investigating"
    action_obj = act_data["action"]
    assert action_obj["incident_id"] == target_id
    assert action_obj["analyst_email"] == "sec_analyst_test@netshield.ai"
    print(f"  [PASS] Action recorded in PostgreSQL: {action_obj}")

    # 3. Test IP Block Action POST /api/incidents/contain-ip
    print("\n3. Testing IP Containment Action POST /api/incidents/contain-ip...")
    contain_res = client.post(
        "/api/incidents/contain-ip",
        json={"alert_id": target_id, "source_ip": target_inc["source_ip"], "actor": "security@gmail.com"},
        headers={"X-User-Email": "security@gmail.com"}
    )
    assert contain_res.status_code == 200
    print(f"  [PASS] IP Block Action recorded: {contain_res.json()['new_status']}")

    # 4. Verify Historical Action Restoration on Re-fetch (Logout / Login restoration simulation)
    print("\n4. Verifying Historical Action Restoration on Re-Fetch...")
    refetch_res = client.get("/api/incidents/queue", headers={"X-User-Email": "new_analyst@gmail.com"})
    assert refetch_res.status_code == 200
    refetched_incidents = refetch_res.json()["incidents"]
    refetched_target = next((i for i in refetched_incidents if i["alert_id"] == target_id), None)
    assert refetched_target is not None
    history = refetched_target.get("action_history", [])
    assert len(history) >= 2, f"Expected at least 2 historical actions, got {len(history)}"
    print(f"  [PASS] Historical actions restored successfully! Action count: {len(history)}")
    for h in history[:2]:
        print(f"    - [{h['timestamp']}] {h['analyst_email']} performed {h['action_type']} ({h['old_value']} -> {h['new_value']})")

    print("\n" + "=" * 60)
    print("=== POSTGRESQL INCIDENT ACTION LOGGING VERIFICATION PASSED ===")
    print("=" * 60)

if __name__ == "__main__":
    test_incident_actions()
