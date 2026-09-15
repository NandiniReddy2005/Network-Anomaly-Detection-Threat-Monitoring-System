import sys
import asyncio
from pathlib import Path
from fastapi.testclient import TestClient

backend_dir = Path(__file__).resolve().parent
if str(backend_dir) not in sys.path:
    sys.path.insert(0, str(backend_dir))

from app.main import app

def test_enhanced_incidents():
    print("=" * 60)
    print("NETSHIELD-AI ENHANCED INCIDENT MODULE VERIFICATION")
    print("=" * 60)

    client = TestClient(app)

    # 1. Test Bulk Actions POST /api/incidents/bulk-action
    print("\n1. Testing Bulk Actions POST /api/incidents/bulk-action...")
    bulk_res = client.post(
        "/api/incidents/bulk-action",
        json={
            "alert_ids": ["ALT-1082", "ALT-1083"],
            "action_type": "CONTAIN",
            "actor": "security@gmail.com",
            "notes": "Bulk IP containment policy enforced."
        },
        headers={"X-User-Email": "security@gmail.com"}
    )
    assert bulk_res.status_code == 200, f"Bulk action failed: {bulk_res.text}"
    bulk_data = bulk_res.json()
    assert bulk_data["status"] == "success"
    assert bulk_data["processed_count"] == 2
    print(f"  [PASS] Bulk operation output: {bulk_data['message']}")

    # 2. Test Dynamic Feature Threat Classifier POST /api/incidents/analyze-add
    print("\n2. Testing Dynamic Feature Inputs POST /api/incidents/analyze-add...")
    add_res = client.post(
        "/api/incidents/analyze-add",
        json={
            "source_ip": "185.220.101.99",
            "target_ip": "10.0.9.47",
            "target_dataset": "UNSW-NB15",
            "dur": "0.12",
            "spkts": "240",
            "dpkts": "180",
            "actor": "security@gmail.com"
        }
    )
    assert add_res.status_code == 200, f"Analyze-add failed: {add_res.text}"
    add_data = add_res.json()
    assert add_data["status"] == "success"
    print(f"  [PASS] Dynamic feature alert created: {add_data['alert_id']} ({add_data['threat_vector']})")

    # 3. Test SSE Telemetry Stream GET /api/incidents/stream
    print("\n3. Testing Telemetry Stream GET /api/incidents/stream...")
    with client.stream("GET", "/api/incidents/stream") as response:
        assert response.status_code == 200
        for line in response.iter_lines():
            if line.startswith("data:"):
                print(f"  [PASS] Received live SSE event data packet length: {len(line)} bytes")
                break

    print("\n" + "=" * 60)
    print("=== ENHANCED INCIDENT MODULE VERIFICATION PASSED ===")
    print("=" * 60)

if __name__ == "__main__":
    test_enhanced_incidents()
