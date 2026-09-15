import sys
import os
import asyncio

sys.path.insert(0, os.path.abspath(os.path.dirname(__file__)))
if hasattr(sys.stdout, 'reconfigure'):
    sys.stdout.reconfigure(encoding='utf-8')

from app.routers.incidents import get_incident_queue, contain_ip_address, unblock_ip_address, analyze_and_add_incident, INCIDENT_QUEUE

class MockDB:
    def add(self, obj):
        pass
    async def commit(self):
        pass
    async def refresh(self, obj):
        pass
    async def rollback(self):
        pass

async def run_tests():
    print("==================================================", flush=True)
    print(" Testing Firewall Containment Engine & Release IP ", flush=True)
    print("==================================================", flush=True)

    # 1. Test GET /api/incidents/queue
    res = await get_incident_queue()
    print(f"\n1. get_incident_queue() -> status: {res.get('status')}", flush=True)
    assert res.get("status") == "success"
    incidents = res.get("data", [])
    print(f"   Fetched {len(incidents)} active incidents from queue.", flush=True)

    # 2. Add Test Incident
    mock_payload = {
        "source_ip": "185.220.101.42",
        "target_ip": "10.0.9.47",
        "dataset": "UNSW-NB15",
        "actor": "security@gmail.com"
    }
    res_analyze = await analyze_and_add_incident(mock_payload)
    analyzed_item = res_analyze.get("data", {})
    alert_id = analyzed_item.get("alert_id")

    # 3. Test POST /api/incidents/contain-ip (Firewall Null-Route + Audit Logging)
    mock_db = MockDB()
    contain_payload = {
        "alert_id": alert_id,
        "source_ip": "185.220.101.42",
        "actor": "security@gmail.com"
    }
    res_contain = await contain_ip_address(payload=contain_payload, db=mock_db)
    print(f"\n2. POST /api/incidents/contain-ip Result:", flush=True)
    print(f"   - Message: {res_contain.get('message')}", flush=True)
    print(f"   - Firewall Command Executed: {res_contain.get('firewall_command')}", flush=True)
    print(f"   - New Status: {res_contain.get('new_status')}", flush=True)
    assert res_contain.get("new_status") == "Contained"
    assert "FIREWALL NULL-ROUTE DEPLOYED" in res_contain.get("message")
    assert "iptables -A INPUT -s 185.220.101.42 -j DROP" in res_contain.get("firewall_command")

    # 4. Test POST /api/incidents/unblock-ip (Reverse Firewall Rule + Active Status)
    unblock_payload = {
        "alert_id": alert_id,
        "source_ip": "185.220.101.42",
        "actor": "security@gmail.com"
    }
    res_unblock = await unblock_ip_address(payload=unblock_payload, db=mock_db)
    print(f"\n3. POST /api/incidents/unblock-ip Result:", flush=True)
    print(f"   - Message: {res_unblock.get('message')}", flush=True)
    print(f"   - Firewall Command Executed: {res_unblock.get('firewall_command')}", flush=True)
    print(f"   - New Status: {res_unblock.get('new_status')}", flush=True)
    assert res_unblock.get("new_status") == "Active"
    assert "FIREWALL RULE REMOVED" in res_unblock.get("message")
    assert "iptables -D INPUT -s 185.220.101.42 -j DROP" in res_unblock.get("firewall_command")

    print("\n[SUCCESS] Firewall Containment Engine & Release IP PASSED!\n", flush=True)

if __name__ == "__main__":
    asyncio.run(run_tests())
