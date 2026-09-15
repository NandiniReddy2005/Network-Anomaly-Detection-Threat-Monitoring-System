import sys
import os
import asyncio

sys.path.insert(0, os.path.abspath(os.path.dirname(__file__)))

from app.database import AsyncSessionLocal, engine, Base
from app.routers.incidents import get_incident_queue, handle_incident_action, IncidentActionPayload

async def run_tests():
    print("==================================================", flush=True)
    print("   Testing Step 1: Incidents & Actions (Direct)   ", flush=True)
    print("==================================================", flush=True)

    # Initialize DB tables
    async with engine.begin() as conn:
        await conn.run_sync(Base.metadata.create_all)

    async with AsyncSessionLocal() as db:
        # 1. Test get_incident_queue()
        res = await get_incident_queue(db=db)
        print(f"\n1. get_incident_queue() -> status: {res.get('status')}", flush=True)
        assert res.get("status") == "success"
        incidents = res.get("data", [])
        print(f"   Fetched {len(incidents)} active incidents from queue.", flush=True)
        for inc in incidents[:3]:
            print(f"   - [{inc['alert_id']}] {inc['timestamp']} | {inc['source_ip']} -> {inc['target_ip']} | {inc['severity']} | Status: {inc['status']}", flush=True)

        class MockRequest:
            def __init__(self):
                self.method = "POST"
                self.headers = {}

        req = MockRequest()
        target_inc = incidents[0] if incidents else None
        target_id = target_inc["alert_id"] if target_inc else "ALT-1"

        # 2. Test handle_incident_action() -> ACKNOWLEDGE
        ack_payload = IncidentActionPayload(
            alert_id=target_id,
            action_type="ACKNOWLEDGE",
            actor="security@gmail.com"
        )
        res_ack = await handle_incident_action(incident_id=target_id, payload=ack_payload, request=req, db=db)
        print(f"\n2. ACKNOWLEDGE Action Result: {res_ack.get('message')}", flush=True)
        assert res_ack.get("new_status") == "Investigating"

        # 3. Test handle_incident_action() -> CONTAIN
        contain_payload = IncidentActionPayload(
            alert_id=target_id,
            action_type="CONTAIN",
            actor="security@gmail.com"
        )
        res_contain = await handle_incident_action(incident_id=target_id, payload=contain_payload, request=req, db=db)
        print(f"\n3. CONTAIN Action Result: {res_contain.get('message')}", flush=True)
        assert res_contain.get("new_status") == "Contained"

        # 4. Test handle_incident_action() -> DISMISS
        dismiss_payload = IncidentActionPayload(
            alert_id=target_id,
            action_type="DISMISS",
            actor="security@gmail.com"
        )
        res_dismiss = await handle_incident_action(incident_id=target_id, payload=dismiss_payload, request=req, db=db)
        print(f"\n4. DISMISS Action Result: {res_dismiss.get('message')}", flush=True)
        assert res_dismiss.get("new_status") == "Resolved"

        # 5. Verify updated queue state
        res_after = await get_incident_queue(db=db)
        incidents_after = res_after.get("data", [])
        target_after = next(x for x in incidents_after if x["alert_id"] == target_id)

        assert target_after["status"] == "Resolved"

        print("\n[SUCCESS] Step 1 Backend Test Suite PASSED! All state transitions verified.\n", flush=True)

if __name__ == "__main__":
    asyncio.run(run_tests())
