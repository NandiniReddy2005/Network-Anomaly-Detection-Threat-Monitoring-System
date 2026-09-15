import sys
import os
import asyncio

sys.path.insert(0, os.path.abspath(os.path.dirname(__file__)))
if hasattr(sys.stdout, 'reconfigure'):
    sys.stdout.reconfigure(encoding='utf-8')

from app.database import AsyncSessionLocal, engine, Base
from app.routers.traffic_router import (
    compute_dynamic_traffic_payload,
    save_traffic_analysis_state,
    get_traffic_analysis_state,
    SaveTrafficStateRequest
)

class DummyRequest:
    def __init__(self, headers=None, user_id=None, json_body=None):
        self.headers = headers or {}
        if user_id:
            self.headers["X-User-Email"] = user_id
        self.method = "POST" if json_body else "GET"
        self._json_body = json_body or {}

    async def json(self):
        return self._json_body

async def run_pipeline_and_session_state_tests():
    print("==========================================================================", flush=True)
    print(" NETSHIELD-AI REAL-DATA PIPELINE & USER SESSION STATE PERSISTENCE TEST", flush=True)
    print("==========================================================================", flush=True)

    async with AsyncSessionLocal() as db:
        # -------------------------------------------------------------------------
        # TEST 1: Real-Data Pipeline Analysis (NPCAP, AbuseIPDB, UNSW, CICIDS)
        # -------------------------------------------------------------------------
        print("\n--- TEST 1: Real-Data Integration Pipeline ---", flush=True)
        
        user_alice = "alice_analyst@netshield.ai"
        user_bob = "bob_analyst@netshield.ai"

        print("Step 1.1: Preparing Alice request...", flush=True)
        req_alice = DummyRequest(user_id=user_alice, json_body={"destination_ip": "1.1.1.1", "source_ip": "10.0.1.55", "protocol": "HTTPS"})
        
        print("Step 1.2: Calling compute_dynamic_traffic_payload for Alice...", flush=True)
        res_alice = await compute_dynamic_traffic_payload(req_alice, db, "1.1.1.1", "10.0.1.55", "HTTPS", is_post=True)
        
        print(f"Step 1.3: Alice analyze 1.1.1.1 HTTPS -> Status: {res_alice.get('status')}", flush=True)
        assert res_alice.get("status") == "success"
        new_rec_alice = res_alice.get("new_record") or res_alice.get("data", {}).get("new_record")
        assert new_rec_alice is not None, "Expected new_record in payload"
        assert new_rec_alice["destination_ip"] == "1.1.1.1"
        assert new_rec_alice["source_ip"] == "10.0.1.55"
        assert "risk_status" in new_rec_alice
        assert "abuse_score" in new_rec_alice
        print(f"   --> PASS: Evaluated flow ({new_rec_alice['destination_ip']}): {new_rec_alice['risk_status']} ({new_rec_alice['abuse_score']})", flush=True)

        # Bob analyzes a suspicious external IP with ICMP (185.220.101.5 ICMP)
        req_bob = DummyRequest(user_id=user_bob, json_body={"destination_ip": "185.220.101.5", "source_ip": "192.168.1.120", "protocol": "ICMP"})
        res_bob = await compute_dynamic_traffic_payload(req_bob, db, "185.220.101.5", "192.168.1.120", "ICMP", is_post=True)
        print(f"\n1.2 Bob analyze 185.220.101.5 ICMP -> Status: {res_bob.get('status')}", flush=True)
        assert res_bob.get("status") == "success"
        new_rec_bob = res_bob.get("new_record") or res_bob.get("data", {}).get("new_record")
        assert new_rec_bob is not None
        assert new_rec_bob["destination_ip"] == "185.220.101.5"
        assert new_rec_bob["protocol"] == "ICMP"
        print(f"   --> PASS: Evaluated flow ({new_rec_bob['destination_ip']}): {new_rec_bob['risk_status']} ({new_rec_bob['abuse_score']})", flush=True)

        # -------------------------------------------------------------------------
        # TEST 2: User Session State Save and Restoration across logged-in users
        # -------------------------------------------------------------------------
        print("\n--- TEST 2: User Session State Persistence & Restoration ---", flush=True)

        # Save session state for Alice
        state_req_alice = SaveTrafficStateRequest(
            user_id=user_alice,
            action_type="FILTER_APPLIED",
            destination_ip="1.1.1.1",
            source_ip="10.0.1.55",
            protocol="HTTPS",
            notes="Investigating active HTTPS stream"
        )
        save_res_alice = await save_traffic_analysis_state(state_req_alice, DummyRequest(user_id=user_alice), db)
        print(f"2.1 save_traffic_analysis_state (Alice) -> Status: {save_res_alice.get('status')}", flush=True)
        assert save_res_alice.get("status") == "success"

        # Save session state for Bob
        state_req_bob = SaveTrafficStateRequest(
            user_id=user_bob,
            action_type="FILTER_APPLIED",
            destination_ip="185.220.101.5",
            source_ip="192.168.1.120",
            protocol="ICMP",
            notes="Monitoring suspicious ICMP burst"
        )
        save_res_bob = await save_traffic_analysis_state(state_req_bob, DummyRequest(user_id=user_bob), db)
        print(f"2.2 save_traffic_analysis_state (Bob) -> Status: {save_res_bob.get('status')}", flush=True)
        assert save_res_bob.get("status") == "success"

        # Retrieve session state for Alice -> assert Alice's state is returned
        get_res_alice = await get_traffic_analysis_state(DummyRequest(user_id=user_alice), user_id=user_alice, db=db)
        print(f"2.3 get_traffic_analysis_state (Alice) -> Status: {get_res_alice.get('status')}", flush=True)
        assert get_res_alice.get("status") == "success"
        assert get_res_alice["user_id"] == user_alice
        alice_payload_retrieved = get_res_alice.get("payload", {})
        assert alice_payload_retrieved.get("destination_ip") == "1.1.1.1"
        assert alice_payload_retrieved.get("protocol") == "HTTPS"
        assert alice_payload_retrieved.get("notes") == "Investigating active HTTPS stream"
        print(f"   --> PASS: Restored session state for Alice: destination={alice_payload_retrieved.get('destination_ip')}, protocol={alice_payload_retrieved.get('protocol')}", flush=True)

        # Retrieve session state for Bob -> assert Bob's state is returned separately
        get_res_bob = await get_traffic_analysis_state(DummyRequest(user_id=user_bob), user_id=user_bob, db=db)
        print(f"\n2.4 get_traffic_analysis_state (Bob) -> Status: {get_res_bob.get('status')}", flush=True)
        assert get_res_bob.get("status") == "success"
        assert get_res_bob["user_id"] == user_bob
        bob_payload_retrieved = get_res_bob.get("payload", {})
        assert bob_payload_retrieved.get("destination_ip") == "185.220.101.5"
        assert bob_payload_retrieved.get("protocol") == "ICMP"
        assert bob_payload_retrieved.get("notes") == "Monitoring suspicious ICMP burst"
        print(f"   --> PASS: Restored session state for Bob: destination={bob_payload_retrieved.get('destination_ip')}, protocol={bob_payload_retrieved.get('protocol')}", flush=True)

        # -------------------------------------------------------------------------
        # TEST 3: User Specific Database Records Fetching
        # -------------------------------------------------------------------------
        print("\n--- TEST 3: User Database Metrics & Records Fetching ---", flush=True)
        metrics_alice = await compute_dynamic_traffic_payload(DummyRequest(user_id=user_alice), db, None, None, "ALL", is_post=False)
        assert metrics_alice["status"] == "success"
        records_alice = metrics_alice.get("records") or metrics_alice.get("data", {}).get("records", [])
        assert len(records_alice) > 0
        assert any(r["destination_ip"] == "1.1.1.1" for r in records_alice)
        print(f"3.1 compute_dynamic_traffic_payload (Alice metrics): Fetched {len(records_alice)} user records", flush=True)

        print("\n==========================================================================", flush=True)
        print(" ALL TRAFFIC PIPELINE & USER SESSION STATE PERSISTENCE TESTS PASSED 100%!", flush=True)
        print("==========================================================================", flush=True)

if __name__ == "__main__":
    asyncio.run(run_pipeline_and_session_state_tests())



