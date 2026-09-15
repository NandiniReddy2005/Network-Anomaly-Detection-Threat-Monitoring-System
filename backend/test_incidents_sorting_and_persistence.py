import sys
import os
import asyncio
import time

sys.path.insert(0, os.path.abspath(os.path.dirname(__file__)))

from app.database import AsyncSessionLocal, engine, Base
from app.routers.incidents import analyze_and_add_incident, get_incident_queue
from app.models import Incident

async def run_sorting_and_persistence_tests():
    print("=" * 70)
    print("  VERIFYING INCIDENT SORTING & STRICT POSTGRESQL PERSISTENCE")
    print("=" * 70)

    # Initialize DB tables
    async with engine.begin() as conn:
        await conn.run_sync(Base.metadata.create_all)

    ts_suffix = int(time.time())
    id1 = f"ALT-SORT-1-{ts_suffix}"
    id2 = f"ALT-SORT-2-{ts_suffix}"

    async with AsyncSessionLocal() as db:
        # 1. Predict and add first IP incident with custom threat metrics
        ip1 = "167.167.23.99"
        payload1 = {
            "alert_id": id1,
            "ip_address": ip1,
            "source_ip": ip1,
            "dataset_engine": "CICIDS",
            "threat_vector": "CICIDS Engine: SSH / FTP Brute Force Attempt",
            "severity": "CRITICAL",
            "abuse_score": 88,
            "protocol": "TCP",
            "user_email": "soc_analyst@netshield.ai"
        }
        
        print(f"\n1. Submitting IP prediction #1 ({ip1})...", flush=True)
        res1 = await analyze_and_add_incident(payload=payload1, db=db)
        assert res1["status"] == "success"
        inc1_data = res1.get("data")
        assert inc1_data["threat_vector"] == "CICIDS Engine: SSH / FTP Brute Force Attempt"
        assert inc1_data["severity"] == "CRITICAL"
        assert inc1_data["abuse_score"] == 88
        print(f"  [PASS] Incident #1 Created: {inc1_data['alert_id']} | Threat: {inc1_data['threat_vector']} | Score: {inc1_data['abuse_score']}%", flush=True)

        await asyncio.sleep(1) # Ensure distinct timestamp gap

        # 2. Predict and add second IP incident
        ip2 = "45.142.120.10"
        payload2 = {
            "alert_id": id2,
            "ip_address": ip2,
            "source_ip": ip2,
            "dataset_engine": "UNSW-NB15",
            "threat_vector": "UNSW-NB15 Engine: Exploits / Shellcode Injection",
            "severity": "HIGH",
            "abuse_score": 76,
            "protocol": "UDP",
            "user_email": "soc_analyst@netshield.ai"
        }

        print(f"\n2. Submitting IP prediction #2 ({ip2})...", flush=True)
        res2 = await analyze_and_add_incident(payload=payload2, db=db)
        assert res2["status"] == "success"
        inc2_data = res2.get("data")
        assert inc2_data["threat_vector"] == "UNSW-NB15 Engine: Exploits / Shellcode Injection"
        assert inc2_data["severity"] == "HIGH"
        assert inc2_data["abuse_score"] == 76
        print(f"  [PASS] Incident #2 Created: {inc2_data['alert_id']} | Threat: {inc2_data['threat_vector']} | Score: {inc2_data['abuse_score']}%", flush=True)

        # 3. Fetch queue from get_incident_queue(db=db) to verify chronological descending order
        print("\n3. Fetching Incident Queue to test sorting and persistence...", flush=True)
        res_queue = await get_incident_queue(db=db)
        assert res_queue["status"] == "success"
        queue = res_queue.get("incidents", [])
        assert len(queue) >= 2

        # Find position of both created test incidents in the queue
        idx2 = next((i for i, item in enumerate(queue) if item["alert_id"] == id2), -1)
        idx1 = next((i for i, item in enumerate(queue) if item["alert_id"] == id1), -1)

        print(f"   Queue Index {id2} (Newest): {idx2}", flush=True)
        print(f"   Queue Index {id1} (Older):  {idx1}", flush=True)

        assert idx2 != -1 and idx1 != -1, "Both created incidents must exist in PostgreSQL queue"
        assert idx2 < idx1, f"Newest incident {id2} (index {idx2}) MUST appear before {id1} (index {idx1})"

        # 4. Verify exact score & threat vector immutability on re-fetch
        fetched2 = queue[idx2]
        fetched1 = queue[idx1]

        assert fetched2["threat_vector"] == "UNSW-NB15 Engine: Exploits / Shellcode Injection"
        assert fetched2["severity"] == "HIGH"
        assert fetched2["abuse_score"] == 76

        assert fetched1["threat_vector"] == "CICIDS Engine: SSH / FTP Brute Force Attempt"
        assert fetched1["severity"] == "CRITICAL"
        assert fetched1["abuse_score"] == 88

        print("\n[SUCCESS] PostgreSQL Persistence & Chronological Sorting Verified!", flush=True)
        print("=" * 70, flush=True)

if __name__ == "__main__":
    asyncio.run(run_sorting_and_persistence_tests())
