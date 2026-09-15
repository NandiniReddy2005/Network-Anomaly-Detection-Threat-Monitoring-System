import sys
import os
import asyncio
import time

sys.path.insert(0, os.path.abspath(os.path.dirname(__file__)))

from app.database import AsyncSessionLocal, engine, Base
from app.routers.incidents import analyze_and_add_incident, get_incident_queue
from app.services.threat_intelligence import threat_service

async def run_integration_tests():
    print("=" * 80)
    print("  VERIFYING FULL INTEGRATION OF CICIDS, UNSW-NB15, AND ABUSEIPDB v2 API")
    print("=" * 80)

    # Initialize DB tables
    async with engine.begin() as conn:
        await conn.run_sync(Base.metadata.create_all)

    ts = int(time.time())
    
    async with AsyncSessionLocal() as db:
        # 1. Test live AbuseIPDB query directly
        print("\n1. Testing AbuseIPDB v2 API query directly (185.220.101.42)...", flush=True)
        abuse_res = await threat_service.check_ip("185.220.101.42")
        assert abuse_res is not None
        assert "abuse_confidence_score" in abuse_res
        print(f"  [PASS] AbuseIPDB v2 Result for 185.220.101.42: Score={abuse_res['abuse_confidence_score']}%, ISP={abuse_res['isp']}, Tor={abuse_res.get('is_tor', False)}", flush=True)

        # 2. Test UNSW-NB15 dynamic IP prediction & ML classification synthesis
        ip_unsw = "198.51.100.44"
        payload_unsw = {
            "alert_id": f"ALT-INT-UNSW-{ts}",
            "ip_address": ip_unsw,
            "source_ip": ip_unsw,
            "dataset_engine": "UNSW-NB15",
            "protocol": "TCP",
            "actor": "security_analyst@netshield.ai"
        }
        print(f"\n2. Testing UNSW-NB15 dynamic threat prediction ({ip_unsw})...", flush=True)
        res_unsw = await analyze_and_add_incident(payload=payload_unsw, db=db)
        assert res_unsw["status"] == "success"
        inc_unsw = res_unsw["data"]
        assert "UNSW-NB15 Engine" in inc_unsw["threat_vector"]
        assert inc_unsw["severity"] in ["CRITICAL", "HIGH", "MEDIUM", "LOW"]
        assert inc_unsw["abuse_score"] >= 0
        print(f"  [PASS] UNSW Incident Created: {inc_unsw['alert_id']} | Vector: {inc_unsw['threat_vector']} | Severity: {inc_unsw['severity']} | Score: {inc_unsw['abuse_score']}%", flush=True)

        await asyncio.sleep(1)

        # 3. Test CICIDS2017 dynamic IP prediction & ML classification synthesis
        ip_cic = "203.0.113.199"
        payload_cic = {
            "alert_id": f"ALT-INT-CIC-{ts}",
            "ip_address": ip_cic,
            "source_ip": ip_cic,
            "dataset_engine": "CICIDS2017",
            "protocol": "UDP",
            "actor": "security_analyst@netshield.ai"
        }
        print(f"\n3. Testing CICIDS2017 dynamic threat prediction ({ip_cic})...", flush=True)
        res_cic = await analyze_and_add_incident(payload=payload_cic, db=db)
        assert res_cic["status"] == "success"
        inc_cic = res_cic["data"]
        assert "CICIDS2017 Engine" in inc_cic["threat_vector"]
        assert inc_cic["severity"] in ["CRITICAL", "HIGH", "MEDIUM", "LOW"]
        assert inc_cic["abuse_score"] >= 0
        print(f"  [PASS] CICIDS Incident Created: {inc_cic['alert_id']} | Vector: {inc_cic['threat_vector']} | Severity: {inc_cic['severity']} | Score: {inc_cic['abuse_score']}%", flush=True)

        # 4. Verify PostgreSQL persistence & descending chronological queue order
        print("\n4. Verifying PostgreSQL persistence & descending chronological queue order...", flush=True)
        queue_res = await get_incident_queue(db=db)
        assert queue_res["status"] == "success"
        queue = queue_res.get("incidents", [])

        idx_cic = next((i for i, item in enumerate(queue) if item["alert_id"] == f"ALT-INT-CIC-{ts}"), -1)
        idx_unsw = next((i for i, item in enumerate(queue) if item["alert_id"] == f"ALT-INT-UNSW-{ts}"), -1)

        assert idx_cic != -1 and idx_unsw != -1, "Both created incidents must exist in PostgreSQL queue"
        assert idx_cic < idx_unsw, f"Newer incident ALT-INT-CIC-{ts} (idx {idx_cic}) MUST appear before older incident ALT-INT-UNSW-{ts} (idx {idx_unsw})"
        print(f"  [PASS] Chronological order verified: Newer (index {idx_cic}) < Older (index {idx_unsw})!")

        print("\n" + "=" * 80)
        print("  ALL CICIDS, UNSW-NB15, AND ABUSEIPDB INTEGRATION TESTS PASSED!")
        print("=" * 80)

if __name__ == "__main__":
    asyncio.run(run_integration_tests())
