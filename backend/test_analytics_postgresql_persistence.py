import sys
import os
import asyncio

sys.path.insert(0, os.path.abspath(os.path.dirname(__file__)))
if hasattr(sys.stdout, 'reconfigure'):
    sys.stdout.reconfigure(encoding='utf-8')

from app.database import AsyncSessionLocal
from app.routers.analytics import get_analytics_summary
from app.routers.incidents import analyze_and_add_incident

async def run_verification():
    print("==========================================================")
    print(" Testing PostgreSQL Database Visual Analytics & Persistence")
    print("==========================================================")

    async with AsyncSessionLocal() as db:
        # 1. Fetch analytics summary for default analyst (security@gmail.com)
        res1 = await get_analytics_summary(user_id="security@gmail.com", db=db)
        print(f"\n1. GET /api/analytics/summary (security@gmail.com) -> Status: {res1.get('status')}")
        assert res1.get("status") == "success"
        summary1 = res1.get("summary", {})
        print(f"   Total Incidents: {summary1.get('total_incidents')}")
        print(f"   Critical: {summary1.get('critical_count')}, High: {summary1.get('high_count')}, Medium: {summary1.get('medium_count')}, Low: {summary1.get('low_count')}")
        print(f"   TCP: {summary1.get('tcp_count')}, UDP: {summary1.get('udp_count')}, ICMP: {summary1.get('icmp_count')}")
        print(f"   UNSW: {summary1.get('unsw_count')}, CICIDS: {summary1.get('cicids_count')}, Abuse: {summary1.get('abuse_count')}")
        assert "severity_distribution" in res1
        assert "telemetry_timeline" in res1
        assert "top_attackers" in res1
        assert "protocol_engine_breakdown" in res1

        # 2. Add a new incident for security@gmail.com
        print("\n2. Simulating new threat submission for security@gmail.com...")
        payload = {
            "source_ip": "198.51.100.222",
            "dataset_engine": "CICIDS2017",
            "protocol": "UDP",
            "actor": "security@gmail.com"
        }
        inc_res = await analyze_and_add_incident(payload=payload, db=db)
        print(f"   Created Incident: {inc_res.get('alert_id')} | Severity: {inc_res.get('severity')}")

        # 3. Verify updated aggregate metrics from PostgreSQL
        res2 = await get_analytics_summary(user_id="security@gmail.com", db=db)
        summary2 = res2.get("summary", {})
        print(f"\n3. GET /api/analytics/summary after insert:")
        print(f"   New Total Incidents: {summary2.get('total_incidents')}")
        assert summary2.get("total_incidents") > summary1.get("total_incidents")

        # 4. Verify user isolation for another analyst
        new_user = "test_analyst_999@netshield.io"
        res_isolated = await get_analytics_summary(user_id=new_user, db=db)
        summary_iso = res_isolated.get("summary", {})
        print(f"\n4. User Session Isolation for '{new_user}':")
        print(f"   Total Incidents for new user: {summary_iso.get('total_incidents')}")
        assert summary_iso.get("total_incidents") == 0

        print("\n[SUCCESS] All PostgreSQL Visual Analytics & Persistence backend tests PASSED!\n")

if __name__ == "__main__":
    asyncio.run(run_verification())
