import sys
import os
import asyncio

sys.path.insert(0, os.path.abspath(os.path.dirname(__file__)))
if hasattr(sys.stdout, 'reconfigure'):
    sys.stdout.reconfigure(encoding='utf-8')

from app.database import AsyncSessionLocal
from app.routers.analytics import get_analytics_threat_types, get_analytics_charts
from app.routers.incidents import analyze_and_add_incident

async def run_verification():
    print("==========================================================")
    print(" Testing GET /api/analytics/threat-types Endpoint        ")
    print("==========================================================")

    async with AsyncSessionLocal() as db:
        user = "security@gmail.com"

        # 1. Test GET /api/analytics/threat-types
        res_tt = await get_analytics_threat_types(user_id=user, db=db)
        print(f"\n1. GET /api/analytics/threat-types -> Status: {res_tt.get('status')}")
        assert res_tt.get("status") == "success"
        breakdown = res_tt.get("data", [])
        print(f"   Threat Vector Breakdown Categories ({len(breakdown)}):")
        for item in breakdown:
            print(f"   - {item.get('category')}: {item.get('count')} incidents")

        # 2. Add a new Web Attack threat to Incident Queue
        print("\n2. Submitting new SQLi Web Attack threat to Incident Queue...")
        payload = {
            "source_ip": "203.0.113.200",
            "dataset_engine": "CICIDS2017",
            "threat_vector": "CICIDS2017 Web Attack - SQLi Payload RCE",
            "protocol": "TCP",
            "actor": user
        }
        inc_res = await analyze_and_add_incident(payload=payload, db=db)
        print(f"   Created Incident: {inc_res.get('alert_id')} | Threat Vector: {inc_res.get('threat_vector')}")

        # 3. Verify real-time update in threat-types endpoint
        res_tt2 = await get_analytics_threat_types(user_id=user, db=db)
        web_item = next((item for item in res_tt2.get("data", []) if item["category"] == "Web Attacks / SQLi"), None)
        print(f"\n3. Updated 'Web Attacks / SQLi' Count: {web_item.get('count') if web_item else 0}")
        assert web_item and web_item.get("count") > 0

        # 4. Verify threat_vector_breakdown inside /charts endpoint
        res_charts = await get_analytics_charts(time_range="7d", user_id=user, db=db)
        print(f"\n4. GET /api/analytics/charts threat_vector_breakdown check:")
        assert "threat_vector_breakdown" in res_charts
        print(f"   Breakdown in /charts: {len(res_charts.get('threat_vector_breakdown'))} categories")

        # 5. User isolation guardrail test
        new_user = "test_threat_type_analyst@netshield.io"
        res_iso = await get_analytics_threat_types(user_id=new_user, db=db)
        print(f"\n5. Isolated User Guardrail test for '{new_user}':")
        assert res_iso.get("status") == "success"
        iso_counts = [item["count"] for item in res_iso.get("data", [])]
        print(f"   Category counts for new user: {iso_counts}")
        assert sum(iso_counts) == 0

        print("\n[SUCCESS] Threat Vector Breakdown Analytics test PASSED!\n")

if __name__ == "__main__":
    asyncio.run(run_verification())
