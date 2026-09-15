import sys
import os
import asyncio

sys.path.insert(0, os.path.abspath(os.path.dirname(__file__)))
if hasattr(sys.stdout, 'reconfigure'):
    sys.stdout.reconfigure(encoding='utf-8')

from app.database import AsyncSessionLocal
from app.routers.analytics import get_analytics_charts
from app.routers.incidents import analyze_and_add_incident

async def run_verification():
    print("==========================================================")
    print(" Testing GET /api/analytics/charts PostgreSQL Endpoint   ")
    print("==========================================================")

    async with AsyncSessionLocal() as db:
        user = "security@gmail.com"

        # 1. Test GET /api/analytics/charts with 7d range
        res7 = await get_analytics_charts(time_range="7d", user_id=user, db=db)
        print(f"\n1. GET /api/analytics/charts?time_range=7d -> Status: {res7.get('status')}")
        assert res7.get("status") == "success"
        assert len(res7.get("time_series", [])) == 7
        print(f"   Severity Counts: {res7.get('severity_counts')}")
        print(f"   Dataset Counts: {res7.get('dataset_counts')}")
        print(f"   Time Series Buckets (7d): {len(res7.get('time_series'))} days returned")

        # 2. Test GET /api/analytics/charts with 15d range
        res15 = await get_analytics_charts(time_range="15d", user_id=user, db=db)
        print(f"\n2. GET /api/analytics/charts?time_range=15d -> Status: {res15.get('status')}")
        assert res15.get("status") == "success"
        assert len(res15.get("time_series", [])) == 15
        print(f"   Time Series Buckets (15d): {len(res15.get('time_series'))} days returned")

        # 3. Test GET /api/analytics/charts with 30d range
        res30 = await get_analytics_charts(time_range="30d", user_id=user, db=db)
        print(f"\n3. GET /api/analytics/charts?time_range=30d -> Status: {res30.get('status')}")
        assert res30.get("status") == "success"
        assert len(res30.get("time_series", [])) == 30
        print(f"   Time Series Buckets (30d): {len(res30.get('time_series'))} days returned")

        # 4. Simulate adding new threat in Incident Queue and check real-time update
        print("\n4. Adding new threat in Incident Queue...")
        payload = {
            "source_ip": "198.51.100.99",
            "dataset_engine": "CICIDS2017",
            "protocol": "TCP",
            "actor": user
        }
        inc_res = await analyze_and_add_incident(payload=payload, db=db)
        print(f"   Created Incident: {inc_res.get('alert_id')} | Severity: {inc_res.get('severity')}")

        res_after = await get_analytics_charts(time_range="7d", user_id=user, db=db)
        print(f"   Updated Total Incidents: {res_after.get('total_incidents')}")
        assert res_after.get("total_incidents") > res7.get("total_incidents")

        # 5. Verify isolated session for new analyst with 0 stored records (Guardrail check)
        new_user = "brand_new_analyst@netshield.io"
        res_new = await get_analytics_charts(time_range="30d", user_id=new_user, db=db)
        print(f"\n5. New User Guardrail Test for '{new_user}':")
        print(f"   Status: {res_new.get('status')} | Total Incidents: {res_new.get('total_incidents')}")
        assert res_new.get("total_incidents") == 0
        assert len(res_new.get("time_series", [])) == 30
        print(f"   New user 30-day date scale generated cleanly without errors! First date: {res_new.get('time_series')[0]['date']}")

        print("\n[SUCCESS] GET /api/analytics/charts tests PASSED!\n")

if __name__ == "__main__":
    asyncio.run(run_verification())
