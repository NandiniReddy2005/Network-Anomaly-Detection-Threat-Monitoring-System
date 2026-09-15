import sys
import os
import asyncio

sys.path.insert(0, os.path.abspath(os.path.dirname(__file__)))
if hasattr(sys.stdout, 'reconfigure'):
    sys.stdout.reconfigure(encoding='utf-8')

from app.routers.analytics import get_threat_distribution, get_severity_trends, get_top_attackers, get_engine_accuracy
from app.routers.reports import generate_pdf_report

class MockDB:
    def add(self, obj):
        pass
    async def commit(self):
        pass
    async def refresh(self, obj):
        pass

async def run_tests():
    print("==================================================", flush=True)
    print(" Testing Milestone 3 Step 4 Bar Chart Analytics   ", flush=True)
    print("==================================================", flush=True)

    mock_db = MockDB()

    # 1. Test GET /api/analytics/threat-distribution
    res_dist = await get_threat_distribution(engine="Both", time_range="7d")
    print(f"\n1. GET /api/analytics/threat-distribution -> status: {res_dist.get('status')}", flush=True)
    assert res_dist.get("status") == "success"
    print(f"   Fetched {len(res_dist.get('data', []))} dataset engine records for vertical stacked bar chart.")

    # 2. Test GET /api/analytics/severity-trends
    res_trends = await get_severity_trends(engine="Both", time_range="7d")
    print(f"\n2. GET /api/analytics/severity-trends -> status: {res_trends.get('status')}", flush=True)
    assert res_trends.get("status") == "success"
    print(f"   Fetched {len(res_trends.get('data', []))} historical trend data points for vertical grouped bar chart.")

    # 3. Test GET /api/analytics/top-attackers
    res_attackers = await get_top_attackers(limit=10)
    print(f"\n3. GET /api/analytics/top-attackers -> status: {res_attackers.get('status')}", flush=True)
    assert res_attackers.get("status") == "success"
    attackers = res_attackers.get("data", [])
    print(f"   Fetched {len(attackers)} ranked attacker IP records for horizontal bar chart. Rank 1 IP: {attackers[0].get('ip') if attackers else 'N/A'}")

    # 4. Test GET /api/analytics/engine-accuracy
    res_acc = await get_engine_accuracy()
    print(f"\n4. GET /api/analytics/engine-accuracy -> status: {res_acc.get('status')}", flush=True)
    assert res_acc.get("status") == "success"
    data_acc = res_acc.get("data", {})
    print(f"   UNSW Accuracy: {data_acc.get('unsw_nb15', {}).get('accuracy')}% | CICIDS Accuracy: {data_acc.get('cicids2017', {}).get('accuracy')}%")

    # 5. Test GET /api/reports/generate-pdf
    res_pdf = await generate_pdf_report(time_scope="Last 30 Days", report_type="Executive CISO Briefing", db=mock_db)
    print(f"\n5. GET /api/reports/generate-pdf -> Media Type: {res_pdf.media_type}", flush=True)
    assert res_pdf.media_type == "text/plain"
    assert "NETSHIELD-AI THREAT INTELLIGENCE & SECURITY REPORT" in res_pdf.body.decode("utf-8")

    print("\n[SUCCESS] Milestone 3 Step 4 Bar Chart Analytics Suite PASSED!\n", flush=True)

if __name__ == "__main__":
    asyncio.run(run_tests())
