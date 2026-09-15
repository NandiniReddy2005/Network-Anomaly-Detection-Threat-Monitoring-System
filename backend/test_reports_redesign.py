import sys
import os
import asyncio

sys.path.insert(0, os.path.abspath(os.path.dirname(__file__)))
if hasattr(sys.stdout, 'reconfigure'):
    sys.stdout.reconfigure(encoding='utf-8')

from app.database import AsyncSessionLocal, engine, Base
from app.models import Incident, UserActivityLog
from app.routers.reports import generate_database_report, generate_pdf_report, export_csv_incident_logs, export_json_telemetry
from app.routers.incidents import analyze_and_add_incident, fetch_incidents_with_action_history

class MockRequest:
    def __init__(self, headers=None):
        self.headers = headers or {}

async def run_tests():
    print("==================================================", flush=True)
    print(" TESTING DATABASE-DRIVEN ANALYTICS & REPORT ENGINE ", flush=True)
    print("==================================================", flush=True)

    # 1. Initialize Tables in DB
    async with engine.begin() as conn:
        await conn.run_sync(Base.metadata.create_all)
    print("1. Database tables initialized successfully.", flush=True)

    async with AsyncSessionLocal() as db:
        mock_req = MockRequest(headers={"X-User-Email": "security@gmail.com"})

        # Seed incidents if database empty
        await fetch_incidents_with_action_history(db)
        print("2. Seed incidents database verification complete.", flush=True)

        # 2. Test GET /api/reports/generate (Default 7 Days, All Datasets)
        res_gen = await generate_database_report(
            request=mock_req,
            user_id="security@gmail.com",
            user_email=None,
            x_user_email="security@gmail.com",
            days=7,
            date_range="Last 7 Days",
            dataset_engine="All Datasets (Both)",
            dataset=None,
            start_date=None,
            end_date=None,
            db=db
        )

        print(f"\n3. GET /api/reports/generate -> status: {res_gen.get('status')}", flush=True)
        assert res_gen.get("status") == "success"
        assert res_gen.get("user_id") == "security@gmail.com"

        metrics = res_gen.get("metrics", {})
        print("   Metric Aggregations (Top Section - Real-Time DB Counts):")
        print(f"   - Total Threats Count : {metrics.get('total_threats')}")
        print(f"   - Severity Breakdown  : {metrics.get('severity_counts')}")
        print(f"   - Dataset Counts      : {metrics.get('dataset_counts')}")
        assert metrics.get("total_threats") > 0
        assert "CRITICAL" in metrics.get("severity_counts", {})
        assert "UNSW-NB15" in metrics.get("dataset_counts", {})

        guardrail = res_gen.get("guardrail", {})
        print(f"\n4. Limited Data Guardrail Check:")
        print(f"   - Triggered: {guardrail.get('triggered')}")
        print(f"   - Available Days: {guardrail.get('available_days')}")
        print(f"   - Notice: {guardrail.get('notice')}")

        data = res_gen.get("data", [])
        print(f"   - Incident Records Returned: {len(data)}")
        if data:
            first = data[0]
            print(f"   - First Incident Preview: [{first['alert_id']}] {first['source_ip']} -> {first['target_ip']} | Sev: {first['severity']} | Engine: {first['dataset_engine']}")

        # 3. Test Filter by Specific Dataset Engine (UNSW-NB15)
        res_unsw = await generate_database_report(
            request=mock_req,
            user_id="security@gmail.com",
            user_email=None,
            x_user_email="security@gmail.com",
            days=30,
            date_range="Last 30 Days",
            dataset_engine="UNSW-NB15",
            dataset=None,
            start_date=None,
            end_date=None,
            db=db
        )
        print(f"\n5. GET /api/reports/generate (Filtered UNSW-NB15) -> count: {len(res_unsw.get('data', []))}", flush=True)
        for inc in res_unsw.get("data", []):
            assert "UNSW" in (inc.get("dataset_engine") or "").upper() or "UNSW" in (inc.get("detection_source") or "").upper()

        # 4. Test New User / Limited Data Guardrail triggering (Request 30 days when history is less)
        res_guard = await generate_database_report(
            request=mock_req,
            user_id="security@gmail.com",
            user_email=None,
            x_user_email="security@gmail.com",
            days=30,
            date_range="Last 30 Days",
            dataset_engine="All Datasets (Both)",
            dataset=None,
            start_date=None,
            end_date=None,
            db=db
        )
        g_info = res_guard.get("guardrail", {})
        if g_info.get("triggered"):
            print(f"\n6. Guardrail Trigger Verified: '{g_info.get('notice')}'", flush=True)

        # 5. Test Export Formats (PDF, CSV, JSON)
        res_pdf = await generate_pdf_report(request=mock_req, time_scope="Last 7 Days", dataset_engine="UNSW-NB15", user_id="security@gmail.com", db=db)
        print(f"\n7. Export PDF -> Media Type: {res_pdf.media_type}", flush=True)
        assert res_pdf.media_type == "text/plain"

        res_csv = await export_csv_incident_logs(request=mock_req, user_id="security@gmail.com", dataset_engine="All Datasets (Both)", db=db)
        print(f"8. Export CSV -> Media Type: {res_csv.media_type}", flush=True)
        assert res_csv.media_type == "text/csv"

        res_json = await export_json_telemetry(request=mock_req, user_id="security@gmail.com", dataset_engine="All Datasets (Both)", db=db)
        print(f"9. Export JSON -> Media Type: {res_json.media_type}", flush=True)
        assert res_json.media_type == "application/json"

    print("\n==================================================", flush=True)
    print(" ALL DATABASE-DRIVEN ANALYTICS & REPORT TESTS PASSED! ", flush=True)
    print("==================================================\n", flush=True)

if __name__ == "__main__":
    asyncio.run(run_tests())
