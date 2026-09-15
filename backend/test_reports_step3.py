import sys
import os
import asyncio

sys.path.insert(0, os.path.abspath(os.path.dirname(__file__)))
if hasattr(sys.stdout, 'reconfigure'):
    sys.stdout.reconfigure(encoding='utf-8')

from app.routers.reports import get_reports_summary, get_reports_audit_logs, export_csv_incident_logs, export_json_telemetry, export_pdf_summary

class MockDB:
    def add(self, obj):
        pass
    async def commit(self):
        pass
    async def refresh(self, obj):
        pass
    async def rollback(self):
        pass
    async def execute(self, stmt):
        class MockResult:
            def scalars(self):
                class MockScalars:
                    def all(self):
                        return []
                return MockScalars()
        return MockResult()

async def run_tests():
    print("==================================================", flush=True)
    print(" Testing Milestone 3 Threat Intelligence & Reports ", flush=True)
    print("==================================================", flush=True)

    mock_db = MockDB()

    # 1. Test GET /api/reports/summary
    res_sum = await get_reports_summary(db=mock_db)
    print(f"\n1. GET /api/reports/summary -> status: {res_sum.get('status')}", flush=True)
    assert res_sum.get("status") == "success"
    data_sum = res_sum.get("data", {})
    print(f"   - Total Threats Analyzed: {data_sum.get('total_threats')}")
    print(f"   - Contained IPs Count: {data_sum.get('contained_ips_count')}")
    print(f"   - Critical/High Ratio: {data_sum.get('critical_high_ratio')}")
    print(f"   - Active Investigations: {data_sum.get('active_investigations')}")
    assert data_sum.get("total_threats") > 0

    # 2. Test GET /api/reports/audit-logs
    res_logs = await get_reports_audit_logs(limit=20, db=mock_db)
    print(f"\n2. GET /api/reports/audit-logs -> status: {res_logs.get('status')}", flush=True)
    assert res_logs.get("status") == "success"
    logs = res_logs.get("data", [])
    print(f"   Fetched {len(logs)} live audit log records.", flush=True)
    if logs:
        sample = logs[0]
        print(f"   Sample Record: [{sample.get('timestamp')}] {sample.get('source_ip')} | {sample.get('action_executed')} | Badge: {sample.get('status_badge')}")

    # 3. Test GET /api/reports/export/csv
    res_csv = await export_csv_incident_logs(db=mock_db)
    print(f"\n3. GET /api/reports/export/csv -> Media Type: {res_csv.media_type}", flush=True)
    assert res_csv.media_type == "text/csv"
    assert "Alert_ID,Timestamp_UTC,Source_IP" in res_csv.body.decode("utf-8")

    # 4. Test GET /api/reports/export/json
    res_json = await export_json_telemetry(db=mock_db)
    print(f"\n4. GET /api/reports/export/json -> Media Type: {res_json.media_type}", flush=True)
    assert res_json.media_type == "application/json"
    assert "NetShield-AI Executive SOC Threat Intelligence" in res_json.body.decode("utf-8")

    # 5. Test GET /api/reports/export/pdf
    res_pdf = await export_pdf_summary(db=mock_db)
    print(f"\n5. GET /api/reports/export/pdf -> Media Type: {res_pdf.media_type}", flush=True)
    assert res_pdf.media_type == "text/plain"
    assert "NETSHIELD-AI EXECUTIVE SOC THREAT INTELLIGENCE REPORT" in res_pdf.body.decode("utf-8")

    print("\n[SUCCESS] Milestone 3 Reports & Export Suite PASSED!\n", flush=True)

if __name__ == "__main__":
    asyncio.run(run_tests())
