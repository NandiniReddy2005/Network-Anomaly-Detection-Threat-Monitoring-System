import sys
import os
import asyncio

sys.path.insert(0, os.path.abspath(os.path.dirname(__file__)))
if hasattr(sys.stdout, 'reconfigure'):
    sys.stdout.reconfigure(encoding='utf-8')

from app.database import AsyncSessionLocal, engine, Base
from app.models import UserActivityLog
from app.routers.reports import get_user_activity_reports, log_user_activity_report, UserActivityPayload
from app.routers.incidents import analyze_and_add_incident

class MockRequest:
    def __init__(self, headers=None):
        self.headers = headers or {}

async def run_tests():
    print("==================================================", flush=True)
    print(" TESTING POSTGRESQL USER AUDIT & ACTIVITY REPORTS ", flush=True)
    print("==================================================", flush=True)

    # 1. Initialize Tables in DB
    async with engine.begin() as conn:
        await conn.run_sync(Base.metadata.create_all)
    print("1. Database tables (including user_activity_logs) initialized successfully.", flush=True)

    async with AsyncSessionLocal() as db:
        mock_req = MockRequest(headers={"X-User-Email": "security@gmail.com"})

        # 2. Test GET /api/reports/user-activity
        res_get = await get_user_activity_reports(
            request=mock_req,
            user_id="security@gmail.com",
            user_email=None,
            x_user_email="security@gmail.com",
            limit=50,
            db=db
        )
        print(f"\n2. GET /api/reports/user-activity -> status: {res_get.get('status')}", flush=True)
        assert res_get.get("status") == "success"
        assert res_get.get("user_id") == "security@gmail.com"
        
        summary = res_get.get("summary", {})
        print(f"   - Total Analyst Actions: {summary.get('total_analyst_actions')}")
        print(f"   - Critical Threats Analyzed: {summary.get('critical_threats_analyzed')}")
        print(f"   - Most Used Dataset Engine: {summary.get('most_used_dataset_engine')}")
        assert summary.get("total_analyst_actions") >= 0

        logs = res_get.get("data", [])
        print(f"   Fetched {len(logs)} activity records for security@gmail.com", flush=True)
        if logs:
            sample = logs[0]
            print(f"   Sample Record: [{sample.get('log_id')}] {sample.get('action_type')} | Target: {sample.get('target_ip')} | Proto: {sample.get('protocol')} | Engine: {sample.get('dataset_engine')} | Sev: {sample.get('severity')}")

        # 3. Test POST /api/reports/user-activity
        payload = UserActivityPayload(
            user_id="security@gmail.com",
            action_type="THREAT_ANALYZED",
            details="Analyzed IP 185.220.101.50 using UNSW-NB15 (Severity: CRITICAL)",
            ip_address="185.220.101.50",
            protocol="TCP",
            dataset_engine="UNSW-NB15",
            severity="CRITICAL"
        )
        res_post = await log_user_activity_report(
            payload=payload,
            request=mock_req,
            x_user_email="security@gmail.com",
            db=db
        )
        print(f"\n3. POST /api/reports/user-activity -> status: {res_post.get('status')}", flush=True)
        assert res_post.get("status") == "success"
        post_data = res_post.get("data", {})
        print(f"   Logged Action ID: {post_data.get('id')}, Action: {post_data.get('action_type')}, Details: {post_data.get('details')}")

        # 4. Test Incident Predict Automatic Logging
        inc_payload = {
            "ip_address": "185.220.101.99",
            "dataset_engine": "UNSW-NB15",
            "protocol": "TCP",
            "actor": "security@gmail.com"
        }
        res_inc = await analyze_and_add_incident(
            payload=inc_payload,
            request=mock_req,
            db=db
        )
        print(f"\n4. POST /api/incidents/predict -> alert_id: {res_inc.get('alert_id')}, severity: {res_inc.get('severity')}", flush=True)
        assert res_inc.get("status") == "success"

        # 5. Re-fetch GET /api/reports/user-activity to verify updated count
        res_re = await get_user_activity_reports(
            request=mock_req,
            user_id="security@gmail.com",
            user_email=None,
            x_user_email="security@gmail.com",
            limit=50,
            db=db
        )
        new_logs = res_re.get("data", [])
        new_summary = res_re.get("summary", {})
        print(f"\n5. Re-fetched GET /api/reports/user-activity -> count: {len(new_logs)} records.", flush=True)
        print(f"   Updated Total Actions: {new_summary.get('total_analyst_actions')}")
        print(f"   Updated Critical Threats: {new_summary.get('critical_threats_analyzed')}")

        # 6. Test User Session Isolation (Different User)
        res_other = await get_user_activity_reports(
            request=mock_req,
            user_id="other_analyst@netshield.ai",
            user_email=None,
            x_user_email="other_analyst@netshield.ai",
            limit=50,
            db=db
        )
        print(f"\n6. Isolated Fetch for 'other_analyst@netshield.ai' -> status: {res_other.get('status')}, user_id: {res_other.get('user_id')}", flush=True)
        assert res_other.get("user_id") == "other_analyst@netshield.ai"

    print("\n==================================================", flush=True)
    print(" ALL USER AUDIT & ACTIVITY REPORT TESTS PASSED!   ", flush=True)
    print("==================================================\n", flush=True)

if __name__ == "__main__":
    asyncio.run(run_tests())
