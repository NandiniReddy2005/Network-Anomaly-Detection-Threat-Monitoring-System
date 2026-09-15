import sys
import os
import asyncio
from pathlib import Path

backend_dir = Path(__file__).resolve().parent
if str(backend_dir) not in sys.path:
    sys.path.insert(0, str(backend_dir))

from app.database import AsyncSessionLocal, engine, Base
from app.routers.dashboard import analyze_critical_alert, get_critical_alerts_list, execute_critical_alert_action, AlertAnalyzePayload, AlertActionPayload
from app.models import CriticalAlert, CriticalAlertAction

async def run_tests():
    print("=" * 70, flush=True)
    print("NETSHIELD-AI CRITICAL ALERTS POSTGRESQL PERSISTENCE & TRIAGE TEST", flush=True)
    print("=" * 70, flush=True)

    # 1. Create tables
    async with engine.begin() as conn:
        await conn.run_sync(Base.metadata.create_all)

    async with AsyncSessionLocal() as db:
        # 1. Fetch initial critical alerts
        print("\n1. Testing get_critical_alerts_list (Initial PostgreSQL Load)...", flush=True)
        res1 = await get_critical_alerts_list(db=db, x_user_email="soc_analyst_lead@netshield.ai")
        assert res1["status"] == "success"
        alerts1 = res1.get("alerts", [])
        print(f"  [PASS] Successfully retrieved {len(alerts1)} critical alerts from PostgreSQL!", flush=True)
        for a in alerts1[:2]:
            print(f"    - [{a['id']}] {a['title']} | Severity: {a['severity']} | Status: {a['status']}", flush=True)

        # 2. Submit new ML Incident Risk Analysis
        print("\n2. Submitting dynamic incident risk analysis via analyze_critical_alert...", flush=True)
        payload_ml = AlertAnalyzePayload(
            dataset="UNSW-NB15",
            source_ip="185.220.101.99",
            destination_ip="10.0.0.2 (Auth Server)",
            source_port=58210,
            destination_port=443,
            protocol="TCP"
        )
        try:
            res_analyze = await analyze_critical_alert(payload=payload_ml, db=db, x_user_email="soc_analyst_lead@netshield.ai")
            print(f"  [DEBUG] res_analyze: {res_analyze}", flush=True)
            assert res_analyze["status"] == "success"
        except Exception as ex:
            print(f"  [ERROR] analyze_critical_alert exception: {ex}", flush=True)
            raise ex
        alert_info = res_analyze.get("data", {})
        created_id = alert_info.get("alert_id") or alert_info.get("id")
        assert created_id is not None
        assert created_id.startswith("ALT-")
        print(f"  [PASS] ML incident risk analysis generated & persisted into PostgreSQL: {created_id}", flush=True)
        print(f"         Attack Type: {alert_info.get('attack_type')} | Risk Score: {alert_info.get('composite_risk_score')}", flush=True)

        # 3. Perform Triage Action: Execute Containment Playbook
        print(f"\n3. Executing Containment Playbook on alert {created_id}...", flush=True)
        action_contain = AlertActionPayload(
            alert_id=created_id,
            action_type="EXECUTE_CONTAINMENT",
            notes="Enforced automated host isolation playbook on core auth node.",
            actor="soc_analyst_lead@netshield.ai"
        )
        res_contain = await execute_critical_alert_action(payload=action_contain, db=db, x_user_email="soc_analyst_lead@netshield.ai")
        assert res_contain["status"] == "success"
        assert res_contain["new_status"] == "Mitigated"
        print(f"  [PASS] Containment action logged in PostgreSQL! Status updated: {res_contain['old_status']} -> {res_contain['new_status']}", flush=True)

        # 4. Perform Triage Action: Resolve Alert
        print(f"\n4. Resolving alert {created_id}...", flush=True)
        action_resolve = AlertActionPayload(
            alert_id=created_id,
            action_type="RESOLVE_ALERT",
            notes="Incident triaged and cleared by SOC lead.",
            actor="soc_analyst_lead@netshield.ai"
        )
        res_resolve = await execute_critical_alert_action(payload=action_resolve, db=db, x_user_email="soc_analyst_lead@netshield.ai")
        assert res_resolve["status"] == "success"
        assert res_resolve["new_status"] == "Resolved"
        print(f"  [PASS] Alert resolution logged in PostgreSQL! Status updated to: {res_resolve['new_status']}", flush=True)

        # 5. Simulate User Logout & Re-login Restoration
        print("\n5. Simulating Analyst Re-login & Session State Restoration...", flush=True)
        res_refetch = await get_critical_alerts_list(db=db, x_user_email="new_login_analyst@netshield.ai")
        assert res_refetch["status"] == "success"
        refetched_alerts = res_refetch.get("alerts", [])
        
        target_alert = next((a for a in refetched_alerts if a["id"] == created_id), None)
        assert target_alert is not None, f"Alert {created_id} must persist in PostgreSQL across user sessions"
        assert target_alert["status"] == "Resolved", f"Expected status 'Resolved', got '{target_alert['status']}'"
        print(f"  [PASS] Re-login restoration verified! Alert {created_id} restored with state '{target_alert['status']}'", flush=True)

    print("\n" + "=" * 70, flush=True)
    print("ALL CRITICAL ALERTS POSTGRESQL PERSISTENCE TESTS PASSED 100%!", flush=True)
    print("=" * 70, flush=True)

if __name__ == "__main__":
    asyncio.run(run_tests())
