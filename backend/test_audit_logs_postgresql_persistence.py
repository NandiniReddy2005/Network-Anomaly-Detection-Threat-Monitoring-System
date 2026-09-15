import sys
import os
import asyncio

sys.path.insert(0, os.path.abspath(os.path.dirname(__file__)))
if hasattr(sys.stdout, 'reconfigure'):
    sys.stdout.reconfigure(encoding='utf-8')

from app.database import AsyncSessionLocal
from app.routers.dashboard import get_audit_logs, create_audit_log_endpoint, AuditLogCreateRequest
from app.services.audit import log_audit_event

async def run_verification():
    print("==========================================================")
    print(" Testing Audit Logs PostgreSQL Persistence & Real-Time Stream")
    print("==========================================================")

    async with AsyncSessionLocal() as db:
        # 1. Fetch initial audit logs from PostgreSQL DB
        print("\n1. Fetching initial Audit Logs from PostgreSQL DB...")
        res1 = await get_audit_logs(limit=None, db=db)
        print(f"   Response Status: {res1.get('status')}")
        assert res1.get("status") == "success"

        logs1 = res1.get("logs", [])
        metrics1 = res1.get("metrics", {})
        roster1 = res1.get("user_roster", {})
        initial_count = res1.get("total_count", len(logs1))

        print(f"   Initial Total Audit Entries in DB: {initial_count}")
        print(f"   User Roster: Total Accounts={roster1.get('total_users')}, Security Admins={roster1.get('security_admins')}, Security Analysts={roster1.get('security_analysts')}")
        print(f"   Metrics: Successful: {metrics1.get('successful_actions')}, Failed: {metrics1.get('failed_actions')}, Admin: {metrics1.get('admin_actions')}, Security: {metrics1.get('security_events')}, High Priority: {metrics1.get('high_priority_events')}")
        assert initial_count > 0, "Expected initial seeded audit logs in PostgreSQL"
        assert roster1.get("total_users", 0) > 0, "Expected active user roster in PostgreSQL"
        assert roster1.get("security_admins", 0) > 0, "Expected Security Administrators in PostgreSQL"
        assert roster1.get("security_analysts", 0) > 0, "Expected Security Analysts in PostgreSQL"

        # 2. Simulate logging a new real-time security event into PostgreSQL
        print("\n2. Logging new real-time forensic security event into PostgreSQL...")
        new_actor = "forensic_analyst@netshield.ai"
        new_action = "Executed Full Subnet Containment Playbook"
        new_module = "Threat Management"
        new_status = "Success"
        new_severity = "High"
        new_details = "Null-routed malicious range 185.220.101.0/24 on edge gateway firewall."

        created_log = await log_audit_event(
            db=db,
            actor=new_actor,
            action=new_action,
            module=new_module,
            ip_origin="192.168.1.95",
            status=new_status,
            severity=new_severity,
            details=new_details
        )
        assert created_log is not None
        print(f"   Successfully persisted log ID {created_log.id} to PostgreSQL database!")

        # 3. Simulate API POST endpoint invocation (/api/audit-logs)
        print("\n3. Testing POST /api/audit-logs endpoint persistence...")
        req_data = AuditLogCreateRequest(
            actor="sys_admin_test@netshield.ai",
            action="Updated Dynamic Threat Threshold",
            module="WAF & Rules",
            ip_origin="192.168.1.50",
            status="Success",
            severity="Informational",
            details="Modified global threat sensitivity to High."
        )
        post_res = await create_audit_log_endpoint(req=req_data, db=db)
        assert post_res.get("status") == "success"
        print(f"   POST Endpoint returned ID: {post_res.get('log', {}).get('id')}")

        # 4. Refetch audit logs stream to verify real-time update and metrics recalculation
        print("\n4. Verifying real-time stream update from PostgreSQL...")
        res2 = await get_audit_logs(limit=None, db=db)
        logs2 = res2.get("logs", [])
        metrics2 = res2.get("metrics", {})
        updated_count = res2.get("total_count", len(logs2))

        print(f"   Updated Total Audit Entries in DB: {updated_count}")
        print(f"   Updated Metrics: Successful: {metrics2.get('successful_actions')}, Failed: {metrics2.get('failed_actions')}, Admin: {metrics2.get('admin_actions')}, Security: {metrics2.get('security_events')}, High Priority: {metrics2.get('high_priority_events')}")
        assert updated_count >= initial_count + 2

        # Verify most recent entry is at index 0 (ordered by ID desc) and has forensic table schema fields
        top_log = logs2[0]
        print(f"   Top Log in Stream: ID={top_log.get('id')} | Action={top_log.get('action')} | Actor={top_log.get('actor')} | Type={top_log.get('user_type')} | Login={top_log.get('login_time')} | Logout={top_log.get('logout_time')}")
        assert top_log.get("actor") in ["sys_admin_test@netshield.ai", "forensic_analyst@netshield.ai"]
        assert top_log.get("user_type") in ["Security Administrator", "Security Analyst"]
        assert top_log.get("login_time") is not None
        assert top_log.get("logout_time") is not None

        print("\n[SUCCESS] Audit Logs PostgreSQL Persistence & Forensic Table Stream tests PASSED!\n")

if __name__ == "__main__":
    asyncio.run(run_verification())
