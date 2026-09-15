import sys
import os
import asyncio

sys.path.insert(0, os.path.abspath(os.path.dirname(__file__)))
if hasattr(sys.stdout, 'reconfigure'):
    sys.stdout.reconfigure(encoding='utf-8')

from app.routers.workflow import escalate_monitoring_to_incident, get_workflow_audit_trail, get_soc_performance_metrics

class MockDB:
    def add(self, obj):
        pass
    async def commit(self):
        pass
    async def refresh(self, obj):
        pass

async def run_tests():
    print("==================================================", flush=True)
    print(" Testing Milestone 3 Step 5 Operational Workflow  ", flush=True)
    print("==================================================", flush=True)

    mock_db = MockDB()

    # 1. Test POST /api/workflow/escalate
    escalate_payload = {
        "source_ip": "185.220.101.42",
        "target_ip": "10.0.9.47",
        "protocol": "TCP SYN-ACK",
        "traffic_volume": "1.4 Gbps / 50,000 pps",
        "dataset": "CICIDS2017",
        "actor": "security@gmail.com"
    }
    res_esc = await escalate_monitoring_to_incident(payload=escalate_payload, db=mock_db)
    print(f"\n1. POST /api/workflow/escalate -> status: {res_esc.get('status')}", flush=True)
    assert res_esc.get("status") == "success"
    print(f"   Created Ticket ID: {res_esc.get('alert_id')} for Source IP {res_esc.get('incident', {}).get('source_ip')}")

    # 2. Test GET /api/workflow/audit-trail
    res_audit = await get_workflow_audit_trail(limit=10, db=mock_db)
    print(f"\n2. GET /api/workflow/audit-trail -> status: {res_audit.get('status')}", flush=True)
    assert res_audit.get("status") == "success"
    print(f"   Fetched {res_audit.get('count')} operational audit trail records.")

    # 3. Test GET /api/workflow/soc-performance
    res_perf = await get_soc_performance_metrics(db=mock_db)
    print(f"\n3. GET /api/workflow/soc-performance -> status: {res_perf.get('status')}", flush=True)
    assert res_perf.get("status") == "success"
    data_perf = res_perf.get("data", {})
    print(f"   MTTD: {data_perf.get('mttd_mins')} mins | MTTR: {data_perf.get('mttr_mins')} mins | Containments: {data_perf.get('active_containments')}")

    print("\n[SUCCESS] Milestone 3 Step 5 Operational Closed-Loop Workflow PASSED!\n", flush=True)

if __name__ == "__main__":
    asyncio.run(run_tests())
