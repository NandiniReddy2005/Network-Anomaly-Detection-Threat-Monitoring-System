import sys
import os
import asyncio
import json
from pathlib import Path

backend_dir = Path(__file__).resolve().parent
if str(backend_dir) not in sys.path:
    sys.path.insert(0, str(backend_dir))

from app.database import AsyncSessionLocal, engine, Base
from app.routers.reports import export_json_telemetry
from app.models import CriticalAlert, CriticalAlertAction

async def run_tests():
    print("=" * 70, flush=True)
    print("NETSHIELD-AI DETAILED FORENSIC LOG EXPORT TEST", flush=True)
    print("=" * 70, flush=True)

    async with engine.begin() as conn:
        await conn.run_sync(Base.metadata.create_all)

    async with AsyncSessionLocal() as db:
        res = await export_json_telemetry(db=db, x_user_email="soc_analyst_lead@netshield.ai")
        assert res.status_code == 200, f"Expected status code 200, got {res.status_code}"
        
        payload = json.loads(res.body.decode("utf-8"))
        print("\nJSON Response Payload Keys:", list(payload.keys()), flush=True)
        assert payload.get("status") == "success"
        assert "critical_security_alerts" in payload
        
        crit_alerts = payload["critical_security_alerts"]
        print(f"  [PASS] Successfully retrieved {len(crit_alerts)} detailed critical alert forensic records!", flush=True)
        assert len(crit_alerts) > 0, "Expected at least 1 critical alert in forensic export"
        
        first = crit_alerts[0]
        print("\nFirst Alert Forensic Record Sample:", flush=True)
        print(json.dumps(first, indent=2), flush=True)
        
        # Validate detailed forensic payload schema & mandatory telemetry fields
        assert "alert_id" in first, "Missing alert_id"
        assert "timestamp" in first, "Missing timestamp"
        assert "severity" in first, "Missing severity"
        assert "telemetry" in first, "Missing telemetry"
        assert "source_ip" in first["telemetry"], "Missing source_ip in telemetry"
        assert "destination_ip" in first["telemetry"], "Missing destination_ip in telemetry"
        assert "mitre_attack_framework" in first, "Missing mitre_attack_framework"
        assert "mitre_tag" in first["mitre_attack_framework"], "Missing mitre_tag"
        assert "containment_playbook" in first, "Missing containment_playbook"
        assert "action_recommended" in first["containment_playbook"], "Missing action_recommended"
        
        print("\n" + "=" * 70, flush=True)
        print("ALL DETAILED FORENSIC LOG EXPORT TESTS PASSED 100%!", flush=True)
        print("=" * 70, flush=True)

if __name__ == "__main__":
    asyncio.run(run_tests())
