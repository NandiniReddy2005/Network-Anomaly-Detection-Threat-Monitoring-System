import sys
import os
import asyncio

sys.path.insert(0, os.path.abspath(os.path.dirname(__file__)))
if hasattr(sys.stdout, 'reconfigure'):
    sys.stdout.reconfigure(encoding='utf-8')

from sqlalchemy import select
from app.database import AsyncSessionLocal, engine, Base
from app.models import PcapSession, PcapPacket, Incident
from app.routers.pcap_router import (
    get_pcap_history,
    get_pcap_session_details,
    upload_pcap_capture,
    escalate_pcap_incident,
    get_analyst_packet_capture_persistence,
    PcapUploadPayload,
    EscalateIncidentRequest
)
from fastapi import Request

class DummyRequest:
    def __init__(self, headers=None):
        self.headers = headers or {}
        self.method = "GET"

async def run_pcap_tests():
    print("==========================================================================")
    print(" Testing PostgreSQL PCAP Session Persistence & Incident Queue Escalation")
    print("==========================================================================")

    # 1. Ensure table creation
    async with engine.begin() as conn:
        await conn.run_sync(Base.metadata.create_all)

    async with AsyncSessionLocal() as db:
        test_user = "security@gmail.com"
        dummy_req = DummyRequest(headers={"X-User-Email": test_user})

        # 2. Test GET /api/analyst/packet-capture (auto-seeds session if empty)
        print(f"\n1. GET /api/analyst/packet-capture for '{test_user}'...")
        res1 = await get_analyst_packet_capture_persistence(
            request=dummy_req,
            x_user_email=test_user,
            db=db
        )
        print(f"   Status: {res1.get('status')}")
        print(f"   Active Session: {res1.get('active_session')}")
        print(f"   Packets Retrieved: {len(res1.get('packets', []))}")
        print(f"   Protocol Hierarchy: {res1.get('protocol_hierarchy', {}).get('hierarchy', [])}")
        assert res1.get("status") == "success"
        assert len(res1.get("packets", [])) > 0
        assert "protocol_hierarchy" in res1

        # 3. Test GET /api/pcap/history
        print(f"\n2. GET /api/pcap/history for '{test_user}'...")
        res_hist = await get_pcap_history(request=dummy_req, x_user_email=test_user, db=db)
        print(f"   Status: {res_hist.get('status')}")
        print(f"   Total Sessions: {res_hist.get('total_sessions')}")
        assert res_hist.get("status") == "success"
        assert res_hist.get("total_sessions") >= 1
        session_id = res_hist.get("sessions")[0]["id"]

        # 4. Test GET /api/pcap/session/{id}
        print(f"\n3. GET /api/pcap/session/{session_id} details...")
        res_det = await get_pcap_session_details(
            session_id=session_id,
            request=dummy_req,
            x_user_email=test_user,
            db=db
        )
        print(f"   Status: {res_det.get('status')}")
        print(f"   Session File: {res_det.get('session', {}).get('file_name')}")
        print(f"   Packets in Session: {len(res_det.get('packets', []))}")
        first_pkt = res_det.get("packets", [])[0]
        print(f"   Sample Hex Dump:\n{first_pkt.get('hex_dump')[:100]}...")
        print(f"   Sample ASCII Payload: {first_pkt.get('ascii_payload')[:60]}")
        assert res_det.get("status") == "success"
        assert len(res_det.get("packets", [])) > 0
        assert "hex_dump" in first_pkt
        assert "ascii_payload" in first_pkt

        # 5. Test POST /api/pcap/upload
        print(f"\n4. POST /api/pcap/upload new session for '{test_user}'...")
        upload_payload = PcapUploadPayload(
            file_name="forensic_inspection_test.pcap",
            user_id=test_user,
            packets=[
                {"packet_number": 1, "timestamp": "14:25:00.111", "source_ip": "185.220.101.99", "destination_ip": "10.0.9.47", "protocol": "TCP", "length": 1420, "info": "RST Anomalous Spike"},
                {"packet_number": 2, "timestamp": "14:25:00.222", "source_ip": "192.168.1.105", "destination_ip": "8.8.8.8", "protocol": "DNS", "length": 128, "info": "DNS Query"},
            ]
        )
        res_upload = await upload_pcap_capture(
            request=dummy_req,
            json_payload=upload_payload,
            x_user_email=test_user,
            db=db
        )
        print(f"   Status: {res_upload.get('status')}")
        print(f"   Created Session ID: {res_upload.get('session_id')}")
        print(f"   Flagged Threats Auto-Pushed: {res_upload.get('flagged_threats_count')}")
        assert res_upload.get("status") == "success"

        # 6. Test Escalate Incident
        print(f"\n5. POST /api/pcap/escalate-incident...")
        esc_req = EscalateIncidentRequest(
            source_ip="185.220.101.99",
            destination_ip="10.0.9.47",
            protocol="TCP",
            info="Volumetric SYN Flood Escalate Test",
            threat_score=95,
            notes="Manually escalated during forensic verification"
        )
        res_esc = await escalate_pcap_incident(req=esc_req, request=dummy_req, x_user_email=test_user, db=db)
        print(f"   Status: {res_esc.get('status')}")
        print(f"   Created Incident ID: {res_esc.get('incident_id')} | Severity: {res_esc.get('severity')}")
        assert res_esc.get("status") == "success"

        # Verify incident exists in PostgreSQL incidents table
        inc_check = await db.execute(select(Incident).where(Incident.id == res_esc.get('incident_id')))
        inc_obj = inc_check.scalars().first()
        assert inc_obj is not None
        assert inc_obj.created_by_user == test_user
        print(f"   [DB Verified] Incident '{inc_obj.id}' stored in PostgreSQL for user '{inc_obj.created_by_user}'.")

        # 7. Test User Session Isolation (where user_id = req.user.email)
        isolated_user = "isolated_analyst_777@netshield.io"
        dummy_iso_req = DummyRequest(headers={"X-User-Email": isolated_user})
        print(f"\n6. User Session Isolation test for '{isolated_user}'...")
        res_iso_hist = await get_pcap_history(request=dummy_iso_req, x_user_email=isolated_user, db=db)
        print(f"   Status: {res_iso_hist.get('status')}")
        print(f"   Total Sessions for new isolated user: {res_iso_hist.get('total_sessions')}")
        assert res_iso_hist.get("total_sessions") == 0
        print(f"   [Isolation Verified] User '{isolated_user}' cannot see session data of '{test_user}'.")

        print("\n[SUCCESS] All PostgreSQL PCAP Persistence & Session Management tests PASSED!\n")

if __name__ == "__main__":
    asyncio.run(run_pcap_tests())
