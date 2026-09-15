import sys
import os
import asyncio

sys.path.insert(0, os.path.abspath(os.path.dirname(__file__)))
if hasattr(sys.stdout, 'reconfigure'):
    sys.stdout.reconfigure(encoding='utf-8')

from app.database import AsyncSessionLocal, engine, Base
from app.routers.pcap_router import (
    evaluate_packet_threat_py,
    create_captured_packet,
    get_captured_packets,
    CreatePacketRequest
)

class DummyRequest:
    def __init__(self, headers=None):
        self.headers = headers or {}
        self.method = "GET"

async def test_threat_evaluation():
    print("==========================================================================")
    print(" Testing Dynamic Threat Classification Rule Engine & Persistence")
    print("==========================================================================")

    async with engine.begin() as conn:
        await conn.run_sync(Base.metadata.create_all)

    # 1. Direct Python Evaluation Unit Tests
    print("\n--- 1. Testing evaluate_packet_threat_py Rule Engine ---")

    # Scenarios for Malicious
    m1 = evaluate_packet_threat_py("192.168.1.50", "10.0.0.12", "TCP", 5000)
    print(f"Oversized (5000B): score={m1['threat_score']}, type={m1['packet_type']}, flag={m1['flag_status']}")
    assert m1['threat_score'] >= 0.75
    assert m1['packet_type'] == "Malicious"
    assert m1['flag_status'] == "FLAGGED"

    m2 = evaluate_packet_threat_py("134.87.2.1", "10.0.0.12", "TCP", 512)
    print(f"Known Malicious IP (134.87.2.1): score={m2['threat_score']}, type={m2['packet_type']}, flag={m2['flag_status']}")
    assert m2['threat_score'] >= 0.75
    assert m2['packet_type'] == "Malicious"
    assert m2['flag_status'] == "FLAGGED"

    m3 = evaluate_packet_threat_py("192.168.1.150", "10.0.0.12", "TCP", 1200)
    print(f"High byte IP (192.168.1.150, 1200B): score={m3['threat_score']}, type={m3['packet_type']}, flag={m3['flag_status']}")
    assert m3['threat_score'] >= 0.75
    assert m3['packet_type'] == "Malicious"
    assert m3['flag_status'] == "FLAGGED"

    m4 = evaluate_packet_threat_py("192.168.1.50", "10.0.0.12", "ICMP", 1500)
    print(f"Anomalous ICMP (1500B): score={m4['threat_score']}, type={m4['packet_type']}, flag={m4['flag_status']}")
    assert m4['threat_score'] >= 0.75
    assert m4['packet_type'] == "Malicious"
    assert m4['flag_status'] == "FLAGGED"

    # Scenarios for Medium Risk
    med1 = evaluate_packet_threat_py("192.168.1.50", "10.0.0.12", "TCP", 2000)
    print(f"Moderate size (2000B): score={med1['threat_score']}, type={med1['packet_type']}, flag={med1['flag_status']}")
    assert 0.40 <= med1['threat_score'] <= 0.74
    assert med1['packet_type'] == "Medium Risk"
    assert med1['flag_status'] == "MONITORED"

    med2 = evaluate_packet_threat_py("10.0.4.52", "10.0.0.12", "TCP", 512)
    print(f"Suspicious IP (10.0.4.52): score={med2['threat_score']}, type={med2['packet_type']}, flag={med2['flag_status']}")
    assert 0.40 <= med2['threat_score'] <= 0.74
    assert med2['packet_type'] == "Medium Risk"
    assert med2['flag_status'] == "MONITORED"

    med3 = evaluate_packet_threat_py("192.168.1.50", "10.0.0.12", "DNS", 600)
    print(f"Large DNS (600B): score={med3['threat_score']}, type={med3['packet_type']}, flag={med3['flag_status']}")
    assert 0.40 <= med3['threat_score'] <= 0.74
    assert med3['packet_type'] == "Medium Risk"
    assert med3['flag_status'] == "MONITORED"

    # Scenarios for Safe
    s1 = evaluate_packet_threat_py("192.168.1.50", "10.0.0.12", "TCP", 512)
    print(f"Normal local (512B): score={s1['threat_score']}, type={s1['packet_type']}, flag={s1['flag_status']}")
    assert s1['threat_score'] < 0.40
    assert s1['packet_type'] == "Safe"
    assert s1['flag_status'] == "SAFE"

    print("\n[SUCCESS] Direct rule engine evaluation tests PASSED!")

    # 2. Database API Integration Tests
    print("\n--- 2. Testing POST & GET /api/packets API Integration ---")
    async with AsyncSessionLocal() as db:
        user_email = "security@gmail.com"
        dummy_req = DummyRequest(headers={"X-User-Email": user_email})

        # POST Malicious packet
        post_m = await create_captured_packet(
            req=CreatePacketRequest(
                source_ip="134.87.55.10",
                dest_ip="10.0.0.12",
                protocol="TCP",
                packet_size=512
            ),
            request=dummy_req,
            x_user_email=user_email,
            db=db
        )
        assert post_m['packet']['packet_type'] == "Malicious"
        assert post_m['packet']['flag_status'] == "FLAGGED"
        assert post_m['packet']['threat_score'] >= 0.75
        print(f"POST Malicious Packet ID={post_m['id']} -> type={post_m['packet']['packet_type']}, flag={post_m['packet']['flag_status']}, score={post_m['packet']['threat_score']}")

        # POST Medium Risk packet
        post_med = await create_captured_packet(
            req=CreatePacketRequest(
                source_ip="192.168.1.50",
                dest_ip="10.0.0.12",
                protocol="UDP",
                packet_size=1500
            ),
            request=dummy_req,
            x_user_email=user_email,
            db=db
        )
        assert post_med['packet']['packet_type'] == "Medium Risk"
        assert post_med['packet']['flag_status'] == "MONITORED"
        assert 0.40 <= post_med['packet']['threat_score'] <= 0.74
        print(f"POST Medium Risk Packet ID={post_med['id']} -> type={post_med['packet']['packet_type']}, flag={post_med['packet']['flag_status']}, score={post_med['packet']['threat_score']}")

        # POST Safe packet
        post_safe = await create_captured_packet(
            req=CreatePacketRequest(
                source_ip="192.168.1.50",
                dest_ip="10.0.0.12",
                protocol="TCP",
                packet_size=256
            ),
            request=dummy_req,
            x_user_email=user_email,
            db=db
        )
        assert post_safe['packet']['packet_type'] == "Safe"
        assert post_safe['packet']['flag_status'] == "SAFE"
        assert post_safe['packet']['threat_score'] < 0.40
        print(f"POST Safe Packet ID={post_safe['id']} -> type={post_safe['packet']['packet_type']}, flag={post_safe['packet']['flag_status']}, score={post_safe['packet']['threat_score']}")

        # GET /api/packets verification
        get_res = await get_captured_packets(request=dummy_req, x_user_email=user_email, db=db)
        print(f"GET /api/packets fetched {get_res['count']} packets")
        assert get_res['status'] == "success"

        pkts = get_res['packets']
        m_fetched = next((p for p in pkts if p['id'] == post_m['id']), None)
        med_fetched = next((p for p in pkts if p['id'] == post_med['id']), None)
        s_fetched = next((p for p in pkts if p['id'] == post_safe['id']), None)

        assert m_fetched is not None and m_fetched['packet_type'] == "Malicious" and m_fetched['flag_status'] == "FLAGGED"
        assert med_fetched is not None and med_fetched['packet_type'] == "Medium Risk" and med_fetched['flag_status'] == "MONITORED"
        assert s_fetched is not None and s_fetched['packet_type'] == "Safe" and s_fetched['flag_status'] == "SAFE"

        print("\n[SUCCESS] All API integration & database persistence tests PASSED!\n")

if __name__ == "__main__":
    asyncio.run(test_threat_evaluation())
