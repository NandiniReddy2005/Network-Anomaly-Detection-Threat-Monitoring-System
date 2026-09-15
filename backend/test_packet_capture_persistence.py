import sys
import os
import asyncio

sys.path.insert(0, os.path.abspath(os.path.dirname(__file__)))
if hasattr(sys.stdout, 'reconfigure'):
    sys.stdout.reconfigure(encoding='utf-8')

from sqlalchemy import select
from app.database import AsyncSessionLocal, engine, Base
from app.models import CapturedPacket
from app.routers.pcap_router import (
    get_captured_packets,
    create_captured_packet,
    CreatePacketRequest
)

class DummyRequest:
    def __init__(self, headers=None):
        self.headers = headers or {}
        self.method = "GET"

async def run_packet_persistence_tests():
    print("==========================================================================")
    print(" Testing PostgreSQL /api/packets Persistence & Retrieval")
    print("==========================================================================")

    async with engine.begin() as conn:
        await conn.run_sync(Base.metadata.create_all)

    async with AsyncSessionLocal() as db:
        test_user = "security@gmail.com"
        dummy_req = DummyRequest(headers={"X-User-Email": test_user})

        # 1. Create a packet via POST /api/packets
        print(f"\n1. Testing POST /api/packets for '{test_user}'...")
        req_payload = CreatePacketRequest(
            source_ip="192.168.1.150",
            dest_ip="10.0.0.88",
            protocol="TCP",
            packet_size=1024,
            flag_status="Monitored",
            packet_type="Medium Risk",
            timestamp="2026-08-27 12:05:00 UTC"
        )

        res_post = await create_captured_packet(
            req=req_payload,
            request=dummy_req,
            x_user_email=test_user,
            db=db
        )

        print(f"   Response Status: {res_post.get('status')}")
        print(f"   Created DB ID: {res_post.get('id')}")
        print(f"   Packet Object: {res_post.get('packet')}")
        assert res_post.get("status") == "success"
        assert res_post.get("id") is not None

        created_id = res_post.get("id")

        # 2. Retrieve packets via GET /api/packets
        print(f"\n2. Testing GET /api/packets...")
        res_get = await get_captured_packets(
            request=dummy_req,
            x_user_email=test_user,
            db=db
        )

        print(f"   Response Status: {res_get.get('status')}")
        print(f"   Total Packets Fetched: {res_get.get('count')}")
        assert res_get.get("status") == "success"
        assert res_get.get("count") >= 1

        packets = res_get.get("packets", [])
        found_packet = next((p for p in packets if p.get("id") == created_id), None)
        assert found_packet is not None, f"Packet ID {created_id} should exist in GET /api/packets output"
        
        print(f"   Fetched Packet Match: ID={found_packet['id']}, Source={found_packet['source_ip']}, Dest={found_packet['dest_ip']}, Size={found_packet['packet_size']}, Type={found_packet['packet_type']}")
        
        print("\n[SUCCESS] /api/packets Persistence & Retrieval tests PASSED cleanly!\n")

if __name__ == "__main__":
    asyncio.run(run_packet_persistence_tests())
