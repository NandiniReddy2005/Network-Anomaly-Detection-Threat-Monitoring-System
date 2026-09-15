import asyncio
import sys
import os

# Add backend directory to sys.path
sys.path.insert(0, os.path.abspath(os.path.dirname(__file__)))

from app.database import AsyncSessionLocal
from app.routers.incidents import fetch_incidents_with_action_history, analyze_and_add_incident

async def main():
    print("=================================================================")
    print("  TESTING PROTOCOL SELECTION (TCP/UDP/ICMP/HTTP) & PERSISTENCE  ")
    print("=================================================================")

    async with AsyncSessionLocal() as db:
        # 1. Fetch current queue
        print("\n1. Fetching initial incident queue...")
        queue = await fetch_incidents_with_action_history(db)
        print(f"  [PASS] Retrieved {len(queue)} incidents from queue!")
        for inc in queue:
            print(f"    - ID: {inc['alert_id']} | Protocol: {inc.get('protocol')} | Severity: {inc['severity']} | Source: {inc['source_ip']}")

        # 2. Add threat with UDP protocol
        print("\n2. Adding threat alert with UDP protocol...")
        udp_res = await analyze_and_add_incident(
            payload={
                "ip_address": "198.51.100.200",
                "dataset_engine": "CICIDS2017 ML Engine",
                "protocol": "UDP",
                "user_email": "analyst_protocol@netshield.io"
            },
            db=db,
            request=None
        )
        print(f"  [PASS] Created incident ID: '{udp_res['alert_id']}' with Protocol: '{udp_res.get('protocol')}'!")

        # 3. Add threat with ICMP protocol
        print("\n3. Adding threat alert with ICMP protocol...")
        icmp_res = await analyze_and_add_incident(
            payload={
                "ip_address": "203.0.113.99",
                "dataset_engine": "UNSW-NB15 ML Engine",
                "protocol": "ICMP",
                "user_email": "analyst_protocol@netshield.io"
            },
            db=db,
            request=None
        )
        print(f"  [PASS] Created incident ID: '{icmp_res['alert_id']}' with Protocol: '{icmp_res.get('protocol')}'!")

        # 4. Verify queue items have correct protocol values
        print("\n4. Re-fetching queue from database to verify persistence...")
        updated_queue = await fetch_incidents_with_action_history(db)
        udp_found = any(i['alert_id'] == udp_res['alert_id'] and i.get('protocol') == 'UDP' for i in updated_queue)
        icmp_found = any(i['alert_id'] == icmp_res['alert_id'] and i.get('protocol') == 'ICMP' for i in updated_queue)

        assert udp_found, "UDP incident protocol not found in DB!"
        assert icmp_found, "ICMP incident protocol not found in DB!"

        print("  [PASS] Verified UDP and ICMP persistence in PostgreSQL database!")

    print("\n=================================================================")
    print("  ALL PROTOCOL SELECTION & ANALYTICS TESTS PASSED SUCCESSFULLY! ")
    print("=================================================================")

if __name__ == "__main__":
    asyncio.run(main())
