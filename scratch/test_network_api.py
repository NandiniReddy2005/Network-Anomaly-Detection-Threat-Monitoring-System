import asyncio
import sys
import os

sys.path.insert(0, os.path.join(os.getcwd(), "backend"))

from app.database import AsyncSessionLocal
from app.routers.network_router import NetworkAnalyzeRequest, run_packet_analysis

async def main():
    async with AsyncSessionLocal() as session:
        # Test 1: UNSW-NB15 on clean target (10.0.9.47) -> Expected: SAFE (Green)
        req1 = NetworkAnalyzeRequest(destination_ip="10.0.9.47", dataset="UNSW-NB15", source_ip="192.168.1.50")
        res1 = await run_packet_analysis(payload=req1, db=session)
        print("=== TEST 1: UNSW-NB15 on Clean IP (10.0.9.47) ===")
        print("is_safe:", res1["is_safe"], "| status:", res1["safety_status"])
        print("reason:", res1["analysis_reason"])

        # Test 2: CICIDS2017 on clean target (10.0.9.47) -> Expected: SAFE (Green)
        req2 = NetworkAnalyzeRequest(destination_ip="10.0.9.47", dataset="CICIDS2017", source_ip="192.168.1.50")
        res2 = await run_packet_analysis(payload=req2, db=session)
        print("\n=== TEST 2: CICIDS2017 on Clean IP (10.0.9.47) ===")
        print("is_safe:", res2["is_safe"], "| status:", res2["safety_status"])
        print("reason:", res2["analysis_reason"])

        # Test 3: UNSW-NB15 on Threat Suffix (.200) -> Expected: UNSAFE (Red)
        req3 = NetworkAnalyzeRequest(destination_ip="10.0.9.200", dataset="UNSW-NB15", source_ip="192.168.1.50")
        res3 = await run_packet_analysis(payload=req3, db=session)
        print("\n=== TEST 3: UNSW-NB15 on Threat IP (.200) ===")
        print("is_safe:", res3["is_safe"], "| status:", res3["safety_status"])
        print("reason:", res3["analysis_reason"])

        # Test 4: CICIDS2017 on Threat Suffix (.150) -> Expected: UNSAFE (Red)
        req4 = NetworkAnalyzeRequest(destination_ip="192.168.1.150", dataset="CICIDS2017", source_ip="192.168.1.50")
        res4 = await run_packet_analysis(payload=req4, db=session)
        print("\n=== TEST 4: CICIDS2017 on Threat IP (.150) ===")
        print("is_safe:", res4["is_safe"], "| status:", res4["safety_status"])
        print("reason:", res4["analysis_reason"])

if __name__ == "__main__":
    asyncio.run(main())
