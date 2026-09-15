import asyncio
import logging
import sys
from pathlib import Path

# Add backend directory to sys.path
backend_dir = Path(__file__).resolve().parent
if str(backend_dir) not in sys.path:
    sys.path.insert(0, str(backend_dir))

from app.core.config import settings
from app.services.threat_intelligence import ThreatIntelligenceService, threat_intel_service

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger("test_threat_intelligence")

async def run_tests():
    print("=" * 60)
    print("NETSHIELD-AI THREAT INTELLIGENCE & CONFIG VERIFICATION")
    print("=" * 60)

    # 1. Verify Configuration Loading
    print("\n1. Testing Centralized Configuration (app.core.config)...")
    assert settings.DATABASE_URL, "DATABASE_URL should not be empty"
    print(f"  [PASS] DATABASE_URL loaded: {settings.DATABASE_URL}")
    
    assert settings.ABUSEIPDB_API_KEY, "ABUSEIPDB_API_KEY should be present in .env"
    print(f"  [PASS] ABUSEIPDB_API_KEY loaded: {settings.ABUSEIPDB_API_KEY[:8]}... ({len(settings.ABUSEIPDB_API_KEY)} chars)")

    # 2. Testing Threat Intelligence Service Instance
    print("\n2. Testing ThreatIntelligenceService instantiation...")
    service = ThreatIntelligenceService()
    assert service.api_key == settings.ABUSEIPDB_API_KEY, "Service should read API key from central settings"
    print("  [PASS] Service initialized with central config settings")

    # 3. Test Invalid IP Input Handling
    print("\n3. Testing invalid IP format handling...")
    res_invalid = await service.check_ip("not-an-ip-address")
    assert res_invalid["status"] == "error", f"Expected error status for invalid IP, got {res_invalid['status']}"
    assert "Invalid IP address format" in res_invalid["error_message"]
    print(f"  [PASS] Invalid IP handling verified: {res_invalid['error_message']}")

    # 4. Test Missing API Key Fallback
    print("\n4. Testing missing API key fallback handling...")
    no_key_service = ThreatIntelligenceService(api_key="")
    res_nokey = await no_key_service.check_ip("8.8.8.8")
    assert res_nokey["status"] == "fallback", f"Expected fallback status for missing API key, got {res_nokey['status']}"
    assert res_nokey["is_public"] == True
    print(f"  [PASS] Missing API key fallback verified: {res_nokey['error_message']}")

    # 5. Test Live AbuseIPDB API Query for a known public IP
    print("\n5. Testing Live AbuseIPDB API Query (8.8.8.8)...")
    res_live = await service.check_ip("8.8.8.8")
    print(f"  [RESULT] IP: {res_live.get('ip_address')}")
    print(f"  [RESULT] Status: {res_live.get('status')}")
    print(f"  [RESULT] Abuse Confidence Score: {res_live.get('abuse_confidence_score')}")
    print(f"  [RESULT] ISP: {res_live.get('isp')}")
    print(f"  [RESULT] Country Code: {res_live.get('country_code')}")
    
    assert res_live["status"] == "success", f"Expected success status, got {res_live['status']} (Error: {res_live.get('error_message')})"
    assert res_live["ip_address"] == "8.8.8.8"
    assert "abuse_confidence_score" in res_live
    assert "is_public" in res_live
    print("  [PASS] Live AbuseIPDB API query returned structured threat score successfully!")

    print("\n" + "=" * 60)
    print("=== CENTRALIZED CONFIG & THREAT INTEL VERIFICATION PASSED ===")
    print("=" * 60)

if __name__ == "__main__":
    asyncio.run(run_tests())
