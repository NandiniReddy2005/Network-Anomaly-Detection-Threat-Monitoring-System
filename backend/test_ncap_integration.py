import sys
import os
import asyncio

# Ensure backend path is in sys.path
sys.path.insert(0, os.path.abspath(os.path.dirname(__file__)))
if hasattr(sys.stdout, 'reconfigure'):
    sys.stdout.reconfigure(encoding='utf-8')

from app.routers.pcap_router import NcapPacketEngine, generate_hex_and_ascii

def test_ncap_packet_engine():
    print("--- 1. Testing Ncap CLI Availability Probe ---")
    cli_found = NcapPacketEngine.is_ncap_cli_available()
    print(f"Ncap / Npcap CLI binary available: {cli_found}")

    print("\n--- 2. Testing Ncap Binary Frame Capture & Extraction ---")
    protocols = ["TCP", "UDP", "ICMP", "HTTP", "DNS"]
    
    for proto in protocols:
        hex_dump, ascii_payload = NcapPacketEngine.capture_frame(
            packet_info=f"{proto} Test Packet",
            proto=proto,
            src="192.168.1.50",
            dst="10.0.0.12",
            length=512
        )
        assert hex_dump is not None and len(hex_dump) > 0, f"Hex dump empty for {proto}"
        assert ascii_payload is not None and len(ascii_payload) > 0, f"ASCII payload empty for {proto}"
        print(f"✅ {proto} Frame captured successfully.")
        print(f"   Hex dump snippet: {hex_dump.splitlines()[0] if hex_dump else ''}")
        print(f"   ASCII snippet: {ascii_payload[:40]}...")

def test_generate_hex_and_ascii_wrapper():
    print("\n--- 3. Testing generate_hex_and_ascii() Wrapper ---")
    hex_dump, ascii_payload = generate_hex_and_ascii("MALICIOUS SYN Flood", "TCP", "185.220.101.5", "10.0.0.12", 1024)
    assert "0000" in hex_dump
    assert len(ascii_payload) > 0
    print("✅ generate_hex_and_ascii wrapper verified.")

if __name__ == "__main__":
    print("Starting Ncap Backend Integration Verification...")
    test_ncap_packet_engine()
    test_generate_hex_and_ascii_wrapper()
    print("\n🎉 ALL NCAP INTEGRATION TESTS PASSED SUCCESSFULLY!")
