import sys
import os
from pathlib import Path

backend_dir = Path(__file__).resolve().parent
if str(backend_dir) not in sys.path:
    sys.path.insert(0, str(backend_dir))

from fastapi.testclient import TestClient
from app.main import app

def run_tests():
    out_file = backend_dir / "test_output.txt"
    with open(out_file, "w", encoding="utf-8") as out:
        out.write("=" * 60 + "\n")
        out.write("NETSHIELD-AI TELEMETRY & RISK VERDICT ENDPOINT VERIFICATION\n")
        out.write("=" * 60 + "\n")

        client = TestClient(app)

        scenarios = [
            {
                "name": "Scenario 1: Clean Internal IP with CICIDS2017",
                "payload": {
                    "destination_ip": "10.0.9.47",
                    "source_ip": "192.168.1.50",
                    "dataset": "CICIDS2017"
                }
            },
            {
                "name": "Scenario 2: Threat IP with UNSW-NB15",
                "payload": {
                    "destination_ip": "192.168.1.222",
                    "source_ip": "192.168.1.50",
                    "dataset": "UNSW-NB15"
                }
            },
            {
                "name": "Scenario 3: Public IP with AbuseIPDB Integration (CICIDS2017)",
                "payload": {
                    "destination_ip": "1.1.1.1",
                    "source_ip": "192.168.1.50",
                    "dataset": "CICIDS2017"
                }
            },
            {
                "name": "Scenario 4: Google Public DNS 8.8.8.8 (CICIDS2017)",
                "payload": {
                    "destination_ip": "8.8.8.8",
                    "source_ip": "192.168.1.50",
                    "dataset": "CICIDS2017"
                }
            }
        ]

        for sc in scenarios:
            out.write(f"\n--- {sc['name']} ---\n")
            response = client.post("/api/network/analyze-telemetry", json=sc['payload'])
            out.write(f"HTTP Status: {response.status_code}\n")
            if response.status_code == 200:
                data = response.json()
                out.write(f"Verdict Tier: {data.get('verdict_tier')}\n")
                out.write(f"Safety Status: {data.get('safety_status')}\n")
                out.write(f"Is Safe: {data.get('is_safe')}\n")
                out.write(f"Risk Level: {data.get('risk_level')}\n")
                out.write(f"AbuseIPDB Score: {data.get('abuseipdb_score')}%\n")
                out.write(f"Monitored Packets: {data.get('monitored_packet_count')}\n")
                out.write(f"Avg Packet Size: {data.get('average_packet_size')}\n")
                out.write(f"Bandwidth Usage: {data.get('bandwidth_usage')}\n")
                out.write(f"Latency / Flow Duration: {data.get('latency')} / {data.get('flow_duration')}\n")
                out.write(f"Packet Loss Rate: {data.get('packet_loss_rate')}\n")
                out.write(f"Analysis Reason: {data.get('analysis_reason')}\n")
            else:
                out.write(f"Error Response: {response.text}\n")

        out.write("\n" + "=" * 60 + "\n")
        out.write("=== TELEMETRY & RISK VERDICT ENDPOINT VERIFICATION COMPLETE ===\n")
        out.write("=" * 60 + "\n")

if __name__ == "__main__":
    run_tests()

