import sys
import os

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from fastapi.testclient import TestClient
from app.main import app

def run_phase3_fix_verification():
    print("============================================================")
    print("NETSHIELD-AI PHASE 3 ADMINISTRATOR INTEGRATION VERIFICATION")
    print("============================================================")
    
    with TestClient(app) as client:
        # 1. Test Admin Login
        res_admin_login = client.post("/api/auth/login", json={"email": "sec_admin@gmail.com", "password": "admin123"})
        assert res_admin_login.status_code == 200, f"Admin login failed: {res_admin_login.text}"
        admin_data = res_admin_login.json()
        print(f"Admin Login: PASS (User: {admin_data['user']['email']}, Role: {admin_data['user']['role']})")

        # 2. Test Analyst Login
        res_analyst_login = client.post("/api/auth/login", json={"email": "analyst@gmail.com", "password": "analyst123"})
        assert res_analyst_login.status_code == 200, f"Analyst login failed: {res_analyst_login.text}"
        analyst_data = res_analyst_login.json()
        print(f"Analyst Login: PASS (User: {analyst_data['user']['email']}, Role: {analyst_data['user']['role']})")

        # 3. Test Administrator Endpoints
        print("\nAdministrator Endpoints:")
        endpoints_to_test = [
            ("/api/dashboard/admin/stats", "Admin Stats"),
            ("/api/dashboard/admin/incidents", "Admin Incidents"),
            ("/api/dashboard/threats", "Threats"),
            ("/api/dashboard/critical-alerts", "Critical Alerts"),
            ("/api/dashboard/audit-logs", "Audit Logs"),
            ("/api/auth/users", "User Management Users"),
            ("/api/ml/status", "ML Engine Status"),
            ("/api/ml/metadata/UNSW_NB15", "UNSW-NB15 Metadata"),
            ("/api/ml/metadata/CICIDS2017", "CICIDS2017 Metadata"),
            ("/api/ml/reports/UNSW_NB15/threat", "UNSW Threat Report"),
            ("/api/ml/reports/CICIDS2017/threat", "CICIDS Threat Report"),
            ("/api/ml/reports/UNSW_NB15/risk", "UNSW Risk Report"),
            ("/api/ml/reports/CICIDS2017/risk", "CICIDS Risk Report"),
        ]

        for ep, label in endpoints_to_test:
            res = client.get(ep)
            assert res.status_code == 200, f"{label} ({ep}) failed with status {res.status_code}: {res.text}"
            print(f"  {label} ({ep}): 200 OK")

        # 4. Test Analyst Endpoints
        print("\nAnalyst Endpoints:")
        analyst_eps = [
            ("/api/analyst/network-monitoring", "Network Monitoring"),
            ("/api/analyst/analytics", "Analytics"),
            ("/api/analyst/packet-capture", "Packet Capture"),
            ("/api/analyst/reports", "Compliance Reports"),
        ]
        for ep, label in analyst_eps:
            res = client.get(ep)
            assert res.status_code == 200, f"{label} ({ep}) failed with status {res.status_code}: {res.text}"
            print(f"  {label} ({ep}): 200 OK")

    print("\n============================================================")
    print("ALL ADMINISTRATOR AND ANALYST API VERIFICATIONS PASSED 100%")
    print("============================================================")

if __name__ == "__main__":
    run_phase3_fix_verification()
