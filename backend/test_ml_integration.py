import asyncio
import sys
import os

# Ensure backend root is in sys.path
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from fastapi.testclient import TestClient
from app.main import app

def run_tests():
    print("=== STARTING FASTAPI ML INTEGRATION VERIFICATION ===")
    
    with TestClient(app) as client:
        # 1. Test Root Endpoint
        res_root = client.get("/")
        print("1. Root Endpoint GET /:", res_root.status_code, res_root.json())
        assert res_root.status_code == 200

        # 2. Test GET /api/ml/status
        res_status = client.get("/api/ml/status")
        print("2. ML Status Endpoint GET /api/ml/status:", res_status.status_code)
        status_data = res_status.json()
        print(status_data)
        assert res_status.status_code == 200
        assert status_data["status"] == "success"
        
        unsw = status_data["data"]["UNSW_NB15"]
        cic = status_data["data"]["CICIDS2017"]
        
        assert unsw["model_loaded"] is True
        assert unsw["features_loaded"] is True
        assert unsw["classes_loaded"] is True
        assert unsw["metadata_loaded"] is True
        assert unsw["feature_count"] == 186
        assert unsw["class_count"] == 10

        assert cic["model_loaded"] is True
        assert cic["features_loaded"] is True
        assert cic["classes_loaded"] is True
        assert cic["metadata_loaded"] is True
        assert cic["feature_count"] == 78
        assert cic["class_count"] == 13

        print("--> Dynamic feature & class counts verified:")
        print(f"    UNSW_NB15: {unsw['feature_count']} features, {unsw['class_count']} classes")
        print(f"    CICIDS2017: {cic['feature_count']} features, {cic['class_count']} classes")

        # 3. Test GET /api/ml/metadata/UNSW_NB15
        res_meta_unsw = client.get("/api/ml/metadata/UNSW_NB15")
        print("3. Metadata UNSW_NB15 GET /api/ml/metadata/UNSW_NB15:", res_meta_unsw.status_code)
        assert res_meta_unsw.status_code == 200
        assert res_meta_unsw.json()["data"]["feature_count"] == 186
        assert res_meta_unsw.json()["data"]["class_count"] == 10

        # 4. Test GET /api/ml/metadata/CICIDS2017
        res_meta_cic = client.get("/api/ml/metadata/CICIDS2017")
        print("4. Metadata CICIDS2017 GET /api/ml/metadata/CICIDS2017:", res_meta_cic.status_code)
        assert res_meta_cic.status_code == 200
        assert res_meta_cic.json()["data"]["feature_count"] == 78
        assert res_meta_cic.json()["data"]["class_count"] == 13

        # 5. Test Auth Login
        res_login_analyst = client.post("/api/auth/login", json={"email": "analyst@gmail.com", "password": "analyst123"})
        print("5. Analyst Login POST /api/auth/login:", res_login_analyst.status_code, res_login_analyst.json()["user"])
        assert res_login_analyst.status_code == 200
        assert res_login_analyst.json()["user"]["role"] == "analyst"

        res_login_admin = client.post("/api/auth/login", json={"email": "sec_admin@gmail.com", "password": "admin123"})
        print("6. Admin Login POST /api/auth/login:", res_login_admin.status_code, res_login_admin.json()["user"])
        assert res_login_admin.status_code == 200
        assert res_login_admin.json()["user"]["role"] == "admin"

        # 6. Test Analyst API
        res_monitoring = client.get("/api/analyst/network-monitoring")
        print("7. Network Monitoring GET /api/analyst/network-monitoring:", res_monitoring.status_code)
        assert res_monitoring.status_code == 200

        # 7. Test Admin API
        res_admin_stats = client.get("/api/dashboard/admin/stats")
        print("8. Admin Stats GET /api/dashboard/admin/stats:", res_admin_stats.status_code)
        assert res_admin_stats.status_code == 200

    print("=== ALL VERIFICATION TESTS PASSED SUCCESSFULLY! ===")

if __name__ == "__main__":
    run_tests()
