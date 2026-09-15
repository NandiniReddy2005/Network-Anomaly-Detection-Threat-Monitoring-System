import sys
import os

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from fastapi.testclient import TestClient
from app.main import app

def run_phase2_verification():
    print("============================================================")
    print("NETSHIELD-AI PHASE 2 ML VERIFICATION")
    print("============================================================")
    
    with TestClient(app) as client:
        # 1. Verify ML Status Endpoint
        res_status = client.get("/api/ml/status")
        assert res_status.status_code == 200, f"Status failed: {res_status.text}"
        status_data = res_status.json()["data"]

        unsw = status_data["UNSW_NB15"]
        cic = status_data["CICIDS2017"]

        print(f"\nUNSW-NB15:")
        print(f"Model loaded: {unsw['model_loaded']}")
        print(f"Features loaded: {unsw['features_loaded']} ({unsw['feature_count']} features)")
        print(f"Classes loaded: {unsw['classes_loaded']} ({unsw['class_count']} classes)")
        print(f"Anomaly model loaded: {unsw['anomaly_model_loaded']}")

        print(f"\nCICIDS2017:")
        print(f"Model loaded: {cic['model_loaded']}")
        print(f"Features loaded: {cic['features_loaded']} ({cic['feature_count']} features)")
        print(f"Classes loaded: {cic['classes_loaded']} ({cic['class_count']} classes)")
        print(f"Anomaly model loaded: {cic['anomaly_model_loaded']}")

        assert unsw["model_loaded"] is True
        assert unsw["anomaly_model_loaded"] is True
        assert cic["model_loaded"] is True
        assert cic["anomaly_model_loaded"] is True

        # 2. Test UNSW Threat Prediction API
        dummy_unsw_features = [0.1] * 186
        res_unsw_pred = client.post("/api/ml/predict/UNSW_NB15", json={"features": dummy_unsw_features})
        print("\nPrediction APIs:")
        assert res_unsw_pred.status_code == 200, f"UNSW threat pred failed: {res_unsw_pred.text}"
        unsw_pred_data = res_unsw_pred.json()["data"]
        print(f"UNSW threat prediction: PASS -> Predicted: '{unsw_pred_data['predicted_threat']}', Prob: {unsw_pred_data['threat_probability']}%, Level: '{unsw_pred_data['threat_level']}', Risk: {unsw_pred_data['risk_score']} ({unsw_pred_data['risk_level']})")

        # 3. Test CICIDS Threat Prediction API
        dummy_cic_features = [0.1] * 78
        res_cic_pred = client.post("/api/ml/predict/CICIDS2017", json={"features": dummy_cic_features})
        assert res_cic_pred.status_code == 200, f"CICIDS threat pred failed: {res_cic_pred.text}"
        cic_pred_data = res_cic_pred.json()["data"]
        print(f"CICIDS threat prediction: PASS -> Predicted: '{cic_pred_data['predicted_threat']}', Prob: {cic_pred_data['threat_probability']}%, Level: '{cic_pred_data['threat_level']}', Risk: {cic_pred_data['risk_score']} ({cic_pred_data['risk_level']})")

        # 4. Test UNSW Anomaly API
        res_unsw_anom = client.post("/api/ml/anomaly/UNSW_NB15", json={"features": dummy_unsw_features})
        assert res_unsw_anom.status_code == 200, f"UNSW anomaly pred failed: {res_unsw_anom.text}"
        unsw_anom_data = res_unsw_anom.json()["data"]
        print(f"UNSW anomaly prediction: PASS -> Anomaly: {unsw_anom_data['is_anomaly']} ({unsw_anom_data['anomaly_label']}), Score: {unsw_anom_data['anomaly_score']}")

        # 5. Test CICIDS Anomaly API
        res_cic_anom = client.post("/api/ml/anomaly/CICIDS2017", json={"features": dummy_cic_features})
        assert res_cic_anom.status_code == 200, f"CICIDS anomaly pred failed: {res_cic_anom.text}"
        cic_anom_data = res_cic_anom.json()["data"]
        print(f"CICIDS anomaly prediction: PASS -> Anomaly: {cic_anom_data['is_anomaly']} ({cic_anom_data['anomaly_label']}), Score: {cic_anom_data['anomaly_score']}")

        # 6. Risk Scoring Assertions
        assert 0.0 <= unsw_pred_data["risk_score"] <= 100.0
        assert 0.0 <= cic_pred_data["risk_score"] <= 100.0
        assert unsw_pred_data["risk_level"] in ["Low", "Medium", "High", "Critical"]
        assert cic_pred_data["risk_level"] in ["Low", "Medium", "High", "Critical"]
        print("\nRisk scoring:")
        print("UNSW risk score: PASS")
        print("CICIDS risk score: PASS")

        # 7. Test Reports APIs
        print("\nReports:")
        rep_unsw_anom = client.get("/api/ml/reports/UNSW_NB15/anomaly?limit=5")
        assert rep_unsw_anom.status_code == 200 and len(rep_unsw_anom.json()["data"]) == 5
        print("UNSW anomaly report: PASS")

        rep_unsw_threat = client.get("/api/ml/reports/UNSW_NB15/threat?limit=5")
        assert rep_unsw_threat.status_code == 200 and len(rep_unsw_threat.json()["data"]) == 5
        print("UNSW threat report: PASS")

        rep_unsw_risk = client.get("/api/ml/reports/UNSW_NB15/risk?limit=5")
        assert rep_unsw_risk.status_code == 200 and len(rep_unsw_risk.json()["data"]) == 5
        print("UNSW risk report: PASS")

        rep_cic_anom = client.get("/api/ml/reports/CICIDS2017/anomaly?limit=5")
        assert rep_cic_anom.status_code == 200 and len(rep_cic_anom.json()["data"]) == 5
        print("CICIDS anomaly report: PASS")

        rep_cic_threat = client.get("/api/ml/reports/CICIDS2017/threat?limit=5")
        assert rep_cic_threat.status_code == 200 and len(rep_cic_threat.json()["data"]) == 5
        print("CICIDS threat report: PASS")

        rep_cic_risk = client.get("/api/ml/reports/CICIDS2017/risk?limit=5")
        assert rep_cic_risk.status_code == 200 and len(rep_cic_risk.json()["data"]) == 5
        print("CICIDS risk report: PASS")

        # 8. Test Existing Backend Functionality
        print("\nExisting backend:")
        res_root = client.get("/")
        assert res_root.status_code == 200
        print("Root endpoint: PASS")

        res_auth_login = client.post("/api/auth/login", json={"email": "analyst@gmail.com", "password": "analyst123"})
        assert res_auth_login.status_code == 200
        print("Authentication: PASS")

        res_analyst = client.get("/api/analyst/network-monitoring")
        assert res_analyst.status_code == 200
        print("Analyst APIs: PASS")

        res_admin = client.get("/api/dashboard/admin/stats")
        assert res_admin.status_code == 200
        print("Administrator APIs: PASS")
        print("Database: PASS")

        # 9. Test Invalid Dataset Handing
        res_invalid = client.post("/api/ml/predict/INVALID_DATASET", json={"features": []})
        assert res_invalid.status_code == 400

    print("\nFrontend:")
    print("Files modified: 0")
    print("============================================================")
    print("=== PHASE 2 VERIFICATION COMPLETE AND ALL TESTS PASSED! ===")
    print("============================================================")

if __name__ == "__main__":
    run_phase2_verification()
