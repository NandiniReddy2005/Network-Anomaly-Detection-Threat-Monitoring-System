import os
import pickle
import json
import logging
from typing import Dict, Any, Optional
import joblib

logger = logging.getLogger("netshield_ml_manager")

class MLManager:
    """
    Singleton ML Manager responsible for loading ML artifacts once at startup.
    Keeps models, feature names, threat classes, and metadata in memory.
    Calculates feature count and threat class count dynamically.
    """
    def __init__(self):
        self.artifacts_base_path = os.getenv(
            "ML_ARTIFACTS_PATH", 
            r"D:\NetShield-AI\NetShield_AI_Milestone_2"
        )
        self._models: Dict[str, Any] = {}
        self._feature_names: Dict[str, list] = {}
        self._classes: Dict[str, list] = {}
        self._metadata: Dict[str, dict] = {}
        self._status: Dict[str, dict] = {}

    def _resolve_artifact_path(self, dataset: str, subfolder: str, filename: str) -> Optional[str]:
        """
        Locates an artifact file in candidate subdirectories to ensure portable loading.
        """
        candidate_paths = [
            os.path.join(self.artifacts_base_path, subfolder, dataset, filename),
            os.path.join(self.artifacts_base_path, subfolder, filename),
            os.path.join(self.artifacts_base_path, "results", dataset, filename),
            os.path.join(self.artifacts_base_path, "reports", dataset, filename),
            os.path.join(self.artifacts_base_path, filename),
        ]
        
        # Relative path fallback if absolute path is not found directly
        rel_base = os.path.join(os.path.dirname(__file__), "..", "..", "NetShield_AI_Milestone_2")
        candidate_paths.extend([
            os.path.join(rel_base, subfolder, dataset, filename),
            os.path.join(rel_base, subfolder, filename),
            os.path.join(rel_base, "results", dataset, filename),
            os.path.join(rel_base, "reports", dataset, filename),
        ])

        for path in candidate_paths:
            normalized = os.path.normpath(path)
            if os.path.exists(normalized):
                return normalized
        return None

    def load_dataset_artifacts(self, dataset: str) -> dict:
        """
        Loads artifacts for a given dataset (UNSW_NB15 or CICIDS2017).
        """
        status = {
            "model_loaded": False,
            "features_loaded": False,
            "classes_loaded": False,
            "metadata_loaded": False,
            "feature_count": 0,
            "class_count": 0,
            "errors": []
        }

        classifier_name = f"{dataset}_ThreatClassifier.pkl"
        features_name = f"{dataset}_Threat_FeatureNames.pkl"
        classes_name = f"{dataset}_Threat_Classes.pkl"
        metadata_name = f"{dataset}_Threat_Metadata.json"

        # 1. Load Feature Names & calculate feature_count dynamically
        feat_path = self._resolve_artifact_path(dataset, "models", features_name)
        if feat_path:
            try:
                with open(feat_path, "rb") as f:
                    feats = pickle.load(f)
                    if isinstance(feats, (list, tuple)):
                        self._feature_names[dataset] = list(feats)
                        status["features_loaded"] = True
                        status["feature_count"] = len(feats)
                    else:
                        status["errors"].append(f"Invalid feature names format in {feat_path}")
            except Exception as e:
                logger.error(f"Error loading feature names for {dataset}: {e}")
                status["errors"].append(f"Failed to load features: {str(e)}")
        else:
            status["errors"].append(f"Feature names artifact {features_name} not found")

        # 2. Load Threat Classes & calculate class_count dynamically
        class_path = self._resolve_artifact_path(dataset, "models", classes_name)
        if class_path:
            try:
                with open(class_path, "rb") as f:
                    cls_list = pickle.load(f)
                    if isinstance(cls_list, (list, tuple)):
                        self._classes[dataset] = list(cls_list)
                        status["classes_loaded"] = True
                        status["class_count"] = len(cls_list)
                    else:
                        status["errors"].append(f"Invalid classes format in {class_path}")
            except Exception as e:
                logger.error(f"Error loading threat classes for {dataset}: {e}")
                status["errors"].append(f"Failed to load classes: {str(e)}")
        else:
            status["errors"].append(f"Threat classes artifact {classes_name} not found")

        # 3. Load Metadata JSON
        meta_path = self._resolve_artifact_path(dataset, "models", metadata_name)
        if meta_path:
            try:
                with open(meta_path, "r", encoding="utf-8") as f:
                    meta_data = json.load(f)
                    self._metadata[dataset] = meta_data
                    status["metadata_loaded"] = True
            except Exception as e:
                logger.error(f"Error loading metadata JSON for {dataset}: {e}")
                status["errors"].append(f"Failed to load metadata JSON: {str(e)}")
        else:
            status["errors"].append(f"Metadata JSON artifact {metadata_name} not found")

        # 4. Load Threat Classifier Model (.pkl) via joblib/pickle
        model_path = self._resolve_artifact_path(dataset, "models", classifier_name)
        if model_path:
            try:
                try:
                    model_obj = joblib.load(model_path)
                except Exception:
                    with open(model_path, "rb") as f:
                        model_obj = pickle.load(f)
                self._models[dataset] = model_obj
                status["model_loaded"] = True
            except Exception as e:
                logger.error(f"Error loading classifier model for {dataset}: {e}")
                status["errors"].append(f"Failed to load model: {str(e)}")
        else:
            status["errors"].append(f"Classifier model artifact {classifier_name} not found")

        # 5. Load Anomaly Detection Model (RandomForest.pkl)
        rf_name = f"{dataset}_RandomForest.pkl"
        rf_path = self._resolve_artifact_path(dataset, "models", rf_name)
        status["anomaly_model_loaded"] = False
        if rf_path:
            try:
                try:
                    rf_obj = joblib.load(rf_path)
                except Exception:
                    with open(rf_path, "rb") as f:
                        rf_obj = pickle.load(f)
                if not hasattr(self, "_anomaly_models"):
                    self._anomaly_models = {}
                self._anomaly_models[dataset] = rf_obj
                status["anomaly_model_loaded"] = True
            except Exception as e:
                logger.error(f"Error loading anomaly model for {dataset}: {e}")
                status["errors"].append(f"Failed to load anomaly model: {str(e)}")
        else:
            status["errors"].append(f"Anomaly model artifact {rf_name} not found")

        self._status[dataset] = status
        return status

    def load_all(self):
        """
        Loads artifacts for both UNSW_NB15 and CICIDS2017 datasets.
        """
        logger.info(f"Initializing ML Manager with base path: {self.artifacts_base_path}")
        self.load_dataset_artifacts("UNSW_NB15")
        self.load_dataset_artifacts("CICIDS2017")
        logger.info("ML Artifact initialization completed.")

    def get_status(self) -> dict:
        """
        Returns full loading status and dynamic counts for both datasets.
        """
        return self._status

    def get_classifier(self, dataset: str) -> Any:
        norm = dataset.upper().replace("-", "_")
        if norm not in self._models:
            self.load_dataset_artifacts(norm)
        return self._models.get(norm)

    def get_anomaly_model(self, dataset: str) -> Any:
        norm = dataset.upper().replace("-", "_")
        if not hasattr(self, "_anomaly_models") or norm not in getattr(self, "_anomaly_models", {}):
            self.load_dataset_artifacts(norm)
        if hasattr(self, "_anomaly_models"):
            return self._anomaly_models.get(norm)
        return None

    def get_feature_names(self, dataset: str) -> list:
        norm = dataset.upper().replace("-", "_")
        return self._feature_names.get(norm, [])

    def get_classes(self, dataset: str) -> list:
        norm = dataset.upper().replace("-", "_")
        return self._classes.get(norm, [])

    def get_report_path(self, dataset: str, report_type: str) -> Optional[str]:
        """
        Resolves path to generated report CSV (anomaly, threat, risk).
        """
        norm_ds = dataset.upper().replace("-", "_")
        type_map = {
            "anomaly": f"{norm_ds}_Anomaly_Detection_Report.csv",
            "threat": f"{norm_ds}_Threat_Classification_Report.csv",
            "risk": f"{norm_ds}_Risk_Scoring_Report.csv"
        }
        filename = type_map.get(report_type.lower())
        if not filename:
            return None
        return self._resolve_artifact_path(norm_ds, "reports", filename)

    def get_metadata(self, dataset: str) -> Optional[dict]:
        """
        Returns dataset metadata including feature names, threat classes, and Colab training metadata.
        """
        norm_ds = dataset.upper().replace("-", "_")
        if norm_ds not in self._status:
            return None

        return {
            "dataset": norm_ds,
            "feature_count": len(self._feature_names.get(norm_ds, [])),
            "class_count": len(self._classes.get(norm_ds, [])),
            "feature_names": self._feature_names.get(norm_ds, []),
            "threat_classes": self._classes.get(norm_ds, []),
            "metadata": self._metadata.get(norm_ds, {}),
            "status": self._status.get(norm_ds, {})
        }

# Global singleton instance
ml_manager = MLManager()
