# FastAPI ML Integration & Validation Report

## Executive Summary
This report documents the verification and operational status of the **Activity Security ML Traffic Analyzer** integration between the Next.js frontend (`ActivitySecurityView.jsx`) and the FastAPI backend service (`/api/ml/analyze`).

---

## 1. Endpoint Route & Operational Status

- **Primary Route Endpoint**: `POST /api/ml/analyze`
- **Backend Base URL**: `http://127.0.0.1:8000`
- **Proxy Configuration**: Supports direct `http://127.0.0.1:8000/api/ml/analyze` calls with automatic fallback to `/api/ml/analyze`.
- **HTTP Status Verification**: Verified active with **HTTP 200 OK** across test scenarios.

---

## 2. Request Schema & Validation Rules

### Pydantic Backend Schema (`AnalyzePayload`):
```python
class AnalyzePayload(BaseModel):
    dataset: str
    sourceIp: Optional[str] = "192.168.1.100"
    destinationIp: Optional[str] = "10.0.0.1"
    sourcePort: Optional[Union[int, str]] = "49152"
    destinationPort: Optional[Union[int, str]] = "80"
    protocol: Optional[str] = "TCP"
```

### Frontend Validation Rules (`ActivitySecurityView.jsx`):
1. **IPv4 Formatting Check**:
   - Both `sourceIp` and `destinationIp` are validated using IPv4 regular expression:
     `/^(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)$/`
   - Blocks invalid IPs (e.g., `192.168.1.3000`) and displays inline error alerts.
2. **Port Range Boundaries**:
   - `sourcePort` and `destinationPort` are parsed as integers and validated to fall within range `1` to `65535`.
3. **Supported Datasets**:
   - Validated against `UNSW-NB15` and `CICIDS2017`.

---

## 3. Frontend-to-Backend Field Mapping Matrix

| Frontend State Key | FastAPI Payload Key | Backend Response Key (`data`) | Result Field in UI |
| :--- | :--- | :--- | :--- |
| `targetDataset` | `dataset` | `dataset` | `dataset` |
| `sourceIp` | `sourceIp` / `source_ip` | `target` (formatted) | `target` |
| `destinationIp` | `destinationIp` / `destination_ip` | `target` (formatted) | `target` |
| `sourcePort` | `sourcePort` / `source_port` | `target` (formatted) | `target` |
| `destinationPort` | `destinationPort` / `destination_port` | `target` (formatted) | `target` |
| `protocol` | `protocol` | `target` (formatted) | `target` |
| `predictionResults` | N/A | `predictedThreat` / `predicted_threat` | `predictedThreat` |
| `predictionResults` | N/A | `threatProbability` / `threat_probability` | `threatProbability` |
| `predictionResults` | N/A | `threatLevel` / `threat_level` | `threatLevel` |
| `predictionResults` | N/A | `anomalyStatus` / `anomaly_status` | `anomalyStatus` |
| `predictionResults` | N/A | `anomalyScore` / `anomaly_score` | `anomalyScore` |
| `predictionResults` | N/A | `riskScore` / `risk_score` | `riskScore` |
| `predictionResults` | N/A | `verdict` | `verdict` |
| `predictionResults` | N/A | `isSafe` / `is_safe` | `isSafe` |

---

## 4. Verification Test Results (`test_ml_pipeline.py`)

Three distinct traffic scenarios were executed against `http://127.0.0.1:8000/api/ml/analyze`:

1. **Scenario 1: Benign TCP Traffic**
   - **Target**: `192.168.1.100:49152 → 10.0.0.1:80 (TCP)`
   - **Status**: HTTP 200 OK
   - **Result**: `Reconnaissance` (Threat Probability: `40.9%`, Risk Score: `36.8 (Medium)`)

2. **Scenario 2: PortScan Activity**
   - **Target**: `198.51.100.42:51234 → 10.0.0.5:443 (TCP)`
   - **Status**: HTTP 200 OK
   - **Result**: `PortScan` (Threat Probability: `39.0%`, Risk Score: `38.1 (Medium)`)

3. **Scenario 3: UDP Flood Anomaly**
   - **Target**: `203.0.113.15:12345 → 10.0.0.10:53 (UDP)`
   - **Status**: HTTP 200 OK
   - **Result**: `PortScan` (Threat Probability: `36.3%`, Risk Score: `36.7 (Medium)`)

Logs for each sample execution are persisted in [`ml_verification_log.txt`](file:///d:/NetShield-AI/ml_verification_log.txt).
