import { API_BASE_URL } from "./constants";

export async function fetchApi(endpoint, options = {}) {
  const url = endpoint.startsWith("http")
    ? endpoint
    : `${API_BASE_URL}${endpoint.startsWith("/") ? endpoint : `/${endpoint}`}`;

  let userEmail = "";
  try {
    if (typeof window !== "undefined") {
      const stored = localStorage.getItem("netshield_current_user") || localStorage.getItem("user");
      if (stored) {
        const parsed = JSON.parse(stored);
        userEmail = parsed?.email || "";
      }
    }
  } catch (e) {}

  try {
    const res = await fetch(url, {
      headers: {
        "Content-Type": "application/json",
        ...(userEmail ? { "X-User-Email": userEmail } : {}),
        ...options.headers,
      },
      ...options,
    });

    if (!res.ok) {
      let message = `API request failed with status ${res.status}`;
      try {
        const errorData = await res.json();
        if (errorData && errorData.detail) {
          message = typeof errorData.detail === "string" ? errorData.detail : JSON.stringify(errorData.detail);
        }
      } catch (e) {}
      throw new Error(message);
    }

    const data = await res.json();
    return data;
  } catch (error) {
    console.error(`API Fetch Error [${endpoint}]:`, error);
    throw error;
  }
}

// Milestone 2 FastAPI ML Helper Functions
export async function getMlStatus() {
  return await fetchApi("/api/ml/status");
}

export async function getMlMetadata(dataset = "UNSW_NB15") {
  return await fetchApi(`/api/ml/metadata/${dataset}`);
}

export async function predictThreat(dataset, features) {
  return await fetchApi(`/api/ml/predict/${dataset}`, {
    method: "POST",
    body: JSON.stringify({ features }),
  });
}

export async function predictAnomaly(dataset, features) {
  return await fetchApi(`/api/ml/anomaly/${dataset}`, {
    method: "POST",
    body: JSON.stringify({ features }),
  });
}

export async function getMlReport(dataset = "UNSW_NB15", reportType = "risk", page = 1, limit = 20) {
  const queryParams = new URLSearchParams({
    page: page.toString(),
    limit: limit.toString(),
  });
  return await fetchApi(`/api/ml/reports/${dataset}/${reportType}?${queryParams.toString()}`);
}

export async function analyzeThreatVector(payload) {
  return await fetchApi("/api/threats/analyze", {
    method: "POST",
    body: JSON.stringify(payload),
  });
}

export async function analyzeCriticalAlert(payload) {
  return await fetchApi("/api/alerts/analyze", {
    method: "POST",
    body: JSON.stringify(payload),
  });
}

export async function getCriticalAlerts(userEmail) {
  const queryParams = new URLSearchParams();
  if (userEmail) queryParams.append("user_id", userEmail);
  return await fetchApi(`/api/alerts/critical?${queryParams.toString()}`);
}

export async function executeCriticalAlertAction(alertId, actionType, notes = null, actor = null) {
  return await fetchApi("/api/alerts/action", {
    method: "POST",
    body: JSON.stringify({
      alert_id: alertId,
      action_type: actionType,
      notes: notes,
      actor: actor
    }),
  });
}

export async function querySystemHelp(query) {
  return await fetchApi("/api/help/query", {
    method: "POST",
    body: JSON.stringify({ query }),
  });
}

export async function sendSupportEmail(payload) {
  return await fetchApi("/api/help/support-email", {
    method: "POST",
    body: JSON.stringify(payload),
  });
}

export async function getUserActivityLogs(userEmail) {
  const queryParams = new URLSearchParams();
  if (userEmail) queryParams.append("user_id", userEmail);
  return await fetchApi(`/api/reports/user-activity?${queryParams.toString()}`);
}

export async function logUserActivity(activityData) {
  return await fetchApi("/api/reports/user-activity", {
    method: "POST",
    body: JSON.stringify(activityData),
  });
}

export async function generateDatabaseReport(params = {}) {
  const queryParams = new URLSearchParams();
  if (params.userEmail || params.user_id) queryParams.append("user_id", params.userEmail || params.user_id);
  if (params.days) queryParams.append("days", params.days.toString());
  if (params.dateRange) queryParams.append("date_range", params.dateRange);
  if (params.datasetEngine) queryParams.append("dataset_engine", params.datasetEngine);
  if (params.startDate) queryParams.append("start_date", params.startDate);
  if (params.endDate) queryParams.append("end_date", params.endDate);
  return await fetchApi(`/api/reports/generate?${queryParams.toString()}`);
}

// PostgreSQL PCAP Persistence Helpers
export async function getPcapHistory(userEmail) {
  const queryParams = new URLSearchParams();
  if (userEmail) queryParams.append("user_id", userEmail);
  return await fetchApi(`/api/pcap/history?${queryParams.toString()}`);
}

export async function getPcapSessionDetails(sessionId, userEmail) {
  const queryParams = new URLSearchParams();
  if (userEmail) queryParams.append("user_id", userEmail);
  return await fetchApi(`/api/pcap/session/${sessionId}?${queryParams.toString()}`);
}

export async function uploadPcapFile(fileName, packets = null) {
  return await fetchApi("/api/pcap/upload", {
    method: "POST",
    body: JSON.stringify({
      file_name: fileName,
      packets: packets
    })
  });
}

export async function escalatePcapThreat(threatData) {
  return await fetchApi("/api/pcap/escalate-incident", {
    method: "POST",
    body: JSON.stringify(threatData)
  });
}

export async function predictAndCapturePacket(payload) {
  return await fetchApi("/api/pcap/predict", {
    method: "POST",
    body: JSON.stringify(payload)
  });
}





