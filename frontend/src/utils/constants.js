export const API_BASE_URL = process.env.NEXT_PUBLIC_API_URL || "http://127.0.0.1:8000";

export const ROLES = {
  ANALYST: "analyst",
  ADMIN: "admin",
};

export const DEFAULT_ADMIN_INCIDENTS = [];

export const TELEMETRY_TRAFFIC_ENDPOINT = `${API_BASE_URL}/api/telemetry/traffic?limit=50`;
