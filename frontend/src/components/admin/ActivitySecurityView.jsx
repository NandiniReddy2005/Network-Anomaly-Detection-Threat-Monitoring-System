"use client";
import React, { useState, useEffect, useCallback } from "react";

import DashboardCard from "../DashboardCard";
import LoadingSpinner from "../LoadingSpinner";
import { fetchApi } from "../../utils/api";

export default function ActivitySecurityView() {
  const [securityActivity, setSecurityActivity] = useState([]);
  const [loadingSecurityActivity, setLoadingSecurityActivity] = useState(true);
  const [securityActivityError, setSecurityActivityError] = useState(null);

  const fetchSecurityActivity = useCallback(async () => {
    setLoadingSecurityActivity(true);
    setSecurityActivityError(null);
    try {
      const res = await fetchApi("/api/dashboard/security-activity");
      setSecurityActivity(res.data || res.activity || (Array.isArray(res) ? res : []));
    } catch (err) {
      setSecurityActivityError("Failed to fetch security activities.");
    } finally {
      setLoadingSecurityActivity(false);
    }
  }, []);

  useEffect(() => {
    fetchSecurityActivity();
  }, [fetchSecurityActivity]);

  return (
    <DashboardCard
      title="Activity Security & Policy Enforcement"
      badgeTag="Live Feed"
      className="dedicated-tab-view"
    >
      <p className="tab-description">
        Continuous behavioral auditing, global rule validation, and policy compliance verification.
      </p>
      {loadingSecurityActivity ? (
        <LoadingSpinner text="Loading security activities from FastAPI..." />
      ) : securityActivityError ? (
        <div style={{ padding: "1rem", color: "#f87171", textAlign: "center" }}>
          {securityActivityError}
          <button onClick={fetchSecurityActivity} style={{ marginLeft: "10px" }} className="ns-btn-gradient small">
            Retry
          </button>
        </div>
      ) : securityActivity.length === 0 ? (
        <p style={{ padding: "1rem", textAlign: "center", color: "#94a3b8" }}>
          No security activity logs available.
        </p>
      ) : (
        <div className="table-responsive" style={{ marginTop: "1rem" }}>
          <table className="ns-soc-table">
            <thead>
              <tr>
                <th>Event Type</th>
                <th>Details</th>
                <th>Severity</th>
                <th>Timestamp</th>
              </tr>
            </thead>
            <tbody>
              {securityActivity.map((log) => (
                <tr key={log.id}>
                  <td><code>{log.event_type}</code></td>
                  <td>{log.details}</td>
                  <td>
                    <span className={`severity-badge ${(log.severity || "info").toLowerCase()}`}>
                      {log.severity}
                    </span>
                  </td>
                  <td>{log.timestamp}</td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      )}
    </DashboardCard>
  );
}
