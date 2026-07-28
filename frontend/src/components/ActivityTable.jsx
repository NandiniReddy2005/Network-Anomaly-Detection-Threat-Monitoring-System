"use client";
import React, { useState } from "react";
import LoadingSpinner from "./LoadingSpinner";
import { parseLogItem } from "../utils/helpers";

export default function ActivityTable({
  type = "telemetry",
  data = [],
  loading = false,
  error = null,
  title,
  badgeTag,
  badgeClass = "",
}) {
  const [filterText, setFilterText] = useState("");

  const filteredData = Array.isArray(data)
    ? data.filter((item) => {
        if (!filterText) return true;
        const search = filterText.toLowerCase();
        return JSON.stringify(item).toLowerCase().includes(search);
      })
    : [];

  if (type === "telemetry") {
    return (
      <div className="ns-card">
        <div className="card-header-flex">
          <h3>{title || "Professional Event Log Table (FastAPI Backend Data)"}</h3>
          <input
            type="text"
            placeholder="Filter logs..."
            value={filterText}
            onChange={(e) => setFilterText(e.target.value)}
            className="table-filter-input"
          />
        </div>
        <div className="table-responsive">
          {loading ? (
            <LoadingSpinner text="Loading backend telemetry data..." />
          ) : error ? (
            <p style={{ padding: "1rem", textAlign: "center", color: "#f87171" }}>
              {error}
            </p>
          ) : filteredData.length > 0 ? (
            <table className="ns-soc-table">
              <thead>
                <tr>
                  <th>Timestamp</th>
                  <th>Source IP</th>
                  <th>Destination IP</th>
                  <th>Protocol</th>
                  <th>Packet Size</th>
                  <th>Threat Score</th>
                  <th>Status</th>
                </tr>
              </thead>
              <tbody>
                {filteredData.map((log, index) => {
                  const { timestamp, sourceIp, destIp, proto, size, score, status } = parseLogItem(log);

                  return (
                    <tr key={index}>
                      <td>{timestamp}</td>
                      <td><code>{sourceIp}</code></td>
                      <td><code>{destIp}</code></td>
                      <td><span className="proto-pill">{proto}</span></td>
                      <td>{size}</td>
                      <td>
                        <span className={`score-badge ${score > 80 ? "high" : "low"}`}>
                          {score}/100
                        </span>
                      </td>
                      <td>
                        <span className={`status-badge ${status.toLowerCase()}`}>
                          {status}
                        </span>
                      </td>
                    </tr>
                  );
                })}
              </tbody>
            </table>
          ) : (
            <p style={{ padding: "1rem", textAlign: "center", color: "#94a3b8" }}>
              No telemetry logs returned from backend.
            </p>
          )}
        </div>
      </div>
    );
  }

  if (type === "adminIncidents") {
    return (
      <div className="ns-card">
        <div className="card-header-flex">
          <h3>{title || "Incident Management & Triage Console"}</h3>
          <span className={`badge-tag ${badgeClass || "red"}`}>
            {badgeTag || "Active Queue"}
          </span>
        </div>
        <div className="table-responsive">
          {loading ? (
            <LoadingSpinner text="Loading incident data..." />
          ) : error ? (
            <p style={{ padding: "1rem", textAlign: "center", color: "#f87171" }}>
              {error}
            </p>
          ) : filteredData.length > 0 ? (
            <table className="ns-soc-table">
              <thead>
                <tr>
                  <th>Alert ID</th>
                  <th>Severity</th>
                  <th>Threat Type</th>
                  <th>Assigned Analyst</th>
                  <th>Status</th>
                  <th>Last Updated</th>
                </tr>
              </thead>
              <tbody>
                {filteredData.map((inc) => (
                  <tr key={inc.id}>
                    <td><code>{inc.id}</code></td>
                    <td>
                      <span className={`severity-badge ${(inc.severity || "Medium").toLowerCase()}`}>
                        {inc.severity}
                      </span>
                    </td>
                    <td>{inc.type}</td>
                    <td>{inc.analyst}</td>
                    <td>
                      <span className={`status-badge ${(inc.status || "Open").toLowerCase()}`}>
                        {inc.status}
                      </span>
                    </td>
                    <td>{inc.updated}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          ) : (
            <p style={{ padding: "1rem", textAlign: "center", color: "#94a3b8" }}>
              No incidents found in database.
            </p>
          )}
        </div>
      </div>
    );
  }

  if (type === "packetCapture") {
    return (
      <div className="table-responsive" style={{ marginTop: "1rem" }}>
        {loading ? (
          <LoadingSpinner text="Loading packet capture data..." />
        ) : error ? (
          <p style={{ padding: "1rem", textAlign: "center", color: "#f87171" }}>
            {error}
          </p>
        ) : filteredData.length > 0 ? (
          <table className="ns-soc-table">
            <thead>
              <tr>
                <th>Timestamp</th>
                <th>Source IP</th>
                <th>Destination IP</th>
                <th>Protocol</th>
                <th>Packet Size</th>
                <th>Threat Score</th>
                <th>Status</th>
              </tr>
            </thead>
            <tbody>
              {filteredData.map((log, index) => {
                const { timestamp, sourceIp, destIp, proto, size, score, status } = parseLogItem(log);

                return (
                  <tr key={index}>
                    <td>{timestamp}</td>
                    <td><code>{sourceIp}</code></td>
                    <td><code>{destIp}</code></td>
                    <td><span className="proto-pill">{proto}</span></td>
                    <td>{size}</td>
                    <td>
                      <span className={`score-badge ${score > 80 ? "high" : "low"}`}>
                        {score}/100
                      </span>
                    </td>
                    <td>
                      <span className={`status-badge ${status.toLowerCase()}`}>
                        {status}
                      </span>
                    </td>
                  </tr>
                );
              })}
            </tbody>
          </table>
        ) : (
          <p style={{ padding: "1rem", textAlign: "center", color: "#94a3b8" }}>
            No packet data available
          </p>
        )}
      </div>
    );
  }

  if (type === "userManagement") {
    return (
      <div className="table-responsive" style={{ marginTop: "1rem" }}>
        {loading ? (
          <LoadingSpinner text="Loading user directory from PostgreSQL..." />
        ) : error ? (
          <p style={{ padding: "1rem", textAlign: "center", color: "#f87171" }}>
            {error}
          </p>
        ) : filteredData.length > 0 ? (
          <table className="ns-soc-table">
            <thead>
              <tr>
                <th>User / Agent</th>
                <th>Assigned Role</th>
                <th>Access Level</th>
                <th>Status</th>
              </tr>
            </thead>
            <tbody>
              {filteredData.map((u, i) => (
                <tr key={i}>
                  <td><code>{u.email}</code></td>
                  <td>{u.role}</td>
                  <td>{u.access || (u.role === "Security Administrator" ? "Full Global Control" : "Read / Monitor / Triage")}</td>
                  <td><span className="status-badge normal">{u.status || "Active"}</span></td>
                </tr>
              ))}
            </tbody>
          </table>
        ) : (
          <p style={{ padding: "1rem", textAlign: "center", color: "#94a3b8" }}>
            No registered users found in PostgreSQL database.
          </p>
        )}
      </div>
    );
  }

  if (type === "auditLogs") {
    return (
      <div className="table-responsive" style={{ marginTop: "1rem" }}>
        {loading ? (
          <LoadingSpinner text="Loading audit logs from PostgreSQL..." />
        ) : error ? (
          <p style={{ padding: "1rem", textAlign: "center", color: "#f87171" }}>
            {error}
          </p>
        ) : filteredData.length > 0 ? (
          <table className="ns-soc-table">
            <thead>
              <tr>
                <th>Timestamp</th>
                <th>Actor</th>
                <th>Action Performed</th>
                <th>IP Origin</th>
              </tr>
            </thead>
            <tbody>
              {filteredData.map((log, i) => (
                <tr key={i}>
                  <td>{log.timestamp}</td>
                  <td><code>{log.actor}</code></td>
                  <td>{log.action}</td>
                  <td>{log.ip_origin}</td>
                </tr>
              ))}
            </tbody>
          </table>
        ) : (
          <p style={{ padding: "1rem", textAlign: "center", color: "#94a3b8" }}>
            No audit logs found in PostgreSQL database.
          </p>
        )}
      </div>
    );
  }

  return null;
}
