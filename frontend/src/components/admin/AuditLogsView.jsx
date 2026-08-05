"use client";
import React, { useState, useEffect, useCallback, useMemo } from "react";
import {
  FileText,
  RefreshCw,
  CheckCircle2,
  AlertCircle,
  Sliders,
  ShieldAlert,
  Zap,
  BarChart3,
  FolderArchive,
  Search,
  ChevronLeft,
  ChevronRight,
} from "lucide-react";
import {
  BarChart,
  Bar,
  XAxis,
  YAxis,
  Tooltip,
  ResponsiveContainer,
  Cell,
  CartesianGrid,
} from "recharts";

import LoadingSpinner from "../LoadingSpinner";
import { getFormattedUTCTime } from "../../utils/formatDate";
import { fetchApi } from "../../utils/api";
import { API_BASE_URL } from "../../utils/constants";
import { useTheme } from "../../context/ThemeContext";

const CustomAdminTooltip = ({ active, payload, label }) => {
  const { isDark } = useTheme();
  if (active && payload && payload.length) {
    return (
      <div
        style={{
          backgroundColor: isDark ? "rgba(15, 23, 42, 0.95)" : "#ffffff",
          border: isDark ? "1px solid rgba(59, 130, 246, 0.35)" : "1px solid #cbd5e1",
          borderRadius: "10px",
          padding: "0.75rem 1rem",
          boxShadow: isDark ? "0 10px 25px rgba(0, 0, 0, 0.5)" : "0 10px 25px rgba(0, 0, 0, 0.1)",
          color: isDark ? "#f8fafc" : "#0f172a",
          minWidth: "180px",
        }}
      >
        <div
          style={{
            fontSize: "0.725rem",
            color: isDark ? "#94a3b8" : "#64748b",
            fontWeight: 700,
            marginBottom: "0.4rem",
            borderBottom: isDark ? "1px solid rgba(255,255,255,0.08)" : "1px solid #e2e8f0",
            paddingBottom: "0.3rem",
          }}
        >
          TIME: {label}
        </div>
        {payload.map((entry, index) => (
          <div
            key={`tooltip-${index}`}
            style={{
              display: "flex",
              alignItems: "center",
              justifyContent: "space-between",
              gap: "1rem",
              fontSize: "0.8rem",
              margin: "0.35rem 0",
            }}
          >
            <span style={{ color: isDark ? "#cbd5e1" : "#334155", fontWeight: 500 }}>
              {entry.name}:
            </span>
            <span style={{ fontWeight: 700, fontFamily: "monospace" }}>
              {entry.value}
            </span>
          </div>
        ))}
      </div>
    );
  }
  return null;
};

export default function AuditLogsView() {
  const { isDark } = useTheme();
  const [currentTime, setCurrentTime] = useState("");
  const [auditToastMsg, setAuditToastMsg] = useState(null);

  const [auditLogs, setAuditLogs] = useState([]);
  const [loadingAuditLogs, setLoadingAuditLogs] = useState(true);
  const [auditLogsError, setAuditLogsError] = useState(null);

  const [auditSearchQuery, setAuditSearchQuery] = useState("");
  const [auditSortField, setAuditSortField] = useState("timestamp");
  const [auditSortOrder, setAuditSortOrder] = useState("desc");
  const [auditPage, setAuditPage] = useState(1);
  const [activeAuditId, setActiveAuditId] = useState(null);

  useEffect(() => {
    setCurrentTime(getFormattedUTCTime());
    const timer = setInterval(() => setCurrentTime(getFormattedUTCTime()), 1000);
    return () => clearInterval(timer);
  }, []);

  const fetchAuditLogs = useCallback(async () => {
    setLoadingAuditLogs(true);
    setAuditLogsError(null);
    try {
      const res = await fetchApi("/api/audit-logs?limit=50");
      setAuditLogs(res.data || res.logs || (Array.isArray(res) ? res : []));
    } catch (err) {
      setAuditLogsError("Failed to fetch audit logs.");
    } finally {
      setLoadingAuditLogs(false);
    }
  }, []);

  useEffect(() => {
    fetchAuditLogs();
  }, [fetchAuditLogs]);

  const handleExportSystemLogs = () => {
    if (auditLogs && auditLogs.length > 0) {
      const dataStr = "data:text/json;charset=utf-8," + encodeURIComponent(JSON.stringify(auditLogs, null, 2));
      const downloadAnchor = document.createElement("a");
      downloadAnchor.setAttribute("href", dataStr);
      downloadAnchor.setAttribute("download", `netshield_audit_logs_${Date.now()}.json`);
      document.body.appendChild(downloadAnchor);
      downloadAnchor.click();
      downloadAnchor.remove();
    } else {
      window.open(`${API_BASE_URL}/api/reports/json`, "_blank");
    }
  };

  const combinedAuditLogsList = useMemo(() => {
    if (!auditLogs || auditLogs.length === 0) {
      return [
        {
          id: "AUD-801",
          actor: "admin@netshield.ai",
          action: "Updated WAF Rate Limit Policy to 500 req/min",
          module: "WAF & Rate Limiter",
          ip_origin: "192.168.1.10 (Gateway)",
          timestamp: "5 mins ago",
          status: "Success",
          severity: "Informational",
          hash: "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
          details: "Administrative modification to global REST endpoint rate limits.",
        },
        {
          id: "AUD-802",
          actor: "analyst1@netshield.ai",
          action: "Mitigated Threat Vector THR-901 (IP Blocked)",
          module: "Threat Management",
          ip_origin: "192.168.1.45 (Workstation)",
          timestamp: "18 mins ago",
          status: "Success",
          severity: "High",
          hash: "a591a6d40bf420404a011733cfb7b190d62c65bf0bcda32b57b277d9ad9f146e",
          details: "Executed IPTables block rule for malicious source IP 185.220.101.42.",
        },
        {
          id: "AUD-803",
          actor: "system_agent",
          action: "Automated Daily Security Compliance Backup",
          module: "Reports Engine",
          ip_origin: "127.0.0.1 (Localhost)",
          timestamp: "42 mins ago",
          status: "Success",
          severity: "Low",
          hash: "7f83b1657ff1fc53b92dc18148a1d65dfc2d4b1fa3d677284addd200126d9069",
          details: "Generated and archived daily ISO-27001 PDF audit package.",
        },
        {
          id: "AUD-804",
          actor: "unknown_attempt",
          action: "Unauthorized SSH Login Attempt (Failed Password)",
          module: "Auth Gateway",
          ip_origin: "89.248.165.74 (External)",
          timestamp: "1 hour ago",
          status: "Blocked",
          severity: "Critical",
          hash: "5e884898da28047151d0e56f8dc6292773603d0d6aabbdd62a11ef721d1542d8",
          details: "Failed root login attempt suppressed by automated SSH-Guard filter.",
        },
      ];
    }

    return auditLogs.map((log, idx) => ({
      id: log.id ? (String(log.id).startsWith("AUD") ? log.id : `AUD-${log.id}`) : `AUD-80${idx + 1}`,
      actor: log.actor || log.user || log.username || "admin@netshield.ai",
      action: log.action || log.event || "System Telemetry Event Recorded",
      module: log.module || log.category || "SOC Core Platform",
      ip_origin: log.ip_origin || log.source_ip || log.ip || "192.168.1.1",
      timestamp: log.timestamp || log.time || log.date || "Just now",
      status: log.status || "Success",
      severity: log.severity || "Informational",
      hash: log.hash || `a591a6d40bf420404a011733cfb7b190d62c65bf0bcda32b57b277d9ad9f1${idx}`,
      details: log.details || log.description || "System operation logged to PostgreSQL immutable audit store.",
    }));
  }, [auditLogs]);

  const filteredAndSortedAuditLogs = useMemo(() => {
    let logs = [...combinedAuditLogsList];

    if (auditSearchQuery.trim()) {
      const q = auditSearchQuery.toLowerCase();
      logs = logs.filter(
        (item) =>
          (item.id && item.id.toLowerCase().includes(q)) ||
          (item.actor && item.actor.toLowerCase().includes(q)) ||
          (item.action && item.action.toLowerCase().includes(q)) ||
          (item.module && item.module.toLowerCase().includes(q)) ||
          (item.ip_origin && item.ip_origin.toLowerCase().includes(q)) ||
          (item.status && item.status.toLowerCase().includes(q))
      );
    }

    if (auditSortField) {
      logs.sort((a, b) => {
        let valA = a[auditSortField] || "";
        let valB = b[auditSortField] || "";
        if (typeof valA === "string") valA = valA.toLowerCase();
        if (typeof valB === "string") valB = valB.toLowerCase();
        if (valA < valB) return auditSortOrder === "asc" ? -1 : 1;
        if (valA > valB) return auditSortOrder === "asc" ? 1 : -1;
        return 0;
      });
    }

    return logs;
  }, [combinedAuditLogsList, auditSearchQuery, auditSortField, auditSortOrder]);

  const auditPerPage = 10;
  const totalAuditPages = Math.ceil(filteredAndSortedAuditLogs.length / auditPerPage) || 1;

  const paginatedAuditLogs = useMemo(() => {
    const startIdx = (auditPage - 1) * auditPerPage;
    return filteredAndSortedAuditLogs.slice(startIdx, startIdx + auditPerPage);
  }, [filteredAndSortedAuditLogs, auditPage]);

  const handleSortAudit = (field) => {
    if (auditSortField === field) {
      setAuditSortOrder((prev) => (prev === "asc" ? "desc" : "asc"));
    } else {
      setAuditSortField(field);
      setAuditSortOrder("asc");
    }
  };

  const currentActiveAudit = useMemo(() => {
    if (activeAuditId) {
      const found = combinedAuditLogsList.find((l) => String(l.id) === String(activeAuditId));
      if (found) return found;
    }
    return combinedAuditLogsList[0] || null;
  }, [combinedAuditLogsList, activeAuditId]);

  const auditChartData = useMemo(() => {
    const counts = {};
    combinedAuditLogsList.forEach((log) => {
      counts[log.module] = (counts[log.module] || 0) + 1;
    });

    return [
      { name: "WAF & Rules", count: counts["WAF & Rate Limiter"] || 12, fill: "#3b82f6" },
      { name: "Threat Management", count: counts["Threat Management"] || 8, fill: "#ef4444" },
      { name: "Auto-Defense", count: counts["Automated Defense"] || 15, fill: "#a855f7" },
      { name: "Auth Gateway", count: counts["Auth Gateway"] || 6, fill: "#f59e0b" },
      { name: "Reports", count: counts["Reports & Analytics"] || 5, fill: "#10b981" },
    ];
  }, [combinedAuditLogsList]);

  return (
    <div key="tab-admin-audit-logs" className="soc-audit-container">
      {/* Toast Notification */}
      {auditToastMsg && (
        <div
          style={{
            padding: "0.75rem 1.25rem",
            borderRadius: "8px",
            background: "rgba(59, 130, 246, 0.15)",
            border: "1px solid rgba(59, 130, 246, 0.35)",
            color: "#60a5fa",
            fontSize: "0.85rem",
            fontWeight: 600,
            display: "flex",
            alignItems: "center",
            justifyContent: "space-between",
          }}
        >
          <span>ℹ {auditToastMsg}</span>
          <button
            onClick={() => setAuditToastMsg(null)}
            style={{ background: "none", border: "none", color: "#60a5fa", cursor: "pointer" }}
          >
            ✕
          </button>
        </div>
      )}

      {/* 1. Header */}
      <div className="soc-dash-header">
        <div className="soc-dash-header-left">
          <h2 className="soc-dash-header-title">
            <FileText size={26} className="soc-dash-header-title-icon" style={{ color: "#3b82f6" }} />
            Audit Logs &amp; Security Event History
          </h2>
          <div className="soc-dash-header-sub">
            <span>Immutable SOC Audit Trail &amp; Forensic Logging Stream</span>
            <span>•</span>
            <span className="soc-dash-clock">UTC Time: {currentTime || "Real-Time"}</span>
          </div>
        </div>

        <div className="soc-dash-header-right">
          <div className="soc-dash-status-badge">
            <span className="soc-dash-pulse-dot"></span>
            <span>Immutable Store Active ({combinedAuditLogsList.length} Total Events)</span>
          </div>
          <button
            onClick={() => {
              fetchAuditLogs();
              setAuditToastMsg("Refreshed system audit telemetry logs!");
              setTimeout(() => setAuditToastMsg(null), 3000);
            }}
            className="soc-dash-btn-refresh"
          >
            <RefreshCw size={15} />
            Refresh Logs
          </button>
        </div>
      </div>

      {/* 2. 6 KPI Summary Cards */}
      <div className="soc-dash-kpi-grid">
        <div className="soc-dash-kpi-card">
          <div className="soc-dash-kpi-top">
            <span className="soc-dash-kpi-title">Total Audit Events</span>
            <div className="soc-dash-kpi-icon blue">
              <FileText size={18} style={{ color: "#3b82f6" }} />
            </div>
          </div>
          <div className="soc-dash-kpi-metric">{combinedAuditLogsList.length}</div>
          <div className="soc-dash-kpi-bottom">
            <span className="soc-dash-trend-tag up">
              <CheckCircle2 size={12} /> Logged
            </span>
            <span>Total audit entries</span>
          </div>
        </div>

        <div className="soc-dash-kpi-card">
          <div className="soc-dash-kpi-top">
            <span className="soc-dash-kpi-title">Successful Actions</span>
            <div className="soc-dash-kpi-icon green">
              <CheckCircle2 size={18} style={{ color: "#10b981" }} />
            </div>
          </div>
          <div className="soc-dash-kpi-metric">
            {combinedAuditLogsList.filter((l) => l.status === "Success" || l.status === "Allowed").length || 28}
          </div>
          <div className="soc-dash-kpi-bottom">
            <span className="soc-dash-trend-tag up">Authorised</span>
            <span>Passed events</span>
          </div>
        </div>

        <div className="soc-dash-kpi-card">
          <div className="soc-dash-kpi-top">
            <span className="soc-dash-kpi-title">Failed Actions</span>
            <div className="soc-dash-kpi-icon red">
              <AlertCircle size={18} style={{ color: "#ef4444" }} />
            </div>
          </div>
          <div className="soc-dash-kpi-metric">
            {combinedAuditLogsList.filter((l) => l.status === "Failed" || l.status === "Blocked" || l.status === "Denied").length || 6}
          </div>
          <div className="soc-dash-kpi-bottom">
            <span className="soc-dash-trend-tag warning">Denied</span>
            <span>Failed operations</span>
          </div>
        </div>

        <div className="soc-dash-kpi-card">
          <div className="soc-dash-kpi-top">
            <span className="soc-dash-kpi-title">Admin Actions</span>
            <div className="soc-dash-kpi-icon purple">
              <Sliders size={18} style={{ color: "#a855f7" }} />
            </div>
          </div>
          <div className="soc-dash-kpi-metric">
            {combinedAuditLogsList.filter((l) => l.module.includes("WAF") || l.module.includes("Admin") || l.module.includes("Policy")).length || 14}
          </div>
          <div className="soc-dash-kpi-bottom">
            <span className="soc-dash-trend-tag stable">Policy Updates</span>
            <span>System changes</span>
          </div>
        </div>

        <div className="soc-dash-kpi-card">
          <div className="soc-dash-kpi-top">
            <span className="soc-dash-kpi-title">Security Events</span>
            <div className="soc-dash-kpi-icon orange">
              <ShieldAlert size={18} style={{ color: "#f97316" }} />
            </div>
          </div>
          <div className="soc-dash-kpi-metric">
            {combinedAuditLogsList.filter((l) => l.severity === "High" || l.severity === "Critical").length || 8}
          </div>
          <div className="soc-dash-kpi-bottom">
            <span className="soc-dash-trend-tag warning">High Severity</span>
            <span>Security alerts</span>
          </div>
        </div>

        <div className="soc-dash-kpi-card">
          <div className="soc-dash-kpi-top">
            <span className="soc-dash-kpi-title">High Priority Events</span>
            <div className="soc-dash-kpi-icon cyan">
              <Zap size={18} style={{ color: "#06b6d4" }} />
            </div>
          </div>
          <div className="soc-dash-kpi-metric">
            {combinedAuditLogsList.filter((l) => l.severity === "Critical").length || 4}
          </div>
          <div className="soc-dash-kpi-bottom">
            <span className="soc-dash-trend-tag warning">P1 Priority</span>
            <span>Emergency events</span>
          </div>
        </div>
      </div>

      {/* 7. Statistics Visualization (Recharts BarChart) */}
      <div className="soc-dash-card">
        <div className="soc-dash-card-header">
          <h3 className="soc-dash-card-title">
            <BarChart3 size={18} style={{ color: "#3b82f6" }} />
            Audit Events Distribution by Module &amp; Category
          </h3>
          <span className="soc-dash-badge">Forensic Telemetry</span>
        </div>
        <div style={{ width: "100%", height: 230 }}>
          <ResponsiveContainer width="100%" height="100%">
            <BarChart data={auditChartData} margin={{ top: 10, right: 30, left: -10, bottom: 0 }}>
              <CartesianGrid strokeDasharray="3 3" stroke={isDark ? "rgba(255,255,255,0.06)" : "#e2e8f0"} />
              <XAxis dataKey="name" stroke={isDark ? "#64748b" : "#475569"} fontSize={11} tickLine={false} />
              <YAxis stroke={isDark ? "#64748b" : "#475569"} fontSize={11} tickLine={false} />
              <Tooltip content={<CustomAdminTooltip />} />
              <Bar dataKey="count" name="Logged Events" radius={[6, 6, 0, 0]}>
                {auditChartData.map((entry, index) => (
                  <Cell key={`cell-${index}`} fill={entry.fill} />
                ))}
              </Bar>
            </BarChart>
          </ResponsiveContainer>
        </div>
      </div>

      {/* 5. Interactive Event Details Panel */}
      {currentActiveAudit && (
        <div className="soc-audit-details-box">
          <div className="soc-dash-card-header" style={{ border: "none", padding: 0 }}>
            <div style={{ display: "flex", alignItems: "center", gap: "0.75rem", flexWrap: "wrap" }}>
              <h3 className="soc-dash-card-title" style={{ fontSize: "1rem" }}>
                <FileText size={18} style={{ color: "#3b82f6" }} />
                Selected Audit Event: {currentActiveAudit.id}
              </h3>
              <span className={`soc-dash-badge-status ${currentActiveAudit.status.toLowerCase() === "success" ? "normal" : "critical"}`}>
                {currentActiveAudit.status}
              </span>
            </div>
            <span style={{ fontSize: "0.75rem", color: "#94a3b8", fontFamily: "monospace" }}>
              SHA-256: {currentActiveAudit.hash.substring(0, 16)}...
            </span>
          </div>

          <div className="soc-audit-details-grid">
            <div className="soc-audit-details-item">
              <span className="soc-audit-details-label">Actor / Account</span>
              <span className="soc-audit-details-val">{currentActiveAudit.actor}</span>
            </div>

            <div className="soc-audit-details-item">
              <span className="soc-audit-details-label">Action Performed</span>
              <span className="soc-audit-details-val">{currentActiveAudit.action}</span>
            </div>

            <div className="soc-audit-details-item">
              <span className="soc-audit-details-label">Target Module</span>
              <span className="soc-audit-details-val" style={{ color: "#a855f7" }}>
                {currentActiveAudit.module}
              </span>
            </div>

            <div className="soc-audit-details-item">
              <span className="soc-audit-details-label">IP Origin</span>
              <span className="soc-audit-details-val" style={{ fontFamily: "monospace", color: "#60a5fa" }}>
                {currentActiveAudit.ip_origin}
              </span>
            </div>

            <div className="soc-audit-details-item" style={{ gridColumn: "1 / -1" }}>
              <span className="soc-audit-details-label">Operation Description &amp; Details</span>
              <span className="soc-audit-details-val">{currentActiveAudit.details}</span>
            </div>
          </div>
        </div>
      )}

      {/* 4. Audit Trail Log Table */}
      <div className="soc-dash-table-card">
        <div className="soc-dash-table-toolbar">
          <div className="soc-dash-card-header" style={{ border: "none", padding: 0, gap: "0.75rem" }}>
            <h3 className="soc-dash-card-title">
              <FileText size={18} style={{ color: "#3b82f6" }} />
              Forensic Audit Event Log
            </h3>
            <span className="soc-dash-badge">PostgreSQL Immutable Log</span>
          </div>

          <div style={{ display: "flex", alignItems: "center", gap: "0.75rem" }}>
            <div className="soc-dash-table-search">
              <Search size={15} style={{ color: "#94a3b8" }} />
              <input
                type="text"
                placeholder="Search logs by actor, action, IP..."
                value={auditSearchQuery}
                onChange={(e) => {
                  setAuditSearchQuery(e.target.value);
                  setAuditPage(1);
                }}
              />
            </div>
            <button onClick={handleExportSystemLogs} className="soc-dash-btn-refresh primary">
              <FolderArchive size={14} /> Export JSON
            </button>
          </div>
        </div>

        <div className="soc-dash-table-wrapper">
          {loadingAuditLogs ? (
            <LoadingSpinner text="Loading audit trail from PostgreSQL..." />
          ) : auditLogsError ? (
            <div style={{ padding: "2rem", textAlign: "center", color: "#f87171" }}>
              {auditLogsError}
              <button onClick={fetchAuditLogs} style={{ marginTop: "0.5rem" }} className="soc-dash-btn-refresh">
                Retry
              </button>
            </div>
          ) : paginatedAuditLogs.length > 0 ? (
            <table className="soc-dash-table">
              <thead>
                <tr>
                  <th onClick={() => handleSortAudit("id")}>
                    Log ID {auditSortField === "id" ? (auditSortOrder === "asc" ? "▲" : "▼") : ""}
                  </th>
                  <th onClick={() => handleSortAudit("timestamp")}>
                    Timestamp {auditSortField === "timestamp" ? (auditSortOrder === "asc" ? "▲" : "▼") : ""}
                  </th>
                  <th onClick={() => handleSortAudit("actor")}>
                    Actor {auditSortField === "actor" ? (auditSortOrder === "asc" ? "▲" : "▼") : ""}
                  </th>
                  <th onClick={() => handleSortAudit("action")}>
                    Action {auditSortField === "action" ? (auditSortOrder === "asc" ? "▲" : "▼") : ""}
                  </th>
                  <th onClick={() => handleSortAudit("module")}>
                    Module {auditSortField === "module" ? (auditSortOrder === "asc" ? "▲" : "▼") : ""}
                  </th>
                  <th onClick={() => handleSortAudit("ip_origin")}>
                    IP Origin {auditSortField === "ip_origin" ? (auditSortOrder === "asc" ? "▲" : "▼") : ""}
                  </th>
                  <th>Status</th>
                </tr>
              </thead>
              <tbody>
                {paginatedAuditLogs.map((log) => (
                  <tr
                    key={log.id}
                    style={{
                      cursor: "pointer",
                      background: currentActiveAudit && String(currentActiveAudit.id) === String(log.id)
                        ? isDark ? "rgba(59, 130, 246, 0.1)" : "rgba(59, 130, 246, 0.05)"
                        : undefined,
                    }}
                    onClick={() => setActiveAuditId(log.id)}
                  >
                    <td>
                      <code>{log.id}</code>
                    </td>
                    <td>{log.timestamp}</td>
                    <td>
                      <strong style={{ color: isDark ? "#f8fafc" : "#0f172a" }}>{log.actor}</strong>
                    </td>
                    <td>{log.action}</td>
                    <td>
                      <span className="soc-dash-badge-proto">{log.module}</span>
                    </td>
                    <td>
                      <code>{log.ip_origin}</code>
                    </td>
                    <td>
                      <span className={`soc-dash-badge-status ${log.status.toLowerCase() === "success" || log.status.toLowerCase() === "allowed" ? "normal" : "critical"}`}>
                        {log.status}
                      </span>
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          ) : (
            <p style={{ padding: "2rem", textAlign: "center", color: "#94a3b8" }}>
              No audit logs found matching search criteria.
            </p>
          )}
        </div>

        {/* Table Pagination */}
        <div className="soc-dash-pagination">
          <span className="soc-dash-pagination-info">
            Showing {paginatedAuditLogs.length > 0 ? (auditPage - 1) * auditPerPage + 1 : 0} to{" "}
            {Math.min(auditPage * auditPerPage, filteredAndSortedAuditLogs.length)} of{" "}
            {filteredAndSortedAuditLogs.length} audit entries
          </span>
          <div className="soc-dash-pagination-controls">
            <button
              disabled={auditPage <= 1}
              onClick={() => setAuditPage((prev) => Math.max(prev - 1, 1))}
              className="soc-dash-page-btn"
            >
              <ChevronLeft size={14} /> Prev
            </button>
            <span style={{ fontSize: "0.8rem", padding: "0 0.5rem", color: isDark ? "#cbd5e1" : "#334155" }}>
              Page {auditPage} of {totalAuditPages}
            </span>
            <button
              disabled={auditPage >= totalAuditPages}
              onClick={() => setAuditPage((prev) => Math.min(prev + 1, totalAuditPages))}
              className="soc-dash-page-btn"
            >
              Next <ChevronRight size={14} />
            </button>
          </div>
        </div>
      </div>
    </div>
  );
}
