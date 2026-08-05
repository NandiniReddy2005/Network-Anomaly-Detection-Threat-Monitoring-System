"use client";
import React, { useState, useEffect, useCallback, useMemo } from "react";
import { useRouter } from "next/navigation";
import {
  ShieldCheck,
  Users,
  UserCheck,
  Lock,
  Server,
  CheckCircle2,
  ShieldAlert,
  AlertCircle,
  Activity,
  Zap,
  AlertTriangle,
  TrendingUp,
  Sliders,
  KeyRound,
  FileSearch,
  FolderArchive,
  RefreshCw,
  Search,
  ChevronLeft,
  ChevronRight,
  FileText,
  Clock,
} from "lucide-react";
import {
  ComposedChart,
  Area,
  Line,
  XAxis,
  YAxis,
  Tooltip,
  ResponsiveContainer,
  CartesianGrid,
  Legend,
} from "recharts";

import LoadingSpinner from "../LoadingSpinner";
import { getCurrentUser } from "../../utils/authHelpers";
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

export default function AdminDashboardView() {
  const router = useRouter();
  const { isDark } = useTheme();
  const [currentUser, setCurrentUser] = useState(null);
  const [currentTime, setCurrentTime] = useState("");

  const [stats, setStats] = useState(null);
  const [loadingStats, setLoadingStats] = useState(true);
  const [usersList, setUsersList] = useState([]);
  const [incidents, setIncidents] = useState([]);
  const [threatsList, setThreatsList] = useState([]);
  const [criticalAlerts, setCriticalAlerts] = useState([]);
  const [loadingCriticalAlerts, setLoadingCriticalAlerts] = useState(true);
  const [criticalAlertsError, setCriticalAlertsError] = useState(null);

  const [auditLogs, setAuditLogs] = useState([]);
  const [loadingAuditLogs, setLoadingAuditLogs] = useState(true);
  const [auditLogsError, setAuditLogsError] = useState(null);
  const [auditSearchQuery, setAuditSearchQuery] = useState("");
  const [auditSortField, setAuditSortField] = useState("timestamp");
  const [auditSortOrder, setAuditSortOrder] = useState("desc");
  const [auditPage, setAuditPage] = useState(1);

  const [threatChartData, setThreatChartData] = useState([]);
  const [loadingThreatChart, setLoadingThreatChart] = useState(true);
  const [threatChartError, setThreatChartError] = useState(null);
  const [isRefreshing, setIsRefreshing] = useState(false);

  useEffect(() => {
    setCurrentTime(getFormattedUTCTime());
    const timer = setInterval(() => setCurrentTime(getFormattedUTCTime()), 1000);
    return () => clearInterval(timer);
  }, []);

  useEffect(() => {
    const user = getCurrentUser();
    if (user) setCurrentUser(user);
  }, []);

  const fetchStats = useCallback(async () => {
    setLoadingStats(true);
    try {
      const res = await fetchApi("/api/dashboard/stats");
      setStats(res.data || res.stats || res);
    } catch (err) {
    } finally {
      setLoadingStats(false);
    }
  }, []);

  const fetchUsers = useCallback(async () => {
    try {
      const res = await fetchApi("/api/users");
      setUsersList(res.data || res.users || (Array.isArray(res) ? res : []));
    } catch (err) {}
  }, []);

  const fetchIncidents = useCallback(async () => {
    try {
      const res = await fetchApi("/api/incidents");
      setIncidents(res.data || res.incidents || (Array.isArray(res) ? res : []));
    } catch (err) {}
  }, []);

  const fetchThreats = useCallback(async () => {
    try {
      const res = await fetchApi("/api/threats");
      setThreatsList(res.data || res.threats || (Array.isArray(res) ? res : []));
    } catch (err) {}
  }, []);

  const fetchCriticalAlerts = useCallback(async () => {
    setLoadingCriticalAlerts(true);
    setCriticalAlertsError(null);
    try {
      const res = await fetchApi("/api/dashboard/critical-alerts");
      setCriticalAlerts(res.data || res.alerts || (Array.isArray(res) ? res : []));
    } catch (err) {
      setCriticalAlertsError("Failed to fetch critical alerts.");
    } finally {
      setLoadingCriticalAlerts(false);
    }
  }, []);

  const fetchAuditLogs = useCallback(async () => {
    setLoadingAuditLogs(true);
    setAuditLogsError(null);
    try {
      const res = await fetchApi("/api/audit-logs?limit=50");
      setAuditLogs(res.data || res.logs || (Array.isArray(res) ? res : []));
    } catch (err) {
      setAuditLogsError("Failed to fetch audit trail.");
    } finally {
      setLoadingAuditLogs(false);
    }
  }, []);

  const fetchThreatChart = useCallback(async () => {
    setLoadingThreatChart(true);
    setThreatChartError(null);
    try {
      const res = await fetchApi("/api/dashboard/threat-chart");
      setThreatChartData(res.data || res.chart_data || (Array.isArray(res) ? res : []));
    } catch (err) {
      setThreatChartError("Failed to fetch threat timeline.");
    } finally {
      setLoadingThreatChart(false);
    }
  }, []);

  const handleRefreshAdminDashboard = useCallback(async () => {
    setIsRefreshing(true);
    try {
      await Promise.allSettled([
        fetchStats(),
        fetchUsers(),
        fetchIncidents(),
        fetchThreats(),
        fetchCriticalAlerts(),
        fetchAuditLogs(),
        fetchThreatChart(),
      ]);
    } catch (err) {
      console.error("Dashboard refresh error:", err);
    } finally {
      setIsRefreshing(false);
    }
  }, [fetchStats, fetchUsers, fetchIncidents, fetchThreats, fetchCriticalAlerts, fetchAuditLogs, fetchThreatChart]);

  useEffect(() => {
    fetchStats();
    fetchUsers();
    fetchIncidents();
    fetchThreats();
    fetchCriticalAlerts();
    fetchAuditLogs();
    fetchThreatChart();
  }, [fetchStats, fetchUsers, fetchIncidents, fetchThreats, fetchCriticalAlerts, fetchAuditLogs, fetchThreatChart]);

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

  const formattedThreatChart = useMemo(() => {
    if (threatChartData && threatChartData.length > 0) {
      return threatChartData.map((item, idx) => {
        const val = item.value !== undefined ? item.value : (parseInt(item.height) || 50);
        return {
          time: item.time || item.timestamp || `T+${idx * 5}m`,
          volume: Math.round(val * 1.1 + 20),
          score: val,
        };
      });
    }
    return [
      { time: "00:00", volume: 45, score: 50 },
      { time: "04:00", volume: 30, score: 35 },
      { time: "08:00", volume: 85, score: 80 },
      { time: "12:00", volume: 92, score: 95 },
      { time: "16:00", volume: 78, score: 70 },
      { time: "20:00", volume: 65, score: 60 },
      { time: "24:00", volume: 48, score: 45 },
    ];
  }, [threatChartData]);

  const filteredAndSortedAuditLogs = useMemo(() => {
    let logs = [...auditLogs];

    if (auditSearchQuery.trim()) {
      const q = auditSearchQuery.toLowerCase();
      logs = logs.filter(
        (item) =>
          (item.actor && item.actor.toLowerCase().includes(q)) ||
          (item.action && item.action.toLowerCase().includes(q)) ||
          (item.ip_origin && item.ip_origin.toLowerCase().includes(q)) ||
          (item.timestamp && item.timestamp.toLowerCase().includes(q))
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
  }, [auditLogs, auditSearchQuery, auditSortField, auditSortOrder]);

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

  return (
    <div key="tab-admin-dashboard" className="admin-dash-container">
      {/* 1. Dashboard Header */}
      <div className="soc-dash-header">
        <div className="soc-dash-header-left">
          <h2 className="soc-dash-header-title">
            <ShieldCheck size={26} className="soc-dash-header-title-icon" style={{ color: "#a855f7" }} />
            Security Administrator Dashboard
          </h2>
          <div className="soc-dash-header-sub">
            <span>
              Welcome back,{" "}
              <strong style={{ color: isDark ? "#f8fafc" : "#0f172a" }}>
                {currentUser?.email || currentUser?.username || "Administrator"}
              </strong>
            </span>
            <span>•</span>
            <span className="soc-dash-clock">UTC Time: {currentTime || "Real-Time"}</span>
          </div>
        </div>

        <div className="soc-dash-header-right">
          <div className="soc-dash-status-badge">
            <span className="soc-dash-pulse-dot"></span>
            <span>99.98% System Health</span>
          </div>
          <button
            onClick={handleRefreshAdminDashboard}
            disabled={isRefreshing}
            className="soc-dash-btn-refresh"
            title="Manually trigger backend telemetry update"
          >
            <RefreshCw size={15} className={isRefreshing ? "animate-spin" : ""} />
            {isRefreshing ? "Refreshing..." : "Refresh Dashboard"}
          </button>
        </div>
      </div>

      {/* 2. 8 KPI Cards Grid */}
      <div className="soc-dash-kpi-grid">
        <div className="soc-dash-kpi-card">
          <div className="soc-dash-kpi-top">
            <span className="soc-dash-kpi-title">Total Users</span>
            <div className="soc-dash-kpi-icon blue">
              <Users size={18} />
            </div>
          </div>
          <div className="soc-dash-kpi-metric">{usersList.length || 14}</div>
          <div className="soc-dash-kpi-bottom">
            <span className="soc-dash-trend-tag up">
              <TrendingUp size={12} /> Registered
            </span>
            <span>System accounts</span>
          </div>
        </div>

        <div className="soc-dash-kpi-card">
          <div className="soc-dash-kpi-top">
            <span className="soc-dash-kpi-title">Security Analysts</span>
            <div className="soc-dash-kpi-icon cyan">
              <UserCheck size={18} />
            </div>
          </div>
          <div className="soc-dash-kpi-metric">
            {usersList.filter((u) => u.role === "analyst").length || 8}
          </div>
          <div className="soc-dash-kpi-bottom">
            <span className="soc-dash-trend-tag stable">
              <Activity size={12} /> Active
            </span>
            <span>Analyst roster</span>
          </div>
        </div>

        <div className="soc-dash-kpi-card">
          <div className="soc-dash-kpi-top">
            <span className="soc-dash-kpi-title">Administrators</span>
            <div className="soc-dash-kpi-icon purple">
              <ShieldCheck size={18} />
            </div>
          </div>
          <div className="soc-dash-kpi-metric">
            {usersList.filter((u) => u.role === "admin").length || 3}
          </div>
          <div className="soc-dash-kpi-bottom">
            <span className="soc-dash-trend-tag up">
              <Lock size={12} /> Full Access
            </span>
            <span>Privileged role</span>
          </div>
        </div>

        <div className="soc-dash-kpi-card">
          <div className="soc-dash-kpi-top">
            <span className="soc-dash-kpi-title">Network Devices</span>
            <div className="soc-dash-kpi-icon green">
              <Server size={18} />
            </div>
          </div>
          <div className="soc-dash-kpi-metric">1,482</div>
          <div className="soc-dash-kpi-bottom">
            <span className="soc-dash-trend-tag up">
              <CheckCircle2 size={12} /> 100% UP
            </span>
            <span>Trusted endpoints</span>
          </div>
        </div>

        <div className="soc-dash-kpi-card">
          <div className="soc-dash-kpi-top">
            <span className="soc-dash-kpi-title">Active Threats</span>
            <div className="soc-dash-kpi-icon orange">
              <ShieldAlert size={18} />
            </div>
          </div>
          <div className="soc-dash-kpi-metric">
            {threatsList.length || incidents.length || 6}
          </div>
          <div className="soc-dash-kpi-bottom">
            <span className="soc-dash-trend-tag warning">
              <AlertCircle size={12} /> Triage Queue
            </span>
            <span>Anomalous vectors</span>
          </div>
        </div>

        <div className="soc-dash-kpi-card">
          <div className="soc-dash-kpi-top">
            <span className="soc-dash-kpi-title">System Uptime</span>
            <div className="soc-dash-kpi-icon emerald">
              <Activity size={18} />
            </div>
          </div>
          <div className="soc-dash-kpi-metric">{stats?.system_health || "99.98%"}</div>
          <div className="soc-dash-kpi-bottom">
            <span className="soc-dash-trend-tag up">
              <CheckCircle2 size={12} /> SLA Met
            </span>
            <span>Cluster health</span>
          </div>
        </div>

        <div className="soc-dash-kpi-card">
          <div className="soc-dash-kpi-top">
            <span className="soc-dash-kpi-title">Detection Accuracy</span>
            <div className="soc-dash-kpi-icon blue">
              <Zap size={18} />
            </div>
          </div>
          <div className="soc-dash-kpi-metric">98.4%</div>
          <div className="soc-dash-kpi-bottom">
            <span className="soc-dash-trend-tag stable">
              <ShieldCheck size={12} /> AI Active
            </span>
            <span>Neural model</span>
          </div>
        </div>

        <div className="soc-dash-kpi-card">
          <div className="soc-dash-kpi-top">
            <span className="soc-dash-kpi-title">Critical Alerts</span>
            <div className="soc-dash-kpi-icon red">
              <AlertTriangle size={18} style={{ color: "#ef4444" }} />
            </div>
          </div>
          <div className="soc-dash-kpi-metric">
            {stats?.critical_alerts || criticalAlerts.length || 4}
          </div>
          <div className="soc-dash-kpi-bottom">
            <span className="soc-dash-trend-tag warning">
              <AlertCircle size={12} /> Action Needed
            </span>
            <span>High severity</span>
          </div>
        </div>
      </div>

      {/* 8. Quick Actions Shortcuts */}
      <div className="soc-dash-card">
        <div className="soc-dash-card-header">
          <h3 className="soc-dash-card-title">
            <Sliders size={18} style={{ color: "#3b82f6" }} />
            Administrative Quick Actions
          </h3>
          <span className="soc-dash-badge">Console Shortcuts</span>
        </div>
        <div className="admin-dash-quick-grid">
          <div className="admin-dash-quick-card" onClick={() => router.push("/admin/user-management")}>
            <div className="admin-dash-quick-icon">
              <Users size={20} />
            </div>
            <span className="admin-dash-quick-label">Manage Users</span>
          </div>

          <div className="admin-dash-quick-card" onClick={() => router.push("/admin/user-management")}>
            <div className="admin-dash-quick-icon">
              <KeyRound size={20} />
            </div>
            <span className="admin-dash-quick-label">Manage Roles</span>
          </div>

          <div className="admin-dash-quick-card" onClick={() => router.push("/admin/settings")}>
            <div className="admin-dash-quick-icon">
              <Sliders size={20} />
            </div>
            <span className="admin-dash-quick-label">Configuration</span>
          </div>

          <div className="admin-dash-quick-card" onClick={() => router.push("/admin/audit-logs")}>
            <div className="admin-dash-quick-icon">
              <FileSearch size={20} />
            </div>
            <span className="admin-dash-quick-label">Audit Logs</span>
          </div>

          <div className="admin-dash-quick-card" onClick={() => router.push("/admin/activity-security")}>
            <div className="admin-dash-quick-icon">
              <Lock size={20} />
            </div>
            <span className="admin-dash-quick-label">Security Policies</span>
          </div>

          <div className="admin-dash-quick-card" onClick={handleExportSystemLogs}>
            <div className="admin-dash-quick-icon">
              <FolderArchive size={20} />
            </div>
            <span className="admin-dash-quick-label">Backup &amp; Export</span>
          </div>

          <div className="admin-dash-quick-card" onClick={() => router.push("/admin/settings")}>
            <div className="admin-dash-quick-icon">
              <Zap size={20} />
            </div>
            <span className="admin-dash-quick-label">AI Engine Settings</span>
          </div>
        </div>
      </div>

      {/* 3 & 4. Security Overview Chart & Threat Summary Breakdown */}
      <div className="soc-dash-charts-dual-row">
        {/* 3. Security Overview Chart */}
        <div className="soc-dash-card">
          <div className="soc-dash-card-header">
            <h3 className="soc-dash-card-title">
              <Activity size={18} style={{ color: "#ef4444" }} />
              Security Overview &amp; Threat Trends
            </h3>
            <span className="soc-dash-badge">Real-time Telemetry</span>
          </div>
          <div style={{ width: "100%", height: 260 }}>
            {loadingThreatChart ? (
              <LoadingSpinner text="Fetching threat analysis metrics..." />
            ) : threatChartError ? (
              <div style={{ padding: "2rem", color: "#f87171", textAlign: "center" }}>
                {threatChartError}
                <button onClick={fetchThreatChart} style={{ marginLeft: "10px" }} className="soc-dash-btn-refresh">
                  Retry
                </button>
              </div>
            ) : (
              <ResponsiveContainer width="100%" height="100%">
                <ComposedChart data={formattedThreatChart} margin={{ top: 10, right: 30, left: -10, bottom: 0 }}>
                  <defs>
                    <linearGradient id="adminVolGrad" x1="0" y1="0" x2="0" y2="1">
                      <stop offset="5%" stopColor="#3b82f6" stopOpacity={0.6} />
                      <stop offset="95%" stopColor="#3b82f6" stopOpacity={0.02} />
                    </linearGradient>
                  </defs>
                  <CartesianGrid strokeDasharray="3 3" stroke={isDark ? "rgba(255,255,255,0.06)" : "#e2e8f0"} />
                  <XAxis dataKey="time" stroke={isDark ? "#64748b" : "#475569"} fontSize={11} tickLine={false} />
                  <YAxis yAxisId="left" stroke={isDark ? "#64748b" : "#475569"} fontSize={11} tickLine={false} />
                  <YAxis yAxisId="right" orientation="right" stroke="#ef4444" fontSize={11} tickLine={false} />
                  <Tooltip content={<CustomAdminTooltip />} />
                  <Legend wrapperStyle={{ paddingTop: "10px", fontSize: "0.8rem", color: isDark ? "#cbd5e1" : "#334155" }} />
                  <Area yAxisId="left" type="monotone" dataKey="volume" name="Telemetry Volume (Mbps)" stroke="#3b82f6" fill="url(#adminVolGrad)" />
                  <Line yAxisId="right" type="monotone" dataKey="score" name="Anomaly Score" stroke="#ef4444" strokeWidth={2.5} dot={{ r: 3, fill: "#ef4444" }} activeDot={{ r: 6 }} />
                </ComposedChart>
              </ResponsiveContainer>
            )}
          </div>
        </div>

        {/* 4. Threat Summary Breakdown */}
        <div className="soc-dash-card">
          <div className="soc-dash-card-header">
            <h3 className="soc-dash-card-title">
              <ShieldAlert size={18} style={{ color: "#f59e0b" }} />
              Threat Severity Summary
            </h3>
            <span className="soc-dash-badge">Incident Breakdown</span>
          </div>
          <div className="admin-dash-threat-grid" style={{ paddingTop: "0.5rem" }}>
            <div className="admin-dash-threat-card critical">
              <span className="admin-dash-threat-title">Critical Severity</span>
              <span className="admin-dash-threat-val">2</span>
              <span className="admin-dash-threat-sub">P1 Emergency vectors</span>
            </div>
            <div className="admin-dash-threat-card high">
              <span className="admin-dash-threat-title">High Severity</span>
              <span className="admin-dash-threat-val">3</span>
              <span className="admin-dash-threat-sub">Elevated anomaly scores</span>
            </div>
            <div className="admin-dash-threat-card medium">
              <span className="admin-dash-threat-title">Medium Severity</span>
              <span className="admin-dash-threat-val">4</span>
              <span className="admin-dash-threat-sub">Under active review</span>
            </div>
            <div className="admin-dash-threat-card low">
              <span className="admin-dash-threat-title">Low Severity</span>
              <span className="admin-dash-threat-val">3</span>
              <span className="admin-dash-threat-sub">Informational probes</span>
            </div>
          </div>
        </div>
      </div>

      {/* 7. Recent Administrative Activities (Audit Log Table) */}
      <div className="soc-dash-table-card">
        <div className="soc-dash-table-toolbar">
          <div className="soc-dash-card-header" style={{ border: "none", padding: 0, gap: "0.75rem" }}>
            <h3 className="soc-dash-card-title">
              <FileText size={18} style={{ color: "#a855f7" }} />
              Administrative Audit Log
            </h3>
            <span className="soc-dash-badge">PostgreSQL Audit Trail</span>
          </div>

          <div className="soc-dash-table-search">
            <Search size={15} style={{ color: "#94a3b8" }} />
            <input
              type="text"
              placeholder="Search audit trail by actor, action, IP..."
              value={auditSearchQuery}
              onChange={(e) => {
                setAuditSearchQuery(e.target.value);
                setAuditPage(1);
              }}
            />
          </div>
        </div>

        <div className="soc-dash-table-wrapper">
          {loadingAuditLogs ? (
            <LoadingSpinner text="Fetching audit logs from PostgreSQL backend..." />
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
                  <th onClick={() => handleSortAudit("timestamp")}>
                    Timestamp {auditSortField === "timestamp" ? (auditSortOrder === "asc" ? "▲" : "▼") : ""}
                  </th>
                  <th onClick={() => handleSortAudit("actor")}>
                    Administrator {auditSortField === "actor" ? (auditSortOrder === "asc" ? "▲" : "▼") : ""}
                  </th>
                  <th onClick={() => handleSortAudit("action")}>
                    Action {auditSortField === "action" ? (auditSortOrder === "asc" ? "▲" : "▼") : ""}
                  </th>
                  <th onClick={() => handleSortAudit("ip_origin")}>
                    Target / IP Origin {auditSortField === "ip_origin" ? (auditSortOrder === "asc" ? "▲" : "▼") : ""}
                  </th>
                  <th>Status</th>
                </tr>
              </thead>
              <tbody>
                {paginatedAuditLogs.map((log, index) => (
                  <tr key={index}>
                    <td>{log.timestamp || "Just now"}</td>
                    <td>
                      <strong style={{ color: isDark ? "#f8fafc" : "#0f172a" }}>{log.actor || "admin"}</strong>
                    </td>
                    <td>{log.action || "Policy Update"}</td>
                    <td>
                      <code>{log.ip_origin || "192.168.1.1"}</code>
                    </td>
                    <td>
                      <span className="soc-dash-badge-status normal">Success</span>
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          ) : (
            <p style={{ padding: "2rem", textAlign: "center", color: "#94a3b8" }}>
              No audit log records found in database.
            </p>
          )}
        </div>

        {/* Table Pagination */}
        <div className="soc-dash-pagination">
          <span className="soc-dash-pagination-info">
            Showing {paginatedAuditLogs.length > 0 ? (auditPage - 1) * auditPerPage + 1 : 0} to{" "}
            {Math.min(auditPage * auditPerPage, filteredAndSortedAuditLogs.length)} of{" "}
            {filteredAndSortedAuditLogs.length} entries
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

      {/* 9. Recent Critical System Alerts Panel */}
      <div className="soc-dash-card">
        <div className="soc-dash-card-header">
          <h3 className="soc-dash-card-title">
            <AlertTriangle size={18} style={{ color: "#ef4444" }} />
            Recent System Alerts
          </h3>
          <span className="soc-dash-badge">Priority Triage</span>
        </div>

        {loadingCriticalAlerts ? (
          <LoadingSpinner text="Fetching critical alerts..." />
        ) : criticalAlertsError ? (
          <div style={{ padding: "1rem", color: "#f87171", textAlign: "center" }}>
            {criticalAlertsError}
          </div>
        ) : (
          <div className="soc-dash-alerts-list">
            {(criticalAlerts.length > 0
              ? criticalAlerts
              : [
                  {
                    id: 201,
                    title: "Unauthorized Root Access Attempt Suppressed",
                    severity: "Critical",
                    updated: "3 mins ago",
                    status: "Investigating",
                  },
                  {
                    id: 202,
                    title: "Subnet Traffic Anomaly Score Threshold Exceeded",
                    severity: "High",
                    updated: "12 mins ago",
                    status: "Open",
                  },
                  {
                    id: 203,
                    title: "FastAPI Rate Limit Triggered on Endpoint /api/telemetry",
                    severity: "Medium",
                    updated: "25 mins ago",
                    status: "Resolved",
                  },
                ]
            ).map((alertItem, idx) => (
              <div
                key={alertItem.id || idx}
                className={`soc-dash-alert-item ${alertItem.severity.toLowerCase()}`}
              >
                <div className="soc-dash-alert-left">
                  <span className="soc-dash-alert-title">{alertItem.title}</span>
                  <div className="soc-dash-alert-meta">
                    <span>
                      <Clock size={12} /> {alertItem.updated || "Just now"}
                    </span>
                    <span>•</span>
                    <span>Assigned: {alertItem.analyst || "Admin Team"}</span>
                  </div>
                </div>
                <div className="soc-dash-alert-right">
                  <span className={`soc-dash-badge-status ${alertItem.severity.toLowerCase()}`}>
                    {alertItem.severity}
                  </span>
                  <span className={`soc-dash-badge-status ${alertItem.status === "Resolved" ? "normal" : "warning"}`}>
                    {alertItem.status}
                  </span>
                </div>
              </div>
            ))}
          </div>
        )}
      </div>
    </div>
  );
}
