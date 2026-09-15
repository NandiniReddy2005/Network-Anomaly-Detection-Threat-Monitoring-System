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
  const [mlStatus, setMlStatus] = useState(null);

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
  const [hoveredModuleIndex, setHoveredModuleIndex] = useState(null);
  const [dashboardStatus, setDashboardStatus] = useState(null);

  const fetchDashboardStatus = useCallback(async () => {
    try {
      const res = await fetchApi("/api/dashboard/status");
      if (res && (res.status === "success" || res.system_gateway_status)) {
        setDashboardStatus(res);
      }
    } catch (err) {
      console.warn("Failed to fetch dashboard status:", err);
    }
  }, []);

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
        fetchDashboardStatus(),
      ]);
    } catch (err) {
      console.error("Dashboard refresh error:", err);
    } finally {
      setIsRefreshing(false);
    }
  }, [fetchStats, fetchUsers, fetchIncidents, fetchThreats, fetchCriticalAlerts, fetchAuditLogs, fetchThreatChart, fetchDashboardStatus]);

  useEffect(() => {
    fetchStats();
    fetchUsers();
    fetchIncidents();
    fetchThreats();
    fetchCriticalAlerts();
    fetchAuditLogs();
    fetchThreatChart();
    fetchDashboardStatus();

    const statusInterval = setInterval(() => {
      fetchDashboardStatus();
    }, 5000);

    return () => clearInterval(statusInterval);
  }, [fetchStats, fetchUsers, fetchIncidents, fetchThreats, fetchCriticalAlerts, fetchAuditLogs, fetchThreatChart, fetchDashboardStatus]);

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
              Welcome,{" "}
              <strong style={{ color: isDark ? "#f8fafc" : "#0f172a" }}>
                Security Administrator
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

      {/* 2. Operational Telemetry & System Status Cards (4 Standalone PostgreSQL Metric Cards) */}
      <div className="soc-dash-kpi-grid" style={{ marginBottom: "1.5rem" }}>
        {/* Card 1: System Gateway Status */}
        <div className="soc-dash-kpi-card">
          <div className="soc-dash-kpi-top">
            <span className="soc-dash-kpi-title">System Gateway Status</span>
            <div className="soc-dash-kpi-icon green">
              <Server size={18} style={{ color: "#10b981" }} />
            </div>
          </div>
          <div className="soc-dash-kpi-metric" style={{ fontSize: "1.05rem", fontWeight: 700, color: "#10b981" }}>
            {dashboardStatus?.system_gateway_status || "Operational (200 OK)"}
          </div>
          <div className="soc-dash-kpi-bottom">
            <span className="soc-dash-trend-tag up">
              <CheckCircle2 size={12} /> Active
            </span>
            <span>PostgreSQL Gateway Status</span>
          </div>
        </div>

        {/* Card 2: FastAPI ML Pipeline State */}
        <div className="soc-dash-kpi-card">
          <div className="soc-dash-kpi-top">
            <span className="soc-dash-kpi-title">FastAPI ML Pipeline State</span>
            <div className="soc-dash-kpi-icon cyan">
              <Zap size={18} style={{ color: "#38bdf8" }} />
            </div>
          </div>
          <div className="soc-dash-kpi-metric" style={{ fontSize: "1.05rem", fontWeight: 700, color: "#38bdf8" }}>
            {dashboardStatus?.ml_engine_status || "Engine Active (UNSW-NB15 / CICIDS2017)"}
          </div>
          <div className="soc-dash-kpi-bottom">
            <span className="soc-dash-trend-tag up">
              ● Neural Engine
            </span>
            <span>Dual Model Inference</span>
          </div>
        </div>

        {/* Card 3: Telemetry Ingestion Rate */}
        <div className="soc-dash-kpi-card">
          <div className="soc-dash-kpi-top">
            <span className="soc-dash-kpi-title">Telemetry Ingestion Rate</span>
            <div className="soc-dash-kpi-icon purple">
              <Activity size={18} style={{ color: "#a855f7" }} />
            </div>
          </div>
          <div className="soc-dash-kpi-metric" style={{ fontSize: "1.25rem", fontWeight: 700, color: "#a855f7" }}>
            {dashboardStatus?.telemetry_rate || "1.4k req/sec"}
          </div>
          <div className="soc-dash-kpi-bottom">
            <span className="soc-dash-trend-tag up">
              ⚡ Ingesting Live
            </span>
            <span>PostgreSQL Traffic Metrics</span>
          </div>
        </div>

        {/* Card 4: Active Incident Queue */}
        <div className="soc-dash-kpi-card">
          <div className="soc-dash-kpi-top">
            <span className="soc-dash-kpi-title">Active Incident Queue</span>
            <div className="soc-dash-kpi-icon red">
              <AlertCircle size={18} style={{ color: "#f59e0b" }} />
            </div>
          </div>
          <div className="soc-dash-kpi-metric" style={{ fontSize: "1.15rem", fontWeight: 700, color: "#f59e0b" }}>
            {dashboardStatus?.active_incidents_count !== undefined ? `${dashboardStatus.active_incidents_count} P1/P2 Alerts Active` : "2 P1/P2 Alerts Active"}
          </div>
          <div className="soc-dash-kpi-bottom">
            <span className="soc-dash-trend-tag warning">
              ⚠️ Triage Queue
            </span>
            <span>PostgreSQL Incident Ledger</span>
          </div>
        </div>
      </div>

      {/* Security Administrator Operations & System Governance */}
      <div className="soc-dash-card">
        <div className="soc-dash-card-header">
          <h3 className="soc-dash-card-title">
            <ShieldCheck size={18} style={{ color: "#38bdf8" }} />
            Security Administrator Operations &amp; System Governance
          </h3>
          <span className="soc-dash-badge" style={{ background: "rgba(56, 189, 248, 0.15)", color: "#38bdf8" }}>
            Executive Overview
          </span>
        </div>

        <div
          style={{
            display: "flex",
            flexDirection: "column",
            gap: "1.75rem",
            paddingTop: "0.75rem",
          }}
        >
          {/* Subsection A: Administrator Responsibilities & Core Governance */}
          <div style={{ display: "flex", flexDirection: "column", gap: "0.85rem" }}>
            <div style={{ display: "flex", alignItems: "center", gap: "0.5rem", marginBottom: "0.25rem" }}>
              <h4 style={{ margin: 0, fontSize: "0.925rem", fontWeight: 700, color: isDark ? "#f8fafc" : "#0f172a" }}>
                Administrator Responsibilities &amp; Core Governance
              </h4>
            </div>

            {[
              {
                title: "Full System Telemetry Oversight",
                desc: "Continuously monitor real-time network flow anomalies, machine learning inference engines, and cluster health metrics.",
                icon: Activity,
                color: "#38bdf8",
              },
              {
                title: "Incident Containment & Response",
                desc: "Execute automated mitigation playbooks, isolate compromised source IPs, and handle P1 Emergency/P2 High Risk alerts.",
                icon: Zap,
                color: "#ef4444",
              },
              {
                title: "Identity & Access Governance (RBAC)",
                desc: "Manage system users, provision Security Analyst roles, and enforce least-privilege administrative access policies.",
                icon: Users,
                color: "#a855f7",
              },
              {
                title: "Audit Compliance & System Security",
                desc: "Track all system interactions via immutable PostgreSQL audit logs and verify model features (UNSW-NB15 / CICIDS2017).",
                icon: FileText,
                color: "#10b981",
              },
            ].map((resp, idx) => {
              const RespIcon = resp.icon;
              return (
                <div
                  key={idx}
                  style={{
                    padding: "0.85rem 1rem",
                    borderRadius: "8px",
                    background: isDark ? "rgba(30, 41, 59, 0.6)" : "#f8fafc",
                    border: isDark ? "1px solid rgba(255, 255, 255, 0.06)" : "1px solid #e2e8f0",
                    display: "flex",
                    gap: "0.75rem",
                    alignItems: "flex-start",
                  }}
                >
                  <div
                    style={{
                      padding: "0.5rem",
                      borderRadius: "6px",
                      background: `rgba(${resp.color === "#38bdf8" ? "56, 189, 248" : resp.color === "#ef4444" ? "239, 68, 68" : resp.color === "#a855f7" ? "168, 85, 247" : "16, 185, 129"}, 0.15)`,
                      color: resp.color,
                      display: "flex",
                      alignItems: "center",
                      justifyContent: "center",
                      flexShrink: 0,
                    }}
                  >
                    <RespIcon size={16} />
                  </div>
                  <div>
                    <h5 style={{ margin: "0 0 0.2rem 0", fontSize: "0.875rem", fontWeight: 600, color: isDark ? "#f8fafc" : "#0f172a" }}>
                      {resp.title}
                    </h5>
                    <p style={{ margin: 0, fontSize: "0.8rem", color: isDark ? "#94a3b8" : "#64748b", lineHeight: 1.45 }}>
                      {resp.desc}
                    </p>
                  </div>
                </div>
              );
            })}
          </div>

          {/* Subsection B: Platform Modules Overview & Purpose */}
          <div style={{ display: "flex", flexDirection: "column", gap: "0.85rem" }}>
            <div style={{ display: "flex", alignItems: "center", gap: "0.5rem", marginBottom: "0.25rem" }}>
              <h4 style={{ margin: 0, fontSize: "0.925rem", fontWeight: 700, color: isDark ? "#f8fafc" : "#0f172a" }}>
                Platform Modules Overview &amp; Purpose
              </h4>
            </div>

            <div style={{ display: "grid", gridTemplateColumns: "repeat(auto-fit, minmax(280px, 1fr))", gap: "0.75rem" }}>
              {[
                {
                  title: "Dashboard (Executive Hub)",
                  desc: "High-level view of system health, real-time threat volume, active alerts, and SLA metrics.",
                  icon: TrendingUp,
                  badge: "● Executive Hub",
                  badgeColor: "#38bdf8",
                  badgeBg: "rgba(56, 189, 248, 0.12)",
                  route: "/admin/dashboard",
                },
                {
                  title: "Activity Security",
                  desc: "Monitors incoming network traffic streams, live telemetry events, and packet anomalies.",
                  icon: Activity,
                  badge: `● ${dashboardStatus?.activity_stream_status || "Streaming Live"}`,
                  badgeColor: "#10b981",
                  badgeBg: "rgba(16, 185, 129, 0.12)",
                  route: "/admin/activity-security",
                },
                {
                  title: "Threats (Predictive ML Lab)",
                  desc: "Interactive analyzer for testing custom IPv4 network traffic against ML pipelines to predict threat scores and severity levels.",
                  icon: Zap,
                  badge: `● ${dashboardStatus?.threat_anomalies_count !== undefined ? dashboardStatus.threat_anomalies_count : 3} Anomalies Detected`,
                  badgeColor: "#f59e0b",
                  badgeBg: "rgba(245, 158, 11, 0.12)",
                  route: "/admin/threats",
                },
                {
                  title: "Critical Alerts (Triage Center)",
                  desc: "Command center for triaging emergency events, tracking response SLAs, and executing containment playbooks.",
                  icon: ShieldAlert,
                  badge: `● ${dashboardStatus?.active_incidents_count !== undefined ? dashboardStatus.active_incidents_count : 2} Action Required`,
                  badgeColor: "#ef4444",
                  badgeBg: "rgba(239, 68, 68, 0.12)",
                  route: "/admin/critical-alerts",
                },
                {
                  title: "System Help (SOC Knowledge Base)",
                  desc: "AI-assisted documentation portal providing instant answers to networking, ML model, and operational queries.",
                  icon: FileSearch,
                  badge: "● AI Assistant Online",
                  badgeColor: "#a855f7",
                  badgeBg: "rgba(168, 85, 247, 0.12)",
                  route: "/admin/system-help",
                },
                {
                  title: "User Management & Audit Logs",
                  desc: "Role assignment interface and immutable logging database tracking all administrative actions.",
                  icon: UserCheck,
                  badge: "● Audit Trail Active",
                  badgeColor: "#6366f1",
                  badgeBg: "rgba(99, 102, 241, 0.12)",
                  route: "/admin/user-management",
                },
              ].map((mod, idx) => {
                const ModIcon = mod.icon;
                const isHovered = hoveredModuleIndex === idx;
                return (
                  <div
                    key={idx}
                    onClick={() => {
                      if (mod.route === "/admin/dashboard") {
                        window.scrollTo({ top: 0, behavior: "smooth" });
                      } else {
                        router.push(mod.route);
                      }
                    }}
                    onMouseEnter={() => setHoveredModuleIndex(idx)}
                    onMouseLeave={() => setHoveredModuleIndex(null)}
                    style={{
                      padding: "0.85rem 1rem",
                      borderRadius: "8px",
                      background: isHovered
                        ? (isDark ? "rgba(59, 130, 246, 0.18)" : "#eff6ff")
                        : (isDark ? "rgba(30, 41, 59, 0.4)" : "#f8fafc"),
                      border: isHovered
                        ? (isDark ? "1px solid rgba(59, 130, 246, 0.5)" : "1px solid #3b82f6")
                        : (isDark ? "1px solid rgba(255, 255, 255, 0.06)" : "1px solid #e2e8f0"),
                      display: "flex",
                      flexDirection: "column",
                      gap: "0.4rem",
                      cursor: "pointer",
                      transition: "all 0.2s ease-in-out",
                      boxShadow: isHovered ? "0 4px 12px rgba(59, 130, 246, 0.2)" : "none",
                    }}
                  >
                    <div style={{ display: "flex", alignItems: "center", justifyContent: "space-between", gap: "0.5rem", flexWrap: "wrap" }}>
                      <div style={{ display: "flex", alignItems: "center", gap: "0.5rem" }}>
                        <div
                          style={{
                            padding: "0.4rem",
                            borderRadius: "6px",
                            background: isHovered ? "rgba(59, 130, 246, 0.25)" : "rgba(168, 85, 247, 0.15)",
                            color: isHovered ? "#3b82f6" : "#a855f7",
                            display: "flex",
                            alignItems: "center",
                            justifyContent: "center",
                            transition: "all 0.2s ease-in-out",
                          }}
                        >
                          <ModIcon size={14} />
                        </div>
                        <h5 style={{ margin: 0, fontSize: "0.825rem", fontWeight: 600, color: isDark ? "#f8fafc" : "#0f172a" }}>
                          {mod.title}
                        </h5>
                      </div>
                      {mod.badge && (
                        <span
                          style={{
                            fontSize: "0.675rem",
                            fontWeight: 600,
                            padding: "0.15rem 0.45rem",
                            borderRadius: "12px",
                            background: mod.badgeBg,
                            color: mod.badgeColor,
                            whiteSpace: "nowrap",
                          }}
                        >
                          {mod.badge}
                        </span>
                      )}
                    </div>
                    <p style={{ margin: 0, fontSize: "0.775rem", color: isDark ? "#94a3b8" : "#64748b", lineHeight: 1.4 }}>
                      {mod.desc}
                    </p>
                  </div>
                );
              })}
            </div>
          </div>
        </div>
      </div>




    </div>
  );
}
