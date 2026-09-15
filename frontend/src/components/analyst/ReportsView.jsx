"use client";
import React, { useState, useEffect, useCallback } from "react";
import {
  Shield,
  BarChart3,
  FileText,
  Search,
  Download,
  AlertTriangle,
  Layers,
  FileCheck,
  Plus,
  RefreshCw,
  Lock,
  Zap,
  CheckCircle2,
  Activity,
  FileSpreadsheet,
  FileCode,
  ShieldAlert,
  Calendar,
  Sliders,
  Clock,
  Gauge,
  User,
  Filter,
  Info,
  Database,
  Cpu,
} from "lucide-react";

import LoadingSpinner from "../LoadingSpinner";
import {
  getUserActivityLogs,
  logUserActivity,
  generateDatabaseReport,
} from "../../utils/api";
import { getCurrentUser } from "../../utils/authHelpers";
import { API_BASE_URL } from "../../utils/constants";
import { useTheme } from "../../context/ThemeContext";
import { useIncidents } from "../../context/IncidentContext";

export default function ReportsView() {
  const { isDark } = useTheme();

  // Active Analyst User State
  const [currentUser, setCurrentUser] = useState(null);

  // Dynamic Report Generator Form State
  const [dateRange, setDateRange] = useState("Last 7 Days");
  const [datasetEngineFilter, setDatasetEngineFilter] = useState("All Datasets (Both)");
  const [customStartDate, setCustomStartDate] = useState("");
  const [customEndDate, setCustomEndDate] = useState("");
  const [isGenerating, setIsGenerating] = useState(false);
  const [exportNotice, setExportNotice] = useState(null);

  // Database Report Query Response State (GET /api/reports/generate)
  const [reportData, setReportData] = useState({
    metrics: {
      total_threats: 0,
      severity_counts: { CRITICAL: 0, HIGH: 0, MEDIUM: 0, LOW: 0 },
      dataset_counts: { "UNSW-NB15": 0, CICIDS2017: 0, AbuseIPDB: 0, Combined: 0 },
    },
    guardrail: {
      triggered: false,
      notice: null,
      available_days: 1,
    },
    data: [],
  });
  const [loadingReportData, setLoadingReportData] = useState(true);

  // User Activity Logs & Summary State (user_activity_logs)
  const [userActivityLogs, setUserActivityLogs] = useState([]);
  const [loadingUserActivity, setLoadingUserActivity] = useState(true);
  const [userSummary, setUserSummary] = useState({
    total_analyst_actions: 0,
    critical_threats_analyzed: 0,
    most_used_dataset_engine: "UNSW-NB15",
  });



  // Helper to map dateRange option string to integer days
  const getDaysValue = (drStr) => {
    if (!drStr) return 7;
    const lower = drStr.toLowerCase();
    if (lower.includes("15")) return 15;
    if (lower.includes("30")) return 30;
    if (lower.includes("24") || lower.includes("1 day")) return 1;
    return 7;
  };

  // 1. Primary PostgreSQL Database Report Generator Fetch (GET /api/reports/generate)
  const executeDatabaseReportQuery = useCallback(async () => {
    setLoadingReportData(true);
    try {
      const activeUser = getCurrentUser();
      const email = activeUser?.email || "security@gmail.com";
      setCurrentUser(activeUser || { email: "security@gmail.com", role: "Security Analyst" });

      const daysVal = dateRange === "Custom Date Range" ? null : getDaysValue(dateRange);

      const params = {
        userEmail: email,
        days: daysVal,
        dateRange: dateRange,
        datasetEngine: datasetEngineFilter,
        startDate: customStartDate,
        endDate: customEndDate,
      };

      const res = await generateDatabaseReport(params);
      if (res && res.status === "success") {
        setReportData({
          metrics: res.metrics || {
            total_threats: 0,
            severity_counts: { CRITICAL: 0, HIGH: 0, MEDIUM: 0, LOW: 0 },
            dataset_counts: { "UNSW-NB15": 0, CICIDS2017: 0, AbuseIPDB: 0, Combined: 0 },
          },
          guardrail: res.guardrail || { triggered: false, notice: null, available_days: 1 },
          data: res.data || res.incidents || [],
        });
      }
    } catch (err) {
      console.warn("Failed to generate database report from PostgreSQL:", err);
    } finally {
      setLoadingReportData(false);
      setIsGenerating(false);
    }
  }, [dateRange, datasetEngineFilter, customStartDate, customEndDate]);

  // 2. Fetch User Session Activity History from PostgreSQL (GET /api/reports/user-activity)
  const fetchUserActivity = useCallback(async () => {
    setLoadingUserActivity(true);
    try {
      const activeUser = getCurrentUser();
      const email = activeUser?.email || "security@gmail.com";
      const res = await getUserActivityLogs(email);
      if (res && res.data) {
        setUserActivityLogs(res.data);
      }
      if (res && res.summary) {
        setUserSummary(res.summary);
      }
    } catch (err) {
      console.warn("Failed to fetch user activity logs from PostgreSQL:", err);
    } finally {
      setLoadingUserActivity(false);
    }
  }, []);

  useEffect(() => {
    executeDatabaseReportQuery();
    fetchUserActivity();
  }, [executeDatabaseReportQuery, fetchUserActivity]);

  // Handler when clicking [ ⚡ Generate Report Preview ]
  const handleGenerateReportClick = (e) => {
    if (e) e.preventDefault();
    setIsGenerating(true);
    executeDatabaseReportQuery();
    // Log user action to PostgreSQL user_activity_logs
    const email = currentUser?.email || "security@gmail.com";
    logUserActivity({
      user_id: email,
      action_type: "FILTER_APPLIED",
      details: `Generated Report Preview (${dateRange}, ${datasetEngineFilter})`,
      ip_address: "10.0.9.47",
      protocol: "TCP",
      dataset_engine: datasetEngineFilter,
      severity: "INFORMATIONAL",
    }).then(() => fetchUserActivity()).catch(() => {});
  };

  // Export Action Handlers with Dynamic Filter Parameters
  const handleDownloadPdf = async () => {
    setExportNotice(`Generating Executive PDF Security Report (${dateRange})...`);
    const email = currentUser?.email || "security@gmail.com";
    try {
      await logUserActivity({
        user_id: email,
        action_type: "EXPORT_PERFORMED",
        details: `Exported PDF Security Report (${dateRange}, Engine: ${datasetEngineFilter})`,
        ip_address: "185.220.101.42",
        protocol: "TCP",
        dataset_engine: datasetEngineFilter,
        severity: "HIGH",
      });
      fetchUserActivity();
    } catch (e) {}

    const daysVal = getDaysValue(dateRange);
    const url = `${API_BASE_URL}/api/reports/generate-pdf?time_scope=${encodeURIComponent(dateRange)}&days=${daysVal}&dataset_engine=${encodeURIComponent(datasetEngineFilter)}&user_id=${encodeURIComponent(email)}`;
    window.open(url, "_blank");
    setTimeout(() => setExportNotice(null), 4000);
  };

  const { incidents } = useIncidents();

  const handleDownloadCsv = async () => {
    setExportNotice("Downloading Filtered CSV Incident Logs...");
    const email = currentUser?.email || "security@gmail.com";
    try {
      await logUserActivity({
        user_id: email,
        action_type: "EXPORT_PERFORMED",
        details: `Exported CSV Incident Logs (${dateRange}, Engine: ${datasetEngineFilter})`,
        ip_address: "185.220.101.50",
        protocol: "TCP",
        dataset_engine: datasetEngineFilter,
        severity: "MEDIUM",
      });
      fetchUserActivity();
    } catch (e) {}

    const listToExport = (incidents && incidents.length > 0) ? incidents : (reportData.data || []);
    const headers = ["Timestamp", "Source IP", "Threat Type", "Score", "Severity"];
    const rows = listToExport.map((i) => [
      i.timestamp || new Date().toISOString(),
      i.source_ip || i.sourceIp || "10.0.4.52",
      `"${String(i.threat_vector || i.threatType || i.description || '').replace(/"/g, '""')}"`,
      i.threatScore || `${i.abuse_score || 85}%`,
      i.severity || i.threatSeverity || "MEDIUM"
    ]);

    const csvContent = "data:text/csv;charset=utf-8," + [headers.join(","), ...rows.map((e) => e.join(","))].join("\n");
    const encodedUri = encodeURI(csvContent);
    const link = document.createElement("a");
    link.setAttribute("href", encodedUri);
    link.setAttribute("download", `Threat_Report_${new Date().toISOString().slice(0, 10)}.csv`);
    document.body.appendChild(link);
    link.click();
    document.body.removeChild(link);

    setTimeout(() => setExportNotice(null), 4000);
  };

  const handleDownloadJson = async () => {
    setExportNotice("Downloading SIEM Structured JSON Telemetry Payload...");
    const email = currentUser?.email || "security@gmail.com";
    try {
      await logUserActivity({
        user_id: email,
        action_type: "EXPORT_PERFORMED",
        details: `Exported SIEM JSON Telemetry (${dateRange}, Engine: ${datasetEngineFilter})`,
        ip_address: "10.0.9.47",
        protocol: "TCP",
        dataset_engine: datasetEngineFilter,
        severity: "INFORMATIONAL",
      });
      fetchUserActivity();
    } catch (e) {}

    const listToExport = (incidents && incidents.length > 0) ? incidents : (reportData.data || []);
    const jsonString = `data:text/json;charset=utf-8,${encodeURIComponent(JSON.stringify(listToExport, null, 2))}`;
    const link = document.createElement("a");
    link.setAttribute("href", jsonString);
    link.setAttribute("download", `Threat_Report_${new Date().toISOString().slice(0, 10)}.json`);
    document.body.appendChild(link);
    link.click();
    document.body.removeChild(link);

    setTimeout(() => setExportNotice(null), 4000);
  };

  const currentUserEmail = currentUser?.email || "security@gmail.com";
  const metrics = reportData.metrics || {};
  const severityCounts = metrics.severity_counts || { CRITICAL: 0, HIGH: 0, MEDIUM: 0, LOW: 0 };
  const datasetCounts = metrics.dataset_counts || { "UNSW-NB15": 0, CICIDS2017: 0, AbuseIPDB: 0, Combined: 0 };
  const guardrail = reportData.guardrail || {};

  const activeIncidentsList = (incidents && incidents.length > 0) ? incidents : (reportData.data || []);
  const previewIncidents = activeIncidentsList;

  const displayTotalThreats = activeIncidentsList.length > 0 ? activeIncidentsList.length : (metrics.total_threats || 0);

  const displaySeverityCounts = activeIncidentsList.length > 0 ? {
    CRITICAL: activeIncidentsList.filter(i => String(i.severity || i.threatSeverity || '').toUpperCase() === 'CRITICAL').length,
    HIGH: activeIncidentsList.filter(i => String(i.severity || i.threatSeverity || '').toUpperCase() === 'HIGH').length,
    MEDIUM: activeIncidentsList.filter(i => String(i.severity || i.threatSeverity || '').toUpperCase() === 'MEDIUM').length,
    LOW: activeIncidentsList.filter(i => String(i.severity || i.threatSeverity || '').toUpperCase() === 'LOW').length,
  } : severityCounts;

  const displayDatasetCounts = activeIncidentsList.length > 0 ? {
    "UNSW-NB15": activeIncidentsList.filter(i => {
      const src = String(i.detection_source || i.threat_vector || i.threatType || '').toUpperCase();
      return src.includes("UNSW");
    }).length,
    CICIDS2017: activeIncidentsList.filter(i => {
      const src = String(i.detection_source || i.threat_vector || i.threatType || '').toUpperCase();
      return src.includes("CICIDS");
    }).length,
    AbuseIPDB: activeIncidentsList.filter(i => {
      const src = String(i.detection_source || i.threat_vector || i.threatType || '').toUpperCase();
      return src.includes("ABUSE");
    }).length,
    Combined: activeIncidentsList.length,
  } : datasetCounts;

  return (
    <div key="tab-reports" className="rep-container">
      <div className="rep-card">
        {/* Header Title Section */}
        <div className="rep-header-flex" style={{ marginBottom: "1.25rem" }}>
          <div className="rep-header-title">
            <h3 style={{ display: "flex", alignItems: "center", gap: "0.5rem" }}>
              <Database size={22} style={{ color: "#38bdf8" }} />
              Database-Driven Security Analytics &amp; Dynamic Report Generator
            </h3>
            <p>
              Query logged threat incidents directly from PostgreSQL, aggregate real-time metrics, apply date range and dataset filters, and export SIEM security bundles.
            </p>
          </div>
          <div className="rep-header-actions">
            <button className="ns-btn-gradient primary small" onClick={() => { executeDatabaseReportQuery(); fetchUserActivity(); }}>
              <RefreshCw size={14} style={{ marginRight: "4px" }} /> Refresh Database Queries
            </button>
          </div>
        </div>

        {/* 1. Metric Aggregation Cards (Top Section - Real-Time DB Counts) */}
        <div style={{ marginBottom: "1.5rem" }}>
          <div style={{ marginBottom: "0.75rem", display: "flex", alignItems: "center", justifyContent: "space-between", flexWrap: "wrap", gap: "0.5rem" }}>
            <div style={{ display: "flex", alignItems: "center", gap: "0.5rem" }}>
              <Gauge size={18} style={{ color: "#38bdf8" }} />
              <h4 style={{ margin: 0, fontSize: "1rem", fontWeight: "700", color: isDark ? "#f8fafc" : "#0f172a" }}>
                Real-Time PostgreSQL Threat Metric Aggregations ({currentUserEmail})
              </h4>
            </div>
            <span style={{ fontSize: "0.78rem", color: isDark ? "#94a3b8" : "#64748b" }}>
              Live DB Table: <code>incidents</code>
            </span>
          </div>

          {/* Row 1: Total Threats & Severity Counts */}
          <div className="rep-kpi-grid" style={{ marginBottom: "0.85rem" }}>
            {/* Total Threats Count */}
            <div className="rep-stat-card blue">
              <span className="rep-stat-title">Total Logged Threats</span>
              <span className="rep-stat-metric">{displayTotalThreats}</span>
              <span className="rep-stat-sub">COUNT(*) User Incidents</span>
            </div>

            {/* Critical Severity Count */}
            <div className="rep-stat-card purple" style={{ borderLeft: "4px solid #ef4444" }}>
              <span className="rep-stat-title">CRITICAL Severity</span>
              <span className="rep-stat-metric" style={{ color: "#ef4444" }}>
                {displaySeverityCounts.CRITICAL || 0}
              </span>
              <span className="rep-stat-sub">Critical Risk Threshold</span>
            </div>

            {/* High Severity Count */}
            <div className="rep-stat-card cyan" style={{ borderLeft: "4px solid #f97316" }}>
              <span className="rep-stat-title">HIGH Severity</span>
              <span className="rep-stat-metric" style={{ color: "#f97316" }}>
                {displaySeverityCounts.HIGH || 0}
              </span>
              <span className="rep-stat-sub">High Priority Threats</span>
            </div>

            {/* Medium Severity Count */}
            <div className="rep-stat-card green" style={{ borderLeft: "4px solid #eab308" }}>
              <span className="rep-stat-title">MEDIUM Severity</span>
              <span className="rep-stat-metric" style={{ color: "#eab308" }}>
                {displaySeverityCounts.MEDIUM || 0}
              </span>
              <span className="rep-stat-sub">Elevated Anomalies</span>
            </div>

            {/* Low Severity Count */}
            <div className="rep-stat-card green" style={{ borderLeft: "4px solid #38bdf8" }}>
              <span className="rep-stat-title">LOW Severity</span>
              <span className="rep-stat-metric" style={{ color: "#38bdf8" }}>
                {displaySeverityCounts.LOW || 0}
              </span>
              <span className="rep-stat-sub">Informational Signals</span>
            </div>
          </div>

          {/* Row 2: Dataset Engine Counts Breakdown */}
          <div className="rep-kpi-grid">
            {/* UNSW-NB15 Count */}
            <div className="rep-stat-card blue" style={{ borderLeft: "4px solid #3b82f6" }}>
              <span className="rep-stat-title">UNSW-NB15 Threats</span>
              <span className="rep-stat-metric">{displayDatasetCounts["UNSW-NB15"] || 0}</span>
              <span className="rep-stat-sub">DoS / Network Flood Engine</span>
            </div>

            {/* CICIDS2017 Count */}
            <div className="rep-stat-card purple" style={{ borderLeft: "4px solid #a855f7" }}>
              <span className="rep-stat-title">CICIDS2017 Threats</span>
              <span className="rep-stat-metric" style={{ color: "#c084fc" }}>
                {displayDatasetCounts.CICIDS2017 || 0}
              </span>
              <span className="rep-stat-sub">Web Attack &amp; Recon Engine</span>
            </div>

            {/* AbuseIPDB Threat Intel Count */}
            <div className="rep-stat-card cyan" style={{ borderLeft: "4px solid #06b6d4" }}>
              <span className="rep-stat-title">AbuseIPDB Threat Intel</span>
              <span className="rep-stat-metric" style={{ color: "#22d3ee" }}>
                {displayDatasetCounts.AbuseIPDB || 0}
              </span>
              <span className="rep-stat-sub">Malicious IP Intelligence</span>
            </div>

            {/* Combined Datasets Total */}
            <div className="rep-stat-card green" style={{ borderLeft: "4px solid #10b981" }}>
              <span className="rep-stat-title">Combined Datasets Total</span>
              <span className="rep-stat-metric" style={{ color: "#34d399" }}>
                {displayDatasetCounts.Combined || displayTotalThreats}
              </span>
              <span className="rep-stat-sub">Multi-Model SIEM Coverage</span>
            </div>
          </div>
        </div>

        {/* Export Notification Banner */}
        {exportNotice && (
          <div
            style={{
              marginBottom: "1.25rem",
              padding: "0.85rem 1.1rem",
              borderRadius: "8px",
              fontSize: "0.875rem",
              fontWeight: "600",
              display: "flex",
              alignItems: "center",
              gap: "0.6rem",
              backgroundColor: "rgba(59, 130, 246, 0.15)",
              color: "#60a5fa",
              border: "1px solid rgba(59, 130, 246, 0.4)",
            }}
          >
            <Download size={18} />
            <span>{exportNotice}</span>
          </div>
        )}

        {/* 2. Dynamic Report Generator Controls (Filter Bar) & Guardrail Panel */}
        <div
          style={{
            marginBottom: "1.5rem",
            padding: "1.25rem",
            backgroundColor: isDark ? "rgba(30, 41, 59, 0.75)" : "#f8fafc",
            border: isDark ? "1px solid #334155" : "1px solid #cbd5e1",
            borderRadius: "12px",
          }}
        >
          <div style={{ display: "flex", alignItems: "center", justifyContent: "space-between", flexWrap: "wrap", gap: "0.75rem", marginBottom: "1rem" }}>
            <div style={{ display: "flex", alignItems: "center", gap: "0.6rem" }}>
              <Sliders size={20} style={{ color: "#38bdf8" }} />
              <div>
                <h4 style={{ margin: 0, fontSize: "1rem", fontWeight: "700", color: isDark ? "#f8fafc" : "#0f172a" }}>
                  Dynamic Report Generator Controls
                </h4>
                <p style={{ margin: "0.15rem 0 0 0", fontSize: "0.8rem", color: isDark ? "#94a3b8" : "#64748b" }}>
                  Configure targeted date ranges and dataset engine parameters to query PostgreSQL and generate instant report outputs.
                </p>
              </div>
            </div>
          </div>

          {/* New User / Limited Data Guardrail Informational Banner */}
          {guardrail.triggered && guardrail.notice && (
            <div
              style={{
                marginBottom: "1rem",
                padding: "0.85rem 1.1rem",
                borderRadius: "8px",
                fontSize: "0.85rem",
                fontWeight: "600",
                display: "flex",
                alignItems: "center",
                gap: "0.6rem",
                backgroundColor: "rgba(245, 158, 11, 0.15)",
                color: "#fbbf24",
                border: "1px solid rgba(245, 158, 11, 0.4)",
              }}
            >
              <Info size={18} style={{ color: "#fbbf24", flexShrink: 0 }} />
              <span>
                <strong>[ LIMITED DATA GUARDRAIL ]:</strong> {guardrail.notice}
              </span>
            </div>
          )}

          {/* Filter Controls Form */}
          <form onSubmit={handleGenerateReportClick}>
            <div style={{ display: "flex", gap: "1rem", flexWrap: "wrap", alignItems: "flex-end", marginBottom: "1.25rem" }}>
              {/* Date Range Selector Dropdown */}
              <div style={{ flex: "1 1 200px", display: "flex", flexDirection: "column", gap: "0.3rem" }}>
                <label style={{ fontSize: "0.78rem", fontWeight: "700", color: isDark ? "#cbd5e1" : "#475569", display: "flex", alignItems: "center", gap: "0.3rem" }}>
                  <Calendar size={13} style={{ color: "#38bdf8" }} /> Date Range Selector:
                </label>
                <select
                  value={dateRange}
                  onChange={(e) => setDateRange(e.target.value)}
                  style={{
                    width: "100%",
                    padding: "0.55rem 0.75rem",
                    borderRadius: "6px",
                    backgroundColor: isDark ? "#0f172a" : "#ffffff",
                    border: isDark ? "1px solid #334155" : "1px solid #cbd5e1",
                    color: isDark ? "#f8fafc" : "#0f172a",
                    fontSize: "0.85rem",
                    fontWeight: "600",
                    outline: "none",
                    cursor: "pointer",
                  }}
                >
                  <option value="Last 7 Days">Last 7 Days</option>
                  <option value="Last 15 Days">Last 15 Days</option>
                  <option value="Last 30 Days">Last 30 Days</option>
                  <option value="Custom Date Range">Custom Date Range</option>
                </select>
              </div>

              {/* Custom Date Range Inputs (if Custom Date Range selected) */}
              {dateRange === "Custom Date Range" && (
                <>
                  <div style={{ flex: "1 1 150px", display: "flex", flexDirection: "column", gap: "0.3rem" }}>
                    <label style={{ fontSize: "0.75rem", fontWeight: "600", color: isDark ? "#cbd5e1" : "#475569" }}>
                      Start Date:
                    </label>
                    <input
                      type="date"
                      value={customStartDate}
                      onChange={(e) => setCustomStartDate(e.target.value)}
                      style={{
                        padding: "0.5rem 0.65rem",
                        borderRadius: "6px",
                        backgroundColor: isDark ? "#0f172a" : "#ffffff",
                        border: isDark ? "1px solid #334155" : "1px solid #cbd5e1",
                        color: isDark ? "#f8fafc" : "#0f172a",
                        fontSize: "0.82rem",
                      }}
                    />
                  </div>
                  <div style={{ flex: "1 1 150px", display: "flex", flexDirection: "column", gap: "0.3rem" }}>
                    <label style={{ fontSize: "0.75rem", fontWeight: "600", color: isDark ? "#cbd5e1" : "#475569" }}>
                      End Date:
                    </label>
                    <input
                      type="date"
                      value={customEndDate}
                      onChange={(e) => setCustomEndDate(e.target.value)}
                      style={{
                        padding: "0.5rem 0.65rem",
                        borderRadius: "6px",
                        backgroundColor: isDark ? "#0f172a" : "#ffffff",
                        border: isDark ? "1px solid #334155" : "1px solid #cbd5e1",
                        color: isDark ? "#f8fafc" : "#0f172a",
                        fontSize: "0.82rem",
                      }}
                    />
                  </div>
                </>
              )}

              {/* Dataset Engine Filter Dropdown */}
              <div style={{ flex: "1.5 1 240px", display: "flex", flexDirection: "column", gap: "0.3rem" }}>
                <label style={{ fontSize: "0.78rem", fontWeight: "700", color: isDark ? "#cbd5e1" : "#475569", display: "flex", alignItems: "center", gap: "0.3rem" }}>
                  <Cpu size={13} style={{ color: "#a855f7" }} /> Dataset Engine Filter:
                </label>
                <select
                  value={datasetEngineFilter}
                  onChange={(e) => setDatasetEngineFilter(e.target.value)}
                  style={{
                    width: "100%",
                    padding: "0.55rem 0.75rem",
                    borderRadius: "6px",
                    backgroundColor: isDark ? "#0f172a" : "#ffffff",
                    border: isDark ? "1px solid #334155" : "1px solid #cbd5e1",
                    color: isDark ? "#f8fafc" : "#0f172a",
                    fontSize: "0.85rem",
                    fontWeight: "600",
                    outline: "none",
                    cursor: "pointer",
                  }}
                >
                  <option value="All Datasets (Both)">All Datasets (Both)</option>
                  <option value="UNSW-NB15">UNSW-NB15 ML Engine</option>
                  <option value="CICIDS2017">CICIDS2017 ML Engine</option>
                  <option value="AbuseIPDB">AbuseIPDB Threat Intel</option>
                </select>
              </div>

              {/* Generate Preview Action Button */}
              <div>
                <button
                  type="submit"
                  disabled={isGenerating}
                  className="ns-btn-gradient primary small"
                  style={{ padding: "0.6rem 1.1rem", fontWeight: "700", gap: "0.4rem" }}
                >
                  <RefreshCw size={14} className={isGenerating ? "animate-spin" : ""} />
                  {isGenerating ? "Querying PostgreSQL..." : "⚡ Generate Report Preview"}
                </button>
              </div>
            </div>
          </form>

          {/* 3. Export Buttons Bar */}
          <div style={{ paddingTop: "0.85rem", borderTop: isDark ? "1px solid #334155" : "1px solid #e2e8f0", display: "flex", gap: "0.75rem", flexWrap: "wrap", alignItems: "center" }}>
            <span style={{ fontSize: "0.8rem", fontWeight: "700", color: isDark ? "#cbd5e1" : "#475569", marginRight: "0.5rem" }}>
              Immediate Export Formats:
            </span>

            {/* [ Export PDF ] */}
            <button
              onClick={handleDownloadPdf}
              className="ns-btn-gradient primary small"
              style={{ padding: "0.5rem 0.95rem", fontWeight: "700", gap: "0.4rem" }}
            >
              <FileText size={15} /> Export PDF
            </button>

            {/* [ Export CSV ] */}
            <button
              onClick={handleDownloadCsv}
              className="ns-btn-gradient small"
              style={{ background: "linear-gradient(135deg, #059669 0%, #10b981 100%)", color: "#ffffff", padding: "0.5rem 0.95rem", fontWeight: "700", gap: "0.4rem", border: "none" }}
            >
              <FileSpreadsheet size={15} /> Export CSV
            </button>

            {/* [ Export JSON ] */}
            <button
              onClick={handleDownloadJson}
              className="ns-btn-gradient small"
              style={{ background: "linear-gradient(135deg, #7c3aed 0%, #8b5cf6 100%)", color: "#ffffff", padding: "0.5rem 0.95rem", fontWeight: "700", gap: "0.4rem", border: "none" }}
            >
              <FileCode size={15} /> Export JSON
            </button>
          </div>
        </div>

        {/* 3. Live Report Preview Summary Table */}
        <div className="rep-table-box" style={{ marginBottom: "2rem" }}>
          <div style={{ display: "flex", justifyContent: "space-between", alignItems: "center", marginBottom: "1rem", flexWrap: "wrap", gap: "0.75rem" }}>
            <div>
              <h4 style={{ color: isDark ? "#f8fafc" : "#1e293b", margin: 0, fontSize: "1.05rem", fontWeight: "700", display: "flex", alignItems: "center", gap: "0.5rem" }}>
                <FileCheck size={18} style={{ color: "#10b981" }} />
                Generated Security Report Preview Summary Table
              </h4>
              <p style={{ fontSize: "0.8rem", color: isDark ? "#94a3b8" : "#64748b", margin: "0.2rem 0 0 0" }}>
                Matching PostgreSQL incidents for <strong>{dateRange}</strong> ({datasetEngineFilter}) — Logged user: <strong>{currentUserEmail}</strong>
              </p>
            </div>
            <span style={{ fontSize: "0.75rem", color: isDark ? "#94a3b8" : "#64748b" }}>
              Matching Records: <strong>{previewIncidents.length}</strong>
            </span>
          </div>

          {loadingReportData ? (
            <LoadingSpinner text="Executing PostgreSQL incident query..." />
          ) : previewIncidents.length === 0 ? (
            <div style={{ textAlign: "center", padding: "2.5rem", color: isDark ? "#94a3b8" : "#64748b" }}>
              <ShieldAlert size={32} style={{ color: "#94a3b8", marginBottom: "0.5rem" }} />
              <p style={{ margin: 0, fontWeight: "600" }}>No incident records found matching selected filter criteria.</p>
              <p style={{ margin: "0.25rem 0 0 0", fontSize: "0.8rem" }}>Try adjusting the date range selector or selecting "All Datasets".</p>
            </div>
          ) : (
            <div style={{ overflowX: "auto", width: "100%", borderRadius: "8px" }}>
              <table
                style={{
                  width: "100%",
                  minWidth: "1100px",
                  tableLayout: "fixed",
                  borderCollapse: "collapse",
                  fontSize: "0.82rem",
                  lineHeight: "1.5",
                }}
              >
                <thead>
                  <tr
                    style={{
                      backgroundColor: isDark ? "rgba(30, 41, 59, 0.8)" : "#f1f5f9",
                      borderBottom: isDark ? "1px solid #334155" : "1px solid #cbd5e1",
                    }}
                  >
                    <th style={{ width: "95px", padding: "0.75rem 0.85rem", textAlign: "left", color: isDark ? "#94a3b8" : "#475569", fontWeight: "700", fontSize: "0.75rem", textTransform: "uppercase", letterSpacing: "0.04em" }}>
                      Alert ID
                    </th>
                    <th style={{ width: "175px", padding: "0.75rem 0.85rem", textAlign: "left", color: isDark ? "#94a3b8" : "#475569", fontWeight: "700", fontSize: "0.75rem", textTransform: "uppercase", letterSpacing: "0.04em" }}>
                      Timestamp (UTC)
                    </th>
                    <th style={{ width: "160px", padding: "0.75rem 0.85rem", textAlign: "left", color: isDark ? "#94a3b8" : "#475569", fontWeight: "700", fontSize: "0.75rem", textTransform: "uppercase", letterSpacing: "0.04em" }}>
                      Source / Target IP
                    </th>
                    <th style={{ width: "260px", padding: "0.75rem 0.85rem", textAlign: "left", color: isDark ? "#94a3b8" : "#475569", fontWeight: "700", fontSize: "0.75rem", textTransform: "uppercase", letterSpacing: "0.04em" }}>
                      Threat Vector / Summary
                    </th>
                    <th style={{ width: "90px", padding: "0.75rem 0.85rem", textAlign: "center", color: isDark ? "#94a3b8" : "#475569", fontWeight: "700", fontSize: "0.75rem", textTransform: "uppercase", letterSpacing: "0.04em" }}>
                      Protocol
                    </th>
                    <th style={{ width: "150px", padding: "0.75rem 0.85rem", textAlign: "left", color: isDark ? "#94a3b8" : "#475569", fontWeight: "700", fontSize: "0.75rem", textTransform: "uppercase", letterSpacing: "0.04em" }}>
                      Dataset Engine
                    </th>
                    <th style={{ width: "115px", padding: "0.75rem 0.85rem", textAlign: "center", color: isDark ? "#94a3b8" : "#475569", fontWeight: "700", fontSize: "0.75rem", textTransform: "uppercase", letterSpacing: "0.04em" }}>
                      Severity
                    </th>
                    <th style={{ width: "110px", padding: "0.75rem 0.85rem", textAlign: "center", color: isDark ? "#94a3b8" : "#475569", fontWeight: "700", fontSize: "0.75rem", textTransform: "uppercase", letterSpacing: "0.04em" }}>
                      Status
                    </th>
                  </tr>
                </thead>
                <tbody>
                  {previewIncidents.map((inc, idx) => {
                    const sev = (inc.severity || "CRITICAL").toUpperCase();
                    let sevColor = "#ef4444";
                    let sevBg = "rgba(239, 68, 68, 0.18)";
                    let sevBorder = "rgba(239, 68, 68, 0.35)";

                    if (sev === "HIGH") {
                      sevColor = "#f97316";
                      sevBg = "rgba(249, 115, 22, 0.18)";
                      sevBorder = "rgba(249, 115, 22, 0.35)";
                    } else if (sev === "MEDIUM") {
                      sevColor = "#eab308";
                      sevBg = "rgba(234, 179, 8, 0.18)";
                      sevBorder = "rgba(234, 179, 8, 0.35)";
                    } else if (sev === "LOW") {
                      sevColor = "#38bdf8";
                      sevBg = "rgba(56, 189, 248, 0.18)";
                      sevBorder = "rgba(56, 189, 248, 0.35)";
                    }

                    const st = (inc.status || "Active").toUpperCase();
                    let stColor = "#f87171";
                    let stBg = "rgba(239, 68, 68, 0.15)";

                    if (st === "CONTAINED") {
                      stColor = "#c084fc";
                      stBg = "rgba(168, 85, 247, 0.18)";
                    } else if (st === "INVESTIGATING") {
                      stColor = "#60a5fa";
                      stBg = "rgba(59, 130, 246, 0.18)";
                    } else if (st === "RESOLVED") {
                      stColor = "#34d399";
                      stBg = "rgba(16, 185, 129, 0.18)";
                    }

                    return (
                      <tr
                        key={inc.alert_id || inc.id || idx}
                        style={{
                          borderBottom: isDark ? "1px solid rgba(255, 255, 255, 0.06)" : "1px solid #e2e8f0",
                          backgroundColor: idx % 2 === 0 ? "transparent" : (isDark ? "rgba(255, 255, 255, 0.015)" : "#f8fafc"),
                          transition: "background 0.15s ease",
                        }}
                      >
                        {/* 1. Alert ID */}
                        <td style={{ padding: "0.75rem 0.85rem", verticalAlign: "middle" }}>
                          <code style={{ fontSize: "0.8rem", color: isDark ? "#38bdf8" : "#0284c7", fontWeight: "700" }}>
                            {inc.alert_id || inc.id}
                          </code>
                        </td>

                        {/* 2. Timestamp (UTC) */}
                        <td style={{ padding: "0.75rem 0.85rem", color: isDark ? "#cbd5e1" : "#475569", whiteSpace: "nowrap", verticalAlign: "middle" }}>
                          <span style={{ fontSize: "0.78rem", fontFamily: "monospace" }}>
                            {inc.timestamp}
                          </span>
                        </td>

                        {/* 3. Source / Target IP */}
                        <td style={{ padding: "0.75rem 0.85rem", verticalAlign: "middle" }}>
                          <code style={{ display: "block", fontSize: "0.8rem", color: isDark ? "#f8fafc" : "#0f172a", fontWeight: "700", fontFamily: "monospace" }}>
                            {inc.source_ip}
                          </code>
                          <span style={{ fontSize: "0.7rem", color: isDark ? "#94a3b8" : "#64748b" }}>
                            &rarr; {inc.target_ip}
                          </span>
                        </td>

                        {/* 4. Threat Vector / Summary */}
                        <td
                          title={inc.threat_vector || inc.details}
                          style={{ padding: "0.75rem 0.85rem", verticalAlign: "middle" }}
                        >
                          <span
                            style={{
                              display: "block",
                              maxWidth: "240px",
                              overflow: "hidden",
                              textOverflow: "ellipsis",
                              whiteSpace: "nowrap",
                              fontSize: "0.8rem",
                              fontWeight: "600",
                              color: isDark ? "#cbd5e1" : "#334155",
                            }}
                          >
                            {inc.threat_vector || inc.details}
                          </span>
                        </td>

                        {/* 5. Protocol */}
                        <td style={{ padding: "0.75rem 0.85rem", textAlign: "center", verticalAlign: "middle" }}>
                          <span style={{ fontSize: "0.75rem", fontWeight: "700", padding: "0.15rem 0.45rem", borderRadius: "4px", backgroundColor: isDark ? "rgba(255,255,255,0.08)" : "#e2e8f0", color: isDark ? "#cbd5e1" : "#334155" }}>
                            {inc.protocol || "TCP"}
                          </span>
                        </td>

                        {/* 6. Dataset Engine */}
                        <td style={{ padding: "0.75rem 0.85rem", verticalAlign: "middle" }}>
                          <span style={{ fontSize: "0.78rem", fontWeight: "600", color: isDark ? "#cbd5e1" : "#334155" }}>
                            {inc.dataset_engine || "UNSW-NB15"}
                          </span>
                        </td>

                        {/* 7. Severity */}
                        <td style={{ padding: "0.75rem 0.85rem", textAlign: "center", verticalAlign: "middle" }}>
                          <span
                            style={{
                              display: "inline-flex",
                              alignItems: "center",
                              justifyContent: "center",
                              padding: "0.2rem 0.55rem",
                              borderRadius: "9999px",
                              fontSize: "0.72rem",
                              fontWeight: "700",
                              backgroundColor: sevBg,
                              color: sevColor,
                              border: `1px solid ${sevBorder}`,
                            }}
                          >
                            {sev}
                          </span>
                        </td>

                        {/* 8. Status */}
                        <td style={{ padding: "0.75rem 0.85rem", textAlign: "center", verticalAlign: "middle" }}>
                          <span
                            style={{
                              display: "inline-flex",
                              alignItems: "center",
                              justifyContent: "center",
                              padding: "0.2rem 0.55rem",
                              borderRadius: "9999px",
                              fontSize: "0.72rem",
                              fontWeight: "700",
                              backgroundColor: stBg,
                              color: stColor,
                            }}
                          >
                            {st}
                          </span>
                        </td>
                      </tr>
                    );
                  })}
                </tbody>
              </table>
            </div>
          )}
        </div>

        {/* 4. PostgreSQL User Audit & Historical Activity Reports Table */}
        <div className="rep-table-box" style={{ marginBottom: "2rem" }}>
          <div style={{ display: "flex", justifyContent: "space-between", alignItems: "center", marginBottom: "1rem", flexWrap: "wrap", gap: "0.75rem" }}>
            <div>
              <h4 style={{ color: isDark ? "#f8fafc" : "#1e293b", margin: 0, fontSize: "1.05rem", fontWeight: "700", display: "flex", alignItems: "center", gap: "0.5rem" }}>
                <Activity size={18} style={{ color: "#38bdf8" }} />
                Analyst User Activity Timeline &amp; Table (`user_activity_logs`)
              </h4>
              <p style={{ fontSize: "0.8rem", color: isDark ? "#94a3b8" : "#64748b", margin: "0.2rem 0 0 0" }}>
                Historical actions, threat analysis, and rule operations for logged-in user: <strong>{currentUserEmail}</strong>
              </p>
            </div>
            <span style={{ fontSize: "0.75rem", color: isDark ? "#94a3b8" : "#64748b" }}>
              Total Analyst Events: <strong>{userActivityLogs.length}</strong>
            </span>
          </div>

          {loadingUserActivity ? (
            <LoadingSpinner text="Fetching user activity history from PostgreSQL user_activity_logs..." />
          ) : userActivityLogs.length === 0 ? (
            <div style={{ textAlign: "center", padding: "2rem", color: isDark ? "#94a3b8" : "#64748b" }}>
              <p style={{ margin: 0, fontWeight: "600" }}>No activity log events recorded for this user yet.</p>
            </div>
          ) : (
            <div style={{ overflowX: "auto", width: "100%", borderRadius: "8px" }}>
              <table
                style={{
                  width: "100%",
                  minWidth: "1150px",
                  tableLayout: "fixed",
                  borderCollapse: "collapse",
                  fontSize: "0.82rem",
                  lineHeight: "1.5",
                }}
              >
                <thead>
                  <tr
                    style={{
                      backgroundColor: isDark ? "rgba(30, 41, 59, 0.8)" : "#f1f5f9",
                      borderBottom: isDark ? "1px solid #334155" : "1px solid #cbd5e1",
                    }}
                  >
                    <th style={{ width: "95px", padding: "0.75rem 0.85rem", textAlign: "left", color: isDark ? "#94a3b8" : "#475569", fontWeight: "700", fontSize: "0.75rem", textTransform: "uppercase", letterSpacing: "0.04em" }}>
                      Log ID
                    </th>
                    <th style={{ width: "175px", padding: "0.75rem 0.85rem", textAlign: "left", color: isDark ? "#94a3b8" : "#475569", fontWeight: "700", fontSize: "0.75rem", textTransform: "uppercase", letterSpacing: "0.04em" }}>
                      Timestamp (UTC)
                    </th>
                    <th style={{ width: "160px", padding: "0.75rem 0.85rem", textAlign: "left", color: isDark ? "#94a3b8" : "#475569", fontWeight: "700", fontSize: "0.75rem", textTransform: "uppercase", letterSpacing: "0.04em" }}>
                      Action Type
                    </th>
                    <th style={{ width: "140px", padding: "0.75rem 0.85rem", textAlign: "left", color: isDark ? "#94a3b8" : "#475569", fontWeight: "700", fontSize: "0.75rem", textTransform: "uppercase", letterSpacing: "0.04em" }}>
                      Target IP / Subject
                    </th>
                    <th style={{ width: "90px", padding: "0.75rem 0.85rem", textAlign: "center", color: isDark ? "#94a3b8" : "#475569", fontWeight: "700", fontSize: "0.75rem", textTransform: "uppercase", letterSpacing: "0.04em" }}>
                      Protocol
                    </th>
                    <th style={{ width: "160px", padding: "0.75rem 0.85rem", textAlign: "left", color: isDark ? "#94a3b8" : "#475569", fontWeight: "700", fontSize: "0.75rem", textTransform: "uppercase", letterSpacing: "0.04em" }}>
                      Engine / Dataset
                    </th>
                    <th style={{ width: "130px", padding: "0.75rem 0.85rem", textAlign: "center", color: isDark ? "#94a3b8" : "#475569", fontWeight: "700", fontSize: "0.75rem", textTransform: "uppercase", letterSpacing: "0.04em" }}>
                      Resulting Severity
                    </th>
                    <th style={{ width: "280px", padding: "0.75rem 0.85rem", textAlign: "left", color: isDark ? "#94a3b8" : "#475569", fontWeight: "700", fontSize: "0.75rem", textTransform: "uppercase", letterSpacing: "0.04em" }}>
                      Action Details / Summary
                    </th>
                  </tr>
                </thead>
                <tbody>
                  {userActivityLogs.map((log, idx) => {
                    const sev = (log.severity || "CRITICAL").toUpperCase();
                    let sevColor = "#ef4444";
                    let sevBg = "rgba(239, 68, 68, 0.18)";
                    let sevBorder = "rgba(239, 68, 68, 0.35)";

                    if (sev === "HIGH") {
                      sevColor = "#f97316";
                      sevBg = "rgba(249, 115, 22, 0.18)";
                      sevBorder = "rgba(249, 115, 22, 0.35)";
                    } else if (sev === "MEDIUM") {
                      sevColor = "#eab308";
                      sevBg = "rgba(234, 179, 8, 0.18)";
                      sevBorder = "rgba(234, 179, 8, 0.35)";
                    } else if (sev === "LOW" || sev === "INFORMATIONAL") {
                      sevColor = "#38bdf8";
                      sevBg = "rgba(56, 189, 248, 0.18)";
                      sevBorder = "rgba(56, 189, 248, 0.35)";
                    }

                    return (
                      <tr
                        key={log.id || idx}
                        style={{
                          borderBottom: isDark ? "1px solid rgba(255, 255, 255, 0.06)" : "1px solid #e2e8f0",
                          backgroundColor: idx % 2 === 0 ? "transparent" : (isDark ? "rgba(255, 255, 255, 0.015)" : "#f8fafc"),
                          transition: "background 0.15s ease",
                        }}
                      >
                        {/* 1. Log ID */}
                        <td style={{ padding: "0.75rem 0.85rem", verticalAlign: "middle" }}>
                          <code style={{ fontSize: "0.8rem", color: isDark ? "#38bdf8" : "#0284c7", fontWeight: "700" }}>
                            {log.id || log.log_id || `LOG-${idx + 1}`}
                          </code>
                        </td>

                        {/* 2. Timestamp (UTC) */}
                        <td style={{ padding: "0.75rem 0.85rem", color: isDark ? "#cbd5e1" : "#475569", whiteSpace: "nowrap", verticalAlign: "middle" }}>
                          <span style={{ fontSize: "0.78rem", fontFamily: "monospace" }}>
                            {log.timestamp}
                          </span>
                        </td>

                        {/* 3. Action Type */}
                        <td style={{ padding: "0.75rem 0.85rem", verticalAlign: "middle" }}>
                          <span style={{ fontSize: "0.78rem", fontWeight: "700", color: isDark ? "#f8fafc" : "#0f172a" }}>
                            {log.action_type}
                          </span>
                        </td>

                        {/* 4. Target IP / Subject */}
                        <td style={{ padding: "0.75rem 0.85rem", verticalAlign: "middle" }}>
                          <code style={{ fontSize: "0.82rem", color: isDark ? "#f8fafc" : "#0f172a", fontWeight: "700", fontFamily: "monospace" }}>
                            {log.target_ip || log.ip_address || "185.220.101.50"}
                          </code>
                        </td>

                        {/* 5. Protocol */}
                        <td style={{ padding: "0.75rem 0.85rem", textAlign: "center", verticalAlign: "middle" }}>
                          <span style={{ fontSize: "0.75rem", fontWeight: "700", padding: "0.15rem 0.5rem", borderRadius: "4px", backgroundColor: isDark ? "rgba(255,255,255,0.08)" : "#e2e8f0", color: isDark ? "#cbd5e1" : "#334155" }}>
                            {log.protocol || "TCP"}
                          </span>
                        </td>

                        {/* 6. Engine / Dataset */}
                        <td style={{ padding: "0.75rem 0.85rem", verticalAlign: "middle" }}>
                          <span style={{ fontSize: "0.78rem", fontWeight: "600", color: isDark ? "#cbd5e1" : "#334155" }}>
                            {log.dataset_engine || "UNSW-NB15"}
                          </span>
                        </td>

                        {/* 7. Resulting Severity */}
                        <td style={{ padding: "0.75rem 0.85rem", textAlign: "center", verticalAlign: "middle" }}>
                          <span
                            style={{
                              display: "inline-flex",
                              alignItems: "center",
                              justifyContent: "center",
                              padding: "0.2rem 0.6rem",
                              borderRadius: "9999px",
                              fontSize: "0.72rem",
                              fontWeight: "700",
                              backgroundColor: sevBg,
                              color: sevColor,
                              border: `1px solid ${sevBorder}`,
                            }}
                          >
                            {sev}
                          </span>
                        </td>

                        {/* 8. Action Details / Summary */}
                        <td
                          title={log.details}
                          style={{
                            padding: "0.75rem 0.85rem",
                            verticalAlign: "middle",
                          }}
                        >
                          <span
                            style={{
                              display: "block",
                              maxWidth: "260px",
                              overflow: "hidden",
                              textOverflow: "ellipsis",
                              whiteSpace: "nowrap",
                              fontSize: "0.8rem",
                              color: isDark ? "#cbd5e1" : "#475569",
                            }}
                          >
                            {log.details}
                          </span>
                        </td>
                      </tr>
                    );
                  })}
                </tbody>
              </table>
            </div>
          )}
        </div>


      </div>
    </div>
  );
}
