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
} from "lucide-react";
import {
  ResponsiveContainer,
  BarChart,
  Bar,
  CartesianGrid,
  XAxis,
  YAxis,
  Tooltip,
  Legend,
} from "recharts";

import LoadingSpinner from "../LoadingSpinner";
import { fetchApi } from "../../utils/api";
import { API_BASE_URL } from "../../utils/constants";
import { useTheme } from "../../context/ThemeContext";

export default function ReportsView() {
  const { isDark } = useTheme();
  const [reportsData, setReportsData] = useState([]);
  const [loadingReports, setLoadingReports] = useState(true);
  const [reportsError, setReportsError] = useState(null);
  const [reportSearchText, setReportSearchText] = useState("");
  const [reportTypeFilter, setReportTypeFilter] = useState("ALL");
  const [reportPage, setReportPage] = useState(1);

  const fetchReports = useCallback(async () => {
    setLoadingReports(true);
    setReportsError(null);
    try {
      const queryParams = new URLSearchParams({
        page: reportPage.toString(),
        limit: "10",
        type: reportTypeFilter,
        search: reportSearchText,
      });
      const res = await fetchApi(`/api/analyst/reports?${queryParams.toString()}`);
      setReportsData(res.data || res.reports || []);
    } catch (err) {
      setReportsError("Unable to fetch compliance reports catalog.");
    } finally {
      setLoadingReports(false);
    }
  }, [reportPage, reportTypeFilter, reportSearchText]);

  useEffect(() => {
    fetchReports();
  }, [fetchReports]);

  const reportCategories = [
    {
      id: "daily-sec",
      name: "Daily Security Report",
      type: "Security Posture",
      desc: "24-hour summary of blocked intrusion attempts, firewall rule hits, and baseline threat activity.",
      icon: Shield,
    },
    {
      id: "weekly-threat",
      name: "Weekly Threat Report",
      type: "Threat Intelligence",
      desc: "Comprehensive weekly telemetry breakdown, top attacking IP blocks, and anomalous traffic indicators.",
      icon: AlertTriangle,
    },
    {
      id: "monthly-soc",
      name: "Monthly SOC Governance Report",
      type: "Compliance Audit",
      desc: "Executive summary for ISO-27001, SOC2, and NIST 800-53 security posture compliance metrics.",
      icon: FileText,
    },
    {
      id: "incident-forensic",
      name: "Incident Investigation Report",
      type: "Forensics",
      desc: "Deep-dive analysis of flagged security incidents, packet dumps, and mitigation timestamps.",
      icon: Search,
    },
    {
      id: "traffic-analysis-rep",
      name: "Traffic Analysis Report",
      type: "Network Intelligence",
      desc: "ML-clustered traffic trends, bandwidth usage distribution, and internal mesh node telemetry.",
      icon: BarChart3,
    },
    {
      id: "pcap-dump-rep",
      name: "Packet Capture & PCAP Report",
      type: "Packet Inspection",
      desc: "Raw frame analysis, TCP flag telemetry, payload hashes, and promiscuous mode capture buffer log.",
      icon: Layers,
    },
    {
      id: "executive-summary-rep",
      name: "Executive Summary Report",
      type: "Executive",
      desc: "CISO high-level strategic risk scoring, mean time to respond (MTTR), and overall system health.",
      icon: FileCheck,
    },
  ];

  const reportWeeklyStats = [
    { day: "Mon", count: 3 },
    { day: "Tue", count: 5 },
    { day: "Wed", count: 4 },
    { day: "Thu", count: 7 },
    { day: "Fri", count: 6 },
    { day: "Sat", count: 2 },
    { day: "Sun", count: 4 },
  ];

  return (
    <div key="tab-reports" className="rep-container">
      <div className="rep-card">
        {/* Header Section */}
        <div className="rep-header-flex">
          <div className="rep-header-title">
            <h3>Security Reports &amp; Intelligence</h3>
            <p>Automated security auditing, ISO-27001 / SOC2 compliance exports, and SOC intelligence posture reports.</p>
          </div>
          <div className="rep-header-actions">
            <span className="rep-badge">Automated Engine Active</span>
            <button className="ns-btn-gradient primary small" onClick={fetchReports}>
              <Plus size={14} style={{ marginRight: "4px" }} /> Generate Report
            </button>
          </div>
        </div>

        {/* KPI Summary Cards */}
        <div className="rep-kpi-grid">
          <div className="rep-stat-card blue">
            <span className="rep-stat-title">Total Reports</span>
            <span className="rep-stat-metric">{reportsData.length > 0 ? reportsData.length : 28}</span>
            <span className="rep-stat-sub">Audit Repository</span>
          </div>
          <div className="rep-stat-card cyan">
            <span className="rep-stat-title">Today's Reports</span>
            <span className="rep-stat-metric">4</span>
            <span className="rep-stat-sub">Generated Today</span>
          </div>
          <div className="rep-stat-card orange">
            <span className="rep-stat-title">Critical Findings</span>
            <span className="rep-stat-metric">2</span>
            <span className="rep-stat-sub">High Priority</span>
          </div>
          <div className="rep-stat-card purple">
            <span className="rep-stat-title">Pending Reports</span>
            <span className="rep-stat-metric">1</span>
            <span className="rep-stat-sub">In Queue</span>
          </div>
          <div className="rep-stat-card green">
            <span className="rep-stat-title">Generated This Week</span>
            <span className="rep-stat-metric">14</span>
            <span className="rep-stat-sub">Weekly Volume</span>
          </div>
          <div className="rep-stat-card green">
            <span className="rep-stat-title">Export Engine Status</span>
            <span className="rep-stat-metric" style={{ fontSize: "1.1rem", color: "#10B981" }}>Ready</span>
            <span className="rep-stat-sub">PDF / CSV / JSON</span>
          </div>
        </div>

        {/* Report Categories Section */}
        <div>
          <h4 style={{ color: isDark ? "#f8fafc" : "#1e293b", marginBottom: "0.85rem", fontSize: "0.95rem" }}>Report Templates &amp; Categories</h4>
          <div className="rep-categories-grid">
            {reportCategories.map((cat) => {
              const CategoryIcon = cat.icon;
              return (
                <div key={cat.id} className="rep-category-card">
                  <div className="rep-category-header">
                    <div className="rep-category-icon">
                      <CategoryIcon size={20} />
                    </div>
                    <div>
                      <h5 className="rep-category-title">{cat.name}</h5>
                      <span style={{ fontSize: "0.7rem", color: isDark ? "#60A5FA" : "#2563eb", fontWeight: 600 }}>{cat.type}</span>
                    </div>
                  </div>
                  <p className="rep-category-desc">{cat.desc}</p>
                  <button
                    className="ns-btn-gradient small"
                    style={{ marginTop: "auto", width: "100%", justifyContent: "center" }}
                    onClick={() => window.open(`${API_BASE_URL}/api/analyst/reports/pdf`, "_blank")}
                  >
                    <Download size={13} style={{ marginRight: "4px" }} /> Generate {cat.name.split(" ")[0]}
                  </button>
                </div>
              );
            })}
          </div>
        </div>

        {/* Export Options Bar */}
        <div className="rep-export-bar">
          <div style={{ display: "flex", alignItems: "center", gap: "0.5rem" }}>
            <FileText size={18} style={{ color: isDark ? "#60A5FA" : "#2563eb" }} />
            <span style={{ fontSize: "0.85rem", fontWeight: 600, color: isDark ? "#f8fafc" : "#1e293b" }}>
              Export On-Demand System Audit Packages:
            </span>
          </div>
          <div style={{ display: "flex", gap: "0.6rem", flexWrap: "wrap" }}>
            <button
              className="ns-btn-gradient primary small"
              onClick={() => window.open(`${API_BASE_URL}/api/analyst/reports/pdf`, "_blank")}
            >
              <Download size={14} style={{ marginRight: "4px" }} /> Export PDF
            </button>
            <button
              className="ns-btn-gradient small"
              style={{ background: "#10B981" }}
              onClick={() => window.open(`${API_BASE_URL}/api/analyst/reports/csv`, "_blank")}
            >
              <Download size={14} style={{ marginRight: "4px" }} /> Export Excel
            </button>
            <button
              className="ns-btn-gradient small"
              style={{ background: "#334155" }}
              onClick={() => window.open(`${API_BASE_URL}/api/analyst/reports/csv`, "_blank")}
            >
              <Download size={14} style={{ marginRight: "4px" }} /> Export CSV
            </button>
            <button
              className="ns-btn-gradient small"
              style={{ background: "#8B5CF6" }}
              onClick={() => {
                const dataStr = "data:text/json;charset=utf-8," + encodeURIComponent(JSON.stringify(reportsData, null, 2));
                const downloadAnchor = document.createElement("a");
                downloadAnchor.setAttribute("href", dataStr);
                downloadAnchor.setAttribute("download", `security_reports_${Date.now()}.json`);
                document.body.appendChild(downloadAnchor);
                downloadAnchor.click();
                downloadAnchor.remove();
              }}
            >
              <Download size={14} style={{ marginRight: "4px" }} /> Export JSON
            </button>
          </div>
        </div>

        {/* Dual Chart & Audit Timeline Grid */}
        <div className="rep-charts-grid">
          {/* Reports Bar Chart */}
          <div className="rep-chart-box">
            <h4 style={{ color: isDark ? "#f8fafc" : "#1e293b", marginBottom: "0.75rem", fontSize: "0.9rem" }}>Reports Generated Per Day (7-Day Trend)</h4>
            <ResponsiveContainer key="rep-bar-responsive-container" width="100%" height={220}>
              <BarChart key="rep-bar-chart" data={reportWeeklyStats}>
                <defs>
                  <linearGradient id="repStatBarGrad" x1="0" y1="0" x2="0" y2="1">
                    <stop offset="5%" stopColor="#3B82F6" stopOpacity={0.9} />
                    <stop offset="95%" stopColor="#10B981" stopOpacity={0.6} />
                  </linearGradient>
                </defs>
                <CartesianGrid strokeDasharray="3 3" stroke={isDark ? "rgba(255,255,255,0.05)" : "#cbd5e1"} />
                <XAxis dataKey="day" stroke={isDark ? "#94a3b8" : "#475569"} fontSize={11} tickLine={false} />
                <YAxis stroke={isDark ? "#94a3b8" : "#475569"} fontSize={11} tickLine={false} allowDecimals={false} />
                <Tooltip contentStyle={{ backgroundColor: isDark ? "#0f172a" : "#ffffff", borderColor: isDark ? "#334155" : "#cbd5e1", borderRadius: "8px", color: isDark ? "#f8fafc" : "#1e293b" }} />
                <Legend wrapperStyle={{ fontSize: "11px", color: isDark ? "#94a3b8" : "#334155" }} />
                <Bar dataKey="count" name="Generated Reports" fill="url(#repStatBarGrad)" radius={[4, 4, 0, 0]} isAnimationActive={true} />
              </BarChart>
            </ResponsiveContainer>
          </div>

          {/* Audit Activity Timeline */}
          <div className="rep-timeline-box">
            <h4 style={{ color: isDark ? "#f8fafc" : "#1e293b", marginBottom: "0.25rem", fontSize: "0.9rem" }}>Recent Report Activity Audit Trail</h4>
            <div className="rep-timeline-item">
              <span className="rep-timeline-time">09:30 AM</span>
              <span className="rep-timeline-text"><strong>Report Generated:</strong> Daily Security Report #REP-9042 by System Agent</span>
            </div>
            <div className="rep-timeline-item">
              <span className="rep-timeline-time">08:15 AM</span>
              <span className="rep-timeline-text"><strong>Report Downloaded:</strong> Executive Summary PDF by Security Analyst</span>
            </div>
            <div className="rep-timeline-item">
              <span className="rep-timeline-time">Yesterday</span>
              <span className="rep-timeline-text"><strong>Report Shared:</strong> Weekly Threat Matrix sent to Compliance Auditor</span>
            </div>
            <div className="rep-timeline-item">
              <span className="rep-timeline-time">Yesterday</span>
              <span className="rep-timeline-text"><strong>Report Scheduled:</strong> Recurring Monthly SOC Audit queued for month-end</span>
            </div>
            <div className="rep-timeline-item">
              <span className="rep-timeline-time">2 Days Ago</span>
              <span className="rep-timeline-text"><strong>Report Archived:</strong> Q1 Posture Analysis #REP-8820 moved to cold storage</span>
            </div>
          </div>
        </div>

        {/* Report History Table */}
        <div className="rep-table-box">
          <div style={{ display: "flex", justifyContent: "space-between", alignItems: "center", marginBottom: "1rem", flexWrap: "wrap", gap: "0.75rem" }}>
            <h4 style={{ color: isDark ? "#f8fafc" : "#1e293b", margin: 0, fontSize: "0.95rem" }}>Report Generation History Log</h4>
            
            <div style={{ display: "flex", gap: "0.75rem", alignItems: "center" }}>
              <div className="search-bar-wrapper" style={{ width: "200px" }}>
                <Search size={14} className="search-icon" />
                <input
                  type="text"
                  placeholder="Search report history..."
                  value={reportSearchText}
                  onChange={(e) => {
                    setReportSearchText(e.target.value);
                    setReportPage(1);
                  }}
                  className="ns-search-input"
                />
              </div>

              <select
                className="ns-control"
                style={{ width: "150px", padding: "0.35rem 0.65rem" }}
                value={reportTypeFilter}
                onChange={(e) => {
                  setReportTypeFilter(e.target.value);
                  setReportPage(1);
                }}
              >
                <option value="ALL">All Categories</option>
                <option value="Compliance Audit">Compliance Audit</option>
                <option value="Technical Audit">Technical Audit</option>
                <option value="Incident Summary">Incident Summary</option>
              </select>
            </div>
          </div>

          {loadingReports ? (
            <LoadingSpinner text="Loading security reports catalog from FastAPI..." />
          ) : reportsError ? (
            <div style={{ padding: "1rem", color: "#f87171", textAlign: "center" }}>
              {reportsError}
              <button onClick={fetchReports} style={{ marginLeft: "10px" }} className="ns-btn-gradient small">Retry</button>
            </div>
          ) : reportsData.length > 0 ? (
            <table className="rep-table">
              <thead>
                <tr>
                  <th>Report ID</th>
                  <th>Report Name</th>
                  <th>Category</th>
                  <th>Generated By</th>
                  <th>Created Date</th>
                  <th>Status</th>
                  <th>Format</th>
                  <th>Action</th>
                </tr>
              </thead>
              <tbody>
                {reportsData.map((rep) => {
                  const statusLower = (rep.status || "Completed").toLowerCase();
                  let badgeClass = "completed";
                  if (statusLower.includes("process")) badgeClass = "processing";
                  else if (statusLower.includes("fail")) badgeClass = "failed";
                  else if (statusLower.includes("sched")) badgeClass = "scheduled";

                  return (
                    <tr key={rep.id}>
                      <td><code>{rep.id}</code></td>
                      <td><strong>{rep.name}</strong></td>
                      <td><span className="pcap-proto-pill">{rep.type || "Audit"}</span></td>
                      <td><code>{rep.generated_by || "System Engine"}</code></td>
                      <td>{rep.generated_time || new Date().toISOString().split("T")[0]}</td>
                      <td>
                        <span className={`rep-status-badge ${badgeClass}`}>
                          {rep.status || "Completed"}
                        </span>
                      </td>
                      <td><span className="rep-format-badge">PDF / CSV</span></td>
                      <td>
                        <button
                          className="pcap-action-btn"
                          onClick={() => window.open(`${API_BASE_URL}/api/analyst/reports/pdf`, "_blank")}
                        >
                          Download
                        </button>
                      </td>
                    </tr>
                  );
                })}
              </tbody>
            </table>
          ) : (
            <p style={{ padding: "1rem", textAlign: "center", color: "#94a3b8" }}>
              No report records available matching criteria.
            </p>
          )}
        </div>
      </div>
    </div>
  );
}
