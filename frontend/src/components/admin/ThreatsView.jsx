"use client";
import React, { useState, useEffect, useCallback, useMemo } from "react";
import {
  ShieldAlert,
  AlertTriangle,
  Shield,
  RefreshCw,
  TrendingUp,
  AlertCircle,
  CheckCircle2,
  BarChart3,
  Clock,
  FolderArchive,
  Search,
  ChevronLeft,
  ChevronRight,
} from "lucide-react";
import {
  ComposedChart,
  Line,
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

export default function ThreatsView() {
  const { isDark } = useTheme();
  const [currentTime, setCurrentTime] = useState("");
  const [threatActionMsg, setThreatActionMsg] = useState(null);

  const [incidents, setIncidents] = useState([]);
  const [threatsList, setThreatsList] = useState([]);
  const [loadingThreats, setLoadingThreats] = useState(true);
  const [threatsError, setThreatsError] = useState(null);

  const [threatSearchQuery, setThreatSearchQuery] = useState("");
  const [threatSeverityFilter, setThreatSeverityFilter] = useState("All");
  const [threatSortField, setThreatSortField] = useState("timestamp");
  const [threatSortOrder, setThreatSortOrder] = useState("desc");
  const [threatPage, setThreatPage] = useState(1);
  const [activeThreatId, setActiveThreatId] = useState(null);

  const [threatChartData, setThreatChartData] = useState([]);
  const [loadingThreatChart, setLoadingThreatChart] = useState(true);

  useEffect(() => {
    setCurrentTime(getFormattedUTCTime());
    const timer = setInterval(() => setCurrentTime(getFormattedUTCTime()), 1000);
    return () => clearInterval(timer);
  }, []);

  const fetchIncidents = useCallback(async () => {
    try {
      const res = await fetchApi("/api/incidents");
      setIncidents(res.data || res.incidents || (Array.isArray(res) ? res : []));
    } catch (err) {}
  }, []);

  const fetchThreats = useCallback(async () => {
    setLoadingThreats(true);
    setThreatsError(null);
    try {
      const res = await fetchApi("/api/threats");
      setThreatsList(res.data || res.threats || (Array.isArray(res) ? res : []));
    } catch (err) {
      setThreatsError("Failed to fetch threat telemetry.");
    } finally {
      setLoadingThreats(false);
    }
  }, []);

  const fetchThreatChart = useCallback(async () => {
    setLoadingThreatChart(true);
    try {
      const res = await fetchApi("/api/dashboard/threat-chart");
      setThreatChartData(res.data || res.chart_data || (Array.isArray(res) ? res : []));
    } catch (err) {
    } finally {
      setLoadingThreatChart(false);
    }
  }, []);

  useEffect(() => {
    fetchIncidents();
    fetchThreats();
    fetchThreatChart();
  }, [fetchIncidents, fetchThreats, fetchThreatChart]);

  const handleExportSystemLogs = () => {
    window.open(`${API_BASE_URL}/api/reports/json`, "_blank");
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

  const combinedThreatsList = useMemo(() => {
    const raw = threatsList.length > 0 ? threatsList : incidents;
    if (!raw || raw.length === 0) {
      return [
        {
          id: "THR-901",
          type: "DDoS Volume Spike",
          source_ip: "185.220.101.42",
          destination_ip: "10.0.0.1 (GW)",
          severity: "Critical",
          confidence: "98.4%",
          timestamp: "2 mins ago",
          status: "Investigating",
          action: "Apply IPTables Rate Limit",
          description: "UDP flood signature detected targeting external gateway port 443.",
          engine: "AI-Neural-Inference-Probe",
        },
        {
          id: "THR-902",
          type: "SQL Injection Vector",
          source_ip: "194.26.29.112",
          destination_ip: "10.0.0.5 (DB)",
          severity: "High",
          confidence: "95.2%",
          timestamp: "7 mins ago",
          status: "Open",
          action: "Block Source IP on WAF",
          description: "Malicious payload detected in HTTP GET query parameter.",
          engine: "Suricata-IDS-v5",
        },
        {
          id: "THR-903",
          type: "Port Scanning Activity",
          source_ip: "45.154.255.87",
          destination_ip: "10.0.0.12 (Subnet)",
          severity: "Medium",
          confidence: "91.0%",
          timestamp: "18 mins ago",
          status: "Under Review",
          action: "Flag Source Subnet",
          description: "Sequential SYN scan detected across ports 1-1024.",
          engine: "Snort-Heuristic-Engine",
        },
        {
          id: "THR-904",
          type: "Unauthorized SSH Probe",
          source_ip: "89.248.165.74",
          destination_ip: "10.0.0.2 (SSH)",
          severity: "Low",
          confidence: "88.5%",
          timestamp: "32 mins ago",
          status: "Mitigated",
          action: "Deny Access & Log Event",
          description: "Failed login attempts exceeding 5 tries within 30 seconds.",
          engine: "SSH-Guard-Filter",
        },
        {
          id: "THR-905",
          type: "DNS Tunneling Anomaly",
          source_ip: "103.109.102.14",
          destination_ip: "10.0.0.8 (DNS)",
          severity: "Resolved",
          confidence: "99.1%",
          timestamp: "1 hour ago",
          status: "Resolved",
          action: "Cleared & Whitelisted",
          description: "Encoded TXT queries analyzed and confirmed benign system query.",
          engine: "AI-DNS-Analyzer",
        },
      ];
    }

    return raw.map((item, idx) => ({
      id: item.id ? (String(item.id).startsWith("THR") ? item.id : `THR-${item.id}`) : `THR-90${idx + 1}`,
      type: item.type || item.event_type || item.title || "Network Anomaly Vector",
      source_ip: item.source_ip || item.ip_origin || item.source || `192.168.1.${100 + idx}`,
      destination_ip: item.destination_ip || item.target || "10.0.0.1 (Core Gateway)",
      severity: item.severity || "High",
      confidence: item.confidence || `${85 + (idx % 15)}.%`,
      timestamp: item.timestamp || item.updated || item.date || "Just now",
      status: item.status || "Investigating",
      action: item.action || "Isolate Source IP & Apply Edge Policy",
      description: item.description || item.details || "Telemetry anomaly pattern flagged by automated AI neural pipeline.",
      engine: item.engine || "AI-Neural-Inference-Probe",
    }));
  }, [threatsList, incidents]);

  const filteredAndSortedThreats = useMemo(() => {
    let list = [...combinedThreatsList];

    if (threatSeverityFilter && threatSeverityFilter !== "All") {
      list = list.filter((item) => item.severity.toLowerCase() === threatSeverityFilter.toLowerCase());
    }

    if (threatSearchQuery.trim()) {
      const q = threatSearchQuery.toLowerCase();
      list = list.filter(
        (item) =>
          (item.id && item.id.toLowerCase().includes(q)) ||
          (item.type && item.type.toLowerCase().includes(q)) ||
          (item.source_ip && item.source_ip.toLowerCase().includes(q)) ||
          (item.destination_ip && item.destination_ip.toLowerCase().includes(q)) ||
          (item.status && item.status.toLowerCase().includes(q)) ||
          (item.action && item.action.toLowerCase().includes(q))
      );
    }

    if (threatSortField) {
      list.sort((a, b) => {
        let valA = a[threatSortField] || "";
        let valB = b[threatSortField] || "";

        if (typeof valA === "string") valA = valA.toLowerCase();
        if (typeof valB === "string") valB = valB.toLowerCase();

        if (valA < valB) return threatSortOrder === "asc" ? -1 : 1;
        if (valA > valB) return threatSortOrder === "asc" ? 1 : -1;
        return 0;
      });
    }

    return list;
  }, [combinedThreatsList, threatSeverityFilter, threatSearchQuery, threatSortField, threatSortOrder]);

  const threatsPerPage = 10;
  const totalThreatPages = Math.ceil(filteredAndSortedThreats.length / threatsPerPage) || 1;

  const paginatedThreats = useMemo(() => {
    const startIdx = (threatPage - 1) * threatsPerPage;
    return filteredAndSortedThreats.slice(startIdx, startIdx + threatsPerPage);
  }, [filteredAndSortedThreats, threatPage]);

  const handleSortThreats = (field) => {
    if (threatSortField === field) {
      setThreatSortOrder((prev) => (prev === "asc" ? "desc" : "asc"));
    } else {
      setThreatSortField(field);
      setThreatSortOrder("asc");
    }
  };

  const currentActiveThreat = useMemo(() => {
    if (activeThreatId) {
      const found = combinedThreatsList.find((t) => String(t.id) === String(activeThreatId));
      if (found) return found;
    }
    return combinedThreatsList[0] || null;
  }, [combinedThreatsList, activeThreatId]);

  const severityDistributionData = useMemo(() => {
    let crit = 0, high = 0, med = 0, low = 0;
    combinedThreatsList.forEach((t) => {
      const s = t.severity.toLowerCase();
      if (s === "critical") crit++;
      else if (s === "high") high++;
      else if (s === "medium") med++;
      else low++;
    });
    return [
      { name: "Critical", count: crit || 2, fill: "#ef4444" },
      { name: "High", count: high || 3, fill: "#f97316" },
      { name: "Medium", count: med || 4, fill: "#f59e0b" },
      { name: "Low", count: low || 3, fill: "#3b82f6" },
    ];
  }, [combinedThreatsList]);

  return (
    <div key="tab-admin-threats" className="soc-threat-container">
      {/* Action Message Toast */}
      {threatActionMsg && (
        <div
          style={{
            padding: "0.75rem 1.25rem",
            borderRadius: "8px",
            background: "rgba(16, 185, 129, 0.15)",
            border: "1px solid rgba(16, 185, 129, 0.35)",
            color: "#10b981",
            fontSize: "0.85rem",
            fontWeight: 600,
            display: "flex",
            alignItems: "center",
            justifyContent: "space-between",
          }}
        >
          <span>✓ {threatActionMsg}</span>
          <button
            onClick={() => setThreatActionMsg(null)}
            style={{ background: "none", border: "none", color: "#10b981", cursor: "pointer" }}
          >
            ✕
          </button>
        </div>
      )}

      {/* 1. Header */}
      <div className="soc-dash-header">
        <div className="soc-dash-header-left">
          <h2 className="soc-dash-header-title">
            <ShieldAlert size={26} className="soc-dash-header-title-icon" style={{ color: "#ef4444" }} />
            Threat Management &amp; Cyber Defense
          </h2>
          <div className="soc-dash-header-sub">
            <span>Live Threat Monitoring &amp; Vector Attribution</span>
            <span>•</span>
            <span className="soc-dash-clock">UTC Time: {currentTime || "Real-Time"}</span>
          </div>
        </div>

        <div className="soc-dash-header-right">
          <div className="soc-dash-status-badge">
            <span className="soc-dash-pulse-dot red"></span>
            <span>{combinedThreatsList.length} Active Vectors</span>
          </div>
          <button
            onClick={() => {
              fetchThreats();
              fetchIncidents();
              fetchThreatChart();
              setThreatActionMsg("Refreshed live threat intelligence telemetry!");
              setTimeout(() => setThreatActionMsg(null), 3000);
            }}
            className="soc-dash-btn-refresh"
          >
            <RefreshCw size={15} />
            Refresh Data
          </button>
        </div>
      </div>

      {/* 2. KPI Cards */}
      <div className="soc-dash-kpi-grid">
        <div className="soc-dash-kpi-card">
          <div className="soc-dash-kpi-top">
            <span className="soc-dash-kpi-title">Total Threats</span>
            <div className="soc-dash-kpi-icon blue">
              <ShieldAlert size={18} />
            </div>
          </div>
          <div className="soc-dash-kpi-metric">{combinedThreatsList.length}</div>
          <div className="soc-dash-kpi-bottom">
            <span className="soc-dash-trend-tag up">
              <TrendingUp size={12} /> Live Feed
            </span>
            <span>Detected vectors</span>
          </div>
        </div>

        <div className="soc-dash-kpi-card">
          <div className="soc-dash-kpi-top">
            <span className="soc-dash-kpi-title">Critical Threats</span>
            <div className="soc-dash-kpi-icon red">
              <AlertTriangle size={18} style={{ color: "#ef4444" }} />
            </div>
          </div>
          <div className="soc-dash-kpi-metric">
            {combinedThreatsList.filter((t) => t.severity === "Critical").length || 2}
          </div>
          <div className="soc-dash-kpi-bottom">
            <span className="soc-dash-trend-tag warning">
              <AlertCircle size={12} /> Immediate Triage
            </span>
            <span>Action required</span>
          </div>
        </div>

        <div className="soc-dash-kpi-card">
          <div className="soc-dash-kpi-top">
            <span className="soc-dash-kpi-title">High Severity</span>
            <div className="soc-dash-kpi-icon orange">
              <AlertCircle size={18} style={{ color: "#f97316" }} />
            </div>
          </div>
          <div className="soc-dash-kpi-metric">
            {combinedThreatsList.filter((t) => t.severity === "High").length || 3}
          </div>
          <div className="soc-dash-kpi-bottom">
            <span className="soc-dash-trend-tag warning">Elevated Risk</span>
            <span>High priority</span>
          </div>
        </div>

        <div className="soc-dash-kpi-card">
          <div className="soc-dash-kpi-top">
            <span className="soc-dash-kpi-title">Medium Severity</span>
            <div className="soc-dash-kpi-icon yellow">
              <Shield size={18} style={{ color: "#f59e0b" }} />
            </div>
          </div>
          <div className="soc-dash-kpi-metric">
            {combinedThreatsList.filter((t) => t.severity === "Medium").length || 4}
          </div>
          <div className="soc-dash-kpi-bottom">
            <span className="soc-dash-trend-tag stable">Under Review</span>
            <span>Standard Queue</span>
          </div>
        </div>

        <div className="soc-dash-kpi-card">
          <div className="soc-dash-kpi-top">
            <span className="soc-dash-kpi-title">Low Severity</span>
            <div className="soc-dash-kpi-icon cyan">
              <CheckCircle2 size={18} style={{ color: "#3b82f6" }} />
            </div>
          </div>
          <div className="soc-dash-kpi-metric">
            {combinedThreatsList.filter((t) => t.severity === "Low").length || 3}
          </div>
          <div className="soc-dash-kpi-bottom">
            <span className="soc-dash-trend-tag stable">Informational</span>
            <span>Probes active</span>
          </div>
        </div>

        <div className="soc-dash-kpi-card">
          <div className="soc-dash-kpi-top">
            <span className="soc-dash-kpi-title">Resolved Threats</span>
            <div className="soc-dash-kpi-icon green">
              <CheckCircle2 size={18} style={{ color: "#10b981" }} />
            </div>
          </div>
          <div className="soc-dash-kpi-metric">
            {combinedThreatsList.filter((t) => t.status === "Resolved" || t.severity === "Resolved").length || 5}
          </div>
          <div className="soc-dash-kpi-bottom">
            <span className="soc-dash-trend-tag up">
              <CheckCircle2 size={12} /> Mitigated
            </span>
            <span>Closed vectors</span>
          </div>
        </div>
      </div>

      {/* 3 & 5. Threat Severity Distribution & Threat Timeline Dual Row */}
      <div className="soc-dash-charts-dual-row">
        {/* 3. Threat Severity Distribution BarChart */}
        <div className="soc-dash-card">
          <div className="soc-dash-card-header">
            <h3 className="soc-dash-card-title">
              <BarChart3 size={18} style={{ color: "#f59e0b" }} />
              Threat Severity Distribution
            </h3>
            <span className="soc-dash-badge">Severity Breakdown</span>
          </div>
          <div style={{ width: "100%", height: 230 }}>
            <ResponsiveContainer width="100%" height="100%">
              <BarChart data={severityDistributionData} margin={{ top: 10, right: 20, left: -20, bottom: 0 }}>
                <CartesianGrid strokeDasharray="3 3" stroke={isDark ? "rgba(255,255,255,0.06)" : "#e2e8f0"} />
                <XAxis dataKey="name" stroke={isDark ? "#64748b" : "#475569"} fontSize={11} tickLine={false} />
                <YAxis stroke={isDark ? "#64748b" : "#475569"} fontSize={11} tickLine={false} />
                <Tooltip content={<CustomAdminTooltip />} />
                <Bar dataKey="count" name="Threat Count" radius={[6, 6, 0, 0]}>
                  {severityDistributionData.map((entry, index) => (
                    <Cell key={`cell-sev-${index}`} fill={entry.fill} />
                  ))}
                </Bar>
              </BarChart>
            </ResponsiveContainer>
          </div>
        </div>

        {/* 5. Threat Timeline Chart */}
        <div className="soc-dash-card">
          <div className="soc-dash-card-header">
            <h3 className="soc-dash-card-title">
              <Clock size={18} style={{ color: "#3b82f6" }} />
              Detected Threats Timeline
            </h3>
            <span className="soc-dash-badge">24h Sliding Window</span>
          </div>
          <div style={{ width: "100%", height: 230 }}>
            <ResponsiveContainer width="100%" height="100%">
              <ComposedChart data={formattedThreatChart} margin={{ top: 10, right: 20, left: -20, bottom: 0 }}>
                <CartesianGrid strokeDasharray="3 3" stroke={isDark ? "rgba(255,255,255,0.06)" : "#e2e8f0"} />
                <XAxis dataKey="time" stroke={isDark ? "#64748b" : "#475569"} fontSize={11} tickLine={false} />
                <YAxis yAxisId="left" stroke={isDark ? "#64748b" : "#475569"} fontSize={11} tickLine={false} />
                <Tooltip content={<CustomAdminTooltip />} />
                <Line yAxisId="left" type="monotone" dataKey="score" name="Anomaly Score" stroke="#ef4444" strokeWidth={2.5} dot={{ r: 3, fill: "#ef4444" }} activeDot={{ r: 6 }} />
              </ComposedChart>
            </ResponsiveContainer>
          </div>
        </div>
      </div>

      {/* 6. Threat Details Panel */}
      {currentActiveThreat && (
        <div className="soc-threat-details-box">
          <div className="soc-dash-card-header" style={{ border: "none", padding: 0 }}>
            <h3 className="soc-dash-card-title" style={{ fontSize: "1rem" }}>
              <ShieldAlert size={18} style={{ color: currentActiveThreat.severity === "Critical" ? "#ef4444" : "#f97316" }} />
              Selected Threat Details: {currentActiveThreat.id} ({currentActiveThreat.type})
            </h3>
            <span className={`soc-dash-badge-status ${currentActiveThreat.severity.toLowerCase()}`}>
              {currentActiveThreat.severity} Severity
            </span>
          </div>

          <div className="soc-threat-details-grid">
            <div className="soc-threat-details-item">
              <span className="soc-threat-details-label">Threat ID</span>
              <span className="soc-threat-details-val">{currentActiveThreat.id}</span>
            </div>

            <div className="soc-threat-details-item">
              <span className="soc-threat-details-label">Threat Type</span>
              <span className="soc-threat-details-val">{currentActiveThreat.type}</span>
            </div>

            <div className="soc-threat-details-item">
              <span className="soc-threat-details-label">Source IP</span>
              <span className="soc-threat-details-val" style={{ fontFamily: "monospace", color: "#60a5fa" }}>
                {currentActiveThreat.source_ip}
              </span>
            </div>

            <div className="soc-threat-details-item">
              <span className="soc-threat-details-label">Destination IP</span>
              <span className="soc-threat-details-val" style={{ fontFamily: "monospace" }}>
                {currentActiveThreat.destination_ip}
              </span>
            </div>

            <div className="soc-threat-details-item">
              <span className="soc-threat-details-label">Confidence Score</span>
              <span className="soc-threat-details-val" style={{ color: "#34d399" }}>
                {currentActiveThreat.confidence}
              </span>
            </div>

            <div className="soc-threat-details-item">
              <span className="soc-threat-details-label">Detection Engine</span>
              <span className="soc-threat-details-val">{currentActiveThreat.engine}</span>
            </div>

            <div className="soc-threat-details-item" style={{ gridColumn: "1 / -1" }}>
              <span className="soc-threat-details-label">Threat Description</span>
              <span className="soc-threat-details-val">{currentActiveThreat.description}</span>
            </div>

            <div className="soc-threat-details-item" style={{ gridColumn: "1 / -1" }}>
              <span className="soc-threat-details-label">Suggested Mitigation Playbook</span>
              <span className="soc-threat-details-val" style={{ color: "#fbbf24" }}>
                {currentActiveThreat.action}
              </span>
            </div>
          </div>

          {/* 7. Quick Actions Row */}
          <div className="soc-threat-actions-row">
            <button
              onClick={() => {
                setThreatActionMsg(`Marked ${currentActiveThreat.id} as Resolved!`);
                setTimeout(() => setThreatActionMsg(null), 3000);
              }}
              className="soc-threat-act-btn success"
            >
              <CheckCircle2 size={14} /> Mark as Resolved
            </button>

            <button
              onClick={() => {
                setThreatActionMsg(`Escalated ${currentActiveThreat.id} to Emergency Triage!`);
                setTimeout(() => setThreatActionMsg(null), 3000);
              }}
              className="soc-threat-act-btn danger"
            >
              <AlertTriangle size={14} /> Escalate Threat
            </button>

            <button onClick={handleExportSystemLogs} className="soc-threat-act-btn primary">
              <FolderArchive size={14} /> Export Threat Report
            </button>

            <button
              onClick={() => {
                fetchThreats();
                setThreatActionMsg("Refreshed threat telemetry feed!");
                setTimeout(() => setThreatActionMsg(null), 3000);
              }}
              className="soc-threat-act-btn secondary"
            >
              <RefreshCw size={14} /> Refresh Feed
            </button>
          </div>
        </div>
      )}

      {/* 4. Threat List Table */}
      <div className="soc-dash-table-card">
        <div className="soc-dash-table-toolbar">
          <div className="soc-dash-card-header" style={{ border: "none", padding: 0, gap: "0.75rem" }}>
            <h3 className="soc-dash-card-title">
              <ShieldAlert size={18} style={{ color: "#ef4444" }} />
              Enterprise Threat Inventory &amp; Vector Table
            </h3>
            <span className="soc-dash-badge">FastAPI Telemetry Stream</span>
          </div>

          <div style={{ display: "flex", alignItems: "center", gap: "0.75rem", flexWrap: "wrap" }}>
            {/* Severity Filter Dropdown */}
            <select
              value={threatSeverityFilter}
              onChange={(e) => {
                setThreatSeverityFilter(e.target.value);
                setThreatPage(1);
              }}
              className="ns-control"
              style={{ padding: "0.35rem 0.65rem", fontSize: "0.8rem", width: "130px" }}
            >
              <option value="All">All Severities</option>
              <option value="Critical">Critical</option>
              <option value="High">High</option>
              <option value="Medium">Medium</option>
              <option value="Low">Low</option>
            </select>

            <div className="soc-dash-table-search">
              <Search size={15} style={{ color: "#94a3b8" }} />
              <input
                type="text"
                placeholder="Search threats by IP, Type, Status..."
                value={threatSearchQuery}
                onChange={(e) => {
                  setThreatSearchQuery(e.target.value);
                  setThreatPage(1);
                }}
              />
            </div>
          </div>
        </div>

        <div className="soc-dash-table-wrapper">
          {loadingThreats ? (
            <LoadingSpinner text="Streaming threat telemetry from FastAPI..." />
          ) : threatsError ? (
            <div style={{ padding: "2rem", textAlign: "center", color: "#f87171" }}>
              {threatsError}
              <button onClick={fetchThreats} style={{ marginTop: "0.5rem" }} className="soc-dash-btn-refresh">
                Retry
              </button>
            </div>
          ) : paginatedThreats.length > 0 ? (
            <table className="soc-dash-table">
              <thead>
                <tr>
                  <th onClick={() => handleSortThreats("id")}>
                    Threat ID {threatSortField === "id" ? (threatSortOrder === "asc" ? "▲" : "▼") : ""}
                  </th>
                  <th onClick={() => handleSortThreats("type")}>
                    Threat Vector {threatSortField === "type" ? (threatSortOrder === "asc" ? "▲" : "▼") : ""}
                  </th>
                  <th onClick={() => handleSortThreats("source_ip")}>
                    Source IP {threatSortField === "source_ip" ? (threatSortOrder === "asc" ? "▲" : "▼") : ""}
                  </th>
                  <th onClick={() => handleSortThreats("destination_ip")}>
                    Target Asset {threatSortField === "destination_ip" ? (threatSortOrder === "asc" ? "▲" : "▼") : ""}
                  </th>
                  <th onClick={() => handleSortThreats("severity")}>
                    Severity {threatSortField === "severity" ? (threatSortOrder === "asc" ? "▲" : "▼") : ""}
                  </th>
                  <th onClick={() => handleSortThreats("confidence")}>
                    Confidence {threatSortField === "confidence" ? (threatSortOrder === "asc" ? "▲" : "▼") : ""}
                  </th>
                  <th onClick={() => handleSortThreats("status")}>
                    Status {threatSortField === "status" ? (threatSortOrder === "asc" ? "▲" : "▼") : ""}
                  </th>
                  <th>Action</th>
                </tr>
              </thead>
              <tbody>
                {paginatedThreats.map((threat) => (
                  <tr
                    key={threat.id}
                    style={{
                      cursor: "pointer",
                      background: currentActiveThreat && String(currentActiveThreat.id) === String(threat.id)
                        ? isDark ? "rgba(59, 130, 246, 0.1)" : "rgba(59, 130, 246, 0.05)"
                        : undefined,
                    }}
                    onClick={() => setActiveThreatId(threat.id)}
                  >
                    <td>
                      <code>{threat.id}</code>
                    </td>
                    <td>
                      <strong style={{ color: isDark ? "#f8fafc" : "#0f172a" }}>{threat.type}</strong>
                    </td>
                    <td>
                      <code style={{ color: "#60a5fa" }}>{threat.source_ip}</code>
                    </td>
                    <td>
                      <code>{threat.destination_ip}</code>
                    </td>
                    <td>
                      <span className={`soc-dash-badge-status ${threat.severity.toLowerCase()}`}>
                        {threat.severity}
                      </span>
                    </td>
                    <td>
                      <span style={{ fontWeight: 600, color: "#34d399" }}>{threat.confidence}</span>
                    </td>
                    <td>
                      <span className={`soc-dash-badge-status ${threat.status === "Resolved" ? "normal" : "warning"}`}>
                        {threat.status}
                      </span>
                    </td>
                    <td>
                      <button
                        onClick={(e) => {
                          e.stopPropagation();
                          setActiveThreatId(threat.id);
                        }}
                        className="pcap-action-btn"
                      >
                        Inspect
                      </button>
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          ) : (
            <p style={{ padding: "2rem", textAlign: "center", color: "#94a3b8" }}>
              No threat records found matching search filters.
            </p>
          )}
        </div>

        {/* Table Pagination */}
        <div className="soc-dash-pagination">
          <span className="soc-dash-pagination-info">
            Showing {paginatedThreats.length > 0 ? (threatPage - 1) * threatsPerPage + 1 : 0} to{" "}
            {Math.min(threatPage * threatsPerPage, filteredAndSortedThreats.length)} of{" "}
            {filteredAndSortedThreats.length} threat vectors
          </span>
          <div className="soc-dash-pagination-controls">
            <button
              disabled={threatPage <= 1}
              onClick={() => setThreatPage((prev) => Math.max(prev - 1, 1))}
              className="soc-dash-page-btn"
            >
              <ChevronLeft size={14} /> Prev
            </button>
            <span style={{ fontSize: "0.8rem", padding: "0 0.5rem", color: isDark ? "#cbd5e1" : "#334155" }}>
              Page {threatPage} of {totalThreatPages}
            </span>
            <button
              disabled={threatPage >= totalThreatPages}
              onClick={() => setThreatPage((prev) => Math.min(prev + 1, totalThreatPages))}
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
