"use client";
import React, { useState, useEffect, useCallback } from "react";
import {
  RefreshCw,
  BarChart3,
  ShieldAlert,
  Cpu,
  Lock,
  Zap,
  Globe,
  Award,
  Activity,
  CheckCircle2,
  Filter,
  Calendar,
  Layers,
  Radio,
  PieChart as PieIcon,
  TrendingUp,
  UserCheck,
  Database,
  Crosshair,
} from "lucide-react";
import {
  ResponsiveContainer,
  BarChart,
  Bar,
  PieChart,
  Pie,
  Cell,
  AreaChart,
  Area,
  CartesianGrid,
  XAxis,
  YAxis,
  Tooltip,
  Legend,
} from "recharts";

import LoadingSpinner from "../LoadingSpinner";
import { fetchApi } from "../../utils/api";
import { useTheme } from "../../context/ThemeContext";
import { useIncidents } from "../../context/IncidentContext";

export default function AnalyticsView() {
  const { isDark } = useTheme();

  // Analyst Session State
  const [currentAnalyst, setCurrentAnalyst] = useState("security@gmail.com");

  // Dynamic Controls State (Time Horizon: 7d, 15d, 30d)
  const [timeRange, setTimeRange] = useState("7d");
  const [severityFilter, setSeverityFilter] = useState("ALL");

  // PostgreSQL Dynamic Chart Data States (From GET /api/analytics/charts & GET /api/analytics/threat-types)
  const [totalIncidents, setTotalIncidents] = useState(0);
  const [severityCounts, setSeverityCounts] = useState([]);
  const [datasetCounts, setDatasetCounts] = useState([]);
  const [threatVectorBreakdown, setThreatVectorBreakdown] = useState([]);
  const [timeSeriesData, setTimeSeriesData] = useState([]);

  const [loadingAnalytics, setLoadingAnalytics] = useState(true);
  const [analyticsError, setAnalyticsError] = useState(null);
  const [lastSyncTime, setLastSyncTime] = useState("");

  // Retrieve Logged-In User from LocalStorage on mount & login restoration
  useEffect(() => {
    try {
      if (typeof window !== "undefined") {
        const stored = localStorage.getItem("netshield_current_user") || localStorage.getItem("user");
        if (stored) {
          const parsed = JSON.parse(stored);
          if (parsed && parsed.email) {
            setCurrentAnalyst(parsed.email);
          }
        }
      }
    } catch (e) {
      console.warn("User session retrieval error:", e);
    }
  }, []);

  // Fetch Live PostgreSQL Analytics Suite Data
  const fetchAnalyticsSuite = useCallback(
    async (isSilent = false) => {
      if (!isSilent) setLoadingAnalytics(true);
      setAnalyticsError(null);
      try {
        const userEmail = currentAnalyst || "security@gmail.com";
        const chartsUrl = `/api/analytics/charts?user_id=${encodeURIComponent(userEmail)}&time_range=${encodeURIComponent(timeRange)}`;

        const res = await fetchApi(chartsUrl, {
          headers: { "X-User-Email": userEmail },
        });

        if (res && res.status === "success") {
          if (res.total_incidents !== undefined) {
            setTotalIncidents(res.total_incidents);
          }
          if (res.severity_counts) {
            setSeverityCounts(res.severity_counts);
          }
          if (res.dataset_counts) {
            setDatasetCounts(res.dataset_counts);
          }
          if (res.threat_vector_breakdown) {
            setThreatVectorBreakdown(res.threat_vector_breakdown);
          }
          if (res.time_series) {
            setTimeSeriesData(res.time_series);
          }
        }

        // Also fetch GET /api/analytics/threat-types for backup sync
        const threatTypesUrl = `/api/analytics/threat-types?user_id=${encodeURIComponent(userEmail)}`;
        const ttRes = await fetchApi(threatTypesUrl, {
          headers: { "X-User-Email": userEmail },
        });
        if (ttRes && ttRes.data && ttRes.data.length > 0) {
          setThreatVectorBreakdown(ttRes.data);
        }

        setLastSyncTime(new Date().toLocaleTimeString());
      } catch (err) {
        console.warn("Failed to fetch PostgreSQL analytics charts from backend:", err);
        if (!isSilent) setAnalyticsError("Unable to compute PostgreSQL threat analytics suite.");
      } finally {
        if (!isSilent) setLoadingAnalytics(false);
      }
    },
    [currentAnalyst, timeRange]
  );

  // Initial fetch and 3-second dynamic polling loop
  useEffect(() => {
    fetchAnalyticsSuite(false);

    const interval = setInterval(() => {
      fetchAnalyticsSuite(true);
    }, 3000);

    return () => clearInterval(interval);
  }, [fetchAnalyticsSuite]);

  const { incidents } = useIncidents();
  const incidentData = incidents || [];

  // Derive live dynamic metrics from IncidentContext
  const liveTotalIncidents = incidentData.length;

  const liveSeverityCounts = [
    {
      severity: "CRITICAL",
      count: incidentData.filter((i) => String(i.severity || i.threatSeverity || "").toUpperCase() === "CRITICAL").length,
      color: "#ef4444",
    },
    {
      severity: "HIGH",
      count: incidentData.filter((i) => String(i.severity || i.threatSeverity || "").toUpperCase() === "HIGH").length,
      color: "#f97316",
    },
    {
      severity: "MEDIUM",
      count: incidentData.filter((i) => String(i.severity || i.threatSeverity || "").toUpperCase() === "MEDIUM").length,
      color: "#eab308",
    },
    {
      severity: "LOW",
      count: incidentData.filter((i) => String(i.severity || i.threatSeverity || "").toUpperCase() === "LOW").length,
    },
  ];

  const liveDatasetCounts = [
    {
      dataset_engine: "UNSW-NB15",
      count: incidentData.filter((i) => {
        const src = String(i.detection_source || i.threat_vector || i.threatType || "").toUpperCase();
        return src.includes("UNSW");
      }).length,
      color: "#3b82f6",
    },
    {
      dataset_engine: "CICIDS2017",
      count: incidentData.filter((i) => {
        const src = String(i.detection_source || i.threat_vector || i.threatType || "").toUpperCase();
        return src.includes("CICIDS");
      }).length,
      color: "#a855f7",
    },
    {
      dataset_engine: "AbuseIPDB",
      count: incidentData.filter((i) => {
        const src = String(i.detection_source || i.threat_vector || i.threatType || "").toUpperCase();
        return src.includes("ABUSE");
      }).length,
      color: "#06b6d4",
    },
  ];

  const computeThreatVectorBreakdown = (items) => {
    const categories = {
      "DoS / SYN Flood": 0,
      "PortScan / Recon": 0,
      "Brute Force / SQLi": 0,
      "Tor Exit / Intel": 0,
      "Exploits / Shellcode": 0,
      "Fuzzers / Payload": 0,
      "Malicious Scanner": 0,
    };

    items.forEach((item) => {
      const type = String(item.threat_vector || item.threatType || item.details || "").toUpperCase();
      if (type.includes("DOS") || type.includes("SYN") || type.includes("FLOOD")) categories["DoS / SYN Flood"]++;
      else if (type.includes("SCAN") || type.includes("RECON") || type.includes("PORT")) categories["PortScan / Recon"]++;
      else if (type.includes("BRUTE") || type.includes("SQL") || type.includes("WEB") || type.includes("XSS")) categories["Brute Force / SQLi"]++;
      else if (type.includes("TOR") || type.includes("INTEL") || type.includes("ABUSE")) categories["Tor Exit / Intel"]++;
      else if (type.includes("EXPLOIT") || type.includes("SHELL") || type.includes("INFILTRATION")) categories["Exploits / Shellcode"]++;
      else if (type.includes("FUZZER") || type.includes("PAYLOAD") || type.includes("WORM")) categories["Fuzzers / Payload"]++;
      else categories["Malicious Scanner"]++;
    });

    const colors = ["#ef4444", "#f97316", "#a855f7", "#06b6d4", "#3b82f6", "#10b981", "#eab308"];
    return Object.entries(categories).map(([category, count], idx) => ({
      category,
      count,
      color: colors[idx % colors.length],
    }));
  };

  const liveThreatVectorBreakdown = computeThreatVectorBreakdown(incidentData);

  const activeTotalIncidents = incidentData.length > 0 ? liveTotalIncidents : totalIncidents;
  const activeSeverityCounts = incidentData.length > 0 ? liveSeverityCounts : severityCounts;
  const activeDatasetCounts = incidentData.length > 0 ? liveDatasetCounts : datasetCounts;
  const activeThreatVectorBreakdown = incidentData.length > 0 ? liveThreatVectorBreakdown : threatVectorBreakdown;

  // Filtered severity counts logic
  const filteredSeverityCounts = severityFilter === "ALL"
    ? activeSeverityCounts
    : activeSeverityCounts.filter((item) => item.severity === severityFilter);

  return (
    <div key="tab-analytics" className="anlt-container" style={{ width: "100%", maxWidth: "100%", minWidth: "100%", boxSizing: "border-box" }}>
      <div className="anlt-card" style={{ width: "100%", maxWidth: "100%", minWidth: "100%", boxSizing: "border-box" }}>
        {/* Header Section */}
        <div className="anlt-header-flex">
          <div className="anlt-header-title">
            <h3 style={{ display: "flex", alignItems: "center", gap: "0.5rem", flexWrap: "wrap" }}>
              Dynamic PostgreSQL Analytics Dashboard
            </h3>
            <p style={{ marginTop: "0.25rem" }}>
              Full 4-Chart Visual Suite: Severity distribution, dataset engine breakdown, specific threat vector subtypes, and dynamic historical trend plots.
            </p>
          </div>

        </div>

        {/* Analytics Dynamic Filter Toolbar */}
        <div
          style={{
            marginBottom: "1.5rem",
            padding: "0.85rem 1.1rem",
            backgroundColor: isDark ? "rgba(30, 41, 59, 0.7)" : "#f8fafc",
            border: isDark ? "1px solid #334155" : "1px solid #cbd5e1",
            borderRadius: "10px",
            display: "flex",
            alignItems: "center",
            justifyContent: "space-between",
            flexWrap: "wrap",
            gap: "1rem",
          }}
        >
          <div style={{ display: "flex", alignItems: "center", gap: "0.5rem" }}>
            <Filter size={16} style={{ color: "#38bdf8" }} />
            <span style={{ fontSize: "0.85rem", fontWeight: "700", color: isDark ? "#f8fafc" : "#0f172a" }}>
              Dynamic Controls &amp; Horizon Toggles:
            </span>
          </div>

          <div style={{ display: "flex", gap: "1rem", flexWrap: "wrap", alignItems: "center" }}>
            {/* Time Horizon Selector (7, 15, 30 Days) */}
            <div style={{ display: "flex", alignItems: "center", gap: "0.4rem" }}>
              <Calendar size={14} style={{ color: "#a855f7" }} />
              <span style={{ fontSize: "0.78rem", fontWeight: "600", color: isDark ? "#cbd5e1" : "#475569" }}>Time Horizon:</span>
              <div style={{ display: "flex", gap: "0.2rem", backgroundColor: isDark ? "#0f172a" : "#e2e8f0", padding: "0.15rem", borderRadius: "6px" }}>
                {[
                  { label: "Last 7 Days", value: "7d" },
                  { label: "Last 15 Days", value: "15d" },
                  { label: "Last 30 Days", value: "30d" },
                ].map((rng) => (
                  <button
                    key={rng.value}
                    onClick={() => setTimeRange(rng.value)}
                    style={{
                      padding: "0.25rem 0.65rem",
                      borderRadius: "4px",
                      fontSize: "0.75rem",
                      fontWeight: "700",
                      backgroundColor: timeRange === rng.value ? "#a855f7" : "transparent",
                      color: timeRange === rng.value ? "#ffffff" : isDark ? "#94a3b8" : "#475569",
                      border: "none",
                      cursor: "pointer",
                      transition: "all 0.2s ease",
                    }}
                  >
                    {rng.label}
                  </button>
                ))}
              </div>
            </div>

            {/* Severity Filter Dropdown */}
            <div style={{ display: "flex", alignItems: "center", gap: "0.4rem" }}>
              <span style={{ fontSize: "0.78rem", fontWeight: "600", color: isDark ? "#cbd5e1" : "#475569" }}>Severity Filter:</span>
              <select
                value={severityFilter}
                onChange={(e) => setSeverityFilter(e.target.value)}
                style={{
                  padding: "0.35rem 0.65rem",
                  borderRadius: "6px",
                  backgroundColor: isDark ? "#0f172a" : "#ffffff",
                  border: isDark ? "1px solid #334155" : "1px solid #cbd5e1",
                  color: isDark ? "#f8fafc" : "#0f172a",
                  fontSize: "0.78rem",
                  fontWeight: "600",
                  outline: "none",
                  cursor: "pointer",
                }}
              >
                <option value="ALL">All Severities</option>
                <option value="CRITICAL">Critical Only</option>
                <option value="HIGH">High Only</option>
                <option value="MEDIUM">Medium Only</option>
                <option value="LOW">Low Only</option>
              </select>
            </div>
          </div>
        </div>

        {loadingAnalytics ? (
          <LoadingSpinner text="Querying PostgreSQL incidents table & compiling 4-chart suite..." />
        ) : analyticsError ? (
          <div style={{ padding: "1.5rem", color: "#f87171", textAlign: "center" }}>
            {analyticsError}
            <button onClick={() => fetchAnalyticsSuite(false)} style={{ marginLeft: "10px" }} className="ns-btn-gradient small">
              Retry Connection
            </button>
          </div>
        ) : (
          <>
            {/* Live Aggregate KPI Cards */}
            <div className="anlt-kpi-grid" style={{ marginBottom: "1.5rem" }}>
              {/* Total Incidents Card */}
              <div className="anlt-stat-card blue" style={{ borderLeft: "4px solid #3b82f6" }}>
                <span className="anlt-stat-title">Total Threat Incidents</span>
                <span className="anlt-stat-metric" style={{ color: "#60a5fa" }}>
                  {activeTotalIncidents}
                </span>
                <span className="anlt-stat-sub">Logged under {currentAnalyst}</span>
              </div>

              {/* Critical Severity Count */}
              <div className="anlt-stat-card red" style={{ borderLeft: "4px solid #ef4444" }}>
                <span className="anlt-stat-title">Critical Threats</span>
                <span className="anlt-stat-metric" style={{ color: "#f87171" }}>
                  {activeSeverityCounts.find((s) => s.severity === "CRITICAL")?.count || 0}
                </span>
                <span className="anlt-stat-sub">Immediate Null-Route Firewalled</span>
              </div>

              {/* High Severity Count */}
              <div className="anlt-stat-card orange" style={{ borderLeft: "4px solid #f97316" }}>
                <span className="anlt-stat-title">High Threats</span>
                <span className="anlt-stat-metric" style={{ color: "#fb923c" }}>
                  {activeSeverityCounts.find((s) => s.severity === "HIGH")?.count || 0}
                </span>
                <span className="anlt-stat-sub">Active Triage / Deep Inspection</span>
              </div>

              {/* Medium & Low Threats Count */}
              <div className="anlt-stat-card green" style={{ borderLeft: "4px solid #10b981" }}>
                <span className="anlt-stat-title">Medium &amp; Low Threats</span>
                <span className="anlt-stat-metric" style={{ color: "#34d399" }}>
                  {(activeSeverityCounts.find((s) => s.severity === "MEDIUM")?.count || 0) +
                    (activeSeverityCounts.find((s) => s.severity === "LOW")?.count || 0)}
                </span>
                <span className="anlt-stat-sub">Low Priority / Routine Monitoring</span>
              </div>
            </div>

            {/* FULL 4-CHART VISUAL DASHBOARD SUITE */}
            <div style={{ width: "100%", minWidth: "100%", display: "flex", flexDirection: "column", gap: "1.5rem" }}>
              {/* ROW 1: STRICT 50/50 GRID FOR CHART 1 & CHART 2 */}
              <div
                style={{
                  display: "grid",
                  gridTemplateColumns: "repeat(auto-fit, minmax(350px, 1fr))",
                  gap: "1.5rem",
                  width: "100%",
                  minWidth: "100%",
                  boxSizing: "border-box",
                }}
              >
                {/* CHART 1: SEVERITY DISTRIBUTION BAR CHART (DYNAMIC) */}
                <div className="anlt-chart-box" style={{ width: "100%", minWidth: "100%", boxSizing: "border-box" }}>
                  <h4 className="anlt-chart-title" style={{ display: "flex", alignItems: "center", gap: "0.4rem", marginBottom: "1rem" }}>
                    <BarChart3 size={16} style={{ color: "#ef4444" }} />
                    1. Severity Distribution Bar Chart (Dynamic)
                  </h4>
                  <ResponsiveContainer width="100%" minWidth="100%" height={280}>
                    <BarChart data={filteredSeverityCounts}>
                      <CartesianGrid strokeDasharray="3 3" stroke={isDark ? "rgba(255,255,255,0.06)" : "#cbd5e1"} />
                      <XAxis dataKey="severity" stroke={isDark ? "#94a3b8" : "#475569"} fontSize={11} tickLine={false} />
                      <YAxis stroke={isDark ? "#94a3b8" : "#475569"} fontSize={11} tickLine={false} allowDecimals={false} />
                      <Tooltip
                        content={({ active, payload }) => {
                          if (active && payload && payload.length) {
                            const data = payload[0].payload;
                            return (
                              <div
                                style={{
                                  padding: "0.6rem 0.85rem",
                                  backgroundColor: isDark ? "#0f172a" : "#ffffff",
                                  border: isDark ? "1px solid #334155" : "1px solid #cbd5e1",
                                  borderRadius: "8px",
                                  color: isDark ? "#f8fafc" : "#1e293b",
                                  boxShadow: "0 10px 25px -5px rgba(0,0,0,0.5)",
                                }}
                              >
                                <p style={{ fontWeight: "700", margin: 0, color: data.color || (isDark ? "#f8fafc" : "#0f172a"), fontSize: "0.9rem" }}>
                                  {data.severity}
                                </p>
                                <p style={{ margin: "4px 0 0 0", fontSize: "0.82rem", color: isDark ? "#cbd5e1" : "#475569" }}>
                                  Incidents Count : <span style={{ fontWeight: "700", color: "#38bdf8" }}>{data.count}</span>
                                </p>
                              </div>
                            );
                          }
                          return null;
                        }}
                      />
                      <Legend wrapperStyle={{ fontSize: "11px", color: isDark ? "#94a3b8" : "#334155" }} />
                      <Bar dataKey="count" name="Incidents Count" radius={[4, 4, 0, 0]} isAnimationActive={true}>
                        {filteredSeverityCounts.map((entry, index) => (
                          <Cell key={`sev-cell-${index}`} fill={entry.color || "#3b82f6"} />
                        ))}
                      </Bar>
                    </BarChart>
                  </ResponsiveContainer>
                </div>

                {/* CHART 2: DATASET ENGINE BREAKDOWN CHART (DYNAMIC DONUT/PIE) */}
                <div className="anlt-chart-box" style={{ width: "100%", minWidth: "100%", boxSizing: "border-box" }}>
                  <h4 className="anlt-chart-title" style={{ display: "flex", alignItems: "center", gap: "0.4rem", marginBottom: "1rem" }}>
                    <PieIcon size={16} style={{ color: "#a855f7" }} />
                    2. Dataset Engine Breakdown Chart (Dynamic Volume)
                  </h4>
                  <ResponsiveContainer width="100%" minWidth="100%" height={280}>
                    <PieChart>
                      <Pie
                        data={activeDatasetCounts}
                        cx="50%"
                        cy="50%"
                        innerRadius={55}
                        outerRadius={85}
                        paddingAngle={4}
                        dataKey="count"
                        nameKey="dataset_engine"
                        label={({ dataset_engine, count }) => `${dataset_engine}: ${count}`}
                        isAnimationActive={true}
                      >
                        {activeDatasetCounts.map((entry, index) => (
                          <Cell key={`ds-cell-${index}`} fill={entry.color || "#3b82f6"} />
                        ))}
                      </Pie>
                      <Tooltip
                        contentStyle={{
                          backgroundColor: isDark ? "#0f172a" : "#ffffff",
                          borderColor: isDark ? "#334155" : "#cbd5e1",
                          borderRadius: "8px",
                          color: isDark ? "#f8fafc" : "#1e293b",
                        }}
                      />
                      <Legend wrapperStyle={{ fontSize: "11px", color: isDark ? "#94a3b8" : "#334155" }} />
                    </PieChart>
                  </ResponsiveContainer>
                </div>
              </div>

              {/* CHART 3: SPECIFIC THREAT VECTOR BREAKDOWN (NEW HORIZONTAL BAR CHART) */}
              <div className="anlt-chart-box" style={{ width: "100%", minWidth: "100%", boxSizing: "border-box" }}>
                <h4 className="anlt-chart-title" style={{ display: "flex", alignItems: "center", gap: "0.4rem", marginBottom: "1rem" }}>
                  <Crosshair size={16} style={{ color: "#f97316" }} />
                  3. Specific Threat Vector Breakdown (UNSW-NB15 &amp; CICIDS2017)
                </h4>
                <ResponsiveContainer width="100%" minWidth="100%" height={280}>
                  <BarChart data={activeThreatVectorBreakdown} layout="vertical">
                    <defs>
                      <linearGradient id="vectorGrad" x1="0" y1="0" x2="1" y2="0">
                        <stop offset="0%" stopColor="#f97316" stopOpacity={0.9} />
                        <stop offset="100%" stopColor="#a855f7" stopOpacity={0.9} />
                      </linearGradient>
                    </defs>
                    <CartesianGrid strokeDasharray="3 3" stroke={isDark ? "rgba(255,255,255,0.06)" : "#cbd5e1"} />
                    <XAxis type="number" stroke={isDark ? "#94a3b8" : "#475569"} fontSize={11} tickLine={false} allowDecimals={false} />
                    <YAxis dataKey="category" type="category" stroke={isDark ? "#94a3b8" : "#475569"} fontSize={11} tickLine={false} width={160} />
                    <Tooltip
                      contentStyle={{
                        backgroundColor: isDark ? "#0f172a" : "#ffffff",
                        borderColor: isDark ? "#334155" : "#cbd5e1",
                        borderRadius: "8px",
                        color: isDark ? "#f8fafc" : "#1e293b",
                      }}
                    />
                    <Legend wrapperStyle={{ fontSize: "11px", color: isDark ? "#94a3b8" : "#334155" }} />
                    <Bar dataKey="count" name="Detected Attack Subtypes" fill="url(#vectorGrad)" radius={[0, 4, 4, 0]} barSize={20} isAnimationActive={true}>
                      {activeThreatVectorBreakdown.map((entry, index) => (
                        <Cell key={`vec-cell-${index}`} fill={entry.color || "#f97316"} />
                      ))}
                    </Bar>
                  </BarChart>
                </ResponsiveContainer>
              </div>

              {/* CHART 4: USER THREAT HISTORY & TREND PLOT (DYNAMIC TIME HORIZON) */}
              <div className="anlt-chart-box" style={{ width: "100%", minWidth: "100%", boxSizing: "border-box" }}>
                <div style={{ display: "flex", justifyContent: "space-between", alignItems: "center", flexWrap: "wrap", gap: "0.5rem", marginBottom: "1rem" }}>
                  <h4 className="anlt-chart-title" style={{ margin: 0, display: "flex", alignItems: "center", gap: "0.4rem" }}>
                    <TrendingUp size={16} style={{ color: "#38bdf8" }} />
                    4. Historical Threat Trend Plot ({timeRange.toUpperCase()} Horizon)
                  </h4>
                  <span style={{ fontSize: "0.75rem", color: isDark ? "#94a3b8" : "#64748b" }}>
                    Interval Scale: <strong>{timeSeriesData.length} Days Plotted</strong>
                  </span>
                </div>
                <ResponsiveContainer width="100%" minWidth="100%" height={280}>
                  <AreaChart data={timeSeriesData}>
                    <defs>
                      <linearGradient id="historyGrad" x1="0" y1="0" x2="0" y2="1">
                        <stop offset="5%" stopColor="#38bdf8" stopOpacity={0.8} />
                        <stop offset="95%" stopColor="#38bdf8" stopOpacity={0.0} />
                      </linearGradient>
                    </defs>
                    <CartesianGrid strokeDasharray="3 3" stroke={isDark ? "rgba(255,255,255,0.06)" : "#cbd5e1"} />
                    <XAxis dataKey="label" stroke={isDark ? "#94a3b8" : "#475569"} fontSize={11} tickLine={false} />
                    <YAxis stroke={isDark ? "#94a3b8" : "#475569"} fontSize={11} tickLine={false} allowDecimals={false} />
                    <Tooltip
                      contentStyle={{
                        backgroundColor: isDark ? "#0f172a" : "#ffffff",
                        borderColor: isDark ? "#334155" : "#cbd5e1",
                        borderRadius: "8px",
                        color: isDark ? "#f8fafc" : "#1e293b",
                      }}
                      labelFormatter={(label, items) => {
                        const item = items && items[0] && items[0].payload;
                        return item ? `Date: ${item.date}` : label;
                      }}
                    />
                    <Legend wrapperStyle={{ fontSize: "11px", color: isDark ? "#94a3b8" : "#334155" }} />
                    <Area type="monotone" dataKey="daily_total" name="Daily Threat Volume" stroke="#38bdf8" fillOpacity={1} fill="url(#historyGrad)" isAnimationActive={true} />
                    <Area type="monotone" dataKey="critical" name="Critical Severities" stroke="#ef4444" fillOpacity={0} isAnimationActive={true} />
                    <Area type="monotone" dataKey="high" name="High Severities" stroke="#f97316" fillOpacity={0} isAnimationActive={true} />
                  </AreaChart>
                </ResponsiveContainer>
              </div>
            </div>
          </>
        )}
      </div>
    </div>
  );
}
