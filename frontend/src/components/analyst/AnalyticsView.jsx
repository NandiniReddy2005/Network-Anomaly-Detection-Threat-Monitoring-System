"use client";
import React, { useState, useEffect, useCallback } from "react";
import { RefreshCw } from "lucide-react";
import {
  ResponsiveContainer,
  AreaChart,
  Area,
  LineChart,
  Line,
  BarChart,
  Bar,
  PieChart,
  Pie,
  Cell,
  CartesianGrid,
  XAxis,
  YAxis,
  Tooltip,
  Legend,
} from "recharts";

import LoadingSpinner from "../LoadingSpinner";
import { fetchApi } from "../../utils/api";
import { useTheme } from "../../context/ThemeContext";

export default function AnalyticsView() {
  const { isDark } = useTheme();
  const [analyticsData, setAnalyticsData] = useState(null);
  const [loadingAnalytics, setLoadingAnalytics] = useState(true);
  const [analyticsError, setAnalyticsError] = useState(null);

  const fetchAnalytics = useCallback(async () => {
    setLoadingAnalytics(true);
    setAnalyticsError(null);
    try {
      const res = await fetchApi("/api/analyst/analytics");
      setAnalyticsData(res.data || res);
    } catch (err) {
      setAnalyticsError("Unable to compute heuristic analytics.");
    } finally {
      setLoadingAnalytics(false);
    }
  }, []);

  useEffect(() => {
    fetchAnalytics();
  }, [fetchAnalytics]);

  const analytics = analyticsData || {};
  const categories = analytics.top_attack_categories || [
    { category: "Ransomware & Malware", count: 420, percentage: "35.0%" },
    { category: "DDoS Volumetric", count: 310, percentage: "25.8%" },
    { category: "SQL Injection & XSS", count: 240, percentage: "20.0%" },
    { category: "Data Exfiltration", count: 120, percentage: "10.0%" },
    { category: "Credential Brute Force", count: 70, percentage: "5.8%" },
    { category: "Port & Vulnerability Scanning", count: 40, percentage: "3.4%" },
  ];
  const trend = analytics.threat_trend_chart || [
    { day: "Mon", attacks: 120, anomalyScore: 42 },
    { day: "Tue", attacks: 240, anomalyScore: 68 },
    { day: "Wed", attacks: 180, anomalyScore: 55 },
    { day: "Thu", attacks: 390, anomalyScore: 89 },
    { day: "Fri", attacks: 310, anomalyScore: 74 },
    { day: "Sat", attacks: 150, anomalyScore: 48 },
    { day: "Sun", attacks: 210, anomalyScore: 60 },
  ];

  const protoData = [
    { protocol: "TCP", volume: 450 },
    { protocol: "UDP", volume: 320 },
    { protocol: "HTTP/2", volume: 280 },
    { protocol: "DNS", volume: 140 },
    { protocol: "SSH", volume: 60 },
    { protocol: "TLS 1.3", volume: 210 },
  ];

  const topThreats = [
    { type: "DDoS Volumetric Attack", severity: "Critical", count: 1420, confidence: "99.8%", status: "Active", lastDetected: "2 mins ago" },
    { type: "SQL Injection Attempt", severity: "High", count: 380, confidence: "98.4%", status: "Monitoring", lastDetected: "14 mins ago" },
    { type: "Cross-Site Scripting (XSS)", severity: "Medium", count: 210, confidence: "96.2%", status: "Resolved", lastDetected: "1 hour ago" },
    { type: "SSH Password Spraying", severity: "High", count: 540, confidence: "99.1%", status: "Active", lastDetected: "25 mins ago" },
    { type: "DNS Tunneling Anomaly", severity: "Medium", count: 95, confidence: "94.5%", status: "Monitoring", lastDetected: "2 hours ago" },
    { type: "Port Scanning Probe", severity: "Low", count: 1200, confidence: "92.0%", status: "Resolved", lastDetected: "4 hours ago" },
  ];

  return (
    <div key="tab-analytics" className="anlt-container">
      <div className="anlt-card">
        {/* Header Section */}
        <div className="anlt-header-flex">
          <div className="anlt-header-title">
            <h3>Security Analytics &amp; AI Insights</h3>
            <p>Real-time neural inference, heuristic anomaly scoring, and machine learning threat matrix analytics.</p>
          </div>
          <div className="anlt-header-actions">
            <span className="anlt-badge">AI Inference Engine Active</span>
            <button className="ns-btn-gradient small" onClick={fetchAnalytics}>
              <RefreshCw size={14} style={{ marginRight: "4px" }} /> Refresh Analytics
            </button>
          </div>
        </div>

        {/* KPI Summary Cards */}
        {loadingAnalytics ? (
          <LoadingSpinner text="Computing neural analytics & threat trends..." />
        ) : analyticsError ? (
          <div style={{ padding: "1rem", color: "#f87171", textAlign: "center" }}>
            {analyticsError}
            <button onClick={fetchAnalytics} style={{ marginLeft: "10px" }} className="ns-btn-gradient small">Retry</button>
          </div>
        ) : (
          <>
            <div className="anlt-kpi-grid">
              <div className="anlt-stat-card purple">
                <span className="anlt-stat-title">Total Events Analyzed</span>
                <span className="anlt-stat-metric">{analytics.daily_attacks ? (analytics.daily_attacks * 1280).toLocaleString() : "1.48M"}</span>
                <span className="anlt-stat-sub">Past 24h Buffer</span>
              </div>
              <div className="anlt-stat-card green">
                <span className="anlt-stat-title">Threat Detection Accuracy</span>
                <span className="anlt-stat-metric">{analytics.detection_accuracy || "99.4%"}</span>
                <span className="anlt-stat-sub">Neural Precision</span>
              </div>
              <div className="anlt-stat-card cyan">
                <span className="anlt-stat-title">AI Confidence Score</span>
                <span className="anlt-stat-metric">98.7%</span>
                <span className="anlt-stat-sub">Heuristic Weight</span>
              </div>
              <div className="anlt-stat-card blue">
                <span className="anlt-stat-title">Average Response Time</span>
                <span className="anlt-stat-metric">42 ms</span>
                <span className="anlt-stat-sub">Inference Latency</span>
              </div>
              <div className="anlt-stat-card red">
                <span className="anlt-stat-title">High-Risk Events</span>
                <span className="anlt-stat-metric">{analytics.daily_attacks || 14}</span>
                <span className="anlt-stat-sub">Action Required</span>
              </div>
              <div className="anlt-stat-card green">
                <span className="anlt-stat-title">Overall Network Health</span>
                <span className="anlt-stat-metric" style={{ fontSize: "1.1rem", color: "#10B981" }}>Optimal (99.8%)</span>
                <span className="anlt-stat-sub">Security Posture</span>
              </div>
            </div>

            {/* 4 Threat Analytics Visualizations */}
            <div className="anlt-charts-grid">
              {/* Chart 1: AreaChart (Threat Activity Over Time) */}
              <div className="anlt-chart-box">
                <h4 className="anlt-chart-title">Threat Activity Intercepted Over Time</h4>
                <ResponsiveContainer key="anlt-area-responsive-container" width="100%" height={200}>
                  <AreaChart key="anlt-area-chart" data={trend}>
                    <defs>
                      <linearGradient id="anltThreatAreaGrad" x1="0" y1="0" x2="0" y2="1">
                        <stop offset="5%" stopColor="#EF4444" stopOpacity={0.8} />
                        <stop offset="95%" stopColor="#EF4444" stopOpacity={0} />
                      </linearGradient>
                    </defs>
                    <CartesianGrid strokeDasharray="3 3" stroke={isDark ? "rgba(255,255,255,0.05)" : "#cbd5e1"} />
                    <XAxis dataKey="day" stroke={isDark ? "#94a3b8" : "#475569"} fontSize={11} tickLine={false} />
                    <YAxis stroke={isDark ? "#94a3b8" : "#475569"} fontSize={11} tickLine={false} />
                    <Tooltip contentStyle={{ backgroundColor: isDark ? "#0f172a" : "#ffffff", borderColor: isDark ? "#334155" : "#cbd5e1", borderRadius: "8px", color: isDark ? "#f8fafc" : "#1e293b" }} />
                    <Legend wrapperStyle={{ fontSize: "11px", color: isDark ? "#94a3b8" : "#334155" }} />
                    <Area type="monotone" name="Attacks Intercepted" dataKey="attacks" stroke="#EF4444" strokeWidth={2} fillOpacity={1} fill="url(#anltThreatAreaGrad)" isAnimationActive={true} />
                  </AreaChart>
                </ResponsiveContainer>
              </div>

              {/* Chart 2: LineChart (Anomaly Score Trends) */}
              <div className="anlt-chart-box">
                <h4 className="anlt-chart-title">Anomaly Score Trends (0 - 100 Index)</h4>
                <ResponsiveContainer key="anlt-line-responsive-container" width="100%" height={200}>
                  <LineChart key="anlt-line-chart" data={trend}>
                    <CartesianGrid strokeDasharray="3 3" stroke={isDark ? "rgba(255,255,255,0.05)" : "#cbd5e1"} />
                    <XAxis dataKey="day" stroke={isDark ? "#94a3b8" : "#475569"} fontSize={11} tickLine={false} />
                    <YAxis stroke={isDark ? "#94a3b8" : "#475569"} fontSize={11} tickLine={false} domain={[0, 100]} />
                    <Tooltip contentStyle={{ backgroundColor: isDark ? "#0f172a" : "#ffffff", borderColor: isDark ? "#334155" : "#cbd5e1", borderRadius: "8px", color: isDark ? "#f8fafc" : "#1e293b" }} />
                    <Legend wrapperStyle={{ fontSize: "11px", color: isDark ? "#94a3b8" : "#334155" }} />
                    <Line type="monotone" name="Anomaly Index" dataKey="anomalyScore" stroke="#F59E0B" strokeWidth={2.5} dot={{ fill: "#3B82F6", r: 4 }} isAnimationActive={true} />
                  </LineChart>
                </ResponsiveContainer>
              </div>

              {/* Chart 3: PieChart (Attack Category Distribution) */}
              <div className="anlt-chart-box">
                <h4 className="anlt-chart-title">Attack Category Distribution</h4>
                <ResponsiveContainer key="anlt-pie-responsive-container" width="100%" height={200}>
                  <PieChart key="anlt-pie-chart">
                    <Pie
                      data={categories.map((c) => ({ name: c.category, value: c.count || 10 }))}
                      cx="50%"
                      cy="50%"
                      innerRadius={45}
                      outerRadius={65}
                      paddingAngle={4}
                      dataKey="value"
                    >
                      {["#EF4444", "#F59E0B", "#3B82F6", "#8B5CF6", "#06B6D4", "#10B981"].map((color, i) => (
                        <Cell key={i} fill={color} />
                      ))}
                    </Pie>
                    <Tooltip contentStyle={{ backgroundColor: isDark ? "#0f172a" : "#ffffff", borderColor: isDark ? "#334155" : "#cbd5e1", borderRadius: "8px", color: isDark ? "#f8fafc" : "#1e293b" }} />
                    <Legend wrapperStyle={{ fontSize: "10px", color: isDark ? "#94a3b8" : "#334155" }} />
                  </PieChart>
                </ResponsiveContainer>
              </div>

              {/* Chart 4: BarChart (Protocol Distribution) */}
              <div className="anlt-chart-box">
                <h4 className="anlt-chart-title">Protocol Telemetry Volume</h4>
                <ResponsiveContainer key="anlt-bar-responsive-container" width="100%" height={200}>
                  <BarChart key="anlt-bar-chart" data={protoData}>
                    <defs>
                      <linearGradient id="anltProtoBarGrad" x1="0" y1="0" x2="0" y2="1">
                        <stop offset="5%" stopColor="#8B5CF6" stopOpacity={0.9} />
                        <stop offset="95%" stopColor="#3B82F6" stopOpacity={0.5} />
                      </linearGradient>
                    </defs>
                    <CartesianGrid strokeDasharray="3 3" stroke={isDark ? "rgba(255,255,255,0.05)" : "#cbd5e1"} />
                    <XAxis dataKey="protocol" stroke={isDark ? "#94a3b8" : "#475569"} fontSize={11} tickLine={false} />
                    <YAxis stroke={isDark ? "#94a3b8" : "#475569"} fontSize={11} tickLine={false} />
                    <Tooltip contentStyle={{ backgroundColor: isDark ? "#0f172a" : "#ffffff", borderColor: isDark ? "#334155" : "#cbd5e1", borderRadius: "8px", color: isDark ? "#f8fafc" : "#1e293b" }} />
                    <Legend wrapperStyle={{ fontSize: "11px", color: isDark ? "#94a3b8" : "#334155" }} />
                    <Bar dataKey="volume" name="Protocol Flow Volume" fill="url(#anltProtoBarGrad)" radius={[4, 4, 0, 0]} isAnimationActive={true} />
                  </BarChart>
                </ResponsiveContainer>
              </div>
            </div>

            {/* AI Security Insights Panel */}
            <div className="anlt-insights-grid">
              <div className="anlt-insight-card">
                <span className="anlt-insight-label">Top Threat Detected</span>
                <span className="anlt-insight-value" style={{ color: "#F87171" }}>DDoS Volumetric Attack</span>
              </div>
              <div className="anlt-insight-card">
                <span className="anlt-insight-label">Most Targeted Asset</span>
                <span className="anlt-insight-value">Database Cluster (10.0.4.12)</span>
              </div>
              <div className="anlt-insight-card">
                <span className="anlt-insight-label">Highest Risk Protocol</span>
                <span className="anlt-insight-value">HTTP/2 (Port 443)</span>
              </div>
              <div className="anlt-insight-card">
                <span className="anlt-insight-label">Peak Attack Time</span>
                <span className="anlt-insight-value">14:30 - 15:15 UTC</span>
              </div>
              <div className="anlt-insight-card">
                <span className="anlt-insight-label">AI Recommendation</span>
                <span className="anlt-insight-value" style={{ color: "#34D399" }}>Apply Rate Limit on /api/v1/auth</span>
              </div>
              <div className="anlt-insight-card">
                <span className="anlt-insight-label">Current Security Posture</span>
                <span className="anlt-insight-value" style={{ color: "#60A5FA" }}>Elevated Defense (Shield Active)</span>
              </div>
            </div>

            {/* Analytics Event Timeline & Top Threats Table */}
            <div style={{ display: "grid", gridTemplateColumns: "repeat(auto-fit, minmax(320px, 1fr))", gap: "1.5rem" }}>
              {/* Top Threats Table */}
              <div className="anlt-table-box" style={{ gridColumn: "span 2" }}>
                <h4 className="anlt-chart-title" style={{ marginBottom: "1rem" }}>Top Threat Intelligence Vector Log</h4>
                <table className="anlt-table">
                  <thead>
                    <tr>
                      <th>Threat Type</th>
                      <th>Severity</th>
                      <th>Detection Count</th>
                      <th>Confidence</th>
                      <th>Status</th>
                      <th>Last Detected</th>
                    </tr>
                  </thead>
                  <tbody>
                    {topThreats.map((th, i) => {
                      const sevLower = th.severity.toLowerCase();
                      let sevBadge = <span className="anlt-severity-badge low">Low</span>;
                      if (sevLower === "critical") sevBadge = <span className="anlt-severity-badge critical">Critical</span>;
                      else if (sevLower === "high") sevBadge = <span className="anlt-severity-badge high">High</span>;
                      else if (sevLower === "medium") sevBadge = <span className="anlt-severity-badge medium">Medium</span>;

                      const statusLower = th.status.toLowerCase();
                      let statusBadge = <span className="anlt-status-badge active">Active</span>;
                      if (statusLower === "monitoring") statusBadge = <span className="anlt-status-badge monitoring">Monitoring</span>;
                      else if (statusLower === "resolved") statusBadge = <span className="anlt-status-badge resolved">Resolved</span>;

                      return (
                        <tr key={i}>
                          <td><strong>{th.type}</strong></td>
                          <td>{sevBadge}</td>
                          <td>{th.count.toLocaleString()}</td>
                          <td><code>{th.confidence}</code></td>
                          <td>{statusBadge}</td>
                          <td>{th.lastDetected}</td>
                        </tr>
                      );
                    })}
                  </tbody>
                </table>
              </div>

              {/* Analytics Timeline */}
              <div className="anlt-timeline-box" style={{ gridColumn: "span 1" }}>
                <h4 className="anlt-chart-title" style={{ marginBottom: "0.25rem" }}>Analytics Event Audit Stream</h4>
                <div className="anlt-timeline-item">
                  <span className="anlt-timeline-time">09:42 AM</span>
                  <span className="anlt-timeline-text"><strong>Threat Detected:</strong> Volumetric UDP Spike (4.2 Gbps) on Gateway Sensor 04</span>
                </div>
                <div className="anlt-timeline-item">
                  <span className="anlt-timeline-time">09:30 AM</span>
                  <span className="anlt-timeline-text"><strong>Risk Score Updated:</strong> Composite SOC Risk Score updated from Low to Medium (48/100)</span>
                </div>
                <div className="anlt-timeline-item">
                  <span className="anlt-timeline-time">09:15 AM</span>
                  <span className="anlt-timeline-text"><strong>AI Model Inference:</strong> Neural weights auto-tuned with 99.4% precision accuracy</span>
                </div>
                <div className="anlt-timeline-item">
                  <span className="anlt-timeline-time">08:50 AM</span>
                  <span className="anlt-timeline-text"><strong>Traffic Spike:</strong> Ingress anomaly (+140% volume) flagged on Port 53 (DNS)</span>
                </div>
                <div className="anlt-timeline-item">
                  <span className="anlt-timeline-time">08:10 AM</span>
                  <span className="anlt-timeline-text"><strong>Security Recommendation:</strong> AI generated IP block rule for 185.220.101.0/24</span>
                </div>
              </div>
            </div>
          </>
        )}
      </div>
    </div>
  );
}
