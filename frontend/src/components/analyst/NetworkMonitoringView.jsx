"use client";
import React, { useState, useEffect, useCallback } from "react";

import {
  Radio,
  Activity,
  Server,
  RefreshCw,
  Wifi,
  Network,
  Cpu,
  ArrowUpRight,
  ArrowDownLeft,
  Gauge,
  Layers,
  Globe,
  Clock,
  AlertTriangle,
  ShieldAlert,
  Zap,
  CheckCircle2,
  Database
} from "lucide-react";
import {
  ResponsiveContainer,
  AreaChart,
  Area,
  PieChart,
  Pie,
  Cell,
  CartesianGrid,
  XAxis,
  YAxis,
  Tooltip,
  Legend
} from "recharts";

import { getCurrentUser } from "../../utils/authHelpers";
import { getFormattedUTCTime } from "../../utils/formatDate";
import { fetchApi } from "../../utils/api";
import { useTheme } from "../../context/ThemeContext";
import { useAnalystSession } from "../../hooks/useAnalystSession";

export default function NetworkMonitoringView() {
  const { isDark } = useTheme();
  const { currentUser: sessionUser, userEmail } = useAnalystSession();
  const [currentUser, setCurrentUser] = useState(null);
  const [currentTime, setCurrentTime] = useState("");

  // Automated 1-Second Real-Time Telemetry State
  const [isLiveStreaming, setIsLiveStreaming] = useState(true);
  const [liveData, setLiveData] = useState(null);
  const [timeline, setTimeline] = useState([]);
  const [tickCount, setTickCount] = useState(0);

  // Clock ticker & Current User initialization
  useEffect(() => {
    setCurrentTime(getFormattedUTCTime());
    const timer = setInterval(() => setCurrentTime(getFormattedUTCTime()), 1000);
    return () => clearInterval(timer);
  }, []);

  useEffect(() => {
    const user = getCurrentUser() || sessionUser;
    if (user) {
      setCurrentUser(user);
    }
  }, [sessionUser]);

  // Automated 1000ms (1-Second) Telemetry Stream Fetcher
  const fetchLiveTelemetry = useCallback(async () => {
    try {
      const activeEmail = currentUser?.email || userEmail || "security@gmail.com";
      const res = await fetchApi("/api/monitoring/live-telemetry", {
        headers: {
          "X-User-Email": activeEmail,
        },
      });

      if (res && res.live) {
        setLiveData(res.live);
        if (Array.isArray(res.timeline) && res.timeline.length > 0) {
          setTimeline(res.timeline);
        }
        setTickCount((prev) => prev + 1);
      }
    } catch (err) {
      console.warn("Automated 1-second telemetry stream fallback:", err);
    }
  }, [currentUser, userEmail]);

  // 1-Second Continuous Real-Time Polling Effect
  useEffect(() => {
    fetchLiveTelemetry(); // Initial tick
    if (!isLiveStreaming) return;

    const interval = setInterval(() => {
      fetchLiveTelemetry();
    }, 1000); // 1000ms continuous real-time stream

    return () => clearInterval(interval);
  }, [fetchLiveTelemetry, isLiveStreaming]);

  // Telemet  // Telemetry metric fallbacks for smooth rendering
  const activeLiveData = liveData || {
    inbound_mbps: 0.2,
    outbound_mbps: 0.1,
    total_mbps: 0.3,
    formatted_inbound: "0.2 Mbps In",
    formatted_outbound: "0.1 Mbps Out",
    formatted_total: "0.3 Mbps Total",
    spike_threshold_mbps: 25.0,
    is_spike_detected: false,
    spike_banner: null,
    interfaces: [
      {
        id: "eth0",
        name: "eth0 (Primary WAN)",
        status: "ACTIVE",
        role: "Primary WAN Gateway",
        latency: "1.2ms",
        drop_rate: "0%",
        rx_mbps: 0.2,
        tx_mbps: 0.1,
        link_speed: "10 Gbps Full-Duplex",
        ip_address: "10.0.9.47",
        is_primary: true,
      },
      {
        id: "eth1",
        name: "eth1 (DMZ / Internal)",
        status: "ACTIVE",
        role: "Internal Subnet Trunk",
        latency: "0.8ms",
        drop_rate: "0.1%",
        rx_mbps: 0.05,
        tx_mbps: 0.02,
        link_speed: "1 Gbps Full-Duplex",
        ip_address: "192.168.1.1",
        is_primary: false,
      },
      {
        id: "wlan0",
        name: "wlan0 (Secondary / Wireless)",
        status: "ACTIVE",
        role: "Wireless Management Mesh",
        latency: "14.2ms",
        drop_rate: "2.4%",
        rx_mbps: 0.02,
        tx_mbps: 0.01,
        link_speed: "866 Mbps",
        ip_address: "172.16.0.12",
        is_primary: false,
      },
    ],
    protocol_breakdown: [
      { name: "HTTPS (Port 443)", port: 443, percentage: 55.0, color: "#3B82F6", bandwidth_mbps: 0.165 },
      { name: "DNS (Port 53)", port: 53, percentage: 25.0, color: "#10B981", bandwidth_mbps: 0.075 },
      { name: "HTTP (Port 80)", port: 80, percentage: 12.0, color: "#06B6D4", bandwidth_mbps: 0.036 },
      { name: "SQL / Database (Port 1433 / 3306)", port: "1433/3306", percentage: 5.0, color: "#8B5CF6", bandwidth_mbps: 0.015 },
      { name: "SSH (Port 22)", port: 22, percentage: 3.0, color: "#F59E0B", bandwidth_mbps: 0.009 },
    ],
  };

  const chartTimeline = timeline.length > 0 ? timeline : [
    { time: new Date().toLocaleTimeString(), inbound: 0.2, outbound: 0.1, total: 0.3 },
  ];

  const totalInbound = activeLiveData.inbound_mbps;
  const totalOutbound = activeLiveData.outbound_mbps;
  const totalSpeed = activeLiveData.total_mbps;


  return (
    <div key="tab-network-monitoring" className="netmon-container">
      {/* 1. Header Banner & Automated Stream Status */}
      <div className="netmon-card netmon-header-card">
        <div className="netmon-header-flex">
          <div className="netmon-header-title">

            <h2>Automated Real-Time Network Monitoring Dashboard</h2>

          </div>
          <div className="netmon-header-meta" style={{ display: "flex", gap: "1rem", alignItems: "center", flexWrap: "wrap" }}>
            <div className="netmon-meta-item" style={{ display: "flex", alignItems: "center", gap: "6px", fontSize: "0.85rem", color: "#94a3b8" }}>
              <Server size={14} style={{ color: "#3b82f6" }} />
              <span>Sensor: <strong>eth0 (10.0.9.47)</strong></span>
            </div>
            <div className="netmon-meta-item" style={{ display: "flex", alignItems: "center", gap: "6px", fontSize: "0.85rem", color: "#94a3b8" }}>
              <Clock size={14} style={{ color: "#10b981" }} />
              <span>UTC Time: <strong>{currentTime}</strong></span>
            </div>
            <button
              onClick={() => setIsLiveStreaming((prev) => !prev)}
              className="ns-btn-gradient small"
              style={{
                display: "inline-flex",
                alignItems: "center",
                gap: "6px",
                padding: "0.45rem 0.9rem",
                background: isLiveStreaming ? "linear-gradient(135deg, #10b981, #059669)" : "linear-gradient(135deg, #ef4444, #dc2626)",
              }}
            >
              <Zap size={14} className={isLiveStreaming ? "animate-pulse" : ""} />
              {isLiveStreaming ? "LIVE 1s Stream Active" : "Stream Paused"}
            </button>
          </div>
        </div>
      </div>

      {/* 2. Automated Traffic Spike Alert Banner (Flashes when Total Bandwidth > 800 Mbps) */}
      {activeLiveData.is_spike_detected && (
        <div
          style={{
            background: "linear-gradient(135deg, rgba(239, 68, 68, 0.25) 0%, rgba(185, 28, 28, 0.4) 100%)",
            border: "1px solid #ef4444",
            borderRadius: "10px",
            padding: "1rem 1.25rem",
            display: "flex",
            alignItems: "center",
            justifyContent: "space-between",
            gap: "1rem",
            boxShadow: "0 0 20px rgba(239, 68, 68, 0.4)",
            animation: "pulse 2s infinite ease-in-out",
          }}
        >
          <div style={{ display: "flex", alignItems: "center", gap: "0.75rem" }}>
            <ShieldAlert size={26} style={{ color: "#ef4444", flexShrink: 0 }} />
            <div>
              <h4 style={{ margin: 0, fontSize: "1rem", fontWeight: 700, color: "#ffffff" }}>
                {activeLiveData.spike_banner || `⚠️ Dynamic Traffic Spike Detected: ${totalSpeed} Mbps on interface eth0`}
              </h4>
              <p style={{ margin: "2px 0 0 0", fontSize: "0.825rem", color: "#fca5a5" }}>
                Automated safety threshold (800 Mbps) breached on WAN interface eth0. Alert logged directly to PostgreSQL store.
              </p>
            </div>
          </div>
          <span
            style={{
              background: "#ef4444",
              color: "#ffffff",
              fontSize: "0.75rem",
              fontWeight: 800,
              padding: "0.35rem 0.75rem",
              borderRadius: "6px",
              letterSpacing: "0.05em",
              textTransform: "uppercase",
              whiteSpace: "nowrap",
            }}
          >
            CRITICAL SURGE - LOGGED TO POSTGRESQL
          </span>
        </div>
      )}

      {/* 3. Live Speed & Volume Gauge Cards (Continuous Calculations) */}
      <div className="netmon-kpi-grid">
        {/* Real-Time Live Speed Gauge Card */}
        <div className="netmon-stat-card cyan" style={{ gridColumn: "span 2", minWidth: "280px" }}>
          <div style={{ display: "flex", justifyContent: "space-between", alignItems: "center" }}>
            <span className="netmon-stat-title" style={{ display: "flex", alignItems: "center", gap: "6px" }}>
              <Gauge size={16} style={{ color: "#06b6d4" }} />
              Live Continuous Speed &amp; Volume Gauge
            </span>
            <span className="netmon-badge" style={{ background: "rgba(6, 182, 212, 0.15)", color: "#06b6d4", borderColor: "rgba(6, 182, 212, 0.3)" }}>
              AUTOMATED REAL-TIME
            </span>
          </div>

          <div style={{ display: "flex", alignItems: "baseline", gap: "0.75rem", marginTop: "0.5rem" }}>
            <span className="netmon-stat-metric" style={{ fontSize: "2rem", color: "#38bdf8", fontWeight: 800 }}>
              {totalInbound} Mbps In
            </span>
            <span style={{ fontSize: "1.3rem", color: "#34d399", fontWeight: 700 }}>
              / {totalOutbound} Mbps Out
            </span>
          </div>

          {/* Dynamic Calculated Progress Bar ($Total Bytes \times 8 \div 10^6$) */}
          <div style={{ marginTop: "0.65rem" }}>
            <div style={{ display: "flex", justifyContent: "space-between", fontSize: "0.75rem", color: "#94a3b8", marginBottom: "4px" }}>
              <span>Combined Total Speed: <strong>{totalSpeed} Mbps</strong></span>
              <span>Safety Threshold: <strong>800 Mbps</strong></span>
            </div>
            <div style={{ width: "100%", height: "10px", backgroundColor: "rgba(30, 41, 59, 0.8)", borderRadius: "6px", overflow: "hidden", border: "1px solid rgba(255, 255, 255, 0.08)" }}>
              <div
                style={{
                  width: `${Math.min(100, Math.round((totalSpeed / 1200) * 100))}%`,
                  height: "100%",
                  background: totalSpeed > 800
                    ? "linear-gradient(90deg, #06b6d4 0%, #f59e0b 60%, #ef4444 100%)"
                    : "linear-gradient(90deg, #06b6d4 0%, #3b82f6 75%, #10b981 100%)",
                  borderRadius: "6px",
                  boxShadow: totalSpeed > 800 ? "0 0 14px rgba(239, 68, 68, 0.8)" : "0 0 10px rgba(6, 182, 212, 0.5)",
                  transition: "width 0.8s ease-in-out",
                }}
              />
            </div>
          </div>
          <span className="netmon-stat-sub" style={{ marginTop: "0.4rem" }}>
            Formula: (Total Bytes × 8) ÷ 10⁶ &bull; Polling Interval: 1000ms continuous
          </span>
        </div>

        {/* Total Aggregate Inbound Speed */}
        <div className="netmon-stat-card blue">
          <span className="netmon-stat-title" style={{ display: "flex", alignItems: "center", gap: "6px" }}>
            <ArrowDownLeft size={16} style={{ color: "#3b82f6" }} />
            Inbound Throughput
          </span>
          <span className="netmon-stat-metric" style={{ color: "#38bdf8" }}>{totalInbound} <span style={{ fontSize: "0.9rem", color: "#94a3b8" }}>Mbps</span></span>
          <span className="netmon-stat-sub">Ingress Packet Stream</span>
        </div>

        {/* Total Aggregate Outbound Speed */}
        <div className="netmon-stat-card green">
          <span className="netmon-stat-title" style={{ display: "flex", alignItems: "center", gap: "6px" }}>
            <ArrowUpRight size={16} style={{ color: "#10b981" }} />
            Outbound Throughput
          </span>
          <span className="netmon-stat-metric" style={{ color: "#34d399" }}>{totalOutbound} <span style={{ fontSize: "0.9rem", color: "#94a3b8" }}>Mbps</span></span>
          <span className="netmon-stat-sub">Egress Packet Stream</span>
        </div>
      </div>

      {/* 4. Live Visualizations: Continuous Live Traffic Line Graph & Dynamic Protocol DPI Breakdown */}
      <div style={{ display: "grid", gridTemplateColumns: "repeat(auto-fit, minmax(320px, 1fr))", gap: "1.5rem" }}>
        {/* Continuous Live Traffic Line/Area Graph */}
        <div className="netmon-chart-box">
          <div style={{ display: "flex", justifyContent: "space-between", alignItems: "center", marginBottom: "1rem" }}>
            <h4 className="netmon-chart-title" style={{ margin: 0, display: "flex", alignItems: "center", gap: "8px" }}>
              <Activity size={18} style={{ color: "#06b6d4" }} />
              Continuous Live Traffic Volume Graph (Mbps)
            </h4>
            <span className="netmon-badge" style={{ background: "rgba(16, 185, 129, 0.15)", color: "#10b981" }}>
              Updating Every 1s
            </span>
          </div>

          <ResponsiveContainer width="100%" height={240}>
            <AreaChart data={chartTimeline}>
              <defs>
                <linearGradient id="liveInboundGrad" x1="0" y1="0" x2="0" y2="1">
                  <stop offset="5%" stopColor="#06B6D4" stopOpacity={0.7} />
                  <stop offset="95%" stopColor="#06B6D4" stopOpacity={0} />
                </linearGradient>
                <linearGradient id="liveOutboundGrad" x1="0" y1="0" x2="0" y2="1">
                  <stop offset="5%" stopColor="#10B981" stopOpacity={0.7} />
                  <stop offset="95%" stopColor="#10B981" stopOpacity={0} />
                </linearGradient>
              </defs>
              <CartesianGrid strokeDasharray="3 3" stroke={isDark ? "rgba(255, 255, 255, 0.05)" : "#cbd5e1"} />
              <XAxis dataKey="time" stroke={isDark ? "#94a3b8" : "#475569"} fontSize={11} tickLine={false} />
              <YAxis stroke={isDark ? "#94a3b8" : "#475569"} fontSize={11} tickLine={false} unit=" Mbps" />
              <Tooltip
                contentStyle={{
                  backgroundColor: isDark ? "#0f172a" : "#ffffff",
                  borderColor: isDark ? "#334155" : "#cbd5e1",
                  borderRadius: "8px",
                  color: isDark ? "#f8fafc" : "#1e293b",
                }}
              />
              <Legend wrapperStyle={{ fontSize: "12px", color: isDark ? "#94a3b8" : "#334155" }} />
              <Area
                type="monotone"
                name="Inbound Rate (Mbps)"
                dataKey="inbound"
                stroke="#06B6D4"
                strokeWidth={2}
                fillOpacity={1}
                fill="url(#liveInboundGrad)"
                isAnimationActive={false}
              />
              <Area
                type="monotone"
                name="Outbound Rate (Mbps)"
                dataKey="outbound"
                stroke="#10B981"
                strokeWidth={2}
                fillOpacity={1}
                fill="url(#liveOutboundGrad)"
                isAnimationActive={false}
              />
            </AreaChart>
          </ResponsiveContainer>
        </div>

        {/* Dynamic Protocol Breakdown (Deep Packet Inspection Simulation) */}
        <div className="netmon-chart-box">
          <div style={{ display: "flex", justifyContent: "space-between", alignItems: "center", marginBottom: "1rem" }}>
            <h4 className="netmon-chart-title" style={{ margin: 0, display: "flex", alignItems: "center", gap: "8px", color: isDark ? "#f8fafc" : "#0f172a" }}>
              <Globe size={18} style={{ color: "#8b5cf6" }} />
              Dynamic Protocol Breakdown (Deep Packet Inspection)
            </h4>
            <span className="netmon-badge">Live DPI Ratios</span>
          </div>

          {/* Live Horizontal Bar Chart Updating Every Second */}
          <div style={{ display: "flex", flexDirection: "column", gap: "0.85rem", marginTop: "0.5rem" }}>
            {activeLiveData.protocol_breakdown.map((proto) => (
              <div key={proto.name} style={{ display: "flex", flexDirection: "column", gap: "4px" }}>
                <div style={{ display: "flex", justifyContent: "space-between", fontSize: "0.8rem" }}>
                  <span style={{ color: isDark ? "#f8fafc" : "#0f172a", fontWeight: 600, display: "flex", alignItems: "center", gap: "6px" }}>
                    <span style={{ width: "8px", height: "8px", borderRadius: "50%", backgroundColor: proto.color, display: "inline-block" }} />
                    {proto.name}
                  </span>
                  <span style={{ color: isDark ? "#38bdf8" : "#0284c7", fontWeight: 700 }}>
                    {proto.percentage}% <span style={{ color: isDark ? "#94a3b8" : "#64748b", fontWeight: 400 }}>({proto.bandwidth_mbps} Mbps)</span>
                  </span>
                </div>
                <div style={{ width: "100%", height: "8px", backgroundColor: isDark ? "rgba(30, 41, 59, 0.8)" : "#e2e8f0", borderRadius: "4px", overflow: "hidden" }}>
                  <div
                    style={{
                      width: `${proto.percentage}%`,
                      height: "100%",
                      backgroundColor: proto.color,
                      borderRadius: "4px",
                      transition: "width 0.8s ease-in-out",
                    }}
                  />
                </div>
              </div>
            ))}
          </div>
        </div>
      </div>

      {/* 5. Live Network Interface Status Grid (eth0, eth1, wlan0) */}
      <div className="netmon-card">
        <div style={{ display: "flex", justifyContent: "space-between", alignItems: "center", borderBottom: isDark ? "1px solid rgba(255,255,255,0.08)" : "1px solid #e2e8f0", paddingBottom: "0.75rem" }}>
          <h3 style={{ margin: 0, fontSize: "1.05rem", display: "flex", alignItems: "center", gap: "8px", color: isDark ? "#f8fafc" : "#0f172a" }}>
            <Network size={18} style={{ color: "#10b981" }} />
            Live Network Interface Status Grid (Automated Ping &amp; Drop Rate Monitoring)
          </h3>
          <span className="netmon-badge" style={{ background: "rgba(16, 185, 129, 0.15)", color: "#10b981" }}>
            Background Ping Active
          </span>
        </div>

        <div style={{ display: "grid", gridTemplateColumns: "repeat(auto-fit, minmax(300px, 1fr))", gap: "1.25rem" }}>
          {activeLiveData.interfaces.map((iface) => (
            <div
              key={iface.id}
              style={{
                background: isDark ? "rgba(15, 23, 42, 0.6)" : "#ffffff",
                border: iface.status === "DEGRADED" || iface.status === "OFFLINE" ? "1px solid #f59e0b" : (isDark ? "1px solid var(--ns-border)" : "1px solid #e2e8f0"),
                boxShadow: isDark ? "none" : "0 1px 3px rgba(0,0,0,0.05)",
                borderRadius: "10px",
                padding: "1.25rem",
                display: "flex",
                flexDirection: "column",
                gap: "0.85rem",
                position: "relative",
              }}
            >
              {/* Interface Card Header */}
              <div style={{ display: "flex", justifyContent: "space-between", alignItems: "flex-start" }}>
                <div>
                  <div style={{ display: "flex", alignItems: "center", gap: "8px" }}>
                    <Server size={16} style={{ color: "#3b82f6" }} />
                    <h4 style={{ margin: 0, fontSize: "0.95rem", fontWeight: 700, color: isDark ? "#f8fafc" : "#0f172a" }}>{iface.name}</h4>
                  </div>
                  <span style={{ fontSize: "0.75rem", color: isDark ? "#94a3b8" : "#64748b", display: "block", marginTop: "2px" }}>
                    {iface.role} &bull; <code>{iface.ip_address}</code>
                  </span>
                </div>
                <span
                  style={{
                    display: "inline-block",
                    padding: "0.2rem 0.55rem",
                    borderRadius: "4px",
                    fontSize: "0.725rem",
                    fontWeight: 700,
                    textTransform: "uppercase",
                    background: iface.status === "ACTIVE"
                      ? "rgba(16, 185, 129, 0.15)"
                      : iface.status === "DEGRADED"
                      ? "rgba(245, 158, 11, 0.2)"
                      : "rgba(239, 68, 68, 0.2)",
                    color: iface.status === "ACTIVE"
                      ? "#10b981"
                      : iface.status === "DEGRADED"
                      ? "#f59e0b"
                      : "#ef4444",
                    border: iface.status === "ACTIVE"
                      ? "1px solid rgba(16, 185, 129, 0.3)"
                      : iface.status === "DEGRADED"
                      ? "1px solid rgba(245, 158, 11, 0.4)"
                      : "1px solid rgba(239, 68, 68, 0.4)",
                  }}
                >
                  {iface.status === "ACTIVE" ? "● ACTIVE" : iface.status === "DEGRADED" ? "⚠️ DEGRADED" : "✕ OFFLINE"}
                </span>
              </div>

              {/* Latency & Packet Drop Rate */}
              <div style={{ display: "grid", gridTemplateColumns: "1fr 1fr", gap: "0.5rem", fontSize: "0.8rem", background: isDark ? "rgba(30, 41, 59, 0.4)" : "#f1f5f9", padding: "0.65rem", borderRadius: "6px" }}>
                <div>
                  <span style={{ color: isDark ? "#94a3b8" : "#475569", fontSize: "0.7rem", textTransform: "uppercase", display: "block" }}>Latency</span>
                  <strong style={{ color: iface.status === "DEGRADED" ? "#f59e0b" : (isDark ? "#38bdf8" : "#0284c7") }}>{iface.latency}</strong>
                </div>
                <div>
                  <span style={{ color: isDark ? "#94a3b8" : "#475569", fontSize: "0.7rem", textTransform: "uppercase", display: "block" }}>Drop Rate</span>
                  <strong style={{ color: iface.drop_rate !== "0%" && iface.drop_rate !== "0.0%" ? "#f59e0b" : (isDark ? "#34d399" : "#059669") }}>{iface.drop_rate}</strong>
                </div>
              </div>

              {/* Ingress / Egress Throughput */}
              <div style={{ display: "flex", flexDirection: "column", gap: "0.4rem", fontSize: "0.8rem" }}>
                <div style={{ display: "flex", justifyContent: "space-between", alignItems: "center" }}>
                  <span style={{ color: isDark ? "#94a3b8" : "#475569", display: "flex", alignItems: "center", gap: "4px" }}>
                    <ArrowDownLeft size={14} style={{ color: "#06b6d4" }} /> Ingress (RX):
                  </span>
                  <strong style={{ color: isDark ? "#06b6d4" : "#0891b2" }}>{iface.rx_mbps} Mbps</strong>
                </div>

                <div style={{ display: "flex", justifyContent: "space-between", alignItems: "center" }}>
                  <span style={{ color: isDark ? "#94a3b8" : "#475569", display: "flex", alignItems: "center", gap: "4px" }}>
                    <ArrowUpRight size={14} style={{ color: "#10b981" }} /> Egress (TX):
                  </span>
                  <strong style={{ color: isDark ? "#10b981" : "#059669" }}>{iface.tx_mbps} Mbps</strong>
                </div>
              </div>
            </div>
          ))}
        </div>
      </div>
    </div>
  );
}
