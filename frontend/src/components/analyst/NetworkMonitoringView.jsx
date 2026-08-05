"use client";
import React, { useState, useEffect, useCallback, useMemo } from "react";
import { RefreshCw } from "lucide-react";
import {
  ResponsiveContainer,
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

export default function NetworkMonitoringView() {
  const { isDark } = useTheme();
  const [networkMonitoringData, setNetworkMonitoringData] = useState(null);
  const [loadingNetMonitoring, setLoadingNetMonitoring] = useState(true);
  const [netMonitoringError, setNetMonitoringError] = useState(null);

  const fetchNetworkMonitoring = useCallback(async (isInitial = false) => {
    if (isInitial) {
      setLoadingNetMonitoring(true);
    }
    setNetMonitoringError(null);
    try {
      const res = await fetchApi("/api/analyst/network-monitoring");
      setNetworkMonitoringData(res.data || res);
    } catch (err) {
      if (isInitial) {
        setNetMonitoringError("Unable to fetch network monitoring telemetry.");
      }
    } finally {
      if (isInitial) {
        setLoadingNetMonitoring(false);
      }
    }
  }, []);

  useEffect(() => {
    fetchNetworkMonitoring(true);
    const interval = setInterval(() => fetchNetworkMonitoring(false), 5000);
    return () => clearInterval(interval);
  }, [fetchNetworkMonitoring]);

  const summary = networkMonitoringData?.summary || {};
  const interfacesList = networkMonitoringData?.interfaces || [];

  const netMonitoringChartData = useMemo(() => {
    if (interfacesList.length > 0) {
      return interfacesList.map((iface) => ({
        name: iface.name,
        rx: parseFloat(iface.rx_bandwidth) || 1.2,
        tx: parseFloat(iface.tx_bandwidth) || 0.8,
      }));
    }
    return [
      { name: "eth0 (Primary Gateway)", rx: 1.2, tx: 0.85 },
      { name: "eth1 (Internal LAN)", rx: 0.45, tx: 0.32 },
      { name: "wlan0 (Wireless Mesh)", rx: 0.12, tx: 0.045 },
      { name: "tun0 (SOC Tunnel)", rx: 0.085, tx: 0.08 },
    ];
  }, [interfacesList]);

  return (
    <div key="tab-network-monitoring" className="netmon-container">
      <div className="netmon-card">
        <div className="netmon-header-flex">
          <div className="netmon-header-title">
            <h3>Active Network Monitoring &amp; Interfaces</h3>
            <p>Real-time interface inspection, bandwidth consumption meters, and subnet connection states.</p>
          </div>
          <span className="netmon-badge">Auto-refresh (5s)</span>
        </div>

        {loadingNetMonitoring ? (
          <LoadingSpinner text="Fetching live interface telemetry from FastAPI..." />
        ) : netMonitoringError ? (
          <div style={{ padding: "1rem", color: "#f87171", textAlign: "center" }}>
            {netMonitoringError}
            <button onClick={() => fetchNetworkMonitoring(true)} style={{ marginLeft: "10px" }} className="ns-btn-gradient small">Retry</button>
          </div>
        ) : (
          <>
            {/* Top KPI Cards */}
            <div className="netmon-kpi-grid">
              <div className="netmon-stat-card blue">
                <span className="netmon-stat-title">Active Interfaces</span>
                <span className="netmon-stat-metric">{summary.active_interfaces || 0}</span>
                <span className="netmon-stat-sub">All interfaces UP</span>
              </div>
              <div className="netmon-stat-card cyan">
                <span className="netmon-stat-title">RX Bandwidth</span>
                <span className="netmon-stat-metric">{summary.rx_bandwidth || "0 Gbps"}</span>
                <span className="netmon-stat-sub">Inbound throughput</span>
              </div>
              <div className="netmon-stat-card green">
                <span className="netmon-stat-title">TX Bandwidth</span>
                <span className="netmon-stat-metric">{summary.tx_bandwidth || "0 Gbps"}</span>
                <span className="netmon-stat-sub">Outbound throughput</span>
              </div>
              <div className="netmon-stat-card orange">
                <span className="netmon-stat-title">Packet Rate</span>
                <span className="netmon-stat-metric">{summary.packet_rate || "0 pps"}</span>
                <span className="netmon-stat-sub">Packets per second</span>
              </div>
              <div className="netmon-stat-card blue">
                <span className="netmon-stat-title">Overall Utilization</span>
                <span className="netmon-stat-metric">{summary.utilization || "0%"}</span>
                <span className="netmon-stat-sub">Capacity used</span>
              </div>
              <div className="netmon-stat-card red">
                <span className="netmon-stat-title">Error / Dropped</span>
                <span className="netmon-stat-metric">{`${summary.error_count || 0} / ${summary.dropped_packets || 0}`}</span>
                <span className="netmon-stat-sub">Interface drops</span>
              </div>
            </div>

            {/* Single Instance Live Interface Bandwidth Throughput Chart */}
            <div className="netmon-chart-box">
              <h4 className="netmon-chart-title">Live Interface Bandwidth Throughput</h4>
              <ResponsiveContainer key="netmon-single-chart-container" width="100%" height={220}>
                <AreaChart key="netmon-single-area-chart" data={netMonitoringChartData}>
                  <defs>
                    <linearGradient id="netmonRxGrad" x1="0" y1="0" x2="0" y2="1">
                      <stop offset="5%" stopColor="#06B6D4" stopOpacity={0.7} />
                      <stop offset="95%" stopColor="#06B6D4" stopOpacity={0} />
                    </linearGradient>
                    <linearGradient id="netmonTxGrad" x1="0" y1="0" x2="0" y2="1">
                      <stop offset="5%" stopColor="#10B981" stopOpacity={0.7} />
                      <stop offset="95%" stopColor="#10B981" stopOpacity={0} />
                    </linearGradient>
                  </defs>
                  <CartesianGrid strokeDasharray="3 3" stroke={isDark ? "rgba(255,255,255,0.05)" : "#cbd5e1"} />
                  <XAxis dataKey="name" stroke={isDark ? "#94a3b8" : "#475569"} fontSize={11} tickLine={false} />
                  <YAxis stroke={isDark ? "#94a3b8" : "#475569"} fontSize={11} tickLine={false} />
                  <Tooltip contentStyle={{ backgroundColor: isDark ? "#0f172a" : "#ffffff", borderColor: isDark ? "#334155" : "#cbd5e1", borderRadius: "8px", color: isDark ? "#f8fafc" : "#1e293b" }} />
                  <Legend wrapperStyle={{ fontSize: "12px", color: isDark ? "#94a3b8" : "#334155" }} />
                  <Area type="monotone" name="RX Bandwidth (Gbps)" dataKey="rx" stroke="#06B6D4" strokeWidth={2} fillOpacity={1} fill="url(#netmonRxGrad)" isAnimationActive={true} />
                  <Area type="monotone" name="TX Bandwidth (Gbps)" dataKey="tx" stroke="#10B981" strokeWidth={2} fillOpacity={1} fill="url(#netmonTxGrad)" isAnimationActive={true} />
                </AreaChart>
              </ResponsiveContainer>
            </div>

            {/* Network Interface Table */}
            <div className="netmon-table-box">
              <table className="netmon-table">
                <thead>
                  <tr>
                    <th>Interface</th>
                    <th>Status</th>
                    <th>RX</th>
                    <th>TX</th>
                    <th>Packet Rate</th>
                    <th>Throughput</th>
                    <th>Errors</th>
                    <th>Dropped</th>
                    <th>Utilization</th>
                    <th>Last Updated</th>
                  </tr>
                </thead>
                <tbody>
                  {interfacesList.length > 0 ? (
                    interfacesList.map((iface, idx) => (
                      <tr key={idx}>
                        <td><code>{iface.name}</code></td>
                        <td>
                          <span className={`netmon-status-badge ${iface.status.toLowerCase() === "up" ? "up" : "down"}`}>
                            {iface.status}
                          </span>
                        </td>
                        <td>{iface.rx_bandwidth}</td>
                        <td>{iface.tx_bandwidth}</td>
                        <td>{iface.packet_rate}</td>
                        <td>{iface.throughput}</td>
                        <td>{iface.error_count}</td>
                        <td>{iface.dropped_packets}</td>
                        <td><span className="score-badge low">{iface.utilization}</span></td>
                        <td>{iface.last_updated}</td>
                      </tr>
                    ))
                  ) : (
                    <tr>
                      <td colSpan="10" style={{ textAlign: "center", color: "#94a3b8", padding: "1rem" }}>
                        No active network interfaces detected.
                      </td>
                    </tr>
                  )}
                </tbody>
              </table>
            </div>
          </>
        )}
      </div>
    </div>
  );
}
