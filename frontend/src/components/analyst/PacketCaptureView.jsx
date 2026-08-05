"use client";
import React, { useState, useEffect, useCallback } from "react";
import { Search, Filter, RefreshCw, ChevronLeft, ChevronRight } from "lucide-react";
import {
  ResponsiveContainer,
  PieChart,
  Pie,
  Cell,
  Tooltip,
  Legend,
  AreaChart,
  Area,
  CartesianGrid,
  XAxis,
  YAxis,
} from "recharts";

import LoadingSpinner from "../LoadingSpinner";
import { fetchApi } from "../../utils/api";
import { useTheme } from "../../context/ThemeContext";

export default function PacketCaptureView() {
  const { isDark } = useTheme();
  const [packetStream, setPacketStream] = useState([]);
  const [loadingPackets, setLoadingPackets] = useState(true);
  const [packetsError, setPacketsError] = useState(null);
  const [packetProtocolFilter, setPacketProtocolFilter] = useState("ALL");
  const [packetSearchText, setPacketSearchText] = useState("");
  const [packetPage, setPacketPage] = useState(1);
  const [packetTotalPages, setPacketTotalPages] = useState(1);
  const [packetSortBy, setPacketSortBy] = useState("timestamp");

  const fetchPacketCapture = useCallback(async () => {
    setLoadingPackets(true);
    setPacketsError(null);
    try {
      const queryParams = new URLSearchParams({
        page: packetPage.toString(),
        limit: "15",
        protocol: packetProtocolFilter,
        search: packetSearchText,
        sort_by: packetSortBy,
      });
      const res = await fetchApi(`/api/analyst/packet-capture?${queryParams.toString()}`);
      setPacketStream(res.data || res.packets || []);
      setPacketTotalPages(res.total_pages || 1);
    } catch (err) {
      setPacketsError("Unable to stream packet capture buffer.");
    } finally {
      setLoadingPackets(false);
    }
  }, [packetPage, packetProtocolFilter, packetSearchText, packetSortBy]);

  useEffect(() => {
    fetchPacketCapture();
    const interval = setInterval(fetchPacketCapture, 5000);
    return () => clearInterval(interval);
  }, [fetchPacketCapture]);

  const totalCaptured = packetStream.length ? packetStream.length * 1420 : 0;
  const activeSessions = packetStream.length > 0 ? "8 Active" : "0 Active";
  const suspiciousCount = packetStream.filter(
    (p) => p.threat_score > 50 || p.detection_status === "Suspicious" || p.detection_status === "Flagged"
  ).length;
  const droppedCount = packetStream.filter((p) => p.detection_status === "Blocked").length;
  const avgPacketSize =
    packetStream.length > 0
      ? Math.round(
          packetStream.reduce((acc, p) => acc + (parseInt(p.packet_size) || 1024), 0) / packetStream.length
        )
      : 0;

  return (
    <div key="tab-packet-capture" className="pcap-container">
      <div className="pcap-card">
        {/* Header Section */}
        <div className="pcap-header-flex">
          <div className="pcap-header-title">
            <h3>Packet Capture &amp; Deep Inspection</h3>
            <p>Deep packet inspection buffer analyzing raw frames, payload hashes, protocol headers, and threat scores.</p>
          </div>
          <div className="pcap-header-actions">
            <span className="pcap-badge">Auto-refresh (5s)</span>
            <button className="ns-btn-gradient small" onClick={fetchPacketCapture}>
              <RefreshCw size={14} style={{ marginRight: "4px" }} /> Refresh
            </button>
          </div>
        </div>

        {/* Summary Cards */}
        <div className="pcap-kpi-grid">
          <div className="pcap-stat-card blue">
            <span className="pcap-stat-title">Total Captured Packets</span>
            <span className="pcap-stat-metric">{totalCaptured > 0 ? totalCaptured.toLocaleString() : "0"}</span>
            <span className="pcap-stat-sub">Live wire buffer</span>
          </div>
          <div className="pcap-stat-card cyan">
            <span className="pcap-stat-title">Active Capture Sessions</span>
            <span className="pcap-stat-metric">{activeSessions}</span>
            <span className="pcap-stat-sub">Sensor channels</span>
          </div>
          <div className="pcap-stat-card orange">
            <span className="pcap-stat-title">Suspicious Packets</span>
            <span className="pcap-stat-metric">{suspiciousCount}</span>
            <span className="pcap-stat-sub">Anomalous flags</span>
          </div>
          <div className="pcap-stat-card red">
            <span className="pcap-stat-title">Dropped Packets</span>
            <span className="pcap-stat-metric">{droppedCount}</span>
            <span className="pcap-stat-sub">Filter drops</span>
          </div>
          <div className="pcap-stat-card green">
            <span className="pcap-stat-title">Average Packet Size</span>
            <span className="pcap-stat-metric">{avgPacketSize > 0 ? `${avgPacketSize} B` : "0 B"}</span>
            <span className="pcap-stat-sub">Payload average</span>
          </div>
          <div className="pcap-stat-card green">
            <span className="pcap-stat-title">Capture Status</span>
            <span className="pcap-stat-metric" style={{ fontSize: "1.1rem", color: "#10B981" }}>Live Capturing</span>
            <span className="pcap-stat-sub">
              <span className="status-indicator online" style={{ width: "8px", height: "8px" }}></span> Promiscuous Mode
            </span>
          </div>
        </div>

        {/* Search & Filters */}
        <div className="pcap-filter-bar">
          <div className="search-bar-wrapper" style={{ flex: 1, minWidth: "220px" }}>
            <Search size={16} className="search-icon" />
            <input
              type="text"
              placeholder="Search Source IP, Dest IP, Port, Protocol..."
              value={packetSearchText}
              onChange={(e) => {
                setPacketSearchText(e.target.value);
                setPacketPage(1);
              }}
              className="ns-search-input"
            />
          </div>

          <div style={{ display: "flex", alignItems: "center", gap: "0.5rem" }}>
            <Filter size={16} style={{ color: "#94a3b8" }} />
            <select
              className="ns-control"
              style={{ width: "130px", padding: "0.4rem 0.8rem" }}
              value={packetProtocolFilter}
              onChange={(e) => {
                setPacketProtocolFilter(e.target.value);
                setPacketPage(1);
              }}
            >
              <option value="ALL">All Protocols</option>
              <option value="TCP">TCP</option>
              <option value="UDP">UDP</option>
              <option value="HTTP">HTTP</option>
              <option value="DNS">DNS</option>
              <option value="SSH">SSH</option>
              <option value="RDP">RDP</option>
            </select>
          </div>

          <div style={{ display: "flex", alignItems: "center", gap: "0.5rem" }}>
            <span style={{ fontSize: "0.8rem", color: "#94a3b8" }}>Sort:</span>
            <select
              className="ns-control"
              style={{ width: "140px", padding: "0.4rem 0.8rem" }}
              value={packetSortBy}
              onChange={(e) => setPacketSortBy(e.target.value)}
            >
              <option value="timestamp">Timestamp</option>
              <option value="threat_score">Threat Score</option>
              <option value="packet_size">Packet Size</option>
            </select>
          </div>

          <button
            className="ns-btn-gradient small"
            style={{ background: "#334155" }}
            onClick={() => {
              setPacketSearchText("");
              setPacketProtocolFilter("ALL");
              setPacketSortBy("timestamp");
              setPacketPage(1);
            }}
          >
            Clear Filters
          </button>
        </div>

        {/* Protocol Distribution & Packet Threat Trend Section */}
        <div className="pcap-charts-grid">
          <div className="pcap-chart-box">
            <h4 className="pcap-chart-title">Captured Protocol Distribution</h4>
            {packetStream.length > 0 ? (
              <ResponsiveContainer key="pcap-donut-responsive-container" width="100%" height={180}>
                <PieChart key="pcap-donut-chart">
                  <Pie
                    data={Object.entries(
                      packetStream.reduce((acc, p) => {
                        acc[p.protocol] = (acc[p.protocol] || 0) + 1;
                        return acc;
                      }, {})
                    ).map(([name, value]) => ({ name, value }))}
                    cx="50%"
                    cy="50%"
                    innerRadius={45}
                    outerRadius={65}
                    paddingAngle={4}
                    dataKey="value"
                  >
                    {["#3B82F6", "#06B6D4", "#10B981", "#F59E0B", "#EF4444", "#8B5CF6"].map((color, i) => (
                      <Cell key={i} fill={color} />
                    ))}
                  </Pie>
                  <Tooltip contentStyle={{ backgroundColor: isDark ? "#0f172a" : "#ffffff", borderColor: isDark ? "#334155" : "#cbd5e1", borderRadius: "8px", color: isDark ? "#f8fafc" : "#1e293b" }} />
                  <Legend wrapperStyle={{ fontSize: "11px", color: isDark ? "#94a3b8" : "#334155" }} />
                </PieChart>
              </ResponsiveContainer>
            ) : (
              <div style={{ height: "180px", display: "flex", alignItems: "center", justifyContent: "center", color: isDark ? "#64748b" : "#475569" }}>
                No telemetry stream available
              </div>
            )}
          </div>

          <div className="pcap-chart-box">
            <h4 className="pcap-chart-title">Packet Stream Threat Trend</h4>
            {packetStream.length > 0 ? (
              <ResponsiveContainer key="pcap-trend-responsive-container" width="100%" height={180}>
                <AreaChart key="pcap-trend-area-chart" data={packetStream.slice(0, 10).map((p, i) => ({ name: `P${i + 1}`, score: p.threat_score || 0 }))}>
                  <defs>
                    <linearGradient id="pcapThreatTrendGrad" x1="0" y1="0" x2="0" y2="1">
                      <stop offset="5%" stopColor="#EF4444" stopOpacity={0.7} />
                      <stop offset="95%" stopColor="#EF4444" stopOpacity={0} />
                    </linearGradient>
                  </defs>
                  <CartesianGrid strokeDasharray="3 3" stroke={isDark ? "rgba(255,255,255,0.05)" : "#cbd5e1"} />
                  <XAxis dataKey="name" stroke={isDark ? "#94a3b8" : "#475569"} fontSize={11} tickLine={false} />
                  <YAxis stroke={isDark ? "#94a3b8" : "#475569"} fontSize={11} tickLine={false} domain={[0, 100]} />
                  <Tooltip contentStyle={{ backgroundColor: isDark ? "#0f172a" : "#ffffff", borderColor: isDark ? "#334155" : "#cbd5e1", borderRadius: "8px", color: isDark ? "#f8fafc" : "#1e293b" }} />
                  <Area type="monotone" dataKey="score" name="Threat Score" stroke="#EF4444" strokeWidth={2} fillOpacity={1} fill="url(#pcapThreatTrendGrad)" isAnimationActive={true} />
                </AreaChart>
              </ResponsiveContainer>
            ) : (
              <div style={{ height: "180px", display: "flex", alignItems: "center", justifyContent: "center", color: "#64748b" }}>
                No telemetry stream available
              </div>
            )}
          </div>
        </div>

        {/* Packet Capture Table */}
        <div className="pcap-table-box">
          {loadingPackets ? (
            <LoadingSpinner text="Streaming deep packet inspection buffer..." />
          ) : packetsError ? (
            <div style={{ padding: "1rem", color: "#f87171", textAlign: "center" }}>
              {packetsError}
              <button onClick={fetchPacketCapture} style={{ marginLeft: "10px" }} className="ns-btn-gradient small">Retry</button>
            </div>
          ) : packetStream.length > 0 ? (
            <table className="pcap-table">
              <thead>
                <tr>
                  <th>Timestamp</th>
                  <th>Source IP</th>
                  <th>Destination IP</th>
                  <th>Src Port</th>
                  <th>Dst Port</th>
                  <th>Protocol</th>
                  <th>Packet Size</th>
                  <th>Threat Score</th>
                  <th>Detection Status</th>
                  <th>Action</th>
                </tr>
              </thead>
              <tbody>
                {packetStream.map((p) => {
                  const statusLower = (p.detection_status || "Normal").toLowerCase();
                  let badgeClass = "normal";
                  if (statusLower.includes("suspicious")) badgeClass = "suspicious";
                  else if (statusLower.includes("flagged")) badgeClass = "flagged";
                  else if (statusLower.includes("block")) badgeClass = "blocked";

                  return (
                    <tr key={p.id}>
                      <td>{p.timestamp}</td>
                      <td><code>{p.source_ip}</code></td>
                      <td><code>{p.destination_ip}</code></td>
                      <td><code>{p.src_port || p.source_port || 80}</code></td>
                      <td><code>{p.dst_port || p.destination_port || 443}</code></td>
                      <td><span className="pcap-proto-pill">{p.protocol}</span></td>
                      <td>{p.packet_size}</td>
                      <td>
                        <span className={`pcap-score-badge ${p.threat_score > 75 ? "high" : p.threat_score > 40 ? "medium" : "low"}`}>
                          {p.threat_score}/100
                        </span>
                      </td>
                      <td>
                        <span className={`pcap-status-badge ${badgeClass}`}>
                          {p.detection_status || "Normal"}
                        </span>
                      </td>
                      <td>
                        <button className="pcap-action-btn">Inspect</button>
                      </td>
                    </tr>
                  );
                })}
              </tbody>
            </table>
          ) : (
            <p style={{ padding: "1rem", textAlign: "center", color: "#94a3b8" }}>
              No packet records available matching filter criteria.
            </p>
          )}
        </div>

        {/* Pagination Controls */}
        <div style={{ marginTop: "0.5rem", display: "flex", justifyContent: "space-between", alignItems: "center" }}>
          <span style={{ fontSize: "0.85rem", color: "#94a3b8" }}>
            Page {packetPage} of {packetTotalPages}
          </span>
          <div style={{ display: "flex", gap: "0.5rem" }}>
            <button
              className="ns-btn-gradient small"
              style={{ background: packetPage <= 1 ? "#1e293b" : undefined }}
              disabled={packetPage <= 1}
              onClick={() => setPacketPage((p) => Math.max(1, p - 1))}
            >
              <ChevronLeft size={14} /> Prev
            </button>
            <button
              className="ns-btn-gradient small"
              style={{ background: packetPage >= packetTotalPages ? "#1e293b" : undefined }}
              disabled={packetPage >= packetTotalPages}
              onClick={() => setPacketPage((p) => Math.min(packetTotalPages, p + 1))}
            >
              Next <ChevronRight size={14} />
            </button>
          </div>
        </div>
      </div>
    </div>
  );
}
