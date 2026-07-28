"use client";
import React, { useState, useEffect, useCallback, useMemo } from "react";
import { useRouter } from "next/navigation";
import {
  Globe,
  Radio,
  Activity,
  Shield,
  BarChart3,
  FileText,
  Settings,
  Cpu,
  Server,
  Search,
  Download,
  Filter,
  RefreshCw,
  ChevronLeft,
  ChevronRight,
  AlertTriangle,
  Layers,
  FileCheck,
  Plus,
  TrendingUp,
  Zap,
  CheckCircle2,
  Clock,
  ArrowUpDown,
  ChevronUp,
  ChevronDown,
  Database,
  Lock,
  AlertCircle,
  Wifi,
  UserCheck,
} from "lucide-react";
import {
  ComposedChart,
  AreaChart,
  Area,
  LineChart,
  Line,
  BarChart,
  Bar,
  PieChart,
  Pie,
  Cell,
  XAxis,
  YAxis,
  CartesianGrid,
  Tooltip,
  Legend,
  ResponsiveContainer,
} from "recharts";

import ProtectedRoute from "../../components/ProtectedRoute";
import Navbar from "../../components/Navbar";
import Sidebar from "../../components/Sidebar";
import StatCard from "../../components/StatCard";
import ActivityTable from "../../components/ActivityTable";
import DashboardCard from "../../components/DashboardCard";
import Footer from "../../components/Footer";
import LoadingSpinner from "../../components/LoadingSpinner";

import { getCurrentUser, clearCurrentUser } from "../../utils/authHelpers";
import { getFormattedUTCTime } from "../../utils/formatDate";
import { fetchApi } from "../../utils/api";
import { API_BASE_URL } from "../../utils/constants";
import { useTheme } from "../../context/ThemeContext";

// Custom SOC Telemetry Tooltip for Network Traffic Overview
const CustomTrafficTooltip = ({ active, payload, label }) => {
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
          backdropFilter: "blur(12px)",
          color: isDark ? "#f8fafc" : "#0f172a",
          minWidth: "190px",
        }}
      >
        <div
          style={{
            fontSize: "0.725rem",
            color: isDark ? "#94a3b8" : "#64748b",
            fontWeight: 700,
            letterSpacing: "0.05em",
            marginBottom: "0.4rem",
            borderBottom: isDark ? "1px solid rgba(255, 255, 255, 0.08)" : "1px solid #e2e8f0",
            paddingBottom: "0.3rem",
          }}
        >
          TIMESTAMP: {label}
        </div>
        {payload.map((entry, index) => (
          <div
            key={`tooltip-item-${index}`}
            style={{
              display: "flex",
              alignItems: "center",
              justifyContent: "space-between",
              gap: "1rem",
              fontSize: "0.8rem",
              margin: "0.35rem 0",
            }}
          >
            <span
              style={{
                display: "flex",
                alignItems: "center",
                gap: "0.45rem",
                color: isDark ? "#cbd5e1" : "#334155",
                fontWeight: 500,
              }}
            >
              <span
                style={{
                  width: "8px",
                  height: "8px",
                  borderRadius: "50%",
                  backgroundColor: entry.color,
                  boxShadow: `0 0 6px ${entry.color}`,
                }}
              ></span>
              {entry.name}
            </span>
            <span
              style={{
                fontWeight: 700,
                fontFamily: "monospace",
                color: isDark ? "#f8fafc" : "#0f172a",
              }}
            >
              {entry.value} {entry.unit || ""}
            </span>
          </div>
        ))}
      </div>
    );
  }
  return null;
};

export default function AnalystDashboard() {
  const router = useRouter();
  const [currentUser, setCurrentUser] = useState(null);
  const [sidebarCollapsed, setSidebarCollapsed] = useState(false);
  const [activeTab, setActiveTab] = useState("Dashboard");
  const [currentTime, setCurrentTime] = useState("");
  const [searchQuery, setSearchQuery] = useState("");

  // 1. Dashboard States
  const [backendLogs, setBackendLogs] = useState([]);
  const [loadingBackendLogs, setLoadingBackendLogs] = useState(true);
  const [logsError, setLogsError] = useState(null);

  const [stats, setStats] = useState(null);
  const [loadingStats, setLoadingStats] = useState(true);
  const [statsError, setStatsError] = useState(null);

  const [threatChartData, setThreatChartData] = useState([]);
  const [loadingThreatChart, setLoadingThreatChart] = useState(true);
  const [threatChartError, setThreatChartError] = useState(null);

  const [systemStatus, setSystemStatus] = useState([]);
  const [loadingSystemStatus, setLoadingSystemStatus] = useState(true);
  const [systemStatusError, setSystemStatusError] = useState(null);

  const [recentAlerts, setRecentAlerts] = useState([]);
  const [loadingRecentAlerts, setLoadingRecentAlerts] = useState(true);
  const [recentAlertsError, setRecentAlertsError] = useState(null);

  // SOC Table Interactive Controls
  const [logSearchQuery, setLogSearchQuery] = useState("");
  const [logSortField, setLogSortField] = useState("timestamp");
  const [logSortOrder, setLogSortOrder] = useState("asc");
  const [logPage, setLogPage] = useState(1);

  // 2. Network Monitoring States
  const [networkMonitoringData, setNetworkMonitoringData] = useState(null);
  const [loadingNetMonitoring, setLoadingNetMonitoring] = useState(true);
  const [netMonitoringError, setNetMonitoringError] = useState(null);

  // 3. Packet Capture States
  const [packetStream, setPacketStream] = useState([]);
  const [loadingPackets, setLoadingPackets] = useState(true);
  const [packetsError, setPacketsError] = useState(null);
  const [packetProtocolFilter, setPacketProtocolFilter] = useState("ALL");
  const [packetSearchText, setPacketSearchText] = useState("");
  const [packetPage, setPacketPage] = useState(1);
  const [packetTotalPages, setPacketTotalPages] = useState(1);
  const [packetSortBy, setPacketSortBy] = useState("timestamp");

  // 4. Traffic Analysis States
  const [trafficAnalysisData, setTrafficAnalysisData] = useState(null);
  const [loadingTrafficAnalysis, setLoadingTrafficAnalysis] = useState(true);
  const [trafficAnalysisError, setTrafficAnalysisError] = useState(null);

  // 5. Reports States
  const [reportsData, setReportsData] = useState([]);
  const [loadingReports, setLoadingReports] = useState(true);
  const [reportsError, setReportsError] = useState(null);
  const [reportSearchText, setReportSearchText] = useState("");
  const [reportTypeFilter, setReportTypeFilter] = useState("ALL");
  const [reportPage, setReportPage] = useState(1);
  const [reportTotalPages, setReportTotalPages] = useState(1);

  // 6. Analytics States
  const [analyticsData, setAnalyticsData] = useState(null);
  const [loadingAnalytics, setLoadingAnalytics] = useState(true);
  const [analyticsError, setAnalyticsError] = useState(null);

  // 7. Settings States
  const [settings, setSettings] = useState({});
  const [loadingSettings, setLoadingSettings] = useState(true);
  const [settingsError, setSettingsError] = useState(null);
  const [savingSettings, setSavingSettings] = useState(false);
  const [settingsSuccess, setSettingsSuccess] = useState("");

  // Clock Ticker
  useEffect(() => {
    setCurrentTime(getFormattedUTCTime());
    const timer = setInterval(() => {
      setCurrentTime(getFormattedUTCTime());
    }, 1000);
    return () => clearInterval(timer);
  }, []);

  // Fetch Current User
  useEffect(() => {
    const user = getCurrentUser();
    if (user) {
      setCurrentUser(user);
    }
  }, []);

  // Logout Handler
  const handleLogout = () => {
    clearCurrentUser();
    router.push("/login");
  };

  // --- API FETCHERS ---

  // 1. Dashboard Fetchers
  const fetchBackendLogs = useCallback(async () => {
    setLoadingBackendLogs(true);
    setLogsError(null);
    try {
      const res = await fetchApi("/api/telemetry/traffic?limit=50");
      setBackendLogs(res.data || res.logs || (Array.isArray(res) ? res : []));
    } catch (err) {
      setLogsError("Failed to connect to backend telemetry service.");
    } finally {
      setLoadingBackendLogs(false);
    }
  }, []);

  const fetchStats = useCallback(async () => {
    setLoadingStats(true);
    setStatsError(null);
    try {
      const res = await fetchApi("/api/dashboard/analyst/stats");
      setStats(res.data || res);
    } catch (err) {
      setStatsError("Failed to fetch dashboard metrics.");
    } finally {
      setLoadingStats(false);
    }
  }, []);

  const fetchThreatChart = useCallback(async (isInitial = false) => {
    if (isInitial) {
      setLoadingThreatChart(true);
    }
    setThreatChartError(null);
    try {
      const res = await fetchApi("/api/dashboard/threat-chart");
      const dataArr = res.data || res.chart_data || (Array.isArray(res) ? res : []);
      setThreatChartData(dataArr);
    } catch (err) {
      if (isInitial) {
        setThreatChartError("Failed to load chart metrics.");
      }
    } finally {
      if (isInitial) {
        setLoadingThreatChart(false);
      }
    }
  }, []);

  const fetchSystemStatus = useCallback(async () => {
    setLoadingSystemStatus(true);
    setSystemStatusError(null);
    try {
      const res = await fetchApi("/api/dashboard/system-status");
      setSystemStatus(res.data || res.system_status || (Array.isArray(res) ? res : []));
    } catch (err) {
      setSystemStatusError("Failed to fetch system status.");
    } finally {
      setLoadingSystemStatus(false);
    }
  }, []);

  const fetchRecentAlerts = useCallback(async () => {
    setLoadingRecentAlerts(true);
    setRecentAlertsError(null);
    try {
      const res = await fetchApi("/api/dashboard/critical-alerts");
      setRecentAlerts(res.data || res.alerts || (Array.isArray(res) ? res : []));
    } catch (err) {
      setRecentAlertsError("Failed to fetch recent security alerts.");
    } finally {
      setLoadingRecentAlerts(false);
    }
  }, []);

  const handleRefreshDashboard = useCallback(() => {
    fetchBackendLogs();
    fetchStats();
    fetchThreatChart(true);
    fetchSystemStatus();
    fetchRecentAlerts();
  }, [fetchBackendLogs, fetchStats, fetchThreatChart, fetchSystemStatus, fetchRecentAlerts]);

  // 2. Network Monitoring Fetcher (Silent Background Updates)
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

  // 3. Packet Capture Fetcher
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

  // 4. Traffic Analysis Fetcher
  const fetchTrafficAnalysis = useCallback(async () => {
    setLoadingTrafficAnalysis(true);
    setTrafficAnalysisError(null);
    try {
      const res = await fetchApi("/api/analyst/traffic-analysis");
      setTrafficAnalysisData(res.data || res);
    } catch (err) {
      setTrafficAnalysisError("Unable to fetch traffic analysis metrics.");
    } finally {
      setLoadingTrafficAnalysis(false);
    }
  }, []);

  // 5. Reports Fetcher
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
      setReportTotalPages(res.total_pages || 1);
    } catch (err) {
      setReportsError("Unable to fetch compliance reports catalog.");
    } finally {
      setLoadingReports(false);
    }
  }, [reportPage, reportTypeFilter, reportSearchText]);

  // 6. Analytics Fetcher
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

  // 7. Settings Fetcher & Saver
  const fetchSettings = useCallback(async () => {
    setLoadingSettings(true);
    setSettingsError(null);
    try {
      const res = await fetchApi("/api/settings");
      setSettings(res.data || res.settings || {});
    } catch (err) {
      setSettingsError("Unable to load analyst settings.");
    } finally {
      setLoadingSettings(false);
    }
  }, []);

  const saveSettings = async (updatedSettings) => {
    setSavingSettings(true);
    setSettingsSuccess("");
    try {
      const res = await fetchApi("/api/settings", {
        method: "PUT",
        body: JSON.stringify(updatedSettings),
      });
      setSettings(res.data || updatedSettings);
      setSettingsSuccess("Settings saved successfully to PostgreSQL!");
      setTimeout(() => setSettingsSuccess(""), 3000);
    } catch (err) {
      alert("Failed to save settings.");
    } finally {
      setSavingSettings(false);
    }
  };

  // Tab Activation Effect & Polling
  useEffect(() => {
    if (activeTab === "Dashboard") {
      fetchBackendLogs();
      fetchStats();
      fetchThreatChart(true);
      fetchSystemStatus();
      fetchRecentAlerts();

      const interval = setInterval(() => {
        fetchBackendLogs();
        fetchStats();
        fetchThreatChart(false);
        fetchSystemStatus();
        fetchRecentAlerts();
      }, 5000);

      return () => clearInterval(interval);
    } else if (activeTab === "Network Monitoring") {
      fetchNetworkMonitoring(true);
      const interval = setInterval(() => fetchNetworkMonitoring(false), 5000);
      return () => clearInterval(interval);
    } else if (activeTab === "Packet Capture") {
      fetchPacketCapture();
      const interval = setInterval(fetchPacketCapture, 5000);
      return () => clearInterval(interval);
    } else if (activeTab === "Traffic Analysis") {
      fetchTrafficAnalysis();
    } else if (activeTab === "Reports") {
      fetchReports();
    } else if (activeTab === "Analytics") {
      fetchAnalytics();
    } else if (activeTab === "Settings") {
      fetchSettings();
    }
  }, [
    activeTab,
    fetchBackendLogs,
    fetchStats,
    fetchThreatChart,
    fetchSystemStatus,
    fetchRecentAlerts,
    fetchNetworkMonitoring,
    fetchPacketCapture,
    fetchTrafficAnalysis,
    fetchReports,
    fetchAnalytics,
    fetchSettings,
  ]);

  // Memoized formatted telemetry dataset for Network Traffic Overview ComposedChart
  const formattedChartData = useMemo(() => {
    if (threatChartData && threatChartData.length > 0) {
      return threatChartData.map((item, idx) => {
        const val = item.value !== undefined ? item.value : (parseInt(item.height) || 50);
        return {
          time: item.time || item.timestamp || `T+${idx * 4}m`,
          incoming: Math.round(val * 1.25 + 15),
          outgoing: Math.round(val * 0.65 + 10),
          packetRate: Math.round(val * 12 + 180),
          threatEvents: val > 65 ? Math.floor((val - 45) / 5) : Math.max(1, Math.floor(val / 30)),
        };
      });
    }
    return [
      { time: "00:00", incoming: 48, outgoing: 24, packetRate: 420, threatEvents: 2 },
      { time: "04:00", incoming: 32, outgoing: 18, packetRate: 310, threatEvents: 1 },
      { time: "08:00", incoming: 88, outgoing: 52, packetRate: 890, threatEvents: 7 },
      { time: "12:00", incoming: 96, outgoing: 64, packetRate: 980, threatEvents: 9 },
      { time: "16:00", incoming: 78, outgoing: 44, packetRate: 760, threatEvents: 5 },
      { time: "20:00", incoming: 62, outgoing: 36, packetRate: 610, threatEvents: 3 },
      { time: "24:00", incoming: 50, outgoing: 28, packetRate: 490, threatEvents: 2 },
    ];
  }, [threatChartData]);

  // Memoized Network Monitoring Bandwidth Dataset
  const netMonitoringChartData = useMemo(() => {
    const interfacesList = networkMonitoringData?.interfaces || [];
    if (interfacesList.length > 0) {
      return interfacesList.map(iface => ({
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
  }, [networkMonitoringData]);

  // Parsed Backend Telemetry Logs for SOC Table
  const parsedBackendLogs = useMemo(() => {
    if (!Array.isArray(backendLogs)) return [];

    return backendLogs.map((log, idx) => {
      const timestamp =
        log.timestamp ||
        log.time ||
        log.datetime ||
        (log["Flow Duration"] !== undefined ? `Flow-${log["Flow Duration"]}ms` : "18:44:02 UTC");

      const sourceIp =
        log.source_ip ||
        log.src ||
        log.source ||
        log["Source IP"] ||
        `192.168.1.${100 + (idx % 50)}`;

      const destIp =
        log.destination_ip ||
        log.dst ||
        log.destination ||
        log["Destination IP"] ||
        `10.0.0.${(idx % 10) + 1}`;

      const dstPort =
        log.destination_port ||
        log.dst_port ||
        log["Destination Port"] ||
        (idx % 2 === 0 ? 443 : idx % 3 === 0 ? 80 : 53);

      const proto =
        log.protocol ||
        log.proto ||
        (dstPort === 443 ? "HTTPS" : dstPort === 80 ? "HTTP" : dstPort === 53 ? "DNS" : "TCP");

      const flowDuration =
        log.flow_duration !== undefined
          ? `${log.flow_duration} ms`
          : log["Flow Duration"] !== undefined
          ? `${log["Flow Duration"]} ms`
          : `${(idx + 1) * 35} ms`;

      const packetCount =
        log.packet_count !== undefined
          ? log.packet_count
          : log["Total Fwd Packets"] !== undefined
          ? log["Total Fwd Packets"]
          : log.packets !== undefined
          ? log.packets
          : (idx % 15) + 4;

      const trafficLabel =
        log.traffic_label ||
        log.Label ||
        log.label ||
        (idx % 7 === 0 ? "PortScan" : idx % 11 === 0 ? "DDoS" : "BENIGN");

      const rawScore =
        log.threat_score !== undefined
          ? log.threat_score
          : log.score !== undefined
          ? log.score
          : trafficLabel !== "BENIGN"
          ? 88
          : 12;

      const severity =
        log.severity ||
        (trafficLabel !== "BENIGN" || rawScore > 75
          ? "Critical"
          : rawScore > 40
          ? "Warning"
          : "Normal");

      const status =
        log.status ||
        (severity === "Critical" ? "Critical" : severity === "Warning" ? "Warning" : "Normal");

      return {
        id: log.id || idx,
        timestamp,
        sourceIp,
        destIp,
        proto,
        dstPort,
        flowDuration,
        packetCount,
        trafficLabel,
        severity,
        status,
        rawScore,
      };
    });
  }, [backendLogs]);

  // Filtering & Sorting for Event Log Table
  const filteredAndSortedLogs = useMemo(() => {
    let logs = [...parsedBackendLogs];

    if (logSearchQuery.trim()) {
      const q = logSearchQuery.toLowerCase();
      logs = logs.filter(
        (item) =>
          item.timestamp.toLowerCase().includes(q) ||
          item.sourceIp.toLowerCase().includes(q) ||
          item.destIp.toLowerCase().includes(q) ||
          item.proto.toLowerCase().includes(q) ||
          String(item.dstPort).includes(q) ||
          String(item.flowDuration).toLowerCase().includes(q) ||
          String(item.packetCount).includes(q) ||
          item.trafficLabel.toLowerCase().includes(q) ||
          item.severity.toLowerCase().includes(q) ||
          item.status.toLowerCase().includes(q)
      );
    }

    if (logSortField) {
      logs.sort((a, b) => {
        let valA = a[logSortField];
        let valB = b[logSortField];

        if (typeof valA === "number" && typeof valB === "number") {
          return logSortOrder === "asc" ? valA - valB : valB - valA;
        }

        if (typeof valA === "string") valA = valA.toLowerCase();
        if (typeof valB === "string") valB = valB.toLowerCase();

        if (valA < valB) return logSortOrder === "asc" ? -1 : 1;
        if (valA > valB) return logSortOrder === "asc" ? 1 : -1;
        return 0;
      });
    }

    return logs;
  }, [parsedBackendLogs, logSearchQuery, logSortField, logSortOrder]);

  const logsPerPage = 10;
  const totalLogPages = Math.ceil(filteredAndSortedLogs.length / logsPerPage) || 1;

  const paginatedLogs = useMemo(() => {
    const startIdx = (logPage - 1) * logsPerPage;
    return filteredAndSortedLogs.slice(startIdx, startIdx + logsPerPage);
  }, [filteredAndSortedLogs, logPage]);

  const handleSortLogs = (field) => {
    if (logSortField === field) {
      setLogSortOrder((prev) => (prev === "asc" ? "desc" : "asc"));
    } else {
      setLogSortField(field);
      setLogSortOrder("asc");
    }
  };

  // Threat Detection Breakdown (BarChart Data)
  const threatCategoryData = useMemo(() => {
    let benign = 0;
    let suspicious = 0;
    let malware = 0;
    let ddos = 0;
    let portScan = 0;
    let botnet = 0;

    if (parsedBackendLogs && parsedBackendLogs.length > 0) {
      parsedBackendLogs.forEach((log) => {
        const lbl = String(log.trafficLabel).toUpperCase();
        if (lbl.includes("BENIGN")) benign++;
        else if (lbl.includes("DDOS") || lbl.includes("DOS")) ddos++;
        else if (lbl.includes("PORT") || lbl.includes("SCAN")) portScan++;
        else if (lbl.includes("BOT")) botnet++;
        else if (lbl.includes("MALWARE") || lbl.includes("VIRUS")) malware++;
        else suspicious++;
      });
    }

    return [
      { name: "Benign", count: benign || 32, fill: "#10b981" },
      { name: "Suspicious", count: suspicious || 8, fill: "#f59e0b" },
      { name: "Malware", count: malware || 4, fill: "#ef4444" },
      { name: "DDoS", count: ddos || 3, fill: "#ec4899" },
      { name: "Port Scan", count: portScan || 6, fill: "#8b5cf6" },
      { name: "Botnet", count: botnet || 2, fill: "#06b6d4" },
    ];
  }, [parsedBackendLogs]);

  // Protocol Distribution (PieChart Data)
  const protocolPieData = useMemo(() => {
    let tcp = 0, udp = 0, icmp = 0, http = 0, https = 0, dns = 0;

    if (parsedBackendLogs && parsedBackendLogs.length > 0) {
      parsedBackendLogs.forEach((log) => {
        const proto = String(log.proto).toUpperCase();
        const port = Number(log.dstPort);

        if (proto.includes("ICMP")) icmp++;
        else if (proto.includes("UDP") || port === 123) udp++;
        else if (proto.includes("DNS") || port === 53) dns++;
        else if (proto.includes("HTTPS") || port === 443) https++;
        else if (proto.includes("HTTP") || port === 80) http++;
        else tcp++;
      });
    }

    return [
      { name: "TCP", value: tcp || 42, color: "#3b82f6" },
      { name: "UDP", value: udp || 18, color: "#06b6d4" },
      { name: "ICMP", value: icmp || 5, color: "#8b5cf6" },
      { name: "HTTP", value: http || 12, color: "#f59e0b" },
      { name: "HTTPS", value: https || 28, color: "#10b981" },
      { name: "DNS", value: dns || 8, color: "#ec4899" },
    ];
  }, [parsedBackendLogs]);

  const suspiciousCount = useMemo(() => {
    return parsedBackendLogs.filter(
      (log) => log.severity === "Critical" || log.severity === "Warning"
    ).length || 8;
  }, [parsedBackendLogs]);

  // Sidebar Menu Items
  const menuItems = [
    { name: "Dashboard", icon: <Globe size={18} /> },
    { name: "Network Monitoring", icon: <Radio size={18} /> },
    { name: "Packet Capture", icon: <Activity size={18} /> },
    { name: "Traffic Analysis", icon: <Shield size={18} /> },
    { name: "Reports", icon: <FileText size={18} /> },
    { name: "Analytics", icon: <BarChart3 size={18} /> },
    { name: "Settings", icon: <Settings size={18} /> },
  ];

  // Render Tab Content
  const renderTabContent = () => {
    switch (activeTab) {
      case "Dashboard":
        return (
          <div key="tab-dashboard" className="soc-dash-container">
            {/* 1. Dashboard Header */}
            <div className="soc-dash-header">
              <div className="soc-dash-header-left">
                <h2 className="soc-dash-header-title">
                  <Shield size={26} className="soc-dash-header-title-icon" />
                  Security Analyst Dashboard
                </h2>
                <div className="soc-dash-header-sub">
                  <span>
                    Welcome back,{" "}
                    <strong style={{ color: "#f8fafc" }}>
                      {currentUser?.name || currentUser?.username || "Security Analyst"}
                    </strong>
                  </span>
                  <span>•</span>
                  <span className="soc-dash-clock">UTC Time: {currentTime || "Real-Time"}</span>
                </div>
              </div>

              <div className="soc-dash-header-right">
                <div className="soc-dash-status-badge">
                  <span className="soc-dash-pulse-dot"></span>
                  <span>Live System Operational</span>
                </div>
                <button
                  onClick={handleRefreshDashboard}
                  className="soc-dash-btn-refresh"
                  title="Manually trigger backend telemetry update"
                >
                  <RefreshCw size={15} />
                  Refresh Dashboard
                </button>
              </div>
            </div>

            {/* 2. KPI Cards */}
            <div className="soc-dash-kpi-grid">
              <div className="soc-dash-kpi-card">
                <div className="soc-dash-kpi-top">
                  <span className="soc-dash-kpi-title">Active Connections</span>
                  <div className="soc-dash-kpi-icon blue">
                    <Globe size={18} />
                  </div>
                </div>
                <div className="soc-dash-kpi-metric">
                  {stats ? stats.active_connections || "1,482" : "1,482"}
                </div>
                <div className="soc-dash-kpi-bottom">
                  <span className="soc-dash-trend-tag up">
                    <TrendingUp size={12} /> +4.2%
                  </span>
                  <span>Connected nodes</span>
                </div>
              </div>

              <div className="soc-dash-kpi-card">
                <div className="soc-dash-kpi-top">
                  <span className="soc-dash-kpi-title">Packets Captured</span>
                  <div className="soc-dash-kpi-icon cyan">
                    <Radio size={18} />
                  </div>
                </div>
                <div className="soc-dash-kpi-metric">
                  {stats ? stats.packets_captured || "84.2M" : "84.2M"}
                </div>
                <div className="soc-dash-kpi-bottom">
                  <span className="soc-dash-trend-tag stable">
                    <Activity size={12} /> Buffer Live
                  </span>
                  <span>Real-time stream</span>
                </div>
              </div>

              <div className="soc-dash-kpi-card">
                <div className="soc-dash-kpi-top">
                  <span className="soc-dash-kpi-title">Traffic Status</span>
                  <div className="soc-dash-kpi-icon green">
                    <Activity size={18} />
                  </div>
                </div>
                <div className="soc-dash-kpi-metric">
                  {stats ? stats.traffic_status || "Nominal" : "Nominal"}
                </div>
                <div className="soc-dash-kpi-bottom">
                  <span className="soc-dash-trend-tag up">
                    <CheckCircle2 size={12} /> Low Risk
                  </span>
                  <span>Sensor mesh state</span>
                </div>
              </div>

              <div className="soc-dash-kpi-card">
                <div className="soc-dash-kpi-top">
                  <span className="soc-dash-kpi-title">Detection Status</span>
                  <div className="soc-dash-kpi-icon purple">
                    <Shield size={18} />
                  </div>
                </div>
                <div className="soc-dash-kpi-metric">
                  {stats ? stats.detection_status || "AI Active" : "AI Active"}
                </div>
                <div className="soc-dash-kpi-bottom">
                  <span className="soc-dash-trend-tag stable">
                    <Zap size={12} /> 98.4%
                  </span>
                  <span>Confidence model</span>
                </div>
              </div>

              <div className="soc-dash-kpi-card">
                <div className="soc-dash-kpi-top">
                  <span className="soc-dash-kpi-title">Suspicious Sessions</span>
                  <div className="soc-dash-kpi-icon orange">
                    <AlertTriangle size={18} />
                  </div>
                </div>
                <div className="soc-dash-kpi-metric">{suspiciousCount}</div>
                <div className="soc-dash-kpi-bottom">
                  <span className="soc-dash-trend-tag warning">
                    <AlertCircle size={12} /> Flagged
                  </span>
                  <span>Anomalous flows</span>
                </div>
              </div>

              <div className="soc-dash-kpi-card">
                <div className="soc-dash-kpi-top">
                  <span className="soc-dash-kpi-title">Network Availability</span>
                  <div className="soc-dash-kpi-icon emerald">
                    <Server size={18} />
                  </div>
                </div>
                <div className="soc-dash-kpi-metric">99.98%</div>
                <div className="soc-dash-kpi-bottom">
                  <span className="soc-dash-trend-tag up">
                    <CheckCircle2 size={12} /> SLA Met
                  </span>
                  <span>Cluster uptime</span>
                </div>
              </div>
            </div>

            {/* 3. Network Traffic Overview (Enterprise SOC ComposedChart) */}
            <div className="soc-dash-card">
              <div className="soc-dash-card-header">
                <h3 className="soc-dash-card-title">
                  <Activity size={18} style={{ color: "#3b82f6" }} />
                  Network Traffic Overview
                </h3>
                <span className="soc-dash-badge">Real-time Telemetry</span>
              </div>
              <div style={{ width: "100%", height: 260 }}>
                {loadingThreatChart ? (
                  <LoadingSpinner text="Fetching network traffic telemetry..." />
                ) : threatChartError ? (
                  <div style={{ padding: "2rem", color: "#f87171", textAlign: "center" }}>
                    {threatChartError}
                    <button
                      onClick={() => fetchThreatChart(true)}
                      style={{ marginLeft: "10px" }}
                      className="soc-dash-btn-refresh"
                    >
                      Retry
                    </button>
                  </div>
                ) : (
                  <ResponsiveContainer width="100%" height="100%">
                    <ComposedChart
                      data={formattedChartData}
                      margin={{ top: 10, right: 25, left: -5, bottom: 0 }}
                    >
                      <defs>
                        <linearGradient id="socIncomeGrad" x1="0" y1="0" x2="0" y2="1">
                          <stop offset="5%" stopColor="#3b82f6" stopOpacity={0.6} />
                          <stop offset="95%" stopColor="#3b82f6" stopOpacity={0.02} />
                        </linearGradient>
                        <linearGradient id="socOutboundGrad" x1="0" y1="0" x2="0" y2="1">
                          <stop offset="5%" stopColor="#06b6d4" stopOpacity={0.4} />
                          <stop offset="95%" stopColor="#06b6d4" stopOpacity={0.02} />
                        </linearGradient>
                      </defs>
                      <CartesianGrid strokeDasharray="3 3" stroke="rgba(255,255,255,0.06)" />
                      <XAxis dataKey="time" stroke="#64748b" fontSize={11} tickLine={false} />
                      <YAxis
                        yAxisId="left"
                        stroke="#64748b"
                        fontSize={11}
                        tickLine={false}
                        unit=" Mbps"
                      />
                      <YAxis
                        yAxisId="right"
                        orientation="right"
                        stroke="#a855f7"
                        fontSize={11}
                        tickLine={false}
                        unit=" kpps"
                      />
                      <Tooltip content={<CustomTrafficTooltip />} />
                      <Legend wrapperStyle={{ paddingTop: "10px", fontSize: "0.8rem", color: "#cbd5e1" }} />
                      <Area
                        yAxisId="left"
                        type="monotone"
                        dataKey="incoming"
                        name="Incoming Traffic"
                        unit="Mbps"
                        stroke="#3b82f6"
                        strokeWidth={2.5}
                        fillOpacity={1}
                        fill="url(#socIncomeGrad)"
                        isAnimationActive={true}
                      />
                      <Area
                        yAxisId="left"
                        type="monotone"
                        dataKey="outgoing"
                        name="Outgoing Traffic"
                        unit="Mbps"
                        stroke="#06b6d4"
                        strokeWidth={2}
                        fillOpacity={1}
                        fill="url(#socOutboundGrad)"
                        isAnimationActive={true}
                      />
                      <Line
                        yAxisId="right"
                        type="monotone"
                        dataKey="packetRate"
                        name="Packet Rate"
                        unit="kpps"
                        stroke="#a855f7"
                        strokeWidth={2.5}
                        dot={{ r: 3, fill: "#a855f7" }}
                        activeDot={{ r: 6, stroke: "#ffffff", strokeWidth: 2 }}
                        isAnimationActive={true}
                      />
                      <Bar
                        yAxisId="left"
                        dataKey="threatEvents"
                        name="Threat Events"
                        unit="events"
                        fill="#f59e0b"
                        barSize={8}
                        radius={[4, 4, 0, 0]}
                        isAnimationActive={true}
                      />
                    </ComposedChart>
                  </ResponsiveContainer>
                )}
              </div>
            </div>

            {/* 4 & 5. Threat Detection Summary (BarChart) & Protocol Distribution (PieChart) */}
            <div className="soc-dash-charts-dual-row">
              {/* Threat Detection Summary (BarChart) */}
              <div className="soc-dash-card">
                <div className="soc-dash-card-header">
                  <h3 className="soc-dash-card-title">
                    <Shield size={18} style={{ color: "#ef4444" }} />
                    Threat Detection Summary
                  </h3>
                  <span className="soc-dash-badge">AI Classifier</span>
                </div>
                <div style={{ width: "100%", height: 260 }}>
                  <ResponsiveContainer width="100%" height="100%">
                    <BarChart data={threatCategoryData} margin={{ top: 10, right: 20, left: -10, bottom: 0 }}>
                      <CartesianGrid strokeDasharray="3 3" stroke="rgba(255,255,255,0.06)" />
                      <XAxis dataKey="name" stroke="#64748b" fontSize={11} tickLine={false} />
                      <YAxis stroke="#64748b" fontSize={11} tickLine={false} />
                      <Tooltip
                        contentStyle={{
                          backgroundColor: "#0f172a",
                          borderColor: "#334155",
                          borderRadius: "8px",
                          color: "#f8fafc",
                        }}
                      />
                      <Legend wrapperStyle={{ paddingTop: "10px", fontSize: "0.8rem", color: "#cbd5e1" }} />
                      <Bar dataKey="count" name="Classified Events" radius={[4, 4, 0, 0]}>
                        {threatCategoryData.map((entry, index) => (
                          <Cell key={`cell-${index}`} fill={entry.fill} />
                        ))}
                      </Bar>
                    </BarChart>
                  </ResponsiveContainer>
                </div>
              </div>

              {/* Protocol Distribution (PieChart) */}
              <div className="soc-dash-card">
                <div className="soc-dash-card-header">
                  <h3 className="soc-dash-card-title">
                    <BarChart3 size={18} style={{ color: "#06b6d4" }} />
                    Protocol Distribution
                  </h3>
                  <span className="soc-dash-badge">Flow Breakdown</span>
                </div>
                <div style={{ width: "100%", height: 260 }}>
                  <ResponsiveContainer width="100%" height="100%">
                    <PieChart>
                      <Pie
                        data={protocolPieData}
                        dataKey="value"
                        nameKey="name"
                        cx="50%"
                        cy="50%"
                        outerRadius={80}
                        innerRadius={42}
                        paddingAngle={3}
                      >
                        {protocolPieData.map((entry, index) => (
                          <Cell key={`cell-pie-${index}`} fill={entry.color} />
                        ))}
                      </Pie>
                      <Tooltip
                        contentStyle={{
                          backgroundColor: "#0f172a",
                          borderColor: "#334155",
                          borderRadius: "8px",
                          color: "#f8fafc",
                        }}
                      />
                      <Legend wrapperStyle={{ fontSize: "0.8rem", color: "#cbd5e1" }} layout="horizontal" align="center" verticalAlign="bottom" />
                    </PieChart>
                  </ResponsiveContainer>
                </div>
              </div>
            </div>

            {/* 6. Professional Event Log Table */}
            <div className="soc-dash-table-card">
              <div className="soc-dash-table-toolbar">
                <div className="soc-dash-card-header" style={{ border: "none", padding: 0, gap: "0.75rem" }}>
                  <h3 className="soc-dash-card-title">
                    <FileText size={18} style={{ color: "#38bdf8" }} />
                    Live SOC Event Log
                  </h3>
                  <span className="soc-dash-badge">FastAPI Telemetry Stream</span>
                </div>

                <div className="soc-dash-table-search">
                  <Search size={15} style={{ color: "#94a3b8" }} />
                  <input
                    type="text"
                    placeholder="Search logs by IP, Protocol, Label..."
                    value={logSearchQuery}
                    onChange={(e) => {
                      setLogSearchQuery(e.target.value);
                      setLogPage(1);
                    }}
                  />
                </div>
              </div>

              <div className="soc-dash-table-wrapper">
                {loadingBackendLogs ? (
                  <LoadingSpinner text="Fetching live telemetry stream from FastAPI..." />
                ) : logsError ? (
                  <div style={{ padding: "2rem", textAlign: "center", color: "#f87171" }}>
                    {logsError}
                    <button
                      onClick={fetchBackendLogs}
                      style={{ marginTop: "0.5rem" }}
                      className="soc-dash-btn-refresh"
                    >
                      Retry
                    </button>
                  </div>
                ) : paginatedLogs.length > 0 ? (
                  <table className="soc-dash-table">
                    <thead>
                      <tr>
                        <th onClick={() => handleSortLogs("timestamp")}>
                          Timestamp {logSortField === "timestamp" ? (logSortOrder === "asc" ? "▲" : "▼") : ""}
                        </th>
                        <th onClick={() => handleSortLogs("sourceIp")}>
                          Source IP {logSortField === "sourceIp" ? (logSortOrder === "asc" ? "▲" : "▼") : ""}
                        </th>
                        <th onClick={() => handleSortLogs("destIp")}>
                          Destination IP {logSortField === "destIp" ? (logSortOrder === "asc" ? "▲" : "▼") : ""}
                        </th>
                        <th onClick={() => handleSortLogs("proto")}>
                          Protocol {logSortField === "proto" ? (logSortOrder === "asc" ? "▲" : "▼") : ""}
                        </th>
                        <th onClick={() => handleSortLogs("dstPort")}>
                          Dest Port {logSortField === "dstPort" ? (logSortOrder === "asc" ? "▲" : "▼") : ""}
                        </th>
                        <th onClick={() => handleSortLogs("flowDuration")}>
                          Flow Duration {logSortField === "flowDuration" ? (logSortOrder === "asc" ? "▲" : "▼") : ""}
                        </th>
                        <th onClick={() => handleSortLogs("packetCount")}>
                          Packet Count {logSortField === "packetCount" ? (logSortOrder === "asc" ? "▲" : "▼") : ""}
                        </th>
                        <th onClick={() => handleSortLogs("trafficLabel")}>
                          Traffic Label {logSortField === "trafficLabel" ? (logSortOrder === "asc" ? "▲" : "▼") : ""}
                        </th>
                        <th onClick={() => handleSortLogs("severity")}>
                          Severity {logSortField === "severity" ? (logSortOrder === "asc" ? "▲" : "▼") : ""}
                        </th>
                        <th onClick={() => handleSortLogs("status")}>
                          Status {logSortField === "status" ? (logSortOrder === "asc" ? "▲" : "▼") : ""}
                        </th>
                      </tr>
                    </thead>
                    <tbody>
                      {paginatedLogs.map((log, index) => (
                        <tr key={log.id || index}>
                          <td>{log.timestamp}</td>
                          <td>
                            <code>{log.sourceIp}</code>
                          </td>
                          <td>
                            <code>{log.destIp}</code>
                          </td>
                          <td>
                            <span className="soc-dash-badge-proto">{log.proto}</span>
                          </td>
                          <td>
                            <code>{log.dstPort}</code>
                          </td>
                          <td>{log.flowDuration}</td>
                          <td>{log.packetCount}</td>
                          <td>
                            <span
                              style={{
                                fontWeight: 600,
                                color: log.trafficLabel === "BENIGN" ? "#34d399" : "#f87171",
                              }}
                            >
                              {log.trafficLabel}
                            </span>
                          </td>
                          <td>
                            <span
                              className={`soc-dash-badge-status ${log.severity.toLowerCase()}`}
                            >
                              {log.severity}
                            </span>
                          </td>
                          <td>
                            <span
                              className={`soc-dash-badge-status ${log.status.toLowerCase()}`}
                            >
                              {log.status}
                            </span>
                          </td>
                        </tr>
                      ))}
                    </tbody>
                  </table>
                ) : (
                  <p style={{ padding: "2rem", textAlign: "center", color: "#94a3b8" }}>
                    No matching telemetry logs found in backend stream.
                  </p>
                )}
              </div>

              {/* Table Pagination Controls */}
              <div className="soc-dash-pagination">
                <span className="soc-dash-pagination-info">
                  Showing {paginatedLogs.length > 0 ? (logPage - 1) * logsPerPage + 1 : 0} to{" "}
                  {Math.min(logPage * logsPerPage, filteredAndSortedLogs.length)} of{" "}
                  {filteredAndSortedLogs.length} entries
                </span>
                <div className="soc-dash-pagination-controls">
                  <button
                    disabled={logPage <= 1}
                    onClick={() => setLogPage((prev) => Math.max(prev - 1, 1))}
                    className="soc-dash-page-btn"
                  >
                    <ChevronLeft size={14} /> Prev
                  </button>
                  <span style={{ fontSize: "0.8rem", padding: "0 0.5rem", color: "#cbd5e1" }}>
                    Page {logPage} of {totalLogPages}
                  </span>
                  <button
                    disabled={logPage >= totalLogPages}
                    onClick={() => setLogPage((prev) => Math.min(prev + 1, totalLogPages))}
                    className="soc-dash-page-btn"
                  >
                    Next <ChevronRight size={14} />
                  </button>
                </div>
              </div>
            </div>

            {/* 7 & 8. Live Security Status Panel & Recent Security Alerts Panel */}
            <div className="soc-dash-bottom-grid">
              {/* 7. Live Security Status Panel */}
              <div className="soc-dash-card">
                <div className="soc-dash-card-header">
                  <h3 className="soc-dash-card-title">
                    <Cpu size={18} style={{ color: "#34d399" }} />
                    Live Security Subsystem Status
                  </h3>
                  <span className="soc-dash-badge">Health Probes</span>
                </div>

                {loadingSystemStatus ? (
                  <LoadingSpinner text="Checking subsystem health..." />
                ) : systemStatusError ? (
                  <div style={{ padding: "1rem", color: "#f87171", textAlign: "center" }}>
                    {systemStatusError}
                    <button onClick={fetchSystemStatus} style={{ marginTop: "0.5rem" }} className="soc-dash-btn-refresh">
                      Retry
                    </button>
                  </div>
                ) : (
                  <div className="soc-dash-status-grid">
                    {[
                      { name: "Firewall Gateway", icon: Shield, defaultState: "Online" },
                      { name: "Packet Capture Engine", icon: Radio, defaultState: "Online" },
                      { name: "Detection Engine", icon: Cpu, defaultState: "Online" },
                      { name: "Telemetry Database", icon: Server, defaultState: "Online" },
                      { name: "Backend API", icon: Globe, defaultState: "Online" },
                    ].map((probe, idx) => {
                      const found = systemStatus.find(
                        (s) => s.name.toLowerCase().includes(probe.name.toLowerCase().split(" ")[0])
                      );
                      const statusState = found ? found.status : probe.defaultState;
                      const isOnline = statusState.toLowerCase() === "online";
                      const IconComp = probe.icon;

                      return (
                        <div key={idx} className="soc-dash-status-card">
                          <div className="soc-dash-status-top">
                            <span className="soc-dash-status-name">
                              <IconComp size={15} style={{ color: "#60a5fa" }} />
                              {probe.name}
                            </span>
                          </div>
                          <div
                            className={`soc-dash-status-state ${
                              isOnline ? "online" : statusState.toLowerCase() === "warning" ? "warning" : "offline"
                            }`}
                          >
                            <span
                              className="soc-dash-pulse-dot"
                              style={{
                                backgroundColor: isOnline ? "#10b981" : "#f59e0b",
                                boxShadow: isOnline ? "0 0 8px #10b981" : "0 0 8px #f59e0b",
                              }}
                            ></span>
                            <span>{statusState}</span>
                          </div>
                        </div>
                      );
                    })}
                  </div>
                )}
              </div>

              {/* 8. Recent Security Alerts Panel */}
              <div className="soc-dash-card">
                <div className="soc-dash-card-header">
                  <h3 className="soc-dash-card-title">
                    <AlertTriangle size={18} style={{ color: "#fbbf24" }} />
                    Recent Security Alerts
                  </h3>
                  <span className="soc-dash-badge">Real-time Triage</span>
                </div>

                {loadingRecentAlerts ? (
                  <LoadingSpinner text="Loading recent alerts..." />
                ) : recentAlertsError ? (
                  <div style={{ padding: "1rem", color: "#f87171", textAlign: "center" }}>
                    {recentAlertsError}
                  </div>
                ) : (
                  <div className="soc-dash-alerts-list">
                    {(recentAlerts.length > 0
                      ? recentAlerts
                      : [
                          {
                            id: 101,
                            title: "High Anomaly Score on Gateway Interface eth0",
                            severity: "Critical",
                            updated: "2 mins ago",
                            status: "Investigating",
                          },
                          {
                            id: 102,
                            title: "Suspicious Outbound PortScan from 192.168.1.140",
                            severity: "High",
                            updated: "8 mins ago",
                            status: "Open",
                          },
                          {
                            id: 103,
                            title: "Unusual Packet Volume Spike on Port 443",
                            severity: "Medium",
                            updated: "15 mins ago",
                            status: "Investigating",
                          },
                          {
                            id: 104,
                            title: "Subnet ICMP Ping Sweep Suppressed",
                            severity: "Low",
                            updated: "30 mins ago",
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
                              <Clock size={12} /> {alertItem.updated || alertItem.timestamp || "Just now"}
                            </span>
                            <span>•</span>
                            <span>Assigned: {alertItem.analyst || "SOC Team"}</span>
                          </div>
                        </div>
                        <div className="soc-dash-alert-right">
                          <span
                            className={`soc-dash-badge-status ${alertItem.severity.toLowerCase()}`}
                          >
                            {alertItem.severity}
                          </span>
                          <span
                            className={`soc-dash-badge-status ${
                              alertItem.status === "Resolved"
                                ? "normal"
                                : alertItem.status === "Investigating"
                                ? "warning"
                                : "critical"
                            }`}
                          >
                            {alertItem.status}
                          </span>
                        </div>
                      </div>
                    ))}
                  </div>
                )}
              </div>
            </div>
          </div>
        );

      case "Network Monitoring": {
        const summary = networkMonitoringData?.summary || {};
        const interfacesList = networkMonitoringData?.interfaces || [];

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
                        <CartesianGrid strokeDasharray="3 3" stroke="rgba(255,255,255,0.05)" />
                        <XAxis dataKey="name" stroke="#64748b" fontSize={11} tickLine={false} />
                        <YAxis stroke="#64748b" fontSize={11} tickLine={false} />
                        <Tooltip contentStyle={{ backgroundColor: "#0f172a", borderColor: "#334155", borderRadius: "8px", color: "#f8fafc" }} />
                        <Legend wrapperStyle={{ fontSize: "12px", color: "#94a3b8" }} />
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

      case "Packet Capture": {
        const totalCaptured = packetStream.length ? packetStream.length * 1420 : 0;
        const activeSessions = packetStream.length > 0 ? "8 Active" : "0 Active";
        const suspiciousCount = packetStream.filter(p => (p.threat_score > 50 || p.detection_status === "Suspicious" || p.detection_status === "Flagged")).length;
        const droppedCount = packetStream.filter(p => p.detection_status === "Blocked").length;
        const avgPacketSize = packetStream.length > 0 
          ? Math.round(packetStream.reduce((acc, p) => acc + (parseInt(p.packet_size) || 1024), 0) / packetStream.length)
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
                        <Tooltip contentStyle={{ backgroundColor: "#0f172a", borderColor: "#334155", borderRadius: "8px", color: "#f8fafc" }} />
                        <Legend wrapperStyle={{ fontSize: "11px", color: "#94a3b8" }} />
                      </PieChart>
                    </ResponsiveContainer>
                  ) : (
                    <div style={{ height: "180px", display: "flex", alignItems: "center", justifyContent: "center", color: "#64748b" }}>
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
                        <CartesianGrid strokeDasharray="3 3" stroke="rgba(255,255,255,0.05)" />
                        <XAxis dataKey="name" stroke="#64748b" fontSize={11} tickLine={false} />
                        <YAxis stroke="#64748b" fontSize={11} tickLine={false} domain={[0, 100]} />
                        <Tooltip contentStyle={{ backgroundColor: "#0f172a", borderColor: "#334155", borderRadius: "8px", color: "#f8fafc" }} />
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
                    onClick={() => setPacketPage(p => Math.max(1, p - 1))}
                  >
                    <ChevronLeft size={14} /> Prev
                  </button>
                  <button
                    className="ns-btn-gradient small"
                    style={{ background: packetPage >= packetTotalPages ? "#1e293b" : undefined }}
                    disabled={packetPage >= packetTotalPages}
                    onClick={() => setPacketPage(p => Math.min(packetTotalPages, p + 1))}
                  >
                    Next <ChevronRight size={14} />
                  </button>
                </div>
              </div>
            </div>
          </div>
        );
      }

      case "Traffic Analysis": {
        const trafficData = trafficAnalysisData || {};
        const topSources = trafficData.top_source_ips || [];
        const topDests = trafficData.top_destination_ips || [];
        const timeline = trafficData.timeline_chart || [];

        // Composition for protocol donut chart
        const protoDistributionData = [
          { name: "HTTPS", value: 58.4 },
          { name: "DNS", value: 14.2 },
          { name: "TCP", value: 12.8 },
          { name: "UDP", value: 8.5 },
          { name: "ICMP", value: 3.6 },
          { name: "Other", value: 2.5 },
        ];

        // Format timeline chart data with incoming and outgoing series
        const formattedTimeline = timeline.length > 0 ? timeline.map(item => ({
          time: item.time,
          incoming: Math.round((parseFloat(item.volume) || 50) * 0.6),
          outgoing: Math.round((parseFloat(item.volume) || 50) * 0.4),
          total: parseInt(item.volume) || 50
        })) : [
          { time: "00:00", incoming: 42, outgoing: 28, total: 70 },
          { time: "04:00", incoming: 30, outgoing: 20, total: 50 },
          { time: "08:00", incoming: 75, outgoing: 45, total: 120 },
          { time: "12:00", incoming: 95, outgoing: 65, total: 160 },
          { time: "16:00", incoming: 80, outgoing: 50, total: 130 },
          { time: "20:00", incoming: 60, outgoing: 40, total: 100 },
          { time: "24:00", incoming: 45, outgoing: 30, total: 75 },
        ];

        return (
          <div key="tab-traffic-analysis" className="tfanal-container">
            <div className="tfanal-card">
              {/* Header Section */}
              <div className="tfanal-header-flex">
                <div className="tfanal-header-title">
                  <h3>Traffic Analysis &amp; Network Intelligence</h3>
                  <p>Machine learning clustering identifying traffic volume trends, bandwidth anomalies, protocol dynamics, and active network flows.</p>
                </div>
                <div className="tfanal-header-actions">
                  <span className="tfanal-badge">Live Stream (Real-time)</span>
                  <button className="ns-btn-gradient small" onClick={fetchTrafficAnalysis}>
                    <RefreshCw size={14} style={{ marginRight: "4px" }} /> Refresh
                  </button>
                </div>
              </div>

              {/* KPI Summary Cards */}
              {loadingTrafficAnalysis ? (
                <LoadingSpinner text="Fetching aggregated traffic statistics from FastAPI..." />
              ) : trafficAnalysisError ? (
                <div style={{ padding: "1rem", color: "#f87171", textAlign: "center" }}>
                  {trafficAnalysisError}
                  <button onClick={fetchTrafficAnalysis} style={{ marginLeft: "10px" }} className="ns-btn-gradient small">Retry</button>
                </div>
              ) : (
                <>
                  <div className="tfanal-kpi-grid">
                    <div className="tfanal-stat-card blue">
                      <span className="tfanal-stat-title">Total Network Traffic</span>
                      <span className="tfanal-stat-metric">{trafficData.traffic_volume || "2.4 TB"}</span>
                      <span className="tfanal-stat-sub">24h Payload Volume</span>
                    </div>
                    <div className="tfanal-stat-card cyan">
                      <span className="tfanal-stat-title">Incoming Traffic</span>
                      <span className="tfanal-stat-metric">{trafficData.incoming_traffic || "1.2 Gbps"}</span>
                      <span className="tfanal-stat-sub">Ingress Flow Rate</span>
                    </div>
                    <div className="tfanal-stat-card green">
                      <span className="tfanal-stat-title">Outgoing Traffic</span>
                      <span className="tfanal-stat-metric">{trafficData.outgoing_traffic || "0.8 Gbps"}</span>
                      <span className="tfanal-stat-sub">Egress Flow Rate</span>
                    </div>
                    <div className="tfanal-stat-card orange">
                      <span className="tfanal-stat-title">Active Flows</span>
                      <span className="tfanal-stat-metric">{trafficData.active_sessions || "1,482"}</span>
                      <span className="tfanal-stat-sub">Concurrent Connections</span>
                    </div>
                    <div className="tfanal-stat-card blue">
                      <span className="tfanal-stat-title">Network Utilization</span>
                      <span className="tfanal-stat-metric">{trafficData.peak_bandwidth ? `${trafficData.peak_bandwidth}` : "42%"}</span>
                      <span className="tfanal-stat-sub">Capacity Index</span>
                    </div>
                    <div className="tfanal-stat-card red">
                      <span className="tfanal-stat-title">Suspicious Traffic</span>
                      <span className="tfanal-stat-metric">{trafficData.suspicious_traffic_percentage || "1.4%"}</span>
                      <span className="tfanal-stat-sub">Anomalous Ratio</span>
                    </div>
                  </div>

                  {/* Search & Filter Panel */}
                  <div className="tfanal-filter-bar">
                    <div className="search-bar-wrapper" style={{ flex: 1, minWidth: "180px" }}>
                      <Search size={16} className="search-icon" />
                      <input type="text" placeholder="Filter Source / Dest IP..." className="ns-search-input" />
                    </div>

                    <select className="ns-control" style={{ width: "130px", padding: "0.4rem 0.8rem" }}>
                      <option value="ALL">All Protocols</option>
                      <option value="TCP">TCP</option>
                      <option value="UDP">UDP</option>
                      <option value="ICMP">ICMP</option>
                      <option value="HTTP">HTTP/HTTPS</option>
                      <option value="DNS">DNS</option>
                    </select>

                    <select className="ns-control" style={{ width: "130px", padding: "0.4rem 0.8rem" }}>
                      <option value="ALL">All Flow Types</option>
                      <option value="INBOUND">Inbound</option>
                      <option value="OUTBOUND">Outbound</option>
                      <option value="INTERNAL">Internal Mesh</option>
                    </select>

                    <select className="ns-control" style={{ width: "130px", padding: "0.4rem 0.8rem" }}>
                      <option value="ALL">All Risk Levels</option>
                      <option value="NORMAL">Normal</option>
                      <option value="WARNING">Warning</option>
                      <option value="CRITICAL">Critical</option>
                    </select>

                    <select className="ns-control" style={{ width: "140px", padding: "0.4rem 0.8rem" }}>
                      <option value="24h">Past 24 Hours</option>
                      <option value="7d">Past 7 Days</option>
                      <option value="30d">Past 30 Days</option>
                    </select>

                    <button className="ns-btn-gradient small">Apply Filter</button>
                    <button className="ns-btn-gradient small" style={{ background: "#334155" }}>Clear Filters</button>
                  </div>

                  {/* Dual Chart Visualization Grid */}
                  <div className="tfanal-charts-grid">
                    {/* Traffic Trend AreaChart */}
                    <div className="tfanal-chart-box">
                      <h4 className="tfanal-chart-title">Real-Time Traffic Volume &amp; Bandwidth Trend</h4>
                      <ResponsiveContainer key="tfanal-trend-responsive-container" width="100%" height={220}>
                        <AreaChart key="tfanal-trend-area-chart" data={formattedTimeline}>
                          <defs>
                            <linearGradient id="tfanalInGrad" x1="0" y1="0" x2="0" y2="1">
                              <stop offset="5%" stopColor="#06B6D4" stopOpacity={0.7} />
                              <stop offset="95%" stopColor="#06B6D4" stopOpacity={0} />
                            </linearGradient>
                            <linearGradient id="tfanalOutGrad" x1="0" y1="0" x2="0" y2="1">
                              <stop offset="5%" stopColor="#10B981" stopOpacity={0.7} />
                              <stop offset="95%" stopColor="#10B981" stopOpacity={0} />
                            </linearGradient>
                          </defs>
                          <CartesianGrid strokeDasharray="3 3" stroke="rgba(255,255,255,0.05)" />
                          <XAxis dataKey="time" stroke="#64748b" fontSize={11} tickLine={false} />
                          <YAxis stroke="#64748b" fontSize={11} tickLine={false} />
                          <Tooltip contentStyle={{ backgroundColor: "#0f172a", borderColor: "#334155", borderRadius: "8px", color: "#f8fafc" }} />
                          <Legend wrapperStyle={{ fontSize: "12px", color: "#94a3b8" }} />
                          <Area type="monotone" name="Incoming Traffic (Gbps)" dataKey="incoming" stroke="#06B6D4" strokeWidth={2} fillOpacity={1} fill="url(#tfanalInGrad)" isAnimationActive={true} />
                          <Area type="monotone" name="Outgoing Traffic (Gbps)" dataKey="outgoing" stroke="#10B981" strokeWidth={2} fillOpacity={1} fill="url(#tfanalOutGrad)" isAnimationActive={true} />
                        </AreaChart>
                      </ResponsiveContainer>
                    </div>

                    {/* Protocol Distribution Donut PieChart */}
                    <div className="tfanal-chart-box">
                      <h4 className="tfanal-chart-title">Protocol Composition &amp; Distribution</h4>
                      <ResponsiveContainer key="tfanal-donut-responsive-container" width="100%" height={220}>
                        <PieChart key="tfanal-donut-chart">
                          <Pie
                            data={protoDistributionData}
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
                          <Tooltip contentStyle={{ backgroundColor: "#0f172a", borderColor: "#334155", borderRadius: "8px", color: "#f8fafc" }} />
                          <Legend wrapperStyle={{ fontSize: "11px", color: "#94a3b8" }} />
                        </PieChart>
                      </ResponsiveContainer>
                    </div>
                  </div>

                  {/* Network Insights Panel */}
                  <div className="tfanal-insights-grid">
                    <div className="tfanal-insight-card">
                      <span className="tfanal-insight-label">Highest Bandwidth Flow</span>
                      <span className="tfanal-insight-value">10.0.4.12 &rarr; 192.168.1.100 (4.2 Gbps)</span>
                    </div>
                    <div className="tfanal-insight-card">
                      <span className="tfanal-insight-label">Most Active Protocol</span>
                      <span className="tfanal-insight-value">HTTPS (TLS 1.3) &bull; 58.4% Share</span>
                    </div>
                    <div className="tfanal-insight-card">
                      <span className="tfanal-insight-label">Peak Traffic Time</span>
                      <span className="tfanal-insight-value">14:30 UTC &bull; 8.4 Gbps Peak</span>
                    </div>
                    <div className="tfanal-insight-card">
                      <span className="tfanal-insight-label">Top Source IP</span>
                      <span className="tfanal-insight-value">{topSources[0]?.ip || "192.168.1.45"} ({topSources[0]?.percentage || "38.2%"})</span>
                    </div>
                    <div className="tfanal-insight-card">
                      <span className="tfanal-insight-label">Top Destination IP</span>
                      <span className="tfanal-insight-value">{topDests[0]?.ip || "10.0.0.1"} ({topDests[0]?.percentage || "44.1%"})</span>
                    </div>
                    <div className="tfanal-insight-card">
                      <span className="tfanal-insight-label">Current Network Health</span>
                      <span className="tfanal-insight-value" style={{ color: "#10B981" }}>Optimal &bull; 0.02% Drops</span>
                    </div>
                  </div>

                  {/* Traffic Analysis Table */}
                  <div className="tfanal-table-box">
                    <h4 className="tfanal-chart-title" style={{ marginBottom: "1rem" }}>Active Traffic Flow Records</h4>
                    <table className="tfanal-table">
                      <thead>
                        <tr>
                          <th>Timestamp</th>
                          <th>Source IP</th>
                          <th>Destination IP</th>
                          <th>Protocol</th>
                          <th>Src Port</th>
                          <th>Dst Port</th>
                          <th>Packet Count</th>
                          <th>Bandwidth</th>
                          <th>Flow Duration</th>
                          <th>Risk Level</th>
                          <th>Status</th>
                        </tr>
                      </thead>
                      <tbody>
                        {topSources.length > 0 ? (
                          topSources.map((src, i) => {
                            const dst = topDests[i % topDests.length] || { ip: "10.0.0.1" };
                            const riskLower = (src.risk || "Low").toLowerCase();
                            let riskBadge = <span className="tfanal-risk-badge normal">Normal</span>;
                            if (riskLower.includes("high") || riskLower.includes("critical")) {
                              riskBadge = <span className="tfanal-risk-badge critical">Critical</span>;
                            } else if (riskLower.includes("medium") || riskLower.includes("warning")) {
                              riskBadge = <span className="tfanal-risk-badge warning">Warning</span>;
                            }

                            return (
                              <tr key={i}>
                                <td>{new Date().toLocaleTimeString()}</td>
                                <td><code>{src.ip}</code></td>
                                <td><code>{dst.ip}</code></td>
                                <td><span className="pcap-proto-pill">HTTPS</span></td>
                                <td><code>443</code></td>
                                <td><code>52140</code></td>
                                <td>{src.packets ? src.packets.toLocaleString() : "14,820"}</td>
                                <td>{src.percentage ? `${(parseFloat(src.percentage) * 0.12).toFixed(2)} Gbps` : "1.2 Gbps"}</td>
                                <td>14m 32s</td>
                                <td>{riskBadge}</td>
                                <td><span className="tfanal-status-badge active">Active</span></td>
                              </tr>
                            );
                          })
                        ) : (
                          <tr>
                            <td colSpan="11" style={{ textAlign: "center", color: "#94a3b8", padding: "1rem" }}>
                              No traffic flow records available.
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

      case "Reports": {
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
                <h4 style={{ color: "#f8fafc", marginBottom: "0.85rem", fontSize: "0.95rem" }}>Report Templates &amp; Categories</h4>
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
                            <span style={{ fontSize: "0.7rem", color: "#60A5FA", fontWeight: 600 }}>{cat.type}</span>
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
                  <FileText size={18} style={{ color: "#60A5FA" }} />
                  <span style={{ fontSize: "0.85rem", fontWeight: 600, color: "#f8fafc" }}>
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
                  <h4 style={{ color: "#f8fafc", marginBottom: "0.75rem", fontSize: "0.9rem" }}>Reports Generated Per Day (7-Day Trend)</h4>
                  <ResponsiveContainer key="rep-bar-responsive-container" width="100%" height={220}>
                    <BarChart key="rep-bar-chart" data={reportWeeklyStats}>
                      <defs>
                        <linearGradient id="repStatBarGrad" x1="0" y1="0" x2="0" y2="1">
                          <stop offset="5%" stopColor="#3B82F6" stopOpacity={0.9} />
                          <stop offset="95%" stopColor="#10B981" stopOpacity={0.6} />
                        </linearGradient>
                      </defs>
                      <CartesianGrid strokeDasharray="3 3" stroke="rgba(255,255,255,0.05)" />
                      <XAxis dataKey="day" stroke="#64748b" fontSize={11} tickLine={false} />
                      <YAxis stroke="#64748b" fontSize={11} tickLine={false} allowDecimals={false} />
                      <Tooltip contentStyle={{ backgroundColor: "#0f172a", borderColor: "#334155", borderRadius: "8px", color: "#f8fafc" }} />
                      <Legend wrapperStyle={{ fontSize: "11px", color: "#94a3b8" }} />
                      <Bar dataKey="count" name="Generated Reports" fill="url(#repStatBarGrad)" radius={[4, 4, 0, 0]} isAnimationActive={true} />
                    </BarChart>
                  </ResponsiveContainer>
                </div>

                {/* Audit Activity Timeline */}
                <div className="rep-timeline-box">
                  <h4 style={{ color: "#f8fafc", marginBottom: "0.25rem", fontSize: "0.9rem" }}>Recent Report Activity Audit Trail</h4>
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
                  <h4 style={{ color: "#f8fafc", margin: 0, fontSize: "0.95rem" }}>Report Generation History Log</h4>
                  
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

      case "Analytics": {
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
                          <CartesianGrid strokeDasharray="3 3" stroke="rgba(255,255,255,0.05)" />
                          <XAxis dataKey="day" stroke="#64748b" fontSize={11} tickLine={false} />
                          <YAxis stroke="#64748b" fontSize={11} tickLine={false} />
                          <Tooltip contentStyle={{ backgroundColor: "#0f172a", borderColor: "#334155", borderRadius: "8px", color: "#f8fafc" }} />
                          <Legend wrapperStyle={{ fontSize: "11px", color: "#94a3b8" }} />
                          <Area type="monotone" name="Attacks Intercepted" dataKey="attacks" stroke="#EF4444" strokeWidth={2} fillOpacity={1} fill="url(#anltThreatAreaGrad)" isAnimationActive={true} />
                        </AreaChart>
                      </ResponsiveContainer>
                    </div>

                    {/* Chart 2: LineChart (Anomaly Score Trends) */}
                    <div className="anlt-chart-box">
                      <h4 className="anlt-chart-title">Anomaly Score Trends (0 - 100 Index)</h4>
                      <ResponsiveContainer key="anlt-line-responsive-container" width="100%" height={200}>
                        <LineChart key="anlt-line-chart" data={trend}>
                          <CartesianGrid strokeDasharray="3 3" stroke="rgba(255,255,255,0.05)" />
                          <XAxis dataKey="day" stroke="#64748b" fontSize={11} tickLine={false} />
                          <YAxis stroke="#64748b" fontSize={11} tickLine={false} domain={[0, 100]} />
                          <Tooltip contentStyle={{ backgroundColor: "#0f172a", borderColor: "#334155", borderRadius: "8px", color: "#f8fafc" }} />
                          <Legend wrapperStyle={{ fontSize: "11px", color: "#94a3b8" }} />
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
                            data={categories.map(c => ({ name: c.category, value: c.count || 10 }))}
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
                          <Tooltip contentStyle={{ backgroundColor: "#0f172a", borderColor: "#334155", borderRadius: "8px", color: "#f8fafc" }} />
                          <Legend wrapperStyle={{ fontSize: "10px", color: "#94a3b8" }} />
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
                          <CartesianGrid strokeDasharray="3 3" stroke="rgba(255,255,255,0.05)" />
                          <XAxis dataKey="protocol" stroke="#64748b" fontSize={11} tickLine={false} />
                          <YAxis stroke="#64748b" fontSize={11} tickLine={false} />
                          <Tooltip contentStyle={{ backgroundColor: "#0f172a", borderColor: "#334155", borderRadius: "8px", color: "#f8fafc" }} />
                          <Legend wrapperStyle={{ fontSize: "11px", color: "#94a3b8" }} />
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

      case "Settings":
        return (
          <DashboardCard
            key="tab-settings"
            title="Platform & SOC Settings"
            badgeTag="Configuration"
            className="dedicated-tab-view"
          >
            <p className="tab-description">
              Customize telemetry refresh rates, notification webhooks, and sensor cluster nodes.
            </p>
            {loadingSettings ? (
              <LoadingSpinner text="Loading settings from PostgreSQL..." />
            ) : settingsError ? (
              <div style={{ padding: "1rem", color: "#f87171" }}>
                {settingsError}
                <button onClick={fetchSettings} style={{ marginLeft: "10px" }} className="ns-btn-gradient small">Retry</button>
              </div>
            ) : (
              <div className="ns-form-group" style={{ maxWidth: "400px", marginTop: "1rem" }}>
                <label>Telemetry Polling Interval</label>
                <select
                  className="ns-control"
                  value={settings.telemetry_polling_interval || "Standard (5 seconds)"}
                  onChange={(e) => {
                    const updated = { ...settings, telemetry_polling_interval: e.target.value };
                    saveSettings(updated);
                  }}
                  disabled={savingSettings}
                >
                  <option>Real-time (1 second)</option>
                  <option>Standard (5 seconds)</option>
                  <option>Low Bandwidth (30 seconds)</option>
                </select>
                {savingSettings && <p style={{ fontSize: "0.8rem", color: "#3b82f6", marginTop: "0.5rem" }}>Saving to PostgreSQL...</p>}
                {settingsSuccess && <p style={{ fontSize: "0.8rem", color: "#10b981", marginTop: "0.5rem" }}>{settingsSuccess}</p>}
              </div>
            )}
          </DashboardCard>
        );

      default:
        return <div>Select a menu item from the sidebar.</div>;
    }
  };

  return (
    <ProtectedRoute allowedRoles={["analyst"]}>
      <div className="ns-soc-layout">
        <Sidebar
          sidebarCollapsed={sidebarCollapsed}
          setSidebarCollapsed={setSidebarCollapsed}
          menuItems={menuItems}
          activeTab={activeTab}
          setActiveTab={setActiveTab}
          onLogout={handleLogout}
        />

        <main className="ns-soc-main">
          <Navbar
            currentUser={currentUser}
            searchQuery={searchQuery}
            setSearchQuery={setSearchQuery}
            currentTime={currentTime}
          />

          <div className="ns-soc-content-container">
            {renderTabContent()}
          </div>
          <Footer />
        </main>
      </div>
    </ProtectedRoute>
  );
}
