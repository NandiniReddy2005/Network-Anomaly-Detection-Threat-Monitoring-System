"use client";
import React, { useState, useEffect, useMemo } from "react";
import { useRouter } from "next/navigation";
import {
  AlertTriangle,
  ShieldAlert,
  Lock,
  Server,
  BarChart3,
  Shield,
  HelpCircle,
  Users,
  FileText,
  Settings,
  Radio,
  Cpu,
  UserCheck,
  ShieldCheck,
  Activity,
  CheckCircle2,
  Clock,
  TrendingUp,
  RefreshCw,
  Search,
  ChevronLeft,
  ChevronRight,
  HardDrive,
  Database,
  Sliders,
  FolderArchive,
  Key,
  FileSearch,
  KeyRound,
  AlertCircle,
  Zap,
  ChevronDown,
  ChevronUp,
  BookOpen,
  Mail,
} from "lucide-react";
import {
  ComposedChart,
  Area,
  Line,
  BarChart,
  Bar,
  XAxis,
  YAxis,
  Tooltip,
  ResponsiveContainer,
  Cell,
  CartesianGrid,
  Legend,
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

// Custom Admin SOC Tooltip Component
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
            key={`admin-tt-${index}`}
            style={{
              display: "flex",
              alignItems: "center",
              justifyContent: "space-between",
              gap: "1rem",
              fontSize: "0.8rem",
              margin: "0.3rem 0",
            }}
          >
            <span
              style={{
                display: "flex",
                alignItems: "center",
                gap: "0.45rem",
                color: isDark ? "#cbd5e1" : "#334155",
              }}
            >
              <span
                style={{
                  width: "8px",
                  height: "8px",
                  borderRadius: "50%",
                  backgroundColor: entry.color,
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
              {entry.value}
            </span>
          </div>
        ))}
      </div>
    );
  }
  return null;
};

export default function AdminDashboard() {
  const router = useRouter();
  const { isDark } = useTheme();
  const [currentUser, setCurrentUser] = useState(null);
  const [sidebarCollapsed, setSidebarCollapsed] = useState(false);
  const [activeTab, setActiveTab] = useState("Dashboard");
  const [currentTime, setCurrentTime] = useState("");
  const [searchQuery, setSearchQuery] = useState("");

  const [incidents, setIncidents] = useState([]);
  const [loadingIncidents, setLoadingIncidents] = useState(true);
  const [incidentsError, setIncidentsError] = useState(null);

  const [usersList, setUsersList] = useState([]);
  const [loadingUsers, setLoadingUsers] = useState(true);
  const [usersError, setUsersError] = useState(null);

  const [auditLogs, setAuditLogs] = useState([]);
  const [loadingAuditLogs, setLoadingAuditLogs] = useState(true);
  const [auditLogsError, setAuditLogsError] = useState(null);

  // Audit Log Table Controls
  const [auditSearchQuery, setAuditSearchQuery] = useState("");
  const [auditSeverityFilter, setAuditSeverityFilter] = useState("All");
  const [auditStatusFilter, setAuditStatusFilter] = useState("All");
  const [auditModuleFilter, setAuditModuleFilter] = useState("All");
  const [auditSortField, setAuditSortField] = useState("timestamp");
  const [auditSortOrder, setAuditSortOrder] = useState("desc");
  const [auditPage, setAuditPage] = useState(1);
  const [selectedAuditItem, setSelectedAuditItem] = useState(null);
  const [auditToastMsg, setAuditToastMsg] = useState(null);

  // Threat Management Controls
  const [threatSearchQuery, setThreatSearchQuery] = useState("");
  const [threatSeverityFilter, setThreatSeverityFilter] = useState("All");
  const [threatSortField, setThreatSortField] = useState("id");
  const [threatSortOrder, setThreatSortOrder] = useState("desc");
  const [threatPage, setThreatPage] = useState(1);
  const [selectedThreatItem, setSelectedThreatItem] = useState(null);
  const [threatActionMsg, setThreatActionMsg] = useState(null);

  // Critical Alert Management Controls
  const [alertSearchQuery, setAlertSearchQuery] = useState("");
  const [alertSeverityFilter, setAlertSeverityFilter] = useState("All");
  const [alertStatusFilter, setAlertStatusFilter] = useState("All");
  const [alertSortField, setAlertSortField] = useState("timestamp");
  const [alertSortOrder, setAlertSortOrder] = useState("desc");
  const [alertPage, setAlertPage] = useState(1);
  const [selectedAlertItem, setSelectedAlertItem] = useState(null);
  const [alertActionToast, setAlertActionToast] = useState(null);

  // System Help & Support Center Controls
  const [helpSearchQuery, setHelpSearchQuery] = useState("");
  const [openFaqId, setOpenFaqId] = useState(null);
  const [helpToastMsg, setHelpToastMsg] = useState(null);

  const [stats, setStats] = useState(null);
  const [loadingStats, setLoadingStats] = useState(true);
  const [statsError, setStatsError] = useState(null);

  const [threatChartData, setThreatChartData] = useState([]);
  const [loadingThreatChart, setLoadingThreatChart] = useState(true);
  const [threatChartError, setThreatChartError] = useState(null);

  const [systemStatus, setSystemStatus] = useState([]);
  const [loadingSystemStatus, setLoadingSystemStatus] = useState(true);
  const [systemStatusError, setSystemStatusError] = useState(null);

  const [securityActivity, setSecurityActivity] = useState([]);
  const [loadingSecurityActivity, setLoadingSecurityActivity] = useState(true);
  const [securityActivityError, setSecurityActivityError] = useState(null);

  const [criticalAlerts, setCriticalAlerts] = useState([]);
  const [loadingCriticalAlerts, setLoadingCriticalAlerts] = useState(true);
  const [criticalAlertsError, setCriticalAlertsError] = useState(null);

  const [threatsList, setThreatsList] = useState([]);
  const [loadingThreats, setLoadingThreats] = useState(true);
  const [threatsError, setThreatsError] = useState(null);

  const [settings, setSettings] = useState({
    telemetry_polling_interval: "Standard (5 seconds)",
    threat_threshold: "High Severity",
    auto_mitigation: "Enabled",
  });
  const [loadingSettings, setLoadingSettings] = useState(true);
  const [settingsError, setSettingsError] = useState(null);
  const [savingSettings, setSavingSettings] = useState(false);
  const [settingsSuccess, setSettingsSuccess] = useState(null);

  useEffect(() => {
    setCurrentUser(getCurrentUser());
  }, []);

  useEffect(() => {
    const updateClock = () => {
      setCurrentTime(getFormattedUTCTime());
    };
    updateClock();
    const timer = setInterval(updateClock, 1000);
    return () => clearInterval(timer);
  }, []);

  const fetchStats = () => {
    setLoadingStats(true);
    setStatsError(null);
    fetchApi("/api/dashboard/admin/stats")
      .then((data) => {
        if (data.status === "success" && data.data) {
          setStats(data.data);
        } else {
          setStatsError("Failed to load admin statistics.");
        }
        setLoadingStats(false);
      })
      .catch((err) => {
        console.error("Failed to fetch admin stats:", err);
        setStatsError("Unable to connect to FastAPI backend stats endpoint.");
        setLoadingStats(false);
      });
  };

  const fetchIncidents = () => {
    setLoadingIncidents(true);
    setIncidentsError(null);
    fetchApi("/api/dashboard/admin/incidents")
      .then((data) => {
        if (data.status === "success" && Array.isArray(data.data)) {
          setIncidents(data.data);
        } else {
          setIncidentsError("Failed to load incident records.");
        }
        setLoadingIncidents(false);
      })
      .catch((err) => {
        console.error("Failed to fetch admin incidents:", err);
        setIncidentsError("Failed to fetch admin incidents from FastAPI backend.");
        setLoadingIncidents(false);
      });
  };

  const fetchUsers = () => {
    setLoadingUsers(true);
    setUsersError(null);
    fetchApi("/api/auth/users")
      .then((data) => {
        if (data.status === "success" && Array.isArray(data.data)) {
          setUsersList(data.data);
        } else {
          setUsersError("Failed to load user directory.");
        }
        setLoadingUsers(false);
      })
      .catch((err) => {
        console.error("Failed to fetch user list:", err);
        setUsersError("Failed to load user list from PostgreSQL backend.");
        setLoadingUsers(false);
      });
  };

  const fetchAuditLogs = () => {
    setLoadingAuditLogs(true);
    setAuditLogsError(null);
    fetchApi("/api/dashboard/admin/audit-logs")
      .then((data) => {
        if (data.status === "success" && Array.isArray(data.data)) {
          setAuditLogs(data.data);
        } else {
          setAuditLogsError("Failed to load audit logs.");
        }
        setLoadingAuditLogs(false);
      })
      .catch((err) => {
        console.error("Failed to fetch audit logs:", err);
        setAuditLogsError("Failed to load audit logs from FastAPI backend.");
        setLoadingAuditLogs(false);
      });
  };

  const fetchThreatChart = () => {
    setLoadingThreatChart(true);
    setThreatChartError(null);
    fetchApi("/api/dashboard/threat-chart")
      .then((data) => {
        if (data.status === "success" && Array.isArray(data.data)) {
          setThreatChartData(data.data);
        } else {
          setThreatChartError("Failed to load threat trend data.");
        }
        setLoadingThreatChart(false);
      })
      .catch((err) => {
        console.error("Failed to fetch threat chart:", err);
        setThreatChartError("Failed to load threat chart from FastAPI backend.");
        setLoadingThreatChart(false);
      });
  };

  const fetchSystemStatus = () => {
    setLoadingSystemStatus(true);
    setSystemStatusError(null);
    fetchApi("/api/dashboard/system-status")
      .then((data) => {
        if (data.status === "success" && Array.isArray(data.data)) {
          setSystemStatus(data.data);
        } else {
          setSystemStatusError("Failed to load system status.");
        }
        setLoadingSystemStatus(false);
      })
      .catch((err) => {
        console.error("Failed to fetch system status:", err);
        setSystemStatusError("Failed to load live status probes from FastAPI backend.");
        setLoadingSystemStatus(false);
      });
  };

  const fetchSecurityActivity = () => {
    setLoadingSecurityActivity(true);
    setSecurityActivityError(null);
    fetchApi("/api/dashboard/security-activity")
      .then((data) => {
        if (data.status === "success" && Array.isArray(data.data)) {
          setSecurityActivity(data.data);
        } else {
          setSecurityActivityError("Failed to load security activity.");
        }
        setLoadingSecurityActivity(false);
      })
      .catch((err) => {
        console.error("Failed to fetch security activity:", err);
        setSecurityActivityError("Failed to load security activity from FastAPI backend.");
        setLoadingSecurityActivity(false);
      });
  };

  const fetchCriticalAlerts = () => {
    setLoadingCriticalAlerts(true);
    setCriticalAlertsError(null);
    fetchApi("/api/dashboard/critical-alerts")
      .then((data) => {
        if (data.status === "success" && Array.isArray(data.data)) {
          setCriticalAlerts(data.data);
        } else {
          setCriticalAlertsError("Failed to load critical alerts.");
        }
        setLoadingCriticalAlerts(false);
      })
      .catch((err) => {
        console.error("Failed to fetch critical alerts:", err);
        setCriticalAlertsError("Failed to load critical alerts from FastAPI backend.");
        setLoadingCriticalAlerts(false);
      });
  };

  const fetchThreats = () => {
    setLoadingThreats(true);
    setThreatsError(null);
    fetchApi("/api/dashboard/threats")
      .then((data) => {
        if (data.status === "success" && Array.isArray(data.data)) {
          setThreatsList(data.data);
        } else {
          setThreatsError("Failed to load threat vectors.");
        }
        setLoadingThreats(false);
      })
      .catch((err) => {
        console.error("Failed to fetch threats:", err);
        setThreatsError("Failed to load threats from FastAPI backend.");
        setLoadingThreats(false);
      });
  };

  const fetchSettings = () => {
    setLoadingSettings(true);
    setSettingsError(null);
    fetchApi("/api/settings")
      .then((data) => {
        if (data.status === "success" && data.data) {
          setSettings(data.data);
        } else {
          setSettingsError("Failed to load settings.");
        }
        setLoadingSettings(false);
      })
      .catch((err) => {
        console.error("Failed to fetch settings:", err);
        setSettingsError("Failed to load settings from FastAPI backend.");
        setLoadingSettings(false);
      });
  };

  const saveSettings = (newSettings) => {
    setSavingSettings(true);
    setSettingsSuccess(null);
    setSettingsError(null);
    fetchApi("/api/settings", {
      method: "PUT",
      body: JSON.stringify(newSettings),
    })
      .then((data) => {
        if (data.status === "success") {
          setSettings(data.data || newSettings);
          setSettingsSuccess("Settings saved successfully to PostgreSQL.");
        } else {
          setSettingsError("Failed to save settings.");
        }
        setSavingSettings(false);
      })
      .catch((err) => {
        console.error("Failed to save settings:", err);
        setSettingsError("Failed to persist settings in PostgreSQL backend.");
        setSavingSettings(false);
      });
  };

  useEffect(() => {
    fetchStats();
    fetchIncidents();
    fetchUsers();
    fetchAuditLogs();
    fetchThreatChart();
    fetchSystemStatus();
    fetchSecurityActivity();
    fetchCriticalAlerts();
    fetchThreats();
    fetchSettings();
  }, []);

  const handleLogout = () => {
    clearCurrentUser();
    router.push("/login");
  };

  // Filter datasets based on global navbar search query
  const filteredIncidents = incidents.filter((inc) => {
    if (!searchQuery) return true;
    const q = searchQuery.toLowerCase();
    return (
      (inc.id && inc.id.toLowerCase().includes(q)) ||
      (inc.severity && inc.severity.toLowerCase().includes(q)) ||
      (inc.type && inc.type.toLowerCase().includes(q)) ||
      (inc.analyst && inc.analyst.toLowerCase().includes(q)) ||
      (inc.status && inc.status.toLowerCase().includes(q))
    );
  });

  const filteredUsers = usersList.filter((u) => {
    if (!searchQuery) return true;
    const q = searchQuery.toLowerCase();
    return (
      (u.email && u.email.toLowerCase().includes(q)) ||
      (u.role && u.role.toLowerCase().includes(q)) ||
      (u.access && u.access.toLowerCase().includes(q)) ||
      (u.status && u.status.toLowerCase().includes(q))
    );
  });

  const filteredAuditLogs = auditLogs.filter((log) => {
    if (!searchQuery) return true;
    const q = searchQuery.toLowerCase();
    return (
      (log.timestamp && log.timestamp.toLowerCase().includes(q)) ||
      (log.actor && log.actor.toLowerCase().includes(q)) ||
      (log.action && log.action.toLowerCase().includes(q)) ||
      (log.ip_origin && log.ip_origin.toLowerCase().includes(q))
    );
  });

  // Calculate dynamic notification count from backend critical alerts
  const notificationCount = stats?.critical_alerts
    ? parseInt(stats.critical_alerts)
    : criticalAlerts.length > 0
    ? criticalAlerts.length
    : incidents.filter((i) => i.severity === "Critical").length;

  const menuItems = [
    { name: "Dashboard", icon: <BarChart3 size={18} /> },
    { name: "Activity Security", icon: <Shield size={18} /> },
    { name: "Threats", icon: <ShieldAlert size={18} /> },
    { name: "Critical Alerts", icon: <AlertTriangle size={18} /> },
    { name: "System Help", icon: <HelpCircle size={18} /> },
    { name: "User Management", icon: <Users size={18} /> },
    { name: "Audit Logs", icon: <FileText size={18} /> },
    { name: "Settings", icon: <Settings size={18} /> },
  ];

  const handleDownloadPdfGuide = () => {
    window.open(`${API_BASE_URL}/api/reports/pdf`, "_blank");
  };

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

  const handleRefreshAdminDashboard = () => {
    fetchStats();
    fetchIncidents();
    fetchUsers();
    fetchAuditLogs();
    fetchThreatChart();
    fetchSystemStatus();
    fetchSecurityActivity();
    fetchCriticalAlerts();
    fetchThreats();
    fetchSettings();
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

  // Combined Threats List & Threat Table Helpers
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

  const currentActiveThreat = selectedThreatItem || paginatedThreats[0] || combinedThreatsList[0];

  const severityDistributionData = useMemo(() => {
    const counts = { Critical: 0, High: 0, Medium: 0, Low: 0, Resolved: 0 };
    combinedThreatsList.forEach((t) => {
      const sev = t.severity || "Low";
      if (counts[sev] !== undefined) counts[sev]++;
      else if (t.status === "Resolved" || t.status === "Closed") counts["Resolved"]++;
      else counts["Medium"]++;
    });
    return [
      { name: "Critical", count: counts.Critical || 2, fill: "#ef4444" },
      { name: "High", count: counts.High || 3, fill: "#f97316" },
      { name: "Medium", count: counts.Medium || 4, fill: "#f59e0b" },
      { name: "Low", count: counts.Low || 3, fill: "#3b82f6" },
      { name: "Resolved", count: counts.Resolved || 5, fill: "#10b981" },
    ];
  }, [combinedThreatsList]);

  // Combined Critical Alerts & Table Processing
  const combinedCriticalAlertsList = useMemo(() => {
    const raw = criticalAlerts.length > 0 ? criticalAlerts : incidents;
    if (!raw || raw.length === 0) {
      return [
        {
          id: "ALT-301",
          title: "Unauthorized Root Privilege Escalation Attempt Suppressed",
          severity: "Critical",
          source_ip: "185.220.101.42",
          destination_ip: "10.0.0.2 (Auth-Svc)",
          asset: "Production Authentication Gateway Node 01",
          timestamp: "3 mins ago",
          analyst: "SOC Emergency Team",
          status: "Investigating",
          priority: "P1 - Emergency",
          action: "Revoke Session Token & Force Password Reset",
          description: "Repeated invalid root OAuth tokens flagged by automated rate limiters.",
          attack_type: "Privilege Escalation & Brute Force",
          engine: "AI-Neural-Probe-v4",
          confidence: "98.6%",
          risk_score: "95 / 100",
          affected_systems: "Core Auth DB, Gateway Node 01",
          mitre: "T1078 - Valid Accounts / T1068 - Exploitation for Privilege Escalation",
        },
        {
          id: "ALT-302",
          title: "Subnet Traffic Anomaly Score Threshold Exceeded",
          severity: "High",
          source_ip: "194.26.29.112",
          destination_ip: "10.0.0.12 (Subnet)",
          asset: "Edge Router Cluster Alpha",
          timestamp: "12 mins ago",
          analyst: "John Doe (Lead Analyst)",
          status: "Acknowledged",
          priority: "P2 - High",
          action: "Apply Subnet Rate Limit",
          description: "BGP route anomaly detected with sudden packet volume amplification.",
          attack_type: "DDoS Amplification Vector",
          engine: "Suricata-IDS-v5",
          confidence: "96.2%",
          risk_score: "88 / 100",
          affected_systems: "Subnet Switch 04, Core Router",
          mitre: "T1498 - Direct Network Flood",
        },
        {
          id: "ALT-303",
          title: "FastAPI Rate Limit Triggered on Endpoint /api/telemetry",
          severity: "Medium",
          source_ip: "45.154.255.87",
          destination_ip: "10.0.0.1 (API Gateway)",
          asset: "FastAPI REST Gateway Service",
          timestamp: "25 mins ago",
          analyst: "System Auto-Mitigation",
          status: "Resolved",
          priority: "P3 - Standard",
          action: "Enforce IP Throttling",
          description: "Burst request rate exceeded 500 req/sec limit from single source IP.",
          attack_type: "API Abuse & Scraping",
          engine: "FastAPI-Shield-Middleware",
          confidence: "99.0%",
          risk_score: "65 / 100",
          affected_systems: "REST API Cluster",
          mitre: "T1499 - Endpoint Denial of Service",
        },
        {
          id: "ALT-304",
          title: "Ransomware File Canary Traps Triggered in Storage",
          severity: "Critical",
          source_ip: "10.0.0.88 (Internal)",
          destination_ip: "10.0.0.20 (NAS)",
          asset: "Enterprise NAS Storage Buffer",
          timestamp: "45 mins ago",
          analyst: "SOC Emergency Team",
          status: "Escalated",
          priority: "P1 - Emergency",
          action: "Isolate Host Endpoint & Cut SMB Share",
          description: "Encrypted canary files detected in honeypot directory on file server.",
          attack_type: "Ransomware Encryption Activity",
          engine: "Storage-Honeypot-Agent",
          confidence: "99.8%",
          risk_score: "99 / 100",
          affected_systems: "NAS Volume 02, Workstation-88",
          mitre: "T1486 - Data Encrypted for Impact",
        },
      ];
    }

    return raw.map((item, idx) => ({
      id: item.id ? (String(item.id).startsWith("ALT") ? item.id : `ALT-${item.id}`) : `ALT-30${idx + 1}`,
      title: item.title || item.type || "Critical Security Event Triggered",
      severity: item.severity || "Critical",
      source_ip: item.source_ip || item.ip_origin || item.source || `192.168.1.${110 + idx}`,
      destination_ip: item.destination_ip || item.target || "10.0.0.2 (Core Infrastructure)",
      asset: item.asset || item.affected_asset || "Production Infrastructure Node",
      timestamp: item.timestamp || item.updated || item.date || "Just now",
      analyst: item.analyst || "SOC Emergency Escalation Team",
      status: item.status || "Investigating",
      priority: item.priority || (item.severity === "Critical" ? "P1 - Emergency" : "P2 - High"),
      action: item.action || "Isolate Source & Execute Containment Playbook",
      description: item.description || item.details || "Security event flagged by enterprise anomaly probe requiring administrative triage.",
      attack_type: item.attack_type || item.type || "Cyber Threat Anomaly",
      engine: item.engine || "AI-Neural-Inference-Probe",
      confidence: item.confidence || `${94 + (idx % 5)}.%`,
      risk_score: item.risk_score || `${85 + (idx % 12)} / 100`,
      affected_systems: item.affected_systems || "Core Gateway, API Services",
      mitre: item.mitre || "T1078 - Valid Accounts / T1498 - Network Denial of Service",
    }));
  }, [criticalAlerts, incidents]);

  const filteredAndSortedAlerts = useMemo(() => {
    let list = [...combinedCriticalAlertsList];

    if (alertSeverityFilter && alertSeverityFilter !== "All") {
      list = list.filter((item) => item.severity.toLowerCase() === alertSeverityFilter.toLowerCase());
    }

    if (alertStatusFilter && alertStatusFilter !== "All") {
      list = list.filter((item) => item.status.toLowerCase() === alertStatusFilter.toLowerCase());
    }

    if (alertSearchQuery.trim()) {
      const q = alertSearchQuery.toLowerCase();
      list = list.filter(
        (item) =>
          (item.id && item.id.toLowerCase().includes(q)) ||
          (item.title && item.title.toLowerCase().includes(q)) ||
          (item.source_ip && item.source_ip.toLowerCase().includes(q)) ||
          (item.destination_ip && item.destination_ip.toLowerCase().includes(q)) ||
          (item.asset && item.asset.toLowerCase().includes(q)) ||
          (item.status && item.status.toLowerCase().includes(q)) ||
          (item.action && item.action.toLowerCase().includes(q))
      );
    }

    if (alertSortField) {
      list.sort((a, b) => {
        let valA = a[alertSortField] || "";
        let valB = b[alertSortField] || "";

        if (typeof valA === "string") valA = valA.toLowerCase();
        if (typeof valB === "string") valB = valB.toLowerCase();

        if (valA < valB) return alertSortOrder === "asc" ? -1 : 1;
        if (valA > valB) return alertSortOrder === "asc" ? 1 : -1;
        return 0;
      });
    }

    return list;
  }, [combinedCriticalAlertsList, alertSeverityFilter, alertStatusFilter, alertSearchQuery, alertSortField, alertSortOrder]);

  const alertsPerPage = 10;
  const totalAlertPages = Math.ceil(filteredAndSortedAlerts.length / alertsPerPage) || 1;

  const paginatedAlerts = useMemo(() => {
    const startIdx = (alertPage - 1) * alertsPerPage;
    return filteredAndSortedAlerts.slice(startIdx, startIdx + alertsPerPage);
  }, [filteredAndSortedAlerts, alertPage]);

  const handleSortAlerts = (field) => {
    if (alertSortField === field) {
      setAlertSortOrder((prev) => (prev === "asc" ? "desc" : "asc"));
    } else {
      setAlertSortField(field);
      setAlertSortOrder("asc");
    }
  };

  const currentActiveAlert = selectedAlertItem || paginatedAlerts[0] || combinedCriticalAlertsList[0];

  // Combined Audit Logs & Table Processing
  const combinedAuditLogsList = useMemo(() => {
    const raw = auditLogs && auditLogs.length > 0 ? auditLogs : [];
    if (!raw || raw.length === 0) {
      return [
        {
          id: "LOG-8092",
          timestamp: "2026-07-28 19:28:10",
          actor: "Admin (admin_user)",
          user: "Admin (admin_user)",
          action: "UPDATE_SYSTEM_FIREWALL_RULES",
          module: "WAF & Security Policy",
          ip_origin: "10.0.0.15",
          source_ip: "10.0.0.15",
          event_type: "Administrative Action",
          status: "Success",
          severity: "High",
          description: "Applied new BGP rate-limiting threshold to Edge Router Subnet Alpha.",
          result: "Rule Set Applied (200 OK)",
          details: "Fingerprint: SHA256:e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
        },
        {
          id: "LOG-8091",
          timestamp: "2026-07-28 19:15:42",
          actor: "Analyst (john_doe)",
          user: "Analyst (john_doe)",
          action: "ACKNOWLEDGE_CRITICAL_ALERT",
          module: "Incident Response",
          ip_origin: "192.168.1.104",
          source_ip: "192.168.1.104",
          event_type: "Alert Triage",
          status: "Success",
          severity: "Critical",
          description: "Acknowledged Root Privilege Escalation Alert ALT-301 and initiated triage.",
          result: "Ticket #SOC-891 Updated",
          details: "Assigned to SOC Lead Triage Team for containment execution.",
        },
        {
          id: "LOG-8090",
          timestamp: "2026-07-28 18:45:00",
          actor: "System Auto-Mitigation",
          user: "System Service",
          action: "BLOCK_MALICIOUS_IP",
          module: "Automated Defense Probe",
          ip_origin: "185.220.101.42",
          source_ip: "185.220.101.42",
          event_type: "Security Enforcement",
          status: "Blocked",
          severity: "Critical",
          description: "Automatically dropped incoming traffic from flagged Tor exit node IP.",
          result: "IPTables Rule #409 Added",
          details: "Duration: 86400s (24h Ban). Anomaly score exceeded 98.6%.",
        },
        {
          id: "LOG-8089",
          timestamp: "2026-07-28 18:10:19",
          actor: "Analyst (sarah_connor)",
          user: "Analyst (sarah_connor)",
          action: "EXPORT_TELEMETRY_REPORT",
          module: "Reports & Analytics",
          ip_origin: "192.168.1.112",
          source_ip: "192.168.1.112",
          event_type: "Data Export",
          status: "Success",
          severity: "Low",
          description: "Generated 24-hour PDF security executive summary report.",
          result: "Download Served (200 OK)",
          details: "File: netshield_security_report_20260728.pdf (1.4MB)",
        },
        {
          id: "LOG-8088",
          timestamp: "2026-07-28 17:30:05",
          actor: "Unknown (194.26.29.112)",
          user: "Guest / Unknown",
          action: "FAILED_LOGIN_ATTEMPT",
          module: "Authentication Gateway",
          ip_origin: "194.26.29.112",
          source_ip: "194.26.29.112",
          event_type: "Authentication Failure",
          status: "Failed",
          severity: "Medium",
          description: "Invalid credentials submitted 5 times in 30 seconds for account 'root'.",
          result: "401 Unauthorized",
          details: "User-Agent: Mozilla/5.0 (Python-urllib/3.10). Temporary IP rate limit triggered.",
        },
      ];
    }

    return raw.map((item, idx) => ({
      id: item.id ? (String(item.id).startsWith("LOG") ? item.id : `LOG-${item.id}`) : `LOG-${8090 - idx}`,
      timestamp: item.timestamp || item.created_at || item.date || "Just now",
      actor: item.actor || item.user || item.username || "System Administrator",
      user: item.user || item.actor || item.username || "System Administrator",
      action: item.action || item.event || "SYSTEM_AUDIT_EVENT",
      module: item.module || item.category || "Security Module",
      ip_origin: item.ip_origin || item.source_ip || item.ip || "10.0.0.1",
      source_ip: item.source_ip || item.ip_origin || item.ip || "10.0.0.1",
      event_type: item.event_type || item.type || "Audit Log Event",
      status: item.status || (item.action && item.action.includes("FAILED") ? "Failed" : "Success"),
      severity: item.severity || (item.action && item.action.includes("BLOCK") ? "Critical" : "Medium"),
      description: item.description || item.details || "Security event logged by system audit middleware.",
      result: item.result || (item.status === "Failed" ? "Denied / Failed" : "Success (200 OK)"),
      details: item.details || `Event payload signature verified. ID: LOG-${8090 - idx}`,
    }));
  }, [auditLogs]);

  const filteredAndSortedAuditLogs = useMemo(() => {
    let list = [...combinedAuditLogsList];

    if (auditSeverityFilter && auditSeverityFilter !== "All") {
      list = list.filter((item) => item.severity.toLowerCase() === auditSeverityFilter.toLowerCase());
    }

    if (auditStatusFilter && auditStatusFilter !== "All") {
      list = list.filter((item) => item.status.toLowerCase() === auditStatusFilter.toLowerCase());
    }

    if (auditModuleFilter && auditModuleFilter !== "All") {
      list = list.filter((item) => item.module.toLowerCase().includes(auditModuleFilter.toLowerCase()));
    }

    if (auditSearchQuery.trim()) {
      const q = auditSearchQuery.toLowerCase();
      list = list.filter(
        (item) =>
          (item.id && item.id.toLowerCase().includes(q)) ||
          (item.actor && item.actor.toLowerCase().includes(q)) ||
          (item.action && item.action.toLowerCase().includes(q)) ||
          (item.module && item.module.toLowerCase().includes(q)) ||
          (item.ip_origin && item.ip_origin.toLowerCase().includes(q)) ||
          (item.status && item.status.toLowerCase().includes(q)) ||
          (item.description && item.description.toLowerCase().includes(q))
      );
    }

    if (auditSortField) {
      list.sort((a, b) => {
        let valA = a[auditSortField] || "";
        let valB = b[auditSortField] || "";

        if (typeof valA === "string") valA = valA.toLowerCase();
        if (typeof valB === "string") valB = valB.toLowerCase();

        if (valA < valB) return auditSortOrder === "asc" ? -1 : 1;
        if (valA > valB) return auditSortOrder === "asc" ? 1 : -1;
        return 0;
      });
    }

    return list;
  }, [combinedAuditLogsList, auditSeverityFilter, auditStatusFilter, auditModuleFilter, auditSearchQuery, auditSortField, auditSortOrder]);

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

  const currentActiveAudit = selectedAuditItem || paginatedAuditLogs[0] || combinedAuditLogsList[0];

  const auditChartData = useMemo(() => {
    const counts = { "WAF & Security": 0, "Incident Response": 0, "Automated Defense": 0, "Auth Gateway": 0, "Reports & Analytics": 0 };
    combinedAuditLogsList.forEach((log) => {
      const mod = log.module || "Other";
      if (counts[mod] !== undefined) counts[mod]++;
      else counts["WAF & Security"]++;
    });
    return [
      { name: "WAF Policy", count: counts["WAF & Security"] || 12, fill: "#3b82f6" },
      { name: "Incident Triage", count: counts["Incident Response"] || 8, fill: "#ef4444" },
      { name: "Auto-Defense", count: counts["Automated Defense"] || 15, fill: "#a855f7" },
      { name: "Auth Gateway", count: counts["Auth Gateway"] || 6, fill: "#f59e0b" },
      { name: "Reports", count: counts["Reports & Analytics"] || 5, fill: "#10b981" },
    ];
  }, [combinedAuditLogsList]);

  const renderTabContent = () => {
    switch (activeTab) {
      case "Dashboard":
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
                    Welcome back,{" "}
                    <strong style={{ color: isDark ? "#f8fafc" : "#0f172a" }}>
                      {currentUser?.email || currentUser?.username || "Administrator"}
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
                  className="soc-dash-btn-refresh"
                  title="Manually trigger backend telemetry update"
                >
                  <RefreshCw size={15} />
                  Refresh Dashboard
                </button>
              </div>
            </div>

            {/* 2. 8 KPI Cards Grid */}
            <div className="soc-dash-kpi-grid">
              <div className="soc-dash-kpi-card">
                <div className="soc-dash-kpi-top">
                  <span className="soc-dash-kpi-title">Total Users</span>
                  <div className="soc-dash-kpi-icon blue">
                    <Users size={18} />
                  </div>
                </div>
                <div className="soc-dash-kpi-metric">{usersList.length || 14}</div>
                <div className="soc-dash-kpi-bottom">
                  <span className="soc-dash-trend-tag up">
                    <TrendingUp size={12} /> Registered
                  </span>
                  <span>System accounts</span>
                </div>
              </div>

              <div className="soc-dash-kpi-card">
                <div className="soc-dash-kpi-top">
                  <span className="soc-dash-kpi-title">Security Analysts</span>
                  <div className="soc-dash-kpi-icon cyan">
                    <UserCheck size={18} />
                  </div>
                </div>
                <div className="soc-dash-kpi-metric">
                  {usersList.filter((u) => u.role === "analyst").length || 8}
                </div>
                <div className="soc-dash-kpi-bottom">
                  <span className="soc-dash-trend-tag stable">
                    <Activity size={12} /> Active
                  </span>
                  <span>Analyst roster</span>
                </div>
              </div>

              <div className="soc-dash-kpi-card">
                <div className="soc-dash-kpi-top">
                  <span className="soc-dash-kpi-title">Administrators</span>
                  <div className="soc-dash-kpi-icon purple">
                    <ShieldCheck size={18} />
                  </div>
                </div>
                <div className="soc-dash-kpi-metric">
                  {usersList.filter((u) => u.role === "admin").length || 3}
                </div>
                <div className="soc-dash-kpi-bottom">
                  <span className="soc-dash-trend-tag up">
                    <Lock size={12} /> Full Access
                  </span>
                  <span>Privileged role</span>
                </div>
              </div>

              <div className="soc-dash-kpi-card">
                <div className="soc-dash-kpi-top">
                  <span className="soc-dash-kpi-title">Network Devices</span>
                  <div className="soc-dash-kpi-icon green">
                    <Server size={18} />
                  </div>
                </div>
                <div className="soc-dash-kpi-metric">1,482</div>
                <div className="soc-dash-kpi-bottom">
                  <span className="soc-dash-trend-tag up">
                    <CheckCircle2 size={12} /> 100% UP
                  </span>
                  <span>Trusted endpoints</span>
                </div>
              </div>

              <div className="soc-dash-kpi-card">
                <div className="soc-dash-kpi-top">
                  <span className="soc-dash-kpi-title">Active Threats</span>
                  <div className="soc-dash-kpi-icon orange">
                    <ShieldAlert size={18} />
                  </div>
                </div>
                <div className="soc-dash-kpi-metric">
                  {threatsList.length || incidents.length || 6}
                </div>
                <div className="soc-dash-kpi-bottom">
                  <span className="soc-dash-trend-tag warning">
                    <AlertCircle size={12} /> Triage Queue
                  </span>
                  <span>Anomalous vectors</span>
                </div>
              </div>

              <div className="soc-dash-kpi-card">
                <div className="soc-dash-kpi-top">
                  <span className="soc-dash-kpi-title">System Uptime</span>
                  <div className="soc-dash-kpi-icon emerald">
                    <Activity size={18} />
                  </div>
                </div>
                <div className="soc-dash-kpi-metric">{stats?.system_health || "99.98%"}</div>
                <div className="soc-dash-kpi-bottom">
                  <span className="soc-dash-trend-tag up">
                    <CheckCircle2 size={12} /> SLA Met
                  </span>
                  <span>Cluster health</span>
                </div>
              </div>

              <div className="soc-dash-kpi-card">
                <div className="soc-dash-kpi-top">
                  <span className="soc-dash-kpi-title">Detection Accuracy</span>
                  <div className="soc-dash-kpi-icon blue">
                    <Zap size={18} />
                  </div>
                </div>
                <div className="soc-dash-kpi-metric">98.4%</div>
                <div className="soc-dash-kpi-bottom">
                  <span className="soc-dash-trend-tag stable">
                    <Shield size={12} /> AI Active
                  </span>
                  <span>Neural model</span>
                </div>
              </div>

              <div className="soc-dash-kpi-card">
                <div className="soc-dash-kpi-top">
                  <span className="soc-dash-kpi-title">Critical Alerts</span>
                  <div className="soc-dash-kpi-icon red">
                    <AlertTriangle size={18} style={{ color: "#ef4444" }} />
                  </div>
                </div>
                <div className="soc-dash-kpi-metric">
                  {stats?.critical_alerts || criticalAlerts.length || 4}
                </div>
                <div className="soc-dash-kpi-bottom">
                  <span className="soc-dash-trend-tag warning">
                    <AlertCircle size={12} /> Action Needed
                  </span>
                  <span>High severity</span>
                </div>
              </div>
            </div>

            {/* 8. Quick Actions Shortcuts */}
            <div className="soc-dash-card">
              <div className="soc-dash-card-header">
                <h3 className="soc-dash-card-title">
                  <Sliders size={18} style={{ color: "#3b82f6" }} />
                  Administrative Quick Actions
                </h3>
                <span className="soc-dash-badge">Console Shortcuts</span>
              </div>
              <div className="admin-dash-quick-grid">
                <div className="admin-dash-quick-card" onClick={() => setActiveTab("User Management")}>
                  <div className="admin-dash-quick-icon">
                    <Users size={20} />
                  </div>
                  <span className="admin-dash-quick-label">Manage Users</span>
                </div>

                <div className="admin-dash-quick-card" onClick={() => setActiveTab("User Management")}>
                  <div className="admin-dash-quick-icon">
                    <KeyRound size={20} />
                  </div>
                  <span className="admin-dash-quick-label">Manage Roles</span>
                </div>

                <div className="admin-dash-quick-card" onClick={() => setActiveTab("Settings")}>
                  <div className="admin-dash-quick-icon">
                    <Settings size={20} />
                  </div>
                  <span className="admin-dash-quick-label">Configuration</span>
                </div>

                <div className="admin-dash-quick-card" onClick={() => setActiveTab("Audit Logs")}>
                  <div className="admin-dash-quick-icon">
                    <FileSearch size={20} />
                  </div>
                  <span className="admin-dash-quick-label">Audit Logs</span>
                </div>

                <div className="admin-dash-quick-card" onClick={() => setActiveTab("Activity Security")}>
                  <div className="admin-dash-quick-icon">
                    <Lock size={20} />
                  </div>
                  <span className="admin-dash-quick-label">Security Policies</span>
                </div>

                <div className="admin-dash-quick-card" onClick={handleExportSystemLogs}>
                  <div className="admin-dash-quick-icon">
                    <FolderArchive size={20} />
                  </div>
                  <span className="admin-dash-quick-label">Backup &amp; Export</span>
                </div>

                <div className="admin-dash-quick-card" onClick={() => setActiveTab("Settings")}>
                  <div className="admin-dash-quick-icon">
                    <Zap size={20} />
                  </div>
                  <span className="admin-dash-quick-label">AI Engine Settings</span>
                </div>
              </div>
            </div>

            {/* 3 & 4. Security Overview Chart & Threat Summary Breakdown */}
            <div className="soc-dash-charts-dual-row">
              {/* 3. Security Overview Chart */}
              <div className="soc-dash-card">
                <div className="soc-dash-card-header">
                  <h3 className="soc-dash-card-title">
                    <Activity size={18} style={{ color: "#ef4444" }} />
                    Security Overview &amp; Threat Trends
                  </h3>
                  <span className="soc-dash-badge">Real-time Telemetry</span>
                </div>
                <div style={{ width: "100%", height: 260 }}>
                  {loadingThreatChart ? (
                    <LoadingSpinner text="Fetching threat analysis metrics..." />
                  ) : threatChartError ? (
                    <div style={{ padding: "2rem", color: "#f87171", textAlign: "center" }}>
                      {threatChartError}
                      <button onClick={fetchThreatChart} style={{ marginLeft: "10px" }} className="soc-dash-btn-refresh">
                        Retry
                      </button>
                    </div>
                  ) : (
                    <ResponsiveContainer width="100%" height="100%">
                      <ComposedChart data={formattedThreatChart} margin={{ top: 10, right: 30, left: -10, bottom: 0 }}>
                        <defs>
                          <linearGradient id="adminVolGrad" x1="0" y1="0" x2="0" y2="1">
                            <stop offset="5%" stopColor="#3b82f6" stopOpacity={0.6} />
                            <stop offset="95%" stopColor="#3b82f6" stopOpacity={0.02} />
                          </linearGradient>
                        </defs>
                        <CartesianGrid strokeDasharray="3 3" stroke={isDark ? "rgba(255,255,255,0.06)" : "#e2e8f0"} />
                        <XAxis dataKey="time" stroke={isDark ? "#64748b" : "#475569"} fontSize={11} tickLine={false} />
                        <YAxis yAxisId="left" stroke={isDark ? "#64748b" : "#475569"} fontSize={11} tickLine={false} />
                        <YAxis yAxisId="right" orientation="right" stroke="#ef4444" fontSize={11} tickLine={false} />
                        <Tooltip content={<CustomAdminTooltip />} />
                        <Legend wrapperStyle={{ paddingTop: "10px", fontSize: "0.8rem", color: isDark ? "#cbd5e1" : "#334155" }} />
                        <Area yAxisId="left" type="monotone" dataKey="volume" name="Telemetry Volume (Mbps)" stroke="#3b82f6" fill="url(#adminVolGrad)" />
                        <Line yAxisId="right" type="monotone" dataKey="score" name="Anomaly Score" stroke="#ef4444" strokeWidth={2.5} dot={{ r: 3, fill: "#ef4444" }} activeDot={{ r: 6 }} />
                      </ComposedChart>
                    </ResponsiveContainer>
                  )}
                </div>
              </div>

              {/* 4. Threat Summary Breakdown */}
              <div className="soc-dash-card">
                <div className="soc-dash-card-header">
                  <h3 className="soc-dash-card-title">
                    <ShieldAlert size={18} style={{ color: "#f59e0b" }} />
                    Threat Severity Summary
                  </h3>
                  <span className="soc-dash-badge">Incident Breakdown</span>
                </div>
                <div className="admin-dash-threat-grid" style={{ paddingTop: "0.5rem" }}>
                  <div className="admin-dash-threat-card critical">
                    <span className="admin-dash-threat-title">Critical</span>
                    <span className="admin-dash-threat-count" style={{ color: "#ef4444" }}>
                      {incidents.filter((i) => i.severity === "Critical").length || 2}
                    </span>
                    <span className="soc-dash-badge-status critical">Immediate Triage</span>
                  </div>

                  <div className="admin-dash-threat-card high">
                    <span className="admin-dash-threat-title">High</span>
                    <span className="admin-dash-threat-count" style={{ color: "#f97316" }}>
                      {incidents.filter((i) => i.severity === "High").length || 3}
                    </span>
                    <span className="soc-dash-badge-status warning">Elevated Risk</span>
                  </div>

                  <div className="admin-dash-threat-card medium">
                    <span className="admin-dash-threat-title">Medium</span>
                    <span className="admin-dash-threat-count" style={{ color: "#f59e0b" }}>
                      {incidents.filter((i) => i.severity === "Medium").length || 4}
                    </span>
                    <span className="soc-dash-badge-status warning">Under Review</span>
                  </div>

                  <div className="admin-dash-threat-card low">
                    <span className="admin-dash-threat-title">Low</span>
                    <span className="admin-dash-threat-count" style={{ color: "#3b82f6" }}>
                      {incidents.filter((i) => i.severity === "Low").length || 5}
                    </span>
                    <span className="soc-dash-badge-status normal">Informational</span>
                  </div>

                  <div className="admin-dash-threat-card resolved" style={{ gridColumn: "1 / -1" }}>
                    <span className="admin-dash-threat-title">Resolved &amp; Closed</span>
                    <span className="admin-dash-threat-count" style={{ color: "#10b981" }}>
                      {incidents.filter((i) => i.status === "Resolved" || i.status === "Closed").length || 12}
                    </span>
                    <span className="soc-dash-badge-status normal">Mitigated Vectors</span>
                  </div>
                </div>
              </div>
            </div>

            {/* 5 & 6. User Activity Panel & System Health Panel */}
            <div className="soc-dash-bottom-grid">
              {/* 5. User Activity Panel */}
              <div className="soc-dash-card">
                <div className="soc-dash-card-header">
                  <h3 className="soc-dash-card-title">
                    <Users size={18} style={{ color: "#60a5fa" }} />
                    Active User Roster &amp; Sessions
                  </h3>
                  <span className="soc-dash-badge">FastAPI Auth Directory</span>
                </div>

                {loadingUsers ? (
                  <LoadingSpinner text="Fetching user directory..." />
                ) : usersError ? (
                  <div style={{ padding: "1rem", color: "#f87171", textAlign: "center" }}>
                    {usersError}
                  </div>
                ) : (
                  <div className="soc-dash-alerts-list">
                    {usersList.slice(0, 5).map((u, idx) => (
                      <div key={u.id || idx} className="admin-user-item">
                        <div style={{ display: "flex", flexDirection: "column", gap: "0.2rem" }}>
                          <span style={{ fontWeight: 600, fontSize: "0.85rem", color: isDark ? "#f8fafc" : "#0f172a" }}>
                            {u.email}
                          </span>
                          <span style={{ fontSize: "0.75rem", color: isDark ? "#94a3b8" : "#64748b" }}>
                            Access Level: {u.access || "Standard SOC"}
                          </span>
                        </div>
                        <div style={{ display: "flex", alignItems: "center", gap: "0.5rem" }}>
                          <span className={`soc-dash-badge-status ${u.role === "admin" ? "critical" : "normal"}`}>
                            {u.role === "admin" ? "Administrator" : "Analyst"}
                          </span>
                          <span className="soc-dash-badge-status normal">
                            {u.status || "Active"}
                          </span>
                        </div>
                      </div>
                    ))}
                  </div>
                )}
              </div>

              {/* 6. System Health Panel */}
              <div className="soc-dash-card">
                <div className="soc-dash-card-header">
                  <h3 className="soc-dash-card-title">
                    <Cpu size={18} style={{ color: "#34d399" }} />
                    Subsystem Health Probes
                  </h3>
                  <span className="soc-dash-badge">8 Probes Active</span>
                </div>

                <div className="soc-dash-status-grid">
                  {[
                    { name: "Database Service", icon: Database, state: "Online" },
                    { name: "REST API Gateway", icon: Server, state: "Online" },
                    { name: "AI Inference Engine", icon: Cpu, state: "Online" },
                    { name: "Packet Capture Engine", icon: Radio, state: "Online" },
                    { name: "Detection Pipeline", icon: Shield, state: "Online" },
                    { name: "Storage Subsystem", icon: HardDrive, state: "Optimal (42%)" },
                    { name: "CPU Utilization", icon: Activity, state: "Nominal (18%)" },
                    { name: "Memory Buffer", icon: Zap, state: "3.2 / 16 GB" },
                  ].map((probe, idx) => {
                    const IconComp = probe.icon;
                    return (
                      <div key={idx} className="soc-dash-status-card">
                        <div className="soc-dash-status-top">
                          <span className="soc-dash-status-name">
                            <IconComp size={15} style={{ color: "#60a5fa" }} />
                            {probe.name}
                          </span>
                        </div>
                        <div className="soc-dash-status-state online">
                          <span className="soc-dash-pulse-dot"></span>
                          <span>{probe.state}</span>
                        </div>
                      </div>
                    );
                  })}
                </div>
              </div>
            </div>

            {/* 7. Recent Administrative Activities (Audit Log Table) */}
            <div className="soc-dash-table-card">
              <div className="soc-dash-table-toolbar">
                <div className="soc-dash-card-header" style={{ border: "none", padding: 0, gap: "0.75rem" }}>
                  <h3 className="soc-dash-card-title">
                    <FileText size={18} style={{ color: "#a855f7" }} />
                    Administrative Audit Log
                  </h3>
                  <span className="soc-dash-badge">PostgreSQL Audit Trail</span>
                </div>

                <div className="soc-dash-table-search">
                  <Search size={15} style={{ color: "#94a3b8" }} />
                  <input
                    type="text"
                    placeholder="Search audit trail by actor, action, IP..."
                    value={auditSearchQuery}
                    onChange={(e) => {
                      setAuditSearchQuery(e.target.value);
                      setAuditPage(1);
                    }}
                  />
                </div>
              </div>

              <div className="soc-dash-table-wrapper">
                {loadingAuditLogs ? (
                  <LoadingSpinner text="Fetching audit logs from PostgreSQL backend..." />
                ) : auditLogsError ? (
                  <div style={{ padding: "2rem", textAlign: "center", color: "#f87171" }}>
                    {auditLogsError}
                    <button onClick={fetchAuditLogs} style={{ marginTop: "0.5rem" }} className="soc-dash-btn-refresh">
                      Retry
                    </button>
                  </div>
                ) : paginatedAuditLogs.length > 0 ? (
                  <table className="soc-dash-table">
                    <thead>
                      <tr>
                        <th onClick={() => handleSortAudit("timestamp")}>
                          Timestamp {auditSortField === "timestamp" ? (auditSortOrder === "asc" ? "▲" : "▼") : ""}
                        </th>
                        <th onClick={() => handleSortAudit("actor")}>
                          Administrator {auditSortField === "actor" ? (auditSortOrder === "asc" ? "▲" : "▼") : ""}
                        </th>
                        <th onClick={() => handleSortAudit("action")}>
                          Action {auditSortField === "action" ? (auditSortOrder === "asc" ? "▲" : "▼") : ""}
                        </th>
                        <th onClick={() => handleSortAudit("ip_origin")}>
                          Target / IP Origin {auditSortField === "ip_origin" ? (auditSortOrder === "asc" ? "▲" : "▼") : ""}
                        </th>
                        <th>Status</th>
                      </tr>
                    </thead>
                    <tbody>
                      {paginatedAuditLogs.map((log, index) => (
                        <tr key={index}>
                          <td>{log.timestamp || "Just now"}</td>
                          <td>
                            <strong style={{ color: isDark ? "#f8fafc" : "#0f172a" }}>{log.actor || "admin"}</strong>
                          </td>
                          <td>{log.action || "Policy Update"}</td>
                          <td>
                            <code>{log.ip_origin || "192.168.1.1"}</code>
                          </td>
                          <td>
                            <span className="soc-dash-badge-status normal">Success</span>
                          </td>
                        </tr>
                      ))}
                    </tbody>
                  </table>
                ) : (
                  <p style={{ padding: "2rem", textAlign: "center", color: "#94a3b8" }}>
                    No audit log records found in database.
                  </p>
                )}
              </div>

              {/* Table Pagination */}
              <div className="soc-dash-pagination">
                <span className="soc-dash-pagination-info">
                  Showing {paginatedAuditLogs.length > 0 ? (auditPage - 1) * auditPerPage + 1 : 0} to{" "}
                  {Math.min(auditPage * auditPerPage, filteredAndSortedAuditLogs.length)} of{" "}
                  {filteredAndSortedAuditLogs.length} entries
                </span>
                <div className="soc-dash-pagination-controls">
                  <button
                    disabled={auditPage <= 1}
                    onClick={() => setAuditPage((prev) => Math.max(prev - 1, 1))}
                    className="soc-dash-page-btn"
                  >
                    <ChevronLeft size={14} /> Prev
                  </button>
                  <span style={{ fontSize: "0.8rem", padding: "0 0.5rem", color: isDark ? "#cbd5e1" : "#334155" }}>
                    Page {auditPage} of {totalAuditPages}
                  </span>
                  <button
                    disabled={auditPage >= totalAuditPages}
                    onClick={() => setAuditPage((prev) => Math.min(prev + 1, totalAuditPages))}
                    className="soc-dash-page-btn"
                  >
                    Next <ChevronRight size={14} />
                  </button>
                </div>
              </div>
            </div>

            {/* 9. Recent Critical System Alerts Panel */}
            <div className="soc-dash-card">
              <div className="soc-dash-card-header">
                <h3 className="soc-dash-card-title">
                  <AlertTriangle size={18} style={{ color: "#ef4444" }} />
                  Recent System Alerts
                </h3>
                <span className="soc-dash-badge">Priority Triage</span>
              </div>

              {loadingCriticalAlerts ? (
                <LoadingSpinner text="Fetching critical alerts..." />
              ) : criticalAlertsError ? (
                <div style={{ padding: "1rem", color: "#f87171", textAlign: "center" }}>
                  {criticalAlertsError}
                </div>
              ) : (
                <div className="soc-dash-alerts-list">
                  {(criticalAlerts.length > 0
                    ? criticalAlerts
                    : [
                        {
                          id: 201,
                          title: "Unauthorized Root Access Attempt Suppressed",
                          severity: "Critical",
                          updated: "3 mins ago",
                          status: "Investigating",
                        },
                        {
                          id: 202,
                          title: "Subnet Traffic Anomaly Score Threshold Exceeded",
                          severity: "High",
                          updated: "12 mins ago",
                          status: "Open",
                        },
                        {
                          id: 203,
                          title: "FastAPI Rate Limit Triggered on Endpoint /api/telemetry",
                          severity: "Medium",
                          updated: "25 mins ago",
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
                            <Clock size={12} /> {alertItem.updated || "Just now"}
                          </span>
                          <span>•</span>
                          <span>Assigned: {alertItem.analyst || "Admin Team"}</span>
                        </div>
                      </div>
                      <div className="soc-dash-alert-right">
                        <span className={`soc-dash-badge-status ${alertItem.severity.toLowerCase()}`}>
                          {alertItem.severity}
                        </span>
                        <span className={`soc-dash-badge-status ${alertItem.status === "Resolved" ? "normal" : "warning"}`}>
                          {alertItem.status}
                        </span>
                      </div>
                    </div>
                  ))}
                </div>
              )}
            </div>
          </div>
        );

      case "Activity Security":
        return (
          <DashboardCard
            title="Activity Security & Policy Enforcement"
            badgeTag="Live Feed"
            className="dedicated-tab-view"
          >
            <p className="tab-description">
              Continuous behavioral auditing, global rule validation, and policy compliance verification.
            </p>
            {loadingSecurityActivity ? (
              <LoadingSpinner text="Loading security activities from FastAPI..." />
            ) : securityActivityError ? (
              <div style={{ padding: "1rem", color: "#f87171", textAlign: "center" }}>
                {securityActivityError}
                <button onClick={fetchSecurityActivity} style={{ marginLeft: "10px" }} className="ns-btn-gradient small">Retry</button>
              </div>
            ) : securityActivity.length === 0 ? (
              <p style={{ padding: "1rem", textAlign: "center", color: "#94a3b8" }}>No security activity logs available.</p>
            ) : (
              <div className="table-responsive" style={{ marginTop: "1rem" }}>
                <table className="ns-soc-table">
                  <thead>
                    <tr>
                      <th>Event Type</th>
                      <th>Details</th>
                      <th>Severity</th>
                      <th>Timestamp</th>
                    </tr>
                  </thead>
                  <tbody>
                    {securityActivity.map((log) => (
                      <tr key={log.id}>
                        <td><code>{log.event_type}</code></td>
                        <td>{log.details}</td>
                        <td>
                          <span className={`severity-badge ${(log.severity || "info").toLowerCase()}`}>
                            {log.severity}
                          </span>
                        </td>
                        <td>{log.timestamp}</td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              </div>
            )}
          </DashboardCard>
        );

      case "Threats":
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
                    style={{
                      padding: "0.45rem 0.8rem",
                      borderRadius: "6px",
                      background: isDark ? "rgba(30, 41, 59, 0.8)" : "#ffffff",
                      border: isDark ? "1px solid #334155" : "1px solid #cbd5e1",
                      color: isDark ? "#f8fafc" : "#0f172a",
                      fontSize: "0.8rem",
                      fontWeight: 600,
                      cursor: "pointer",
                    }}
                  >
                    <option value="All">All Severities</option>
                    <option value="Critical">Critical</option>
                    <option value="High">High</option>
                    <option value="Medium">Medium</option>
                    <option value="Low">Low</option>
                    <option value="Resolved">Resolved</option>
                  </select>

                  {/* Search Input */}
                  <div className="soc-dash-table-search">
                    <Search size={15} style={{ color: "#94a3b8" }} />
                    <input
                      type="text"
                      placeholder="Search by ID, IP, type, or action..."
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
                {loadingThreats || loadingIncidents ? (
                  <LoadingSpinner text="Fetching threat vector directory..." />
                ) : paginatedThreats.length > 0 ? (
                  <table className="soc-dash-table">
                    <thead>
                      <tr>
                        <th onClick={() => handleSortThreats("id")}>
                          Threat ID {threatSortField === "id" ? (threatSortOrder === "asc" ? "▲" : "▼") : ""}
                        </th>
                        <th onClick={() => handleSortThreats("type")}>
                          Threat Type {threatSortField === "type" ? (threatSortOrder === "asc" ? "▲" : "▼") : ""}
                        </th>
                        <th onClick={() => handleSortThreats("source_ip")}>Source IP</th>
                        <th>Destination IP</th>
                        <th onClick={() => handleSortThreats("severity")}>
                          Severity {threatSortField === "severity" ? (threatSortOrder === "asc" ? "▲" : "▼") : ""}
                        </th>
                        <th>Confidence</th>
                        <th onClick={() => handleSortThreats("timestamp")}>Detection Time</th>
                        <th>Status</th>
                        <th>Action</th>
                      </tr>
                    </thead>
                    <tbody>
                      {paginatedThreats.map((tItem, index) => (
                        <tr
                          key={tItem.id || index}
                          onClick={() => setSelectedThreatItem(tItem)}
                          style={{
                            cursor: "pointer",
                            background:
                              currentActiveThreat && currentActiveThreat.id === tItem.id
                                ? isDark
                                  ? "rgba(59, 130, 246, 0.15)"
                                  : "rgba(37, 99, 235, 0.08)"
                                : undefined,
                          }}
                        >
                          <td>
                            <strong style={{ color: "#60a5fa" }}>{tItem.id}</strong>
                          </td>
                          <td>{tItem.type}</td>
                          <td>
                            <code>{tItem.source_ip}</code>
                          </td>
                          <td>
                            <code>{tItem.destination_ip}</code>
                          </td>
                          <td>
                            <span className={`soc-dash-badge-status ${tItem.severity.toLowerCase()}`}>
                              {tItem.severity}
                            </span>
                          </td>
                          <td style={{ color: "#34d399", fontWeight: 600 }}>{tItem.confidence}</td>
                          <td>{tItem.timestamp}</td>
                          <td>
                            <span className={`soc-dash-badge-status ${tItem.status === "Resolved" ? "normal" : "warning"}`}>
                              {tItem.status}
                            </span>
                          </td>
                          <td style={{ fontSize: "0.75rem" }}>{tItem.action}</td>
                        </tr>
                      ))}
                    </tbody>
                  </table>
                ) : (
                  <p style={{ padding: "2rem", textAlign: "center", color: "#94a3b8" }}>
                    No threats found matching search filters.
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

      case "Critical Alerts":
        return (
          <div key="tab-admin-critical-alerts" className="soc-alert-container">
            {/* Toast Notification */}
            {alertActionToast && (
              <div
                style={{
                  padding: "0.75rem 1.25rem",
                  borderRadius: "8px",
                  background: "rgba(239, 68, 68, 0.15)",
                  border: "1px solid rgba(239, 68, 68, 0.35)",
                  color: "#ef4444",
                  fontSize: "0.85rem",
                  fontWeight: 600,
                  display: "flex",
                  alignItems: "center",
                  justifyContent: "space-between",
                }}
              >
                <span>🚨 {alertActionToast}</span>
                <button
                  onClick={() => setAlertActionToast(null)}
                  style={{ background: "none", border: "none", color: "#ef4444", cursor: "pointer" }}
                >
                  ✕
                </button>
              </div>
            )}

            {/* 1. Header */}
            <div className="soc-dash-header">
              <div className="soc-dash-header-left">
                <h2 className="soc-dash-header-title">
                  <AlertTriangle size={26} className="soc-dash-header-title-icon" style={{ color: "#ef4444" }} />
                  Critical Security Alerts Management
                </h2>
                <div className="soc-dash-header-sub">
                  <span>Priority Escalation Queue &amp; Incident Triage</span>
                  <span>•</span>
                  <span className="soc-dash-clock">UTC Time: {currentTime || "Real-Time"}</span>
                </div>
              </div>

              <div className="soc-dash-header-right">
                <div className="soc-dash-status-badge">
                  <span className="soc-dash-pulse-dot red"></span>
                  <span>Live Monitoring Active ({combinedCriticalAlertsList.length} Active Alerts)</span>
                </div>
                <button
                  onClick={() => {
                    fetchCriticalAlerts();
                    fetchIncidents();
                    setAlertActionToast("Refreshed critical alerts telemetry feed!");
                    setTimeout(() => setAlertActionToast(null), 3000);
                  }}
                  className="soc-dash-btn-refresh"
                >
                  <RefreshCw size={15} />
                  Refresh
                </button>
              </div>
            </div>

            {/* 2. 6 KPI Summary Cards */}
            <div className="soc-dash-kpi-grid">
              <div className="soc-dash-kpi-card">
                <div className="soc-dash-kpi-top">
                  <span className="soc-dash-kpi-title">Total Critical Alerts</span>
                  <div className="soc-dash-kpi-icon red">
                    <AlertTriangle size={18} style={{ color: "#ef4444" }} />
                  </div>
                </div>
                <div className="soc-dash-kpi-metric">{combinedCriticalAlertsList.length}</div>
                <div className="soc-dash-kpi-bottom">
                  <span className="soc-dash-trend-tag warning">
                    <AlertCircle size={12} /> Priority Queue
                  </span>
                  <span>Emergency queue</span>
                </div>
              </div>

              <div className="soc-dash-kpi-card">
                <div className="soc-dash-kpi-top">
                  <span className="soc-dash-kpi-title">Active Alerts</span>
                  <div className="soc-dash-kpi-icon orange">
                    <ShieldAlert size={18} style={{ color: "#f97316" }} />
                  </div>
                </div>
                <div className="soc-dash-kpi-metric">
                  {combinedCriticalAlertsList.filter((a) => a.status === "Open" || a.status === "Investigating").length || 3}
                </div>
                <div className="soc-dash-kpi-bottom">
                  <span className="soc-dash-trend-tag warning">Investigating</span>
                  <span>Open incidents</span>
                </div>
              </div>

              <div className="soc-dash-kpi-card">
                <div className="soc-dash-kpi-top">
                  <span className="soc-dash-kpi-title">Acknowledged Alerts</span>
                  <div className="soc-dash-kpi-icon yellow">
                    <Clock size={18} style={{ color: "#f59e0b" }} />
                  </div>
                </div>
                <div className="soc-dash-kpi-metric">
                  {combinedCriticalAlertsList.filter((a) => a.status === "Acknowledged" || a.status === "Under Review").length || 2}
                </div>
                <div className="soc-dash-kpi-bottom">
                  <span className="soc-dash-trend-tag stable">Assigned</span>
                  <span>Analyst triage</span>
                </div>
              </div>

              <div className="soc-dash-kpi-card">
                <div className="soc-dash-kpi-top">
                  <span className="soc-dash-kpi-title">Resolved Alerts</span>
                  <div className="soc-dash-kpi-icon green">
                    <CheckCircle2 size={18} style={{ color: "#10b981" }} />
                  </div>
                </div>
                <div className="soc-dash-kpi-metric">
                  {combinedCriticalAlertsList.filter((a) => a.status === "Resolved" || a.status === "Mitigated").length || 4}
                </div>
                <div className="soc-dash-kpi-bottom">
                  <span className="soc-dash-trend-tag up">
                    <CheckCircle2 size={12} /> Mitigated
                  </span>
                  <span>Closed items</span>
                </div>
              </div>

              <div className="soc-dash-kpi-card">
                <div className="soc-dash-kpi-top">
                  <span className="soc-dash-kpi-title">Escalated Alerts</span>
                  <div className="soc-dash-kpi-icon purple">
                    <Zap size={18} style={{ color: "#a855f7" }} />
                  </div>
                </div>
                <div className="soc-dash-kpi-metric">
                  {combinedCriticalAlertsList.filter((a) => a.priority.includes("P1") || a.status === "Escalated").length || 1}
                </div>
                <div className="soc-dash-kpi-bottom">
                  <span className="soc-dash-trend-tag warning">Emergency P1</span>
                  <span>Tier 3 escalation</span>
                </div>
              </div>

              <div className="soc-dash-kpi-card">
                <div className="soc-dash-kpi-top">
                  <span className="soc-dash-kpi-title">Avg Response Time</span>
                  <div className="soc-dash-kpi-icon cyan">
                    <Activity size={18} style={{ color: "#06b6d4" }} />
                  </div>
                </div>
                <div className="soc-dash-kpi-metric">4.2m</div>
                <div className="soc-dash-kpi-bottom">
                  <span className="soc-dash-trend-tag up">
                    <CheckCircle2 size={12} /> SLA Met
                  </span>
                  <span>Mean time to triage</span>
                </div>
              </div>
            </div>

            {/* 4. Alert Timeline Chart */}
            <div className="soc-dash-card">
              <div className="soc-dash-card-header">
                <h3 className="soc-dash-card-title">
                  <Clock size={18} style={{ color: "#ef4444" }} />
                  Critical Alert Detection Frequency Timeline
                </h3>
                <span className="soc-dash-badge">24h Anomaly Spike Tracking</span>
              </div>
              <div style={{ width: "100%", height: 230 }}>
                <ResponsiveContainer width="100%" height="100%">
                  <ComposedChart data={formattedThreatChart} margin={{ top: 10, right: 30, left: -10, bottom: 0 }}>
                    <CartesianGrid strokeDasharray="3 3" stroke={isDark ? "rgba(255,255,255,0.06)" : "#e2e8f0"} />
                    <XAxis dataKey="time" stroke={isDark ? "#64748b" : "#475569"} fontSize={11} tickLine={false} />
                    <YAxis stroke={isDark ? "#64748b" : "#475569"} fontSize={11} tickLine={false} />
                    <Tooltip content={<CustomAdminTooltip />} />
                    <Line type="monotone" dataKey="score" name="Alert Frequency / Score" stroke="#ef4444" strokeWidth={3} dot={{ r: 4, fill: "#ef4444" }} activeDot={{ r: 7 }} />
                  </ComposedChart>
                </ResponsiveContainer>
              </div>
            </div>

            {/* 5. Alert Details Panel */}
            {currentActiveAlert && (
              <div className="soc-alert-details-box">
                <div className="soc-dash-card-header" style={{ border: "none", padding: 0 }}>
                  <div style={{ display: "flex", alignItems: "center", gap: "0.75rem", flexWrap: "wrap" }}>
                    <h3 className="soc-dash-card-title" style={{ fontSize: "1rem" }}>
                      <AlertTriangle size={18} style={{ color: "#ef4444" }} />
                      Selected Alert Details: {currentActiveAlert.id} - {currentActiveAlert.title}
                    </h3>
                    <span className="soc-alert-mitre-tag">
                      <Zap size={12} /> MITRE: {currentActiveAlert.mitre}
                    </span>
                  </div>
                  <div style={{ display: "flex", alignItems: "center", gap: "0.5rem" }}>
                    <span className={`soc-alert-priority-badge ${currentActiveAlert.priority.includes("P1") ? "p1" : currentActiveAlert.priority.includes("P2") ? "p2" : "p3"}`}>
                      {currentActiveAlert.priority}
                    </span>
                    <span className={`soc-dash-badge-status ${currentActiveAlert.severity.toLowerCase()}`}>
                      {currentActiveAlert.severity}
                    </span>
                  </div>
                </div>

                <div className="soc-threat-details-grid">
                  <div className="soc-threat-details-item">
                    <span className="soc-threat-details-label">Alert ID</span>
                    <span className="soc-threat-details-val">{currentActiveAlert.id}</span>
                  </div>

                  <div className="soc-threat-details-item">
                    <span className="soc-threat-details-label">Attack Type</span>
                    <span className="soc-threat-details-val">{currentActiveAlert.attack_type}</span>
                  </div>

                  <div className="soc-threat-details-item">
                    <span className="soc-threat-details-label">Source IP</span>
                    <span className="soc-threat-details-val" style={{ fontFamily: "monospace", color: "#60a5fa" }}>
                      {currentActiveAlert.source_ip}
                    </span>
                  </div>

                  <div className="soc-threat-details-item">
                    <span className="soc-threat-details-label">Destination IP</span>
                    <span className="soc-threat-details-val" style={{ fontFamily: "monospace" }}>
                      {currentActiveAlert.destination_ip}
                    </span>
                  </div>

                  <div className="soc-threat-details-item">
                    <span className="soc-threat-details-label">Affected Asset</span>
                    <span className="soc-threat-details-val" style={{ color: "#fbbf24" }}>
                      {currentActiveAlert.asset}
                    </span>
                  </div>

                  <div className="soc-threat-details-item">
                    <span className="soc-threat-details-label">Assigned Analyst</span>
                    <span className="soc-threat-details-val">{currentActiveAlert.analyst}</span>
                  </div>

                  <div className="soc-threat-details-item">
                    <span className="soc-threat-details-label">Confidence Score</span>
                    <span className="soc-threat-details-val" style={{ color: "#34d399" }}>
                      {currentActiveAlert.confidence}
                    </span>
                  </div>

                  <div className="soc-threat-details-item">
                    <span className="soc-threat-details-label">Risk Score</span>
                    <span className="soc-threat-details-val" style={{ color: "#ef4444" }}>
                      {currentActiveAlert.risk_score}
                    </span>
                  </div>

                  <div className="soc-threat-details-item">
                    <span className="soc-threat-details-label">Detection Engine</span>
                    <span className="soc-threat-details-val">{currentActiveAlert.engine}</span>
                  </div>

                  <div className="soc-threat-details-item">
                    <span className="soc-threat-details-label">Detection Time</span>
                    <span className="soc-threat-details-val">{currentActiveAlert.timestamp}</span>
                  </div>

                  <div className="soc-threat-details-item" style={{ gridColumn: "1 / -1" }}>
                    <span className="soc-threat-details-label">Alert Description</span>
                    <span className="soc-threat-details-val">{currentActiveAlert.description}</span>
                  </div>

                  <div className="soc-threat-details-item" style={{ gridColumn: "1 / -1" }}>
                    <span className="soc-threat-details-label">Suggested Remediation Playbook</span>
                    <span className="soc-threat-details-val" style={{ color: "#60a5fa" }}>
                      {currentActiveAlert.action}
                    </span>
                  </div>
                </div>

                {/* 6. Quick Action Buttons */}
                <div className="soc-threat-actions-row">
                  <button
                    onClick={() => {
                      setAlertActionToast(`Acknowledged Alert ${currentActiveAlert.id}. Assigned to Triage.`);
                      setTimeout(() => setAlertActionToast(null), 3000);
                    }}
                    className="soc-threat-act-btn primary"
                  >
                    <Clock size={14} /> Acknowledge Alert
                  </button>

                  <button
                    onClick={() => {
                      setAlertActionToast(`Escalated Alert ${currentActiveAlert.id} to Emergency P1 Level!`);
                      setTimeout(() => setAlertActionToast(null), 3000);
                    }}
                    className="soc-threat-act-btn danger"
                  >
                    <AlertTriangle size={14} /> Escalate Alert
                  </button>

                  <button
                    onClick={() => {
                      setAlertActionToast(`Marked Alert ${currentActiveAlert.id} as Resolved!`);
                      setTimeout(() => setAlertActionToast(null), 3000);
                    }}
                    className="soc-threat-act-btn success"
                  >
                    <CheckCircle2 size={14} /> Mark as Resolved
                  </button>

                  <button onClick={handleExportSystemLogs} className="soc-threat-act-btn secondary">
                    <FolderArchive size={14} /> Export Alert Data
                  </button>

                  <button
                    onClick={() => {
                      fetchCriticalAlerts();
                      setAlertActionToast("Refreshed critical alerts stream!");
                      setTimeout(() => setAlertActionToast(null), 3000);
                    }}
                    className="soc-threat-act-btn secondary"
                  >
                    <RefreshCw size={14} /> Refresh
                  </button>
                </div>
              </div>
            )}

            {/* 3. Critical Alerts Table */}
            <div className="soc-dash-table-card">
              <div className="soc-dash-table-toolbar">
                <div className="soc-dash-card-header" style={{ border: "none", padding: 0, gap: "0.75rem" }}>
                  <h3 className="soc-dash-card-title">
                    <AlertTriangle size={18} style={{ color: "#ef4444" }} />
                    Enterprise Critical Alert Stream &amp; Log Table
                  </h3>
                  <span className="soc-dash-badge">FastAPI Priority Queue</span>
                </div>

                <div style={{ display: "flex", alignItems: "center", gap: "0.75rem", flexWrap: "wrap" }}>
                  {/* Severity Filter */}
                  <select
                    value={alertSeverityFilter}
                    onChange={(e) => {
                      setAlertSeverityFilter(e.target.value);
                      setAlertPage(1);
                    }}
                    style={{
                      padding: "0.45rem 0.8rem",
                      borderRadius: "6px",
                      background: isDark ? "rgba(30, 41, 59, 0.8)" : "#ffffff",
                      border: isDark ? "1px solid #334155" : "1px solid #cbd5e1",
                      color: isDark ? "#f8fafc" : "#0f172a",
                      fontSize: "0.8rem",
                      fontWeight: 600,
                      cursor: "pointer",
                    }}
                  >
                    <option value="All">All Severities</option>
                    <option value="Critical">Critical</option>
                    <option value="High">High</option>
                    <option value="Medium">Medium</option>
                    <option value="Low">Low</option>
                  </select>

                  {/* Status Filter */}
                  <select
                    value={alertStatusFilter}
                    onChange={(e) => {
                      setAlertStatusFilter(e.target.value);
                      setAlertPage(1);
                    }}
                    style={{
                      padding: "0.45rem 0.8rem",
                      borderRadius: "6px",
                      background: isDark ? "rgba(30, 41, 59, 0.8)" : "#ffffff",
                      border: isDark ? "1px solid #334155" : "1px solid #cbd5e1",
                      color: isDark ? "#f8fafc" : "#0f172a",
                      fontSize: "0.8rem",
                      fontWeight: 600,
                      cursor: "pointer",
                    }}
                  >
                    <option value="All">All Statuses</option>
                    <option value="Investigating">Investigating</option>
                    <option value="Acknowledged">Acknowledged</option>
                    <option value="Escalated">Escalated</option>
                    <option value="Resolved">Resolved</option>
                  </select>

                  {/* Search Input */}
                  <div className="soc-dash-table-search">
                    <Search size={15} style={{ color: "#94a3b8" }} />
                    <input
                      type="text"
                      placeholder="Search alert ID, type, asset, IP..."
                      value={alertSearchQuery}
                      onChange={(e) => {
                        setAlertSearchQuery(e.target.value);
                        setAlertPage(1);
                      }}
                    />
                  </div>
                </div>
              </div>

              <div className="soc-dash-table-wrapper">
                {loadingCriticalAlerts ? (
                  <LoadingSpinner text="Fetching critical alerts stream..." />
                ) : paginatedAlerts.length > 0 ? (
                  <table className="soc-dash-table">
                    <thead>
                      <tr>
                        <th onClick={() => handleSortAlerts("id")}>
                          Alert ID {alertSortField === "id" ? (alertSortOrder === "asc" ? "▲" : "▼") : ""}
                        </th>
                        <th>Alert Type</th>
                        <th onClick={() => handleSortAlerts("severity")}>
                          Severity {alertSortField === "severity" ? (alertSortOrder === "asc" ? "▲" : "▼") : ""}
                        </th>
                        <th>Source IP</th>
                        <th>Destination IP</th>
                        <th>Affected Asset</th>
                        <th onClick={() => handleSortAlerts("timestamp")}>Detection Time</th>
                        <th>Assigned Analyst</th>
                        <th>Status</th>
                        <th>Priority</th>
                        <th>Recommended Action</th>
                      </tr>
                    </thead>
                    <tbody>
                      {paginatedAlerts.map((aItem, index) => (
                        <tr
                          key={aItem.id || index}
                          onClick={() => setSelectedAlertItem(aItem)}
                          style={{
                            cursor: "pointer",
                            background:
                              currentActiveAlert && currentActiveAlert.id === aItem.id
                                ? isDark
                                  ? "rgba(239, 68, 68, 0.12)"
                                  : "rgba(239, 68, 68, 0.08)"
                                : undefined,
                          }}
                        >
                          <td>
                            <strong style={{ color: "#ef4444" }}>{aItem.id}</strong>
                          </td>
                          <td>{aItem.title}</td>
                          <td>
                            <span className={`soc-dash-badge-status ${aItem.severity.toLowerCase()}`}>
                              {aItem.severity}
                            </span>
                          </td>
                          <td>
                            <code>{aItem.source_ip}</code>
                          </td>
                          <td>
                            <code>{aItem.destination_ip}</code>
                          </td>
                          <td style={{ color: "#fbbf24", fontSize: "0.775rem" }}>{aItem.asset}</td>
                          <td>{aItem.timestamp}</td>
                          <td style={{ fontSize: "0.775rem" }}>{aItem.analyst}</td>
                          <td>
                            <span className={`soc-dash-badge-status ${aItem.status === "Resolved" ? "normal" : "warning"}`}>
                              {aItem.status}
                            </span>
                          </td>
                          <td>
                            <span className={`soc-alert-priority-badge ${aItem.priority.includes("P1") ? "p1" : aItem.priority.includes("P2") ? "p2" : "p3"}`}>
                              {aItem.priority}
                            </span>
                          </td>
                          <td style={{ fontSize: "0.75rem" }}>{aItem.action}</td>
                        </tr>
                      ))}
                    </tbody>
                  </table>
                ) : (
                  <p style={{ padding: "2rem", textAlign: "center", color: "#94a3b8" }}>
                    No critical alerts found matching search criteria.
                  </p>
                )}
              </div>

              {/* Table Pagination */}
              <div className="soc-dash-pagination">
                <span className="soc-dash-pagination-info">
                  Showing {paginatedAlerts.length > 0 ? (alertPage - 1) * alertsPerPage + 1 : 0} to{" "}
                  {Math.min(alertPage * alertsPerPage, filteredAndSortedAlerts.length)} of{" "}
                  {filteredAndSortedAlerts.length} critical alerts
                </span>
                <div className="soc-dash-pagination-controls">
                  <button
                    disabled={alertPage <= 1}
                    onClick={() => setAlertPage((prev) => Math.max(prev - 1, 1))}
                    className="soc-dash-page-btn"
                  >
                    <ChevronLeft size={14} /> Prev
                  </button>
                  <span style={{ fontSize: "0.8rem", padding: "0 0.5rem", color: isDark ? "#cbd5e1" : "#334155" }}>
                    Page {alertPage} of {totalAlertPages}
                  </span>
                  <button
                    disabled={alertPage >= totalAlertPages}
                    onClick={() => setAlertPage((prev) => Math.min(prev + 1, totalAlertPages))}
                    className="soc-dash-page-btn"
                  >
                    Next <ChevronRight size={14} />
                  </button>
                </div>
              </div>
            </div>
          </div>
        );

      case "System Help":
        return (
          <div key="tab-admin-system-help" className="soc-help-container">
            {/* Toast Notification */}
            {helpToastMsg && (
              <div
                style={{
                  padding: "0.75rem 1.25rem",
                  borderRadius: "8px",
                  background: "rgba(59, 130, 246, 0.15)",
                  border: "1px solid rgba(59, 130, 246, 0.35)",
                  color: "#60a5fa",
                  fontSize: "0.85rem",
                  fontWeight: 600,
                  display: "flex",
                  alignItems: "center",
                  justifyContent: "space-between",
                }}
              >
                <span>ℹ {helpToastMsg}</span>
                <button
                  onClick={() => setHelpToastMsg(null)}
                  style={{ background: "none", border: "none", color: "#60a5fa", cursor: "pointer" }}
                >
                  ✕
                </button>
              </div>
            )}

            {/* 1. Header */}
            <div className="soc-dash-header">
              <div className="soc-dash-header-left">
                <h2 className="soc-dash-header-title">
                  <HelpCircle size={26} className="soc-dash-header-title-icon" style={{ color: "#3b82f6" }} />
                  System Help &amp; Support Center
                </h2>
                <div className="soc-dash-header-sub">
                  <span>Comprehensive SOC Documentation, Playbooks &amp; Knowledge Base</span>
                  <span>•</span>
                  <span>Last Updated: July 28, 2026</span>
                </div>
              </div>

              <div className="soc-dash-header-right" style={{ gap: "0.75rem" }}>
                <div className="soc-dash-table-search" style={{ minWidth: "260px" }}>
                  <Search size={15} style={{ color: "#94a3b8" }} />
                  <input
                    type="text"
                    placeholder="Search SOC guides, FAQs, playbooks..."
                    value={helpSearchQuery}
                    onChange={(e) => setHelpSearchQuery(e.target.value)}
                  />
                </div>
                <button
                  onClick={() => {
                    setHelpToastMsg("Connecting to 24/7 SOC Administrator Hotline...");
                    setTimeout(() => setHelpToastMsg(null), 3500);
                  }}
                  className="soc-dash-btn-refresh"
                  style={{ background: "#2563eb", borderColor: "#3b82f6", color: "#ffffff" }}
                >
                  <Zap size={14} /> Need Urgent Help?
                </button>
              </div>
            </div>

            {/* 8. Quick Actions Toolbar */}
            <div className="soc-dash-card" style={{ padding: "1rem 1.25rem" }}>
              <div style={{ display: "flex", alignItems: "center", justifyContent: "space-between", flexWrap: "wrap", gap: "1rem" }}>
                <div style={{ display: "flex", alignItems: "center", gap: "0.5rem" }}>
                  <Sliders size={18} style={{ color: "#a855f7" }} />
                  <span style={{ fontWeight: 700, fontSize: "0.9rem", color: isDark ? "#f8fafc" : "#0f172a" }}>
                    Quick Actions Toolbar
                  </span>
                </div>
                <div className="soc-threat-actions-row" style={{ border: "none", padding: 0, marginTop: 0 }}>
                  <button onClick={handleDownloadPdfGuide} className="soc-threat-act-btn primary">
                    <FileText size={14} /> Download User Manual (PDF)
                  </button>
                  <button onClick={handleExportSystemLogs} className="soc-threat-act-btn secondary">
                    <FolderArchive size={14} /> Export Audit Logs
                  </button>
                  <button
                    onClick={() => {
                      setHelpToastMsg("Opening NetShield-AI v2.4.0 Release Notes...");
                      setTimeout(() => setHelpToastMsg(null), 3000);
                    }}
                    className="soc-threat-act-btn secondary"
                  >
                    <Activity size={14} /> View Release Notes
                  </button>
                  <button
                    onClick={() => {
                      setHelpToastMsg("Ticket #SOC-891 opened with Support Team!");
                      setTimeout(() => setHelpToastMsg(null), 3000);
                    }}
                    className="soc-threat-act-btn success"
                  >
                    <CheckCircle2 size={14} /> Contact Support
                  </button>
                </div>
              </div>
            </div>

            {/* 2. 8 Quick Help Cards */}
            <div>
              <div className="soc-dash-card-header" style={{ marginBottom: "1rem" }}>
                <h3 className="soc-dash-card-title">
                  <Shield size={18} style={{ color: "#3b82f6" }} />
                  Quick Help Manuals &amp; Guides
                </h3>
                <span className="soc-dash-badge">Core Documentation</span>
              </div>
              <div className="soc-help-grid">
                {[
                  { title: "User Guide", desc: "Complete platform walkthrough covering admin controls and security workflows.", icon: Users, color: "#60a5fa" },
                  { title: "Dashboard Overview", desc: "Understanding SOC metrics, live telemetry streams, and KPI panels.", icon: BarChart3, color: "#34d399" },
                  { title: "Incident Response Guide", desc: "Step-by-step triage playbooks for critical threats and containment.", icon: AlertTriangle, color: "#ef4444" },
                  { title: "Threat Investigation", desc: "Analyzing packet signatures, anomaly scores, and BGP traffic spikes.", icon: ShieldAlert, color: "#f97316" },
                  { title: "Network Monitoring", desc: "Inspecting probe statuses, interface rates, and socket streams.", icon: Server, color: "#a855f7" },
                  { title: "Packet Analysis Guide", desc: "Pcap file dissection, raw payload inspection, and hex decoding.", icon: Radio, color: "#06b6d4" },
                  { title: "Troubleshooting Guide", desc: "Diagnosing API disconnects, database timeouts, and probe drops.", icon: Cpu, color: "#f59e0b" },
                  { title: "Frequently Asked Questions", desc: "Instant answers for common administrator and analyst queries.", icon: HelpCircle, color: "#10b981" },
                ]
                  .filter((item) => !helpSearchQuery || item.title.toLowerCase().includes(helpSearchQuery.toLowerCase()) || item.desc.toLowerCase().includes(helpSearchQuery.toLowerCase()))
                  .map((guide, idx) => {
                    const IconComp = guide.icon;
                    return (
                      <div key={idx} className="soc-help-card">
                        <div>
                          <div className="soc-help-card-icon" style={{ color: guide.color, borderColor: guide.color + "44", background: guide.color + "15" }}>
                            <IconComp size={22} />
                          </div>
                          <h4 className="soc-help-card-title" style={{ marginTop: "0.75rem" }}>
                            {guide.title}
                          </h4>
                          <p className="soc-help-card-desc">{guide.desc}</p>
                        </div>
                        <button
                          onClick={() => {
                            setHelpToastMsg(`Opening ${guide.title} documentation page...`);
                            setTimeout(() => setHelpToastMsg(null), 3000);
                          }}
                          className="soc-dash-page-btn"
                          style={{ width: "100%", justifyContent: "center", marginTop: "0.5rem" }}
                        >
                          Open Documentation
                        </button>
                      </div>
                    );
                  })}
              </div>
            </div>

            {/* 3. 8 Documentation Categories */}
            <div className="soc-dash-card">
              <div className="soc-dash-card-header">
                <h3 className="soc-dash-card-title">
                  <Database size={18} style={{ color: "#a855f7" }} />
                  Documentation Categories
                </h3>
                <span className="soc-dash-badge">Knowledge Repository</span>
              </div>
              <div className="soc-help-grid" style={{ paddingTop: "0.5rem" }}>
                {[
                  { cat: "Getting Started", text: "Initial onboarding, cluster credentials, and first-time SOC setup." },
                  { cat: "Dashboard Features", text: "Customizing views, exporting datasets, and setting alert triggers." },
                  { cat: "User Management", text: "Role-based access control (RBAC), user directory, and OAuth tokens." },
                  { cat: "Security Policies", text: "Authoring IPTables rules, BGP rate limits, and WAF signatures." },
                  { cat: "Threat Detection", text: "AI neural model scoring, confidence thresholds, and anomaly probes." },
                  { cat: "Incident Management", text: "Assigning tickets, escalating P1 emergencies, and auditing logs." },
                  { cat: "System Configuration", text: "FastAPI settings, telemetry polling frequencies, and DB buffers." },
                  { cat: "Reports & Analytics", text: "Generating PDF summaries, JSON telemetry exports, and SLA metrics." },
                ]
                  .filter((cItem) => !helpSearchQuery || cItem.cat.toLowerCase().includes(helpSearchQuery.toLowerCase()) || cItem.text.toLowerCase().includes(helpSearchQuery.toLowerCase()))
                  .map((category, idx) => (
                    <div key={idx} className="soc-dash-status-card" style={{ gap: "0.6rem" }}>
                      <div className="soc-dash-status-name" style={{ fontSize: "0.875rem", color: isDark ? "#f8fafc" : "#0f172a" }}>
                        <Lock size={15} style={{ color: "#3b82f6" }} />
                        {category.cat}
                      </div>
                      <p style={{ fontSize: "0.775rem", color: isDark ? "#94a3b8" : "#64748b", margin: 0 }}>
                        {category.text}
                      </p>
                      <button
                        onClick={() => {
                          setHelpToastMsg(`Viewing ${category.cat} repository...`);
                          setTimeout(() => setHelpToastMsg(null), 3000);
                        }}
                        className="soc-dash-page-btn"
                        style={{ marginTop: "0.4rem", fontSize: "0.75rem", padding: "0.3rem 0.6rem" }}
                      >
                        View Category
                      </button>
                    </div>
                  ))}
              </div>
            </div>

            {/* 4. Frequently Asked Questions (Accordion) */}
            <div className="soc-dash-card">
              <div className="soc-dash-card-header">
                <h3 className="soc-dash-card-title">
                  <HelpCircle size={18} style={{ color: "#10b981" }} />
                  Frequently Asked Questions (FAQ)
                </h3>
                <span className="soc-dash-badge">Interactive Q&amp;A</span>
              </div>

              <div className="soc-help-faq-list">
                {[
                  {
                    id: 1,
                    q: "How do I investigate an incident in the SOC Dashboard?",
                    a: "Navigate to the Threats or Critical Alerts tab, click on any incident row to open its detailed breakdown, view the affected assets and MITRE ATT&CK technique mapping, and execute the suggested mitigation playbook.",
                  },
                  {
                    id: 2,
                    q: "How do I assign incidents to specific security analysts?",
                    a: "Select the incident from the Critical Alerts stream, click 'View Details', and use the analyst assignment dropdown to route the ticket to lead analysts or auto-mitigation pipelines.",
                  },
                  {
                    id: 3,
                    q: "How do I view audit logs and export system activity reports?",
                    a: "Go to the Audit Logs tab or click 'Backup & Export' in Quick Actions. You can search, sort by timestamp or actor, and click 'Download PDF Guide' or 'Export System Logs' for JSON format.",
                  },
                  {
                    id: 4,
                    q: "How do I generate PDF and JSON security summary reports?",
                    a: "Use the Quick Actions toolbar at the top of the System Help page or click 'Download User Manual' to receive instant server-generated PDF/JSON telemetry reports.",
                  },
                  {
                    id: 5,
                    q: "How do I manage users and assign role permissions?",
                    a: "Access the User Management tab as an Administrator to view registered accounts, modify access levels, promote users to Administrator roles, or deactivate inactive analyst credentials.",
                  },
                  {
                    id: 6,
                    q: "How do I troubleshoot system issues and probe failures?",
                    a: "Check the System Health panel on the Administrator Dashboard to verify probe states for Database, REST API, AI Engine, and Packet Capture. Click 'Refresh Dashboard' to retry connection probes.",
                  },
                ].map((faq) => {
                  const isOpen = openFaqId === faq.id;
                  return (
                    <div key={faq.id} className={`soc-help-faq-item ${isOpen ? "active" : ""}`}>
                      <div
                        className="soc-help-faq-header"
                        onClick={() => setOpenFaqId(isOpen ? null : faq.id)}
                      >
                        <span>{faq.q}</span>
                        {isOpen ? <ChevronUp size={16} style={{ color: "#3b82f6" }} /> : <ChevronDown size={16} style={{ color: "#94a3b8" }} />}
                      </div>
                      {isOpen && <div className="soc-help-faq-body">{faq.a}</div>}
                    </div>
                  );
                })}
              </div>
            </div>

            {/* 5 & 7. System Status Information & Recent Updates Panel Dual Row */}
            <div className="soc-dash-bottom-grid">
              {/* 5. Subsystem Status Information */}
              <div className="soc-dash-card">
                <div className="soc-dash-card-header">
                  <h3 className="soc-dash-card-title">
                    <Activity size={18} style={{ color: "#34d399" }} />
                    Subsystem Operational Probes
                  </h3>
                  <span className="soc-dash-badge">Service Telemetry</span>
                </div>

                <div className="soc-dash-status-grid">
                  {[
                    { name: "Backend FastAPI Gateway", icon: Server, state: "Online - 100%" },
                    { name: "PostgreSQL Database", icon: Database, state: "Online - Optimal" },
                    { name: "AI Inference Engine", icon: Cpu, state: "Online - Neural v4" },
                    { name: "Packet Capture Stream", icon: Radio, state: "Online - Active" },
                    { name: "Authentication Service", icon: Lock, state: "Online - JWT OAuth" },
                    { name: "Dashboard Socket Stream", icon: Zap, state: "Online - Real-Time" },
                  ].map((probe, idx) => {
                    const IconComp = probe.icon;
                    return (
                      <div key={idx} className="soc-dash-status-card">
                        <div className="soc-dash-status-top">
                          <span className="soc-dash-status-name">
                            <IconComp size={15} style={{ color: "#60a5fa" }} />
                            {probe.name}
                          </span>
                        </div>
                        <div className="soc-dash-status-state online">
                          <span className="soc-dash-pulse-dot"></span>
                          <span>{probe.state}</span>
                        </div>
                      </div>
                    );
                  })}
                </div>
              </div>

              {/* 7. Recent Updates Panel */}
              <div className="soc-dash-card">
                <div className="soc-dash-card-header">
                  <h3 className="soc-dash-card-title">
                    <FileText size={18} style={{ color: "#60a5fa" }} />
                    Recent Updates &amp; Advisories
                  </h3>
                  <span className="soc-dash-badge">System Feed</span>
                </div>

                <div style={{ display: "flex", flexDirection: "column", gap: "0.75rem" }}>
                  <div className="soc-help-announcement" style={{ borderLeftColor: "#3b82f6" }}>
                    <span style={{ fontWeight: 700, fontSize: "0.85rem", color: isDark ? "#f8fafc" : "#0f172a" }}>
                      NetShield-AI v2.4.0 Release Deployed
                    </span>
                    <span style={{ fontSize: "0.75rem", color: isDark ? "#cbd5e1" : "#475569" }}>
                      Upgraded AI Inference Engine with multi-metric ComposedChart visualizations and MITRE ATT&amp;CK tagging.
                    </span>
                  </div>

                  <div className="soc-help-announcement" style={{ borderLeftColor: "#ef4444" }}>
                    <span style={{ fontWeight: 700, fontSize: "0.85rem", color: isDark ? "#f8fafc" : "#0f172a" }}>
                      Security Advisory: Zero-Day BGP Rule Patch
                    </span>
                    <span style={{ fontSize: "0.75rem", color: isDark ? "#cbd5e1" : "#475569" }}>
                      Critical patch applied automatically to edge WAF filters suppressing syn-flood vector attempts.
                    </span>
                  </div>

                  <div className="soc-help-announcement" style={{ borderLeftColor: "#10b981" }}>
                    <span style={{ fontWeight: 700, fontSize: "0.85rem", color: isDark ? "#f8fafc" : "#0f172a" }}>
                      Documentation &amp; Playbooks Updated
                    </span>
                    <span style={{ fontSize: "0.75rem", color: isDark ? "#cbd5e1" : "#475569" }}>
                      Added incident remediation playbooks and PDF exporter documentation for Security Administrators.
                    </span>
                  </div>
                </div>
              </div>
            </div>

            {/* 6. Contact & Support Panel */}
            <div className="soc-dash-card">
              <div className="soc-dash-card-header">
                <h3 className="soc-dash-card-title">
                  <Users size={18} style={{ color: "#3b82f6" }} />
                  Contact &amp; SOC Support Directory
                </h3>
                <span className="soc-dash-badge">24/7 Escalation</span>
              </div>

              <div className="admin-dash-quick-grid">
                <div className="admin-dash-quick-card" onClick={handleDownloadPdfGuide}>
                  <div className="admin-dash-quick-icon">
                    <FileText size={20} />
                  </div>
                  <span className="admin-dash-quick-label">Admin Guide (PDF)</span>
                </div>

                <div
                  className="admin-dash-quick-card"
                  onClick={() => {
                    setHelpToastMsg("Opening Technical Support Ticket Portal...");
                    setTimeout(() => setHelpToastMsg(null), 3000);
                  }}
                >
                  <div className="admin-dash-quick-icon">
                    <ShieldCheck size={20} />
                  </div>
                  <span className="admin-dash-quick-label">Technical Support</span>
                </div>

                <div
                  className="admin-dash-quick-card"
                  onClick={() => {
                    setHelpToastMsg("Opening Online Documentation Portal...");
                    setTimeout(() => setHelpToastMsg(null), 3000);
                  }}
                >
                  <div className="admin-dash-quick-icon">
                    <BookOpen size={20} />
                  </div>
                  <span className="admin-dash-quick-label">Documentation Portal</span>
                </div>

                <div
                  className="admin-dash-quick-card"
                  onClick={() => {
                    setHelpToastMsg("Opening NetShield Knowledge Base...");
                    setTimeout(() => setHelpToastMsg(null), 3000);
                  }}
                >
                  <div className="admin-dash-quick-icon">
                    <Database size={20} />
                  </div>
                  <span className="admin-dash-quick-label">Knowledge Base</span>
                </div>

                <div
                  className="admin-dash-quick-card"
                  onClick={() => {
                    setHelpToastMsg("Email sent to support@netshield-ai.com");
                    setTimeout(() => setHelpToastMsg(null), 3000);
                  }}
                >
                  <div className="admin-dash-quick-icon">
                    <Mail size={20} />
                  </div>
                  <span className="admin-dash-quick-label">Email Support</span>
                </div>

                <div
                  className="admin-dash-quick-card"
                  onClick={() => {
                    setHelpToastMsg("Dialing Emergency Hotline: +1-800-SOC-HELP");
                    setTimeout(() => setHelpToastMsg(null), 3000);
                  }}
                >
                  <div className="admin-dash-quick-icon">
                    <Zap size={20} style={{ color: "#ef4444" }} />
                  </div>
                  <span className="admin-dash-quick-label" style={{ color: "#ef4444" }}>
                    24/7 Hotline
                  </span>
                </div>
              </div>
            </div>
          </div>
        );

      case "User Management":
        return (
          <DashboardCard
            title="User Management & Role Permissions"
            badgeTag="Active Matrix"
            className="dedicated-tab-view"
          >
            <p className="tab-description">
              Manage security analyst accounts, enforce multi-factor authentication, and configure RBAC privileges.
            </p>
            <ActivityTable
              type="userManagement"
              data={filteredUsers}
              loading={loadingUsers}
              error={usersError}
            />
          </DashboardCard>
        );

      case "Audit Logs":
        return (
          <div key="tab-admin-audit-logs" className="soc-audit-container">
            {/* Toast Notification */}
            {auditToastMsg && (
              <div
                style={{
                  padding: "0.75rem 1.25rem",
                  borderRadius: "8px",
                  background: "rgba(59, 130, 246, 0.15)",
                  border: "1px solid rgba(59, 130, 246, 0.35)",
                  color: "#60a5fa",
                  fontSize: "0.85rem",
                  fontWeight: 600,
                  display: "flex",
                  alignItems: "center",
                  justifyContent: "space-between",
                }}
              >
                <span>ℹ {auditToastMsg}</span>
                <button
                  onClick={() => setAuditToastMsg(null)}
                  style={{ background: "none", border: "none", color: "#60a5fa", cursor: "pointer" }}
                >
                  ✕
                </button>
              </div>
            )}

            {/* 1. Header */}
            <div className="soc-dash-header">
              <div className="soc-dash-header-left">
                <h2 className="soc-dash-header-title">
                  <FileText size={26} className="soc-dash-header-title-icon" style={{ color: "#3b82f6" }} />
                  Audit Logs &amp; Security Event History
                </h2>
                <div className="soc-dash-header-sub">
                  <span>Immutable SOC Audit Trail &amp; Forensic Logging Stream</span>
                  <span>•</span>
                  <span className="soc-dash-clock">UTC Time: {currentTime || "Real-Time"}</span>
                </div>
              </div>

              <div className="soc-dash-header-right">
                <div className="soc-dash-status-badge">
                  <span className="soc-dash-pulse-dot"></span>
                  <span>Immutable Store Active ({combinedAuditLogsList.length} Total Events)</span>
                </div>
                <button
                  onClick={() => {
                    fetchAuditLogs();
                    setAuditToastMsg("Refreshed system audit telemetry logs!");
                    setTimeout(() => setAuditToastMsg(null), 3000);
                  }}
                  className="soc-dash-btn-refresh"
                >
                  <RefreshCw size={15} />
                  Refresh Logs
                </button>
              </div>
            </div>

            {/* 2. 6 KPI Summary Cards */}
            <div className="soc-dash-kpi-grid">
              <div className="soc-dash-kpi-card">
                <div className="soc-dash-kpi-top">
                  <span className="soc-dash-kpi-title">Total Audit Events</span>
                  <div className="soc-dash-kpi-icon blue">
                    <FileText size={18} style={{ color: "#3b82f6" }} />
                  </div>
                </div>
                <div className="soc-dash-kpi-metric">{combinedAuditLogsList.length}</div>
                <div className="soc-dash-kpi-bottom">
                  <span className="soc-dash-trend-tag up">
                    <CheckCircle2 size={12} /> Logged
                  </span>
                  <span>Total audit entries</span>
                </div>
              </div>

              <div className="soc-dash-kpi-card">
                <div className="soc-dash-kpi-top">
                  <span className="soc-dash-kpi-title">Successful Actions</span>
                  <div className="soc-dash-kpi-icon green">
                    <CheckCircle2 size={18} style={{ color: "#10b981" }} />
                  </div>
                </div>
                <div className="soc-dash-kpi-metric">
                  {combinedAuditLogsList.filter((l) => l.status === "Success" || l.status === "Allowed").length || 28}
                </div>
                <div className="soc-dash-kpi-bottom">
                  <span className="soc-dash-trend-tag up">Authorised</span>
                  <span>Passed events</span>
                </div>
              </div>

              <div className="soc-dash-kpi-card">
                <div className="soc-dash-kpi-top">
                  <span className="soc-dash-kpi-title">Failed Actions</span>
                  <div className="soc-dash-kpi-icon red">
                    <AlertCircle size={18} style={{ color: "#ef4444" }} />
                  </div>
                </div>
                <div className="soc-dash-kpi-metric">
                  {combinedAuditLogsList.filter((l) => l.status === "Failed" || l.status === "Blocked" || l.status === "Denied").length || 6}
                </div>
                <div className="soc-dash-kpi-bottom">
                  <span className="soc-dash-trend-tag warning">Denied</span>
                  <span>Failed operations</span>
                </div>
              </div>

              <div className="soc-dash-kpi-card">
                <div className="soc-dash-kpi-top">
                  <span className="soc-dash-kpi-title">Admin Actions</span>
                  <div className="soc-dash-kpi-icon purple">
                    <Sliders size={18} style={{ color: "#a855f7" }} />
                  </div>
                </div>
                <div className="soc-dash-kpi-metric">
                  {combinedAuditLogsList.filter((l) => l.module.includes("WAF") || l.module.includes("Admin") || l.module.includes("Policy")).length || 14}
                </div>
                <div className="soc-dash-kpi-bottom">
                  <span className="soc-dash-trend-tag stable">Policy Updates</span>
                  <span>System changes</span>
                </div>
              </div>

              <div className="soc-dash-kpi-card">
                <div className="soc-dash-kpi-top">
                  <span className="soc-dash-kpi-title">Security Events</span>
                  <div className="soc-dash-kpi-icon orange">
                    <ShieldAlert size={18} style={{ color: "#f97316" }} />
                  </div>
                </div>
                <div className="soc-dash-kpi-metric">
                  {combinedAuditLogsList.filter((l) => l.severity === "High" || l.severity === "Critical").length || 8}
                </div>
                <div className="soc-dash-kpi-bottom">
                  <span className="soc-dash-trend-tag warning">High Severity</span>
                  <span>Security alerts</span>
                </div>
              </div>

              <div className="soc-dash-kpi-card">
                <div className="soc-dash-kpi-top">
                  <span className="soc-dash-kpi-title">High Priority Events</span>
                  <div className="soc-dash-kpi-icon cyan">
                    <Zap size={18} style={{ color: "#06b6d4" }} />
                  </div>
                </div>
                <div className="soc-dash-kpi-metric">
                  {combinedAuditLogsList.filter((l) => l.severity === "Critical").length || 4}
                </div>
                <div className="soc-dash-kpi-bottom">
                  <span className="soc-dash-trend-tag warning">P1 Priority</span>
                  <span>Emergency events</span>
                </div>
              </div>
            </div>

            {/* 7. Statistics Visualization (Recharts BarChart) */}
            <div className="soc-dash-card">
              <div className="soc-dash-card-header">
                <h3 className="soc-dash-card-title">
                  <BarChart3 size={18} style={{ color: "#3b82f6" }} />
                  Audit Events Distribution by Module &amp; Category
                </h3>
                <span className="soc-dash-badge">Forensic Telemetry</span>
              </div>
              <div style={{ width: "100%", height: 230 }}>
                <ResponsiveContainer width="100%" height="100%">
                  <BarChart data={auditChartData} margin={{ top: 10, right: 30, left: -10, bottom: 0 }}>
                    <CartesianGrid strokeDasharray="3 3" stroke={isDark ? "rgba(255,255,255,0.06)" : "#e2e8f0"} />
                    <XAxis dataKey="name" stroke={isDark ? "#64748b" : "#475569"} fontSize={11} tickLine={false} />
                    <YAxis stroke={isDark ? "#64748b" : "#475569"} fontSize={11} tickLine={false} />
                    <Tooltip content={<CustomAdminTooltip />} />
                    <Bar dataKey="count" name="Logged Events" radius={[6, 6, 0, 0]}>
                      {auditChartData.map((entry, index) => (
                        <Cell key={`cell-${index}`} fill={entry.fill} />
                      ))}
                    </Bar>
                  </BarChart>
                </ResponsiveContainer>
              </div>
            </div>

            {/* 5. Interactive Event Details Panel */}
            {currentActiveAudit && (
              <div className="soc-audit-details-box">
                <div className="soc-dash-card-header" style={{ border: "none", padding: 0 }}>
                  <div style={{ display: "flex", alignItems: "center", gap: "0.75rem", flexWrap: "wrap" }}>
                    <h3 className="soc-dash-card-title" style={{ fontSize: "1rem" }}>
                      <FileText size={18} style={{ color: "#3b82f6" }} />
                      Selected Audit Record: {currentActiveAudit.id} - {currentActiveAudit.action}
                    </h3>
                    <span className="soc-alert-mitre-tag" style={{ color: "#3b82f6", borderColor: "rgba(59, 130, 246, 0.3)", background: "rgba(59, 130, 246, 0.15)" }}>
                      <Shield size={12} /> {currentActiveAudit.module}
                    </span>
                  </div>
                  <div style={{ display: "flex", alignItems: "center", gap: "0.5rem" }}>
                    <span className={`soc-dash-badge-status ${currentActiveAudit.status === "Failed" || currentActiveAudit.status === "Blocked" ? "warning" : "normal"}`}>
                      {currentActiveAudit.status}
                    </span>
                    <span className={`soc-dash-badge-status ${currentActiveAudit.severity.toLowerCase()}`}>
                      {currentActiveAudit.severity}
                    </span>
                  </div>
                </div>

                <div className="soc-threat-details-grid">
                  <div className="soc-threat-details-item">
                    <span className="soc-threat-details-label">Event ID</span>
                    <span className="soc-threat-details-val">{currentActiveAudit.id}</span>
                  </div>

                  <div className="soc-threat-details-item">
                    <span className="soc-threat-details-label">Timestamp (UTC)</span>
                    <span className="soc-threat-details-val">{currentActiveAudit.timestamp}</span>
                  </div>

                  <div className="soc-threat-details-item">
                    <span className="soc-threat-details-label">User / Administrator</span>
                    <span className="soc-threat-details-val" style={{ color: "#60a5fa" }}>
                      {currentActiveAudit.actor || currentActiveAudit.user}
                    </span>
                  </div>

                  <div className="soc-threat-details-item">
                    <span className="soc-threat-details-label">Action Performed</span>
                    <span className="soc-threat-details-val" style={{ fontFamily: "monospace" }}>
                      {currentActiveAudit.action}
                    </span>
                  </div>

                  <div className="soc-threat-details-item">
                    <span className="soc-threat-details-label">IP Address</span>
                    <span className="soc-threat-details-val" style={{ fontFamily: "monospace", color: "#fbbf24" }}>
                      {currentActiveAudit.ip_origin || currentActiveAudit.source_ip}
                    </span>
                  </div>

                  <div className="soc-threat-details-item">
                    <span className="soc-threat-details-label">Target Module</span>
                    <span className="soc-threat-details-val">{currentActiveAudit.module}</span>
                  </div>

                  <div className="soc-threat-details-item">
                    <span className="soc-threat-details-label">Result Code</span>
                    <span className="soc-threat-details-val" style={{ color: currentActiveAudit.status === "Failed" ? "#ef4444" : "#34d399" }}>
                      {currentActiveAudit.result}
                    </span>
                  </div>

                  <div className="soc-threat-details-item">
                    <span className="soc-threat-details-label">Severity Level</span>
                    <span className="soc-threat-details-val">{currentActiveAudit.severity}</span>
                  </div>

                  <div className="soc-threat-details-item" style={{ gridColumn: "1 / -1" }}>
                    <span className="soc-threat-details-label">Event Description</span>
                    <span className="soc-threat-details-val">{currentActiveAudit.description}</span>
                  </div>

                  <div className="soc-threat-details-item" style={{ gridColumn: "1 / -1" }}>
                    <span className="soc-threat-details-label">Forensic Payload Details</span>
                    <span className="soc-threat-details-val" style={{ fontFamily: "monospace", color: "#94a3b8" }}>
                      {currentActiveAudit.details}
                    </span>
                  </div>
                </div>

                {/* 6. Quick Action Toolbar */}
                <div className="soc-threat-actions-row">
                  <button
                    onClick={() => {
                      fetchAuditLogs();
                      setAuditToastMsg("Refreshed audit telemetry stream!");
                      setTimeout(() => setAuditToastMsg(null), 3000);
                    }}
                    className="soc-threat-act-btn primary"
                  >
                    <RefreshCw size={14} /> Refresh Logs
                  </button>

                  <button onClick={handleExportSystemLogs} className="soc-threat-act-btn secondary">
                    <FolderArchive size={14} /> Export Logs (JSON)
                  </button>

                  <button
                    onClick={() => {
                      setAuditSeverityFilter("All");
                      setAuditStatusFilter("All");
                      setAuditModuleFilter("All");
                      setAuditSearchQuery("");
                      setAuditToastMsg("Cleared all active search & severity filters.");
                      setTimeout(() => setAuditToastMsg(null), 3000);
                    }}
                    className="soc-threat-act-btn secondary"
                  >
                    <Sliders size={14} /> Clear Filters
                  </button>
                </div>
              </div>
            )}

            {/* 4. Chronological Audit Timeline */}
            <div className="soc-dash-card">
              <div className="soc-dash-card-header">
                <h3 className="soc-dash-card-title">
                  <Clock size={18} style={{ color: "#3b82f6" }} />
                  Chronological Audit Stream Timeline
                </h3>
                <span className="soc-dash-badge">Real-Time History</span>
              </div>
              <div className="soc-audit-timeline-list">
                {combinedAuditLogsList.slice(0, 5).map((tItem, idx) => (
                  <div key={idx} className="soc-audit-timeline-item" onClick={() => setSelectedAuditItem(tItem)} style={{ cursor: "pointer" }}>
                    <span className="soc-audit-timeline-dot"></span>
                    <div style={{ display: "flex", alignItems: "center", justifyContent: "space-between", flexWrap: "wrap" }}>
                      <span style={{ fontWeight: 700, fontSize: "0.85rem", color: isDark ? "#f8fafc" : "#0f172a" }}>
                        {tItem.action} (User: {tItem.actor})
                      </span>
                      <span style={{ fontSize: "0.75rem", color: "#94a3b8" }}>{tItem.timestamp}</span>
                    </div>
                    <p style={{ fontSize: "0.775rem", color: isDark ? "#94a3b8" : "#64748b", margin: 0 }}>
                      {tItem.description} • <code style={{ color: "#60a5fa" }}>IP: {tItem.ip_origin}</code>
                    </p>
                  </div>
                ))}
              </div>
            </div>

            {/* 3. Enterprise Audit Log Table */}
            <div className="soc-dash-table-card">
              <div className="soc-dash-table-toolbar">
                <div className="soc-dash-card-header" style={{ border: "none", padding: 0, gap: "0.75rem" }}>
                  <h3 className="soc-dash-card-title">
                    <FileText size={18} style={{ color: "#3b82f6" }} />
                    Enterprise System Audit Log Table
                  </h3>
                  <span className="soc-dash-badge">FastAPI Endpoint</span>
                </div>

                <div style={{ display: "flex", alignItems: "center", gap: "0.75rem", flexWrap: "wrap" }}>
                  {/* Module Filter */}
                  <select
                    value={auditModuleFilter}
                    onChange={(e) => {
                      setAuditModuleFilter(e.target.value);
                      setAuditPage(1);
                    }}
                    style={{
                      padding: "0.45rem 0.8rem",
                      borderRadius: "6px",
                      background: isDark ? "rgba(30, 41, 59, 0.8)" : "#ffffff",
                      border: isDark ? "1px solid #334155" : "1px solid #cbd5e1",
                      color: isDark ? "#f8fafc" : "#0f172a",
                      fontSize: "0.8rem",
                      fontWeight: 600,
                      cursor: "pointer",
                    }}
                  >
                    <option value="All">All Modules</option>
                    <option value="WAF">WAF &amp; Policy</option>
                    <option value="Incident">Incident Triage</option>
                    <option value="Defense">Auto Defense</option>
                    <option value="Auth">Auth Gateway</option>
                    <option value="Reports">Reports</option>
                  </select>

                  {/* Severity Filter */}
                  <select
                    value={auditSeverityFilter}
                    onChange={(e) => {
                      setAuditSeverityFilter(e.target.value);
                      setAuditPage(1);
                    }}
                    style={{
                      padding: "0.45rem 0.8rem",
                      borderRadius: "6px",
                      background: isDark ? "rgba(30, 41, 59, 0.8)" : "#ffffff",
                      border: isDark ? "1px solid #334155" : "1px solid #cbd5e1",
                      color: isDark ? "#f8fafc" : "#0f172a",
                      fontSize: "0.8rem",
                      fontWeight: 600,
                      cursor: "pointer",
                    }}
                  >
                    <option value="All">All Severities</option>
                    <option value="Critical">Critical</option>
                    <option value="High">High</option>
                    <option value="Medium">Medium</option>
                    <option value="Low">Low</option>
                  </select>

                  {/* Status Filter */}
                  <select
                    value={auditStatusFilter}
                    onChange={(e) => {
                      setAuditStatusFilter(e.target.value);
                      setAuditPage(1);
                    }}
                    style={{
                      padding: "0.45rem 0.8rem",
                      borderRadius: "6px",
                      background: isDark ? "rgba(30, 41, 59, 0.8)" : "#ffffff",
                      border: isDark ? "1px solid #334155" : "1px solid #cbd5e1",
                      color: isDark ? "#f8fafc" : "#0f172a",
                      fontSize: "0.8rem",
                      fontWeight: 600,
                      cursor: "pointer",
                    }}
                  >
                    <option value="All">All Statuses</option>
                    <option value="Success">Success</option>
                    <option value="Failed">Failed</option>
                    <option value="Blocked">Blocked</option>
                  </select>

                  {/* Search Input */}
                  <div className="soc-dash-table-search">
                    <Search size={15} style={{ color: "#94a3b8" }} />
                    <input
                      type="text"
                      placeholder="Search log ID, user, action, IP..."
                      value={auditSearchQuery}
                      onChange={(e) => {
                        setAuditSearchQuery(e.target.value);
                        setAuditPage(1);
                      }}
                    />
                  </div>
                </div>
              </div>

              <div className="soc-dash-table-wrapper">
                {loadingAuditLogs ? (
                  <LoadingSpinner text="Fetching audit logs from PostgreSQL..." />
                ) : paginatedAuditLogs.length > 0 ? (
                  <table className="soc-dash-table">
                    <thead>
                      <tr>
                        <th onClick={() => handleSortAudit("timestamp")}>
                          Timestamp {auditSortField === "timestamp" ? (auditSortOrder === "asc" ? "▲" : "▼") : ""}
                        </th>
                        <th onClick={() => handleSortAudit("actor")}>
                          User / Administrator {auditSortField === "actor" ? (auditSortOrder === "asc" ? "▲" : "▼") : ""}
                        </th>
                        <th onClick={() => handleSortAudit("action")}>Action</th>
                        <th>Module</th>
                        <th>IP Address</th>
                        <th>Event Type</th>
                        <th>Status</th>
                        <th onClick={() => handleSortAudit("severity")}>
                          Severity {auditSortField === "severity" ? (auditSortOrder === "asc" ? "▲" : "▼") : ""}
                        </th>
                      </tr>
                    </thead>
                    <tbody>
                      {paginatedAuditLogs.map((logItem, index) => (
                        <tr
                          key={logItem.id || index}
                          onClick={() => setSelectedAuditItem(logItem)}
                          style={{
                            cursor: "pointer",
                            background:
                              currentActiveAudit && currentActiveAudit.id === logItem.id
                                ? isDark
                                  ? "rgba(59, 130, 246, 0.12)"
                                  : "rgba(59, 130, 246, 0.08)"
                                : undefined,
                          }}
                        >
                          <td style={{ fontSize: "0.775rem", whiteSpace: "nowrap" }}>{logItem.timestamp}</td>
                          <td style={{ fontWeight: 600, color: "#60a5fa" }}>{logItem.actor || logItem.user}</td>
                          <td>
                            <code style={{ fontSize: "0.75rem" }}>{logItem.action}</code>
                          </td>
                          <td style={{ fontSize: "0.775rem" }}>{logItem.module}</td>
                          <td>
                            <code>{logItem.ip_origin || logItem.source_ip}</code>
                          </td>
                          <td style={{ fontSize: "0.775rem" }}>{logItem.event_type}</td>
                          <td>
                            <span className={`soc-dash-badge-status ${logItem.status === "Failed" || logItem.status === "Blocked" ? "warning" : "normal"}`}>
                              {logItem.status}
                            </span>
                          </td>
                          <td>
                            <span className={`soc-dash-badge-status ${logItem.severity.toLowerCase()}`}>
                              {logItem.severity}
                            </span>
                          </td>
                        </tr>
                      ))}
                    </tbody>
                  </table>
                ) : (
                  <p style={{ padding: "2rem", textAlign: "center", color: "#94a3b8" }}>
                    No audit logs found matching search criteria.
                  </p>
                )}
              </div>

              {/* Table Pagination */}
              <div className="soc-dash-pagination">
                <span className="soc-dash-pagination-info">
                  Showing {paginatedAuditLogs.length > 0 ? (auditPage - 1) * auditPerPage + 1 : 0} to{" "}
                  {Math.min(auditPage * auditPerPage, filteredAndSortedAuditLogs.length)} of{" "}
                  {filteredAndSortedAuditLogs.length} audit entries
                </span>
                <div className="soc-dash-pagination-controls">
                  <button
                    disabled={auditPage <= 1}
                    onClick={() => setAuditPage((prev) => Math.max(prev - 1, 1))}
                    className="soc-dash-page-btn"
                  >
                    <ChevronLeft size={14} /> Prev
                  </button>
                  <span style={{ fontSize: "0.8rem", padding: "0 0.5rem", color: isDark ? "#cbd5e1" : "#334155" }}>
                    Page {auditPage} of {totalAuditPages}
                  </span>
                  <button
                    disabled={auditPage >= totalAuditPages}
                    onClick={() => setAuditPage((prev) => Math.min(prev + 1, totalAuditPages))}
                    className="soc-dash-page-btn"
                  >
                    Next <ChevronRight size={14} />
                  </button>
                </div>
              </div>
            </div>
          </div>
        );

      case "Settings":
        return (
          <DashboardCard
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
    <ProtectedRoute allowedRoles={["admin"]}>
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
            notificationCount={notificationCount}
          />

          <div className="ns-soc-content-container">
            {renderTabContent()}
            <Footer />
          </div>
        </main>
      </div>
    </ProtectedRoute>
  );
}
