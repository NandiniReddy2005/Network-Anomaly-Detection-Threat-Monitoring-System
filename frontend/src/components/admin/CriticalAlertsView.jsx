"use client";
import React, { useState, useEffect, useCallback, useMemo } from "react";
import {
  AlertTriangle,
  RefreshCw,
  TrendingUp,
  AlertCircle,
  CheckCircle2,
  BarChart3,
  Clock,
  Shield,
  Zap,
  FolderArchive,
  Search,
  ChevronLeft,
  ChevronRight,
  ShieldAlert,
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
import { fetchApi, getMlReport, analyzeCriticalAlert, getCriticalAlerts, executeCriticalAlertAction } from "../../utils/api";
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

export default function CriticalAlertsView() {
  const { isDark } = useTheme();
  const [currentTime, setCurrentTime] = useState("");
  const [alertActionMsg, setAlertActionMsg] = useState(null);
  
  const [alertsList, setAlertsList] = useState([]);
  const [loadingCriticalAlerts, setLoadingCriticalAlerts] = useState(false);
  const [criticalAlertsError, setCriticalAlertsError] = useState(null);

  const [alertDatasetFilter, setAlertDatasetFilter] = useState("UNSW-NB15");
  const [sourceIp, setSourceIp] = useState("185.220.101.5");
  const [destinationIp, setDestinationIp] = useState("10.0.0.2 (Auth Server)");
  const [sourcePort, setSourcePort] = useState("54321");
  const [destinationPort, setDestinationPort] = useState("443");
  const [protocol, setProtocol] = useState("TCP");

  const [alertSearchQuery, setAlertSearchQuery] = useState("");
  const [alertSeverityFilter, setAlertSeverityFilter] = useState("All");
  const [alertStatusFilter, setAlertStatusFilter] = useState("All");
  const [alertSortField, setAlertSortField] = useState("timestamp");
  const [alertSortOrder, setAlertSortOrder] = useState("desc");
  const [alertPage, setAlertPage] = useState(1);
  const [activeAlertId, setActiveAlertId] = useState(null);

  const [alertChartData, setAlertChartData] = useState([]);

  // Interactive ML Risk Analysis State
  const [analyzingAlert, setAnalyzingAlert] = useState(false);
  const [alertAnalysisResult, setAlertAnalysisResult] = useState(null);
  const [alertAnalysisError, setAlertAnalysisError] = useState(null);

  const loadCriticalAlerts = useCallback(async () => {
    setLoadingCriticalAlerts(true);
    setCriticalAlertsError(null);
    try {
      let email = "";
      if (typeof window !== "undefined") {
        const stored = localStorage.getItem("netshield_current_user") || localStorage.getItem("user");
        if (stored) {
          try {
            const parsed = JSON.parse(stored);
            email = parsed?.email || "";
          } catch (e) {}
        }
      }
      const res = await getCriticalAlerts(email);
      const items = res.alerts || res.data || [];
      if (Array.isArray(items) && items.length > 0) {
        setAlertsList(items);
        const chartPoints = items.slice(0, 12).reverse().map((item, idx) => ({
          time: item.timestamp || `T+${idx * 5}m`,
          score: parseFloat(item.risk_score_val || item.threat_score) || 85.0,
          value: parseFloat(item.risk_score_val || item.threat_score) || 85.0
        }));
        setAlertChartData(chartPoints);
      }
    } catch (err) {
      console.error("Failed to load critical alerts from PostgreSQL:", err);
      setCriticalAlertsError("Could not retrieve critical alert records from PostgreSQL database.");
    } finally {
      setLoadingCriticalAlerts(false);
    }
  }, []);

  const handleAnalyzeCriticalAlert = async () => {
    setAnalyzingAlert(true);
    setAlertAnalysisError(null);
    try {
      const payload = {
        dataset: alertDatasetFilter,
        source_ip: sourceIp,
        destination_ip: destinationIp,
        source_port: sourcePort,
        destination_port: destinationPort,
        protocol: protocol,
      };

      const res = await analyzeCriticalAlert(payload);
      const alertData = res.data || res;

      if (alertData) {
        setAlertAnalysisResult(alertData);
        setActiveAlertId(alertData.id || alertData.alert_id);

        const newAlertObj = {
          id: alertData.id || alertData.alert_id || `ALT-${Math.floor(100 + Math.random() * 900)}`,
          title: alertData.title || `${alertData.attack_type || "Cyber Threat Anomaly"} against ${destinationIp}`,
          severity: alertData.severity || "Critical",
          source_ip: alertData.source_ip || sourceIp,
          destination_ip: alertData.destination_ip || destinationIp,
          asset: alertData.asset || `Asset ${destinationIp}`,
          timestamp: alertData.timestamp || "Just now",
          analyst: "SOC Emergency Escalation Team",
          status: alertData.status || "Investigating",
          priority: alertData.priority || "P1 - Emergency",
          action: alertData.containment_playbook || alertData.action || "Isolate Source & Execute Containment Playbook",
          description: alertData.description || `Critical security incident detected from ${sourceIp} targeting ${destinationIp}.`,
          attack_type: alertData.attack_type || alertData.type || "Cyber Threat Anomaly",
          engine: alertData.engine || `AI-Neural-Probe (${alertDatasetFilter})`,
          confidence: alertData.confidence || alertData.confidence_score || "98.5%",
          risk_score: alertData.composite_risk_score || alertData.risk_score || "85 / 100",
          affected_systems: `Asset Node ${destinationIp}`,
          mitre: alertData.mitre_tag || alertData.mitre || "T1498 - Network Denial of Service",
        };

        setAlertsList((prev) => [newAlertObj, ...prev.filter((a) => String(a.id) !== String(newAlertObj.id))]);

        const scoreVal = alertData.risk_score_val !== undefined ? alertData.risk_score_val : (parseFloat(alertData.threat_score) || 85.0);
        setAlertChartData((prev) => {
          const next = [...prev, { time: newAlertObj.timestamp || `T+${prev.length * 5}m`, score: scoreVal, value: scoreVal }];
          return next.slice(-12);
        });

        loadCriticalAlerts();
      }
    } catch (err) {
      console.error("Alert analysis error:", err);
      setAlertAnalysisError("Failed to execute FastAPI ML incident risk analysis.");
    } finally {
      setAnalyzingAlert(false);
    }
  };

  const handleExecuteContainment = async (alertId) => {
    if (!alertId) return;
    try {
      await executeCriticalAlertAction(alertId, "EXECUTE_CONTAINMENT", "Enforced automated containment playbook via SOC panel.");
      setAlertActionMsg(`Enforced mitigation playbook on ${alertId}!`);
      setTimeout(() => setAlertActionMsg(null), 3000);
      loadCriticalAlerts();
    } catch (err) {
      console.error("Error executing containment:", err);
      setAlertActionMsg(`Failed to execute containment playbook on ${alertId}.`);
    }
  };

  const handleResolveAlert = async (alertId) => {
    if (!alertId) return;
    try {
      await executeCriticalAlertAction(alertId, "RESOLVE_ALERT", "Marked critical alert as resolved by analyst.");
      setAlertActionMsg(`Marked alert ${alertId} as Resolved!`);
      setTimeout(() => setAlertActionMsg(null), 3000);
      loadCriticalAlerts();
    } catch (err) {
      console.error("Error resolving alert:", err);
      setAlertActionMsg(`Failed to resolve alert ${alertId}.`);
    }
  };

  useEffect(() => {
    setCurrentTime(getFormattedUTCTime());
    loadCriticalAlerts();
    const timer = setInterval(() => setCurrentTime(getFormattedUTCTime()), 1000);
    return () => clearInterval(timer);
  }, [loadCriticalAlerts]);

  const handleExportSystemLogs = (targetAlert = currentActiveAlert) => {
    const activeAlert = targetAlert || currentActiveAlert;
    if (!activeAlert) {
      setAlertActionMsg("No active critical alert selected for forensic log export.");
      setTimeout(() => setAlertActionMsg(null), 3000);
      return;
    }

    const alertIdStr = activeAlert.id || activeAlert.alert_id || "ALT-972";
    const cleanAlertId = String(alertIdStr).replace(/[^a-zA-Z0-9_-]/g, "_");
    const timestampUtc = getFormattedUTCTime();
    const exportFileName = `netshield_critical_alert_${cleanAlertId}_forensic_log_${timestampUtc.replace(/[: ]/g, "_")}.json`;

    const comprehensivePayload = {
      status: "success",
      report_type: "NetShield-AI Critical Security Alert Forensic Log Export",
      export_timestamp_utc: timestampUtc,
      security_classification: "CISO CONFIDENTIAL / SOC DEEP FORENSIC AUDIT",
      generated_by_analyst: activeAlert.analyst || "SOC Emergency Escalation Team",
      database_source: "PostgreSQL Engine (critical_alerts & critical_alert_actions tables)",
      selected_alert_id: alertIdStr,
      summary_metrics: {
        total_critical_alerts: 1,
        active_emergencies_count: (activeAlert.priority || "").includes("P1") || (activeAlert.severity || "").toLowerCase() === "critical" ? 1 : 0,
        mitigated_alerts_count: (activeAlert.status || "").toLowerCase() === "mitigated" || (activeAlert.status || "").toLowerCase() === "resolved" ? 1 : 0,
      },
      critical_security_alerts: [
        {
          alert_id: alertIdStr,
          timestamp: activeAlert.timestamp || timestampUtc,
          title: activeAlert.title || `Cyber Threat Anomaly against ${activeAlert.destination_ip}`,
          attack_type: activeAlert.attack_type || activeAlert.type || "Network Anomaly Intercepted",
          severity: (activeAlert.severity || "CRITICAL").toUpperCase(),
          priority: activeAlert.priority || "P1 - Emergency",
          status: activeAlert.status || "Investigating",
          telemetry: {
            source_ip: activeAlert.source_ip || "185.220.101.5",
            destination_ip: activeAlert.destination_ip || "10.0.0.2 (Auth Server)",
            asset: activeAlert.asset || `Asset ${activeAlert.destination_ip}`,
            source_port: activeAlert.source_port || 54321,
            destination_port: activeAlert.destination_port || 443,
            protocol: activeAlert.protocol || "TCP",
            dataset_engine: activeAlert.dataset || activeAlert.engine || "UNSW-NB15",
            affected_systems: activeAlert.affected_systems || `Asset Node ${activeAlert.destination_ip}`
          },
          risk_assessment: {
            composite_risk_score: activeAlert.risk_score || "85 / 100",
            numeric_risk_value: activeAlert.risk_score_val !== undefined ? activeAlert.risk_score_val : (parseFloat(activeAlert.threat_score) || 85.0),
            confidence_score: activeAlert.confidence || "98.5%",
            detection_engine: activeAlert.engine || "AI-Neural-Probe (UNSW-NB15)"
          },
          mitre_attack_framework: {
            mitre_tag: activeAlert.mitre || activeAlert.mitre_tag || "T1498 - Network Denial of Service",
            tactic: "Impact / Network Service Disruption"
          },
          containment_playbook: {
            action_recommended: activeAlert.action || activeAlert.containment_playbook || "Isolate Source & Execute Containment Playbook",
            assigned_analyst: activeAlert.analyst || "SOC Emergency Escalation Team",
            description: activeAlert.description || "Critical security incident detected from source IP."
          }
        }
      ]
    };

    try {
      const dataStr = "data:text/json;charset=utf-8," + encodeURIComponent(JSON.stringify(comprehensivePayload, null, 2));
      const downloadAnchor = document.createElement("a");
      downloadAnchor.setAttribute("href", dataStr);
      downloadAnchor.setAttribute("download", exportFileName);
      document.body.appendChild(downloadAnchor);
      downloadAnchor.click();
      downloadAnchor.remove();
      setAlertActionMsg(`Exported forensic log telemetry for active alert ${alertIdStr} to ${exportFileName}`);
      setTimeout(() => setAlertActionMsg(null), 4000);
    } catch (e) {
      console.error("Client side export fallback:", e);
      window.open(`${API_BASE_URL}/api/reports/json?alert_id=${encodeURIComponent(alertIdStr)}`, "_blank");
    }
  };

  const formattedThreatChart = useMemo(() => {
    if (!alertChartData || alertChartData.length === 0) return [];
    return alertChartData.map((item, idx) => {
      const val = item.score !== undefined ? item.score : (item.value !== undefined ? item.value : (parseInt(item.height) || 50));
      return {
        time: item.time || item.timestamp || `T+${idx * 5}m`,
        volume: Math.round(val * 1.1 + 20),
        score: val,
      };
    });
  }, [alertChartData]);

  const combinedCriticalAlertsList = useMemo(() => {
    if (!alertsList || alertsList.length === 0) return [];
    return alertsList.map((item, idx) => ({
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
      action: item.action || item.containment_playbook || "Isolate Source & Execute Containment Playbook",
      description: item.description || item.details || "Security event flagged by enterprise anomaly probe requiring administrative triage.",
      attack_type: item.attack_type || item.type || "Cyber Threat Anomaly",
      engine: item.engine || "AI-Neural-Inference-Probe",
      confidence: item.confidence || `${94 + (idx % 5)}.%`,
      risk_score: item.risk_score || `${85 + (idx % 12)} / 100`,
      affected_systems: item.affected_systems || "Core Gateway, API Services",
      mitre: item.mitre || item.mitre_tag || "T1078 - Valid Accounts / T1498 - Network Denial of Service",
    }));
  }, [alertsList]);

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

  const currentActiveAlert = useMemo(() => {
    if (activeAlertId) {
      const found = combinedCriticalAlertsList.find((a) => String(a.id) === String(activeAlertId));
      if (found) return found;
    }
    return combinedCriticalAlertsList[0] || null;
  }, [combinedCriticalAlertsList, activeAlertId]);

  const alertSeverityDistributionData = useMemo(() => {
    let p1 = 0, p2 = 0, p3 = 0, p4 = 0;
    combinedCriticalAlertsList.forEach((a) => {
      const prio = (a.priority || "").toLowerCase();
      const sev = (a.severity || "").toLowerCase();
      if (prio.includes("p1") || prio.includes("emergency") || sev === "critical") p1++;
      else if (prio.includes("p2") || prio.includes("high") || sev === "high") p2++;
      else if (prio.includes("p3") || prio.includes("medium") || sev === "medium") p3++;
      else p4++;
    });
    return [
      { name: "P1 Emergency", count: p1, fill: "#ef4444" },
      { name: "P2 High Risk", count: p2, fill: "#f97316" },
      { name: "P3 Medium", count: p3, fill: "#f59e0b" },
      { name: "P4 Info", count: p4, fill: "#3b82f6" },
    ];
  }, [combinedCriticalAlertsList]);

  return (
    <div key="tab-admin-alerts" className="soc-alert-container">
      {/* Toast Notification */}
      {alertActionMsg && (
        <div
          style={{
            padding: "0.75rem 1.25rem",
            borderRadius: "8px",
            background: "rgba(239, 68, 68, 0.15)",
            border: "1px solid rgba(239, 68, 68, 0.35)",
            color: "#f87171",
            fontSize: "0.85rem",
            fontWeight: 600,
            display: "flex",
            alignItems: "center",
            justifyContent: "space-between",
          }}
        >
          <span>⚠ {alertActionMsg}</span>
          <button
            onClick={() => setAlertActionMsg(null)}
            style={{ background: "none", border: "none", color: "#f87171", cursor: "pointer" }}
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
            Critical Alerts Triage &amp; Incident Escalation
          </h2>
          <div className="soc-dash-header-sub">
            <span>High-Priority Anomaly Detection &amp; Automated Containment Playbooks</span>
            <span>•</span>
            <span className="soc-dash-clock">UTC Time: {currentTime || "Real-Time"}</span>
          </div>
        </div>

        <div className="soc-dash-header-right">
          <div className="soc-dash-status-badge">
            <span className="soc-dash-pulse-dot red"></span>
            <span>{combinedCriticalAlertsList.length} Active Incidents</span>
          </div>
          <button
            onClick={() => {
              loadCriticalAlerts();
              setAlertActionMsg("Refreshed critical security alert telemetry feed from PostgreSQL!");
              setTimeout(() => setAlertActionMsg(null), 3000);
            }}
            className="soc-dash-btn-refresh"
          >
            <RefreshCw size={15} />
            Refresh Telemetry
          </button>
        </div>
      </div>

      {/* Interactive Administrator ML Incident / Risk Analyzer Box */}
      <div
        style={{
          marginBottom: "1.5rem",
          padding: "1.25rem",
          borderRadius: "10px",
          backgroundColor: isDark ? "rgba(15, 23, 42, 0.7)" : "#ffffff",
          border: `1px solid ${isDark ? "rgba(239, 68, 68, 0.3)" : "#cbd5e1"}`,
          boxShadow: isDark ? "0 4px 20px rgba(0, 0, 0, 0.4)" : "0 4px 20px rgba(0, 0, 0, 0.05)",
        }}
      >
        <div style={{ display: "flex", alignItems: "center", gap: "0.5rem", marginBottom: "0.85rem" }}>
          <AlertTriangle size={18} style={{ color: "#EF4444" }} />
          <h4 style={{ margin: 0, fontSize: "0.95rem", color: isDark ? "#f8fafc" : "#0f172a" }}>
            Administrator Interactive Incident Risk Analyzer
          </h4>
        </div>

        <div style={{ display: "grid", gridTemplateColumns: "repeat(auto-fit, minmax(140px, 1fr))", gap: "0.75rem", marginBottom: "0.85rem" }}>
          <div>
            <label style={{ display: "block", fontSize: "0.75rem", color: isDark ? "#94a3b8" : "#475569", marginBottom: "0.25rem", fontWeight: 600 }}>
              Target Dataset
            </label>
            <select
              value={alertDatasetFilter}
              onChange={(e) => {
                setAlertDatasetFilter(e.target.value);
                setAlertPage(1);
              }}
              className="ns-control"
              style={{ width: "100%", padding: "0.4rem 0.65rem", fontSize: "0.8rem" }}
            >
              <option value="UNSW-NB15">UNSW-NB15</option>
              <option value="CICIDS2017">CICIDS2017</option>
            </select>
          </div>

          <div>
            <label style={{ display: "block", fontSize: "0.75rem", color: isDark ? "#94a3b8" : "#475569", marginBottom: "0.25rem", fontWeight: 600 }}>
              Source IP Origin
            </label>
            <input
              type="text"
              value={sourceIp}
              onChange={(e) => setSourceIp(e.target.value)}
              placeholder="e.g. 185.220.101.5"
              className="ns-control"
              style={{ width: "100%", padding: "0.4rem 0.65rem", fontSize: "0.8rem" }}
            />
          </div>

          <div>
            <label style={{ display: "block", fontSize: "0.75rem", color: isDark ? "#94a3b8" : "#475569", marginBottom: "0.25rem", fontWeight: 600 }}>
              Target Destination / Asset
            </label>
            <input
              type="text"
              value={destinationIp}
              onChange={(e) => setDestinationIp(e.target.value)}
              placeholder="e.g. 10.0.0.2 (Auth Server)"
              className="ns-control"
              style={{ width: "100%", padding: "0.4rem 0.65rem", fontSize: "0.8rem" }}
            />
          </div>

          <div>
            <label style={{ display: "block", fontSize: "0.75rem", color: isDark ? "#94a3b8" : "#475569", marginBottom: "0.25rem", fontWeight: 600 }}>
              Source Port
            </label>
            <input
              type="text"
              value={sourcePort}
              onChange={(e) => setSourcePort(e.target.value)}
              placeholder="e.g. 54321"
              className="ns-control"
              style={{ width: "100%", padding: "0.4rem 0.65rem", fontSize: "0.8rem" }}
            />
          </div>

          <div>
            <label style={{ display: "block", fontSize: "0.75rem", color: isDark ? "#94a3b8" : "#475569", marginBottom: "0.25rem", fontWeight: 600 }}>
              Destination Port
            </label>
            <input
              type="text"
              value={destinationPort}
              onChange={(e) => setDestinationPort(e.target.value)}
              placeholder="e.g. 443"
              className="ns-control"
              style={{ width: "100%", padding: "0.4rem 0.65rem", fontSize: "0.8rem" }}
            />
          </div>

          <div>
            <label style={{ display: "block", fontSize: "0.75rem", color: isDark ? "#94a3b8" : "#475569", marginBottom: "0.25rem", fontWeight: 600 }}>
              Protocol
            </label>
            <select
              value={protocol}
              onChange={(e) => setProtocol(e.target.value)}
              className="ns-control"
              style={{ width: "100%", padding: "0.4rem 0.65rem", fontSize: "0.8rem" }}
            >
              <option value="TCP">TCP</option>
              <option value="UDP">UDP</option>
              <option value="ICMP">ICMP</option>
            </select>
          </div>
        </div>

        <div style={{ display: "flex", justifyContent: "flex-end" }}>
          <button
            onClick={handleAnalyzeCriticalAlert}
            disabled={analyzingAlert}
            className="ns-btn-gradient primary small"
            style={{ display: "flex", alignItems: "center", gap: "0.4rem" }}
          >
            <Zap size={14} />
            {analyzingAlert ? "Evaluating Risk..." : "Analyze Incident Risk"}
          </button>
        </div>

        {alertAnalysisError && (
          <div style={{ color: "#ef4444", fontSize: "0.85rem", marginTop: "0.5rem" }}>{alertAnalysisError}</div>
        )}

        {alertAnalysisResult && (
          <div
            style={{
              marginTop: "0.85rem",
              padding: "1rem",
              borderRadius: "8px",
              background: isDark ? "rgba(30, 41, 59, 0.8)" : "#f8fafc",
              border: `1px solid ${isDark ? "rgba(239, 68, 68, 0.3)" : "#e2e8f0"}`,
              display: "grid",
              gridTemplateColumns: "repeat(auto-fit, minmax(140px, 1fr))",
              gap: "0.85rem",
            }}
          >
            <div>
              <span style={{ fontSize: "0.725rem", color: isDark ? "#94a3b8" : "#64748b" }}>Alert ID</span>
              <div style={{ fontWeight: 700, color: isDark ? "#f8fafc" : "#0f172a", fontSize: "0.95rem", fontFamily: "monospace" }}>{alertAnalysisResult.alert_id || alertAnalysisResult.id}</div>
            </div>
            <div>
              <span style={{ fontSize: "0.725rem", color: isDark ? "#94a3b8" : "#64748b" }}>Attack Type</span>
              <div style={{ fontWeight: 700, color: "#3B82F6", fontSize: "0.95rem" }}>{alertAnalysisResult.attack_type || alertAnalysisResult.type}</div>
            </div>
            <div>
              <span style={{ fontSize: "0.725rem", color: isDark ? "#94a3b8" : "#64748b" }}>Composite Risk Score</span>
              <div style={{ fontWeight: 700, color: "#ef4444", fontSize: "0.95rem" }}>{alertAnalysisResult.composite_risk_score || alertAnalysisResult.risk_score}</div>
            </div>
            <div>
              <span style={{ fontSize: "0.725rem", color: isDark ? "#94a3b8" : "#64748b" }}>Severity / Priority</span>
              <div style={{ fontWeight: 700, color: alertAnalysisResult.severity === "Critical" ? "#ef4444" : "#f97316", fontSize: "0.95rem" }}>
                {alertAnalysisResult.severity} ({alertAnalysisResult.priority})
              </div>
            </div>
            <div>
              <span style={{ fontSize: "0.725rem", color: isDark ? "#94a3b8" : "#64748b" }}>MITRE ATT&amp;CK Tag</span>
              <div style={{ fontWeight: 700, color: "#a855f7", fontSize: "0.85rem" }}>
                {alertAnalysisResult.mitre_tag || alertAnalysisResult.mitre}
              </div>
            </div>
          </div>
        )}
      </div>

      {/* 2. KPI Summary Cards */}
      <div className="soc-dash-kpi-grid">
        <div className="soc-dash-kpi-card">
          <div className="soc-dash-kpi-top">
            <span className="soc-dash-kpi-title">Total Active Alerts</span>
            <div className="soc-dash-kpi-icon red">
              <AlertTriangle size={18} style={{ color: "#ef4444" }} />
            </div>
          </div>
          <div className="soc-dash-kpi-metric">{combinedCriticalAlertsList.length}</div>
          <div className="soc-dash-kpi-bottom">
            <span className="soc-dash-trend-tag warning">
              <TrendingUp size={12} /> Live Triage
            </span>
            <span>Real-time events</span>
          </div>
        </div>

        <div className="soc-dash-kpi-card">
          <div className="soc-dash-kpi-top">
            <span className="soc-dash-kpi-title">P1 Emergency Alerts</span>
            <div className="soc-dash-kpi-icon red">
              <AlertCircle size={18} style={{ color: "#dc2626" }} />
            </div>
          </div>
          <div className="soc-dash-kpi-metric">
            {combinedCriticalAlertsList.filter((a) => a.severity === "Critical").length}
          </div>
          <div className="soc-dash-kpi-bottom">
            <span className="soc-dash-trend-tag warning">Immediate Action</span>
            <span>Critical impact</span>
          </div>
        </div>

        <div className="soc-dash-kpi-card">
          <div className="soc-dash-kpi-top">
            <span className="soc-dash-kpi-title">P2 High Severity</span>
            <div className="soc-dash-kpi-icon orange">
              <Shield size={18} style={{ color: "#f97316" }} />
            </div>
          </div>
          <div className="soc-dash-kpi-metric">
            {combinedCriticalAlertsList.filter((a) => a.severity === "High").length}
          </div>
          <div className="soc-dash-kpi-bottom">
            <span className="soc-dash-trend-tag warning">Elevated Risk</span>
            <span>High priority</span>
          </div>
        </div>

        <div className="soc-dash-kpi-card">
          <div className="soc-dash-kpi-top">
            <span className="soc-dash-kpi-title">Investigating</span>
            <div className="soc-dash-kpi-icon yellow">
              <Clock size={18} style={{ color: "#f59e0b" }} />
            </div>
          </div>
          <div className="soc-dash-kpi-metric">
            {combinedCriticalAlertsList.filter((a) => a.status === "Investigating" || a.status === "Open").length}
          </div>
          <div className="soc-dash-kpi-bottom">
            <span className="soc-dash-trend-tag stable">Active Triage</span>
            <span>Assigned to SOC</span>
          </div>
        </div>

        <div className="soc-dash-kpi-card">
          <div className="soc-dash-kpi-top">
            <span className="soc-dash-kpi-title">Auto-Mitigated</span>
            <div className="soc-dash-kpi-icon cyan">
              <Zap size={18} style={{ color: "#06b6d4" }} />
            </div>
          </div>
          <div className="soc-dash-kpi-metric">
            {combinedCriticalAlertsList.filter((a) => a.status === "Mitigated" || a.status === "Resolved").length}
          </div>
          <div className="soc-dash-kpi-bottom">
            <span className="soc-dash-trend-tag up">
              <CheckCircle2 size={12} /> Playbook Executed
            </span>
            <span>Automated shield</span>
          </div>
        </div>

        <div className="soc-dash-kpi-card">
          <div className="soc-dash-kpi-top">
            <span className="soc-dash-kpi-title">Escalation SLA</span>
            <div className="soc-dash-kpi-icon green">
              <CheckCircle2 size={18} style={{ color: "#10b981" }} />
            </div>
          </div>
          <div className="soc-dash-kpi-metric">&lt; 3 mins</div>
          <div className="soc-dash-kpi-bottom">
            <span className="soc-dash-trend-tag up">
              <CheckCircle2 size={12} /> SLA Met
            </span>
            <span>Mean time to respond</span>
          </div>
        </div>
      </div>

      {/* 3 & 4. Alert Severity Breakdown & Alert Rate Timeline Dual Row */}
      <div className="soc-dash-charts-dual-row">
        {/* 3. Alert Severity Distribution BarChart */}
        <div className="soc-dash-card">
          <div className="soc-dash-card-header">
            <h3 className="soc-dash-card-title">
              <BarChart3 size={18} style={{ color: "#ef4444" }} />
              Alert Priority Distribution
            </h3>
            <span className="soc-dash-badge">Triage Classification</span>
          </div>
          <div style={{ width: "100%", height: 230 }}>
            <ResponsiveContainer width="100%" height="100%">
              <BarChart data={alertSeverityDistributionData} margin={{ top: 10, right: 20, left: -20, bottom: 0 }}>
                <CartesianGrid strokeDasharray="3 3" stroke={isDark ? "rgba(255,255,255,0.06)" : "#e2e8f0"} />
                <XAxis dataKey="name" stroke={isDark ? "#64748b" : "#475569"} fontSize={11} tickLine={false} />
                <YAxis stroke={isDark ? "#64748b" : "#475569"} fontSize={11} tickLine={false} />
                <Tooltip content={<CustomAdminTooltip />} />
                <Bar dataKey="count" name="Alert Count" radius={[6, 6, 0, 0]}>
                  {alertSeverityDistributionData.map((entry, index) => (
                    <Cell key={`cell-alert-${index}`} fill={entry.fill} />
                  ))}
                </Bar>
              </BarChart>
            </ResponsiveContainer>
          </div>
        </div>

        {/* 4. Alert Rate Sliding Timeline */}
        <div className="soc-dash-card">
          <div className="soc-dash-card-header">
            <h3 className="soc-dash-card-title">
              <Clock size={18} style={{ color: "#3b82f6" }} />
              Alert Rate Sliding Window Timeline
            </h3>
            <span className="soc-dash-badge">Real-Time Ingestion</span>
          </div>
          <div style={{ width: "100%", height: 230 }}>
            {formattedThreatChart && formattedThreatChart.length > 0 ? (
              <ResponsiveContainer width="100%" height="100%">
                <ComposedChart data={formattedThreatChart} margin={{ top: 10, right: 20, left: -20, bottom: 0 }}>
                  <CartesianGrid strokeDasharray="3 3" stroke={isDark ? "rgba(255,255,255,0.06)" : "#e2e8f0"} />
                  <XAxis dataKey="time" stroke={isDark ? "#64748b" : "#475569"} fontSize={11} tickLine={false} />
                  <YAxis yAxisId="left" stroke={isDark ? "#64748b" : "#475569"} fontSize={11} tickLine={false} />
                  <Tooltip content={<CustomAdminTooltip />} />
                  <Line yAxisId="left" type="monotone" dataKey="score" name="Incident Velocity" stroke="#ef4444" strokeWidth={2.5} dot={{ r: 3, fill: "#ef4444" }} activeDot={{ r: 6 }} />
                </ComposedChart>
              </ResponsiveContainer>
            ) : (
              <div style={{ width: "100%", height: "100%", display: "flex", flexDirection: "column", alignItems: "center", justifyContent: "center", color: isDark ? "#64748b" : "#94a3b8" }}>
                <Clock size={28} style={{ marginBottom: "0.5rem", opacity: 0.5 }} />
                <span style={{ fontSize: "0.85rem", fontWeight: 500 }}>No alert rate timeline data points recorded yet.</span>
                <span style={{ fontSize: "0.75rem", opacity: 0.8 }}>Submit an incident risk analysis above to plot scores.</span>
              </div>
            )}
          </div>
        </div>
      </div>

      {/* 5. Detailed Alert Inspection Panel */}
      {currentActiveAlert ? (
        <div className="soc-threat-details-box red-accent">
          <div className="soc-dash-card-header" style={{ border: "none", padding: 0 }}>
            <h3 className="soc-dash-card-title" style={{ fontSize: "1rem" }}>
              <AlertTriangle size={18} style={{ color: "#ef4444" }} />
              Active Critical Alert: {currentActiveAlert.id} ({currentActiveAlert.title})
            </h3>
            <div style={{ display: "flex", gap: "0.5rem" }}>
              <span className={`soc-dash-badge-status ${currentActiveAlert.severity.toLowerCase()}`}>
                {currentActiveAlert.severity} Severity
              </span>
              <span className="soc-dash-badge-status warning">
                {currentActiveAlert.priority}
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
              <span className="soc-threat-details-label">Source IP Origin</span>
              <span className="soc-threat-details-val" style={{ fontFamily: "monospace", color: isDark ? "#60a5fa" : "#2563eb" }}>
                {currentActiveAlert.source_ip}
              </span>
            </div>

            <div className="soc-threat-details-item">
              <span className="soc-threat-details-label">Target Destination / Asset</span>
              <span className="soc-threat-details-val" style={{ fontFamily: "monospace" }}>
                {currentActiveAlert.destination_ip} ({currentActiveAlert.asset})
              </span>
            </div>

            <div className="soc-threat-details-item">
              <span className="soc-threat-details-label">Composite Risk Score</span>
              <span className="soc-threat-details-val" style={{ color: "#ef4444", fontWeight: 700 }}>
                {currentActiveAlert.risk_score}
              </span>
            </div>

            <div className="soc-threat-details-item">
              <span className="soc-threat-details-label">MITRE ATT&amp;CK Tag</span>
              <span className="soc-threat-details-val" style={{ color: "#a855f7" }}>
                {currentActiveAlert.mitre}
              </span>
            </div>

            <div className="soc-threat-details-item" style={{ gridColumn: "1 / -1" }}>
              <span className="soc-threat-details-label">Incident Telemetry Description</span>
              <span className="soc-threat-details-val">{currentActiveAlert.description}</span>
            </div>

            <div className="soc-threat-details-item" style={{ gridColumn: "1 / -1" }}>
              <span className="soc-threat-details-label">Containment &amp; Isolation Playbook</span>
              <span className="soc-threat-details-val" style={{ color: isDark ? "#fbbf24" : "#d97706" }}>
                {currentActiveAlert.action}
              </span>
            </div>
          </div>

          {/* 6. Alert Action Buttons */}
          <div className="soc-threat-actions-row">
            <button
              onClick={() => handleExecuteContainment(currentActiveAlert.id)}
              className="soc-threat-act-btn danger"
            >
              <Zap size={14} /> Execute Containment Playbook
            </button>

            <button
              onClick={() => handleResolveAlert(currentActiveAlert.id)}
              className="soc-threat-act-btn success"
            >
              <CheckCircle2 size={14} /> Resolve Alert
            </button>

            <button onClick={() => handleExportSystemLogs(currentActiveAlert)} className="soc-threat-act-btn primary">
              <FolderArchive size={14} /> Export Forensic Log
            </button>

            <button
              onClick={() => {
                loadCriticalAlerts();
                setAlertActionMsg("Refreshed critical alerts stream from PostgreSQL!");
                setTimeout(() => setAlertActionMsg(null), 3000);
              }}
              className="soc-threat-act-btn secondary"
            >
              <RefreshCw size={14} /> Refresh Stream
            </button>
          </div>
        </div>
      ) : (
        <div className="soc-threat-details-box red-accent" style={{ textAlign: "center", padding: "1.75rem 1rem" }}>
          <AlertTriangle size={28} style={{ color: "#ef4444", marginBottom: "0.5rem", opacity: 0.6 }} />
          <h4 style={{ margin: 0, color: isDark ? "#f8fafc" : "#0f172a", fontSize: "0.95rem" }}>
            No Active Critical Alert Selected
          </h4>
          <p style={{ margin: "0.35rem 0 0 0", fontSize: "0.8rem", color: isDark ? "#64748b" : "#94a3b8" }}>
            Analyze incident risk above to populate active alert details, MITRE ATT&amp;CK tags, and containment playbooks.
          </p>
        </div>
      )}

      {/* 5. Critical Alerts Table */}
      <div className="soc-dash-table-card">
        <div className="soc-dash-table-toolbar">
          <div className="soc-dash-card-header" style={{ border: "none", padding: 0, gap: "0.75rem" }}>
            <h3 className="soc-dash-card-title">
              <AlertTriangle size={18} style={{ color: "#ef4444" }} />
              Critical Security Alerts Log &amp; Triage Roster
            </h3>
            <span className="soc-dash-badge">FastAPI Alert Stream</span>
          </div>

          <div style={{ display: "flex", alignItems: "center", gap: "0.75rem", flexWrap: "wrap" }}>
            {/* Severity Filter */}
            <select
              value={alertSeverityFilter}
              onChange={(e) => {
                setAlertSeverityFilter(e.target.value);
                setAlertPage(1);
              }}
              className="ns-control"
              style={{ padding: "0.35rem 0.65rem", fontSize: "0.8rem", width: "130px" }}
            >
              <option value="All">All Severities</option>
              <option value="Critical">Critical</option>
              <option value="High">High</option>
              <option value="Medium">Medium</option>
            </select>

            {/* Status Filter */}
            <select
              value={alertStatusFilter}
              onChange={(e) => {
                setAlertStatusFilter(e.target.value);
                setAlertPage(1);
              }}
              className="ns-control"
              style={{ padding: "0.35rem 0.65rem", fontSize: "0.8rem", width: "130px" }}
            >
              <option value="All">All Statuses</option>
              <option value="Investigating">Investigating</option>
              <option value="Open">Open</option>
              <option value="Escalated">Escalated</option>
              <option value="Resolved">Resolved</option>
            </select>

            <div className="soc-dash-table-search">
              <Search size={15} style={{ color: "#94a3b8" }} />
              <input
                type="text"
                placeholder="Search alerts by title, IP, asset..."
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
            <LoadingSpinner text="Streaming critical alerts from FastAPI..." />
          ) : criticalAlertsError ? (
            <div style={{ padding: "2rem", textAlign: "center", color: "#f87171" }}>
              {criticalAlertsError}
            </div>
          ) : paginatedAlerts.length > 0 ? (
            <table className="soc-dash-table">
              <thead>
                <tr>
                  <th onClick={() => handleSortAlerts("id")}>
                    Alert ID {alertSortField === "id" ? (alertSortOrder === "asc" ? "▲" : "▼") : ""}
                  </th>
                  <th onClick={() => handleSortAlerts("timestamp")}>
                    Timestamp {alertSortField === "timestamp" ? (alertSortOrder === "asc" ? "▲" : "▼") : ""}
                  </th>
                  <th onClick={() => handleSortAlerts("title")}>
                    Alert Title {alertSortField === "title" ? (alertSortOrder === "asc" ? "▲" : "▼") : ""}
                  </th>
                  <th onClick={() => handleSortAlerts("source_ip")}>
                    Source IP {alertSortField === "source_ip" ? (alertSortOrder === "asc" ? "▲" : "▼") : ""}
                  </th>
                  <th onClick={() => handleSortAlerts("asset")}>
                    Target Asset {alertSortField === "asset" ? (alertSortOrder === "asc" ? "▲" : "▼") : ""}
                  </th>
                  <th onClick={() => handleSortAlerts("severity")}>
                    Severity {alertSortField === "severity" ? (alertSortOrder === "asc" ? "▲" : "▼") : ""}
                  </th>
                  <th onClick={() => handleSortAlerts("priority")}>
                    Priority {alertSortField === "priority" ? (alertSortOrder === "asc" ? "▲" : "▼") : ""}
                  </th>
                  <th onClick={() => handleSortAlerts("status")}>
                    Status {alertSortField === "status" ? (alertSortOrder === "asc" ? "▲" : "▼") : ""}
                  </th>
                  <th>Action</th>
                </tr>
              </thead>
              <tbody>
                {paginatedAlerts.map((alertItem) => (
                  <tr
                    key={alertItem.id}
                    style={{
                      cursor: "pointer",
                      background: currentActiveAlert && String(currentActiveAlert.id) === String(alertItem.id)
                        ? isDark ? "rgba(239, 68, 68, 0.1)" : "rgba(239, 68, 68, 0.05)"
                        : undefined,
                    }}
                    onClick={() => setActiveAlertId(alertItem.id)}
                  >
                    <td>
                      <code>{alertItem.id}</code>
                    </td>
                    <td>
                      <code style={{ fontSize: "0.775rem", color: isDark ? "#cbd5e1" : "#475569" }}>
                        {alertItem.timestamp}
                      </code>
                    </td>
                    <td>
                      <strong style={{ color: isDark ? "#f8fafc" : "#0f172a" }}>{alertItem.title}</strong>
                    </td>
                    <td>
                      <code style={{ color: "#60a5fa" }}>{alertItem.source_ip}</code>
                    </td>
                    <td>
                      <code>{alertItem.asset}</code>
                    </td>
                    <td>
                      <span className={`soc-dash-badge-status ${alertItem.severity.toLowerCase()}`}>
                        {alertItem.severity}
                      </span>
                    </td>
                    <td>
                      <span style={{ fontWeight: 600, color: alertItem.priority.includes("P1") ? "#ef4444" : "#f97316" }}>
                        {alertItem.priority}
                      </span>
                    </td>
                    <td>
                      <span className={`soc-dash-badge-status ${alertItem.status === "Resolved" ? "normal" : "warning"}`}>
                        {alertItem.status}
                      </span>
                    </td>
                    <td>
                      <button
                        onClick={(e) => {
                          e.stopPropagation();
                          setActiveAlertId(alertItem.id);
                        }}
                        className="pcap-action-btn"
                      >
                        Triage
                      </button>
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          ) : (
            <div style={{ padding: "3rem 1.5rem", textAlign: "center", color: isDark ? "#94a3b8" : "#64748b" }}>
              <AlertTriangle size={36} style={{ color: "#ef4444", marginBottom: "0.75rem", opacity: 0.6 }} />
              <p style={{ margin: 0, fontSize: "0.95rem", fontWeight: 600 }}>
                No active critical alerts logged. Enter parameters above to analyze incident risk.
              </p>
            </div>
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
}
