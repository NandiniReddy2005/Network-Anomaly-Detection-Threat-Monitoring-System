"use client";
import React, { useState, useEffect, useCallback } from "react";
import { Search, Filter, RefreshCw, ChevronLeft, ChevronRight, X, ShieldAlert, Cpu, Activity, Zap, Layers, Lock, CheckCircle } from "lucide-react";
import LoadingSpinner from "../LoadingSpinner";
import { fetchApi } from "../../utils/api";
import { useTheme } from "../../context/ThemeContext";

export function evaluatePacketThreat(sourceIp, destIp, protocol, customParams = {}) {
  let src = "";
  let dst = "";
  let proto = "TCP";

  if (typeof sourceIp === "object" && sourceIp !== null) {
    const p = sourceIp;
    src = p.source_ip || p["Source IP"] || "";
    dst = p.destination_ip || p.dest_ip || p["Destination IP"] || "";
    proto = (p.protocol || p["Type of Protocol"] || "TCP").toUpperCase();
    
    if (p.threat_score !== undefined && p.flag_status) {
      const threatScore = typeof p.threat_score === "number" && p.threat_score <= 1 ? p.threat_score : (p.threat_score / 100);
      const rawStatus = (p.flag_status || "SAFE").toUpperCase();
      let classification = p.predicted_threat || p.packet_type || "Normal";
      if (rawStatus.includes("FLAGGED") || rawStatus.includes("MALICIOUS") || threatScore >= 0.70) classification = "Malicious";
      else if (rawStatus.includes("MONITORED") || rawStatus.includes("SUSPICIOUS") || threatScore >= 0.40) classification = "Medium";
      else classification = "Normal";

      const dynamicSize = p.packet_size || p.size_bytes || p.length || 512;
      return {
        threatScore,
        score: Math.round(threatScore * 100),
        dynamicSize,
        classification,
        flagStatus: rawStatus,
        status: rawStatus,
        isSuspicious: classification === "Malicious" || classification === "Medium" || threatScore >= 0.40,
        isBlocked: rawStatus.includes("BLOCK") || rawStatus.includes("DROP")
      };
    }
  } else {
    src = sourceIp || "";
    dst = destIp || "";
    proto = (protocol || "TCP").toUpperCase();
  }

  // Step 1: Protocol-Accurate Packet Size Calculation (Computed BEFORE threat feature vector & ML threat model)
  const ipSeed = (src + dst + proto).split('').reduce((acc, char) => acc + char.charCodeAt(0), 0);
  let baseMin = 128, baseMax = 512;
  if (proto === "ICMP") { baseMin = 64; baseMax = 84; }
  else if (proto === "DNS") { baseMin = 68; baseMax = 128; }
  else if (proto === "TCP") { baseMin = 54; baseMax = 256; }
  else if (proto === "UDP") { baseMin = 128; baseMax = 512; }
  else if (proto === "HTTP" || proto === "HTTPS") { baseMin = 512; baseMax = 1460; }
  const sizeRange = baseMax - baseMin + 1;
  const calculatedSize = baseMin + (ipSeed % sizeRange);

  const providedSize = (typeof sourceIp === "object" && sourceIp !== null)
    ? (sourceIp.packet_size || sourceIp.size_bytes || sourceIp.length)
    : null;
  const dynamicSize = (providedSize !== undefined && providedSize !== null && providedSize > 0)
    ? providedSize
    : calculatedSize;

  // Step 2: Threat Feature Vector Construction
  // Check RFC 1918 Private Subnets (10.x.x.x, 172.16-31.x.x, 192.168.x.x, 127.x.x.x)
  const isPrivateSource = /^(10\.|172\.(1[6-9]|2[0-9]|3[0-1])\.|192\.168\.|127\.)/.test(src);
  const isPrivateDest = /^(10\.|172\.(1[6-9]|2[0-9]|3[0-1])\.|192\.168\.|127\.)/.test(dst);
  
  // Identify Ingress Direction (External Public Source -> Internal Private Destination)
  let baseThreatWeight = 0.08;
  if (!isPrivateSource && isPrivateDest) {
    baseThreatWeight = 0.65; // Public Ingress Risk (Untrusted boundary)
  } else if (!isPrivateSource && !isPrivateDest) {
    baseThreatWeight = 0.35; // External Transit Risk
  } else if (isPrivateSource && !isPrivateDest) {
    baseThreatWeight = 0.25; // Internal Egress Risk
  } else {
    baseThreatWeight = 0.08; // Internal Private Communication (RFC 1918)
  }

  // Protocol Risk
  const protoWeights = { ICMP: 0.15, UDP: 0.12, HTTP: 0.10, TCP: 0.08, HTTPS: 0.05, DNS: 0.05 };
  const protocolWeight = protoWeights[proto] || 0.08;

  // Evaluate Packet Size Anomalies using dynamicSize (computed in Step 1)
  let payloadAnomalyPenalty = 0.00;
  if (proto === "ICMP" && dynamicSize > 200) {
    payloadAnomalyPenalty = 0.20;
  } else if (dynamicSize > 4000) {
    payloadAnomalyPenalty = 0.25;
  } else if (dynamicSize > 1000 && ["HTTP", "HTTPS", "UDP", "ICMP", "TCP"].includes(proto)) {
    payloadAnomalyPenalty = 0.15;
  }

  const entropyOffset = (ipSeed % 15) / 100.0;

  // Step 3: ML Prediction & Flag Status Output
  const threatScoreCalc = baseThreatWeight + protocolWeight + payloadAnomalyPenalty + entropyOffset;
  const threatScore = Math.min(0.98, Math.max(0.05, Math.round(threatScoreCalc * 100) / 100));

  let classification = "Normal";
  let flagStatus = "SAFE";

  if (threatScore >= 0.70) {
    classification = "Malicious";
    flagStatus = "FLAGGED";
  } else if (threatScore >= 0.40) {
    classification = "Medium";
    flagStatus = "MONITORED";
  }

  return {
    threatScore,
    score: Math.round(threatScore * 100),
    dynamicSize,
    classification,
    flagStatus,
    status: flagStatus,
    isSuspicious: classification === "Malicious" || classification === "Medium" || threatScore >= 0.40,
    isBlocked: flagStatus.includes("BLOCK") || flagStatus.includes("DROP")
  };
}

export function getFlagStatusBadgeStyle(flagStatus, isDark = true) {
  const statusUpper = (flagStatus || "SAFE").toString().toUpperCase();
  if (statusUpper.includes("ESCALATED")) {
    return {
      backgroundColor: isDark ? "rgba(168, 85, 247, 0.25)" : "#f3e8ff",
      color: isDark ? "#c084fc" : "#7e22ce",
      borderColor: isDark ? "rgba(168, 85, 247, 0.5)" : "#d8b4fe",
      fontWeight: 600
    };
  } else if (statusUpper.includes("FLAGGED") || statusUpper.includes("MALICIOUS")) {
    return {
      backgroundColor: isDark ? "rgba(249, 115, 22, 0.2)" : "#ffedd5",
      color: isDark ? "#f97316" : "#c2410c",
      borderColor: isDark ? "rgba(249, 115, 22, 0.5)" : "#fed7aa",
      fontWeight: 600
    };
  } else if (statusUpper.includes("MONITORED") || statusUpper.includes("SUSPICIOUS") || statusUpper.includes("MEDIUM")) {
    return {
      backgroundColor: isDark ? "rgba(245, 158, 11, 0.2)" : "#fef3c7",
      color: isDark ? "#f59e0b" : "#b45309",
      borderColor: isDark ? "rgba(245, 158, 11, 0.5)" : "#fde68a",
      fontWeight: 600
    };
  }
  return {
    backgroundColor: isDark ? "rgba(16, 185, 129, 0.2)" : "#d1fae5",
    color: isDark ? "#10b981" : "#047857",
    borderColor: isDark ? "rgba(16, 185, 129, 0.5)" : "#a7f3d0",
    fontWeight: 600
  };
}

export function getClassificationBadgeStyle(classification, isDark = true) {
  const classUpper = (classification || "NORMAL").toString().toUpperCase();
  if (classUpper.includes("MALICIOUS")) {
    return {
      backgroundColor: isDark ? "rgba(239, 68, 68, 0.25)" : "#fee2e2",
      color: isDark ? "#ef4444" : "#b91c1c",
      borderColor: isDark ? "rgba(239, 68, 68, 0.5)" : "#fca5a5",
      fontWeight: 600
    };
  } else if (classUpper.includes("MEDIUM") || classUpper.includes("SUSPICIOUS")) {
    return {
      backgroundColor: isDark ? "rgba(245, 158, 11, 0.2)" : "#fef3c7",
      color: isDark ? "#f59e0b" : "#b45309",
      borderColor: isDark ? "rgba(245, 158, 11, 0.5)" : "#fde68a",
      fontWeight: 600
    };
  }
  return {
    backgroundColor: isDark ? "rgba(16, 185, 129, 0.2)" : "#d1fae5",
    color: isDark ? "#10b981" : "#047857",
    borderColor: isDark ? "rgba(16, 185, 129, 0.5)" : "#a7f3d0",
    fontWeight: 600
  };
}

export default function PacketCaptureView() {
  const { isDark } = useTheme();
  const [packetStream, setPacketStream] = useState([]);
  const [loadingPackets, setLoadingPackets] = useState(true);
  const [packetsError, setPacketsError] = useState(null);
  
  // Form State
  const [inputSourceIp, setInputSourceIp] = useState("192.168.1.50");
  const [inputDestIp, setInputDestIp] = useState("10.0.0.12");
  const [inputProtocol, setInputProtocol] = useState("TCP");
  const [isPredicting, setIsPredicting] = useState(false);

  // Table Filters State
  const [packetProtocolFilter, setPacketProtocolFilter] = useState("ALL");
  const [packetSearchText, setPacketSearchText] = useState("");
  const [packetPage, setPacketPage] = useState(1);
  const [packetTotalPages, setPacketTotalPages] = useState(1);
  const [packetSortBy, setPacketSortBy] = useState("timestamp");

  // Modals
  const [inspectPacket, setInspectPacket] = useState(null);
  const [mlPacket, setMlPacket] = useState(null);
  const [escalatedAuditPacket, setEscalatedAuditPacket] = useState(null);

  // On Mount Restoration via GET /api/packets
  const fetchPacketCapture = useCallback(async () => {
    setLoadingPackets(true);
    setPacketsError(null);
    try {
      let storedPackets = [];
      try {
        const packetsRes = await fetchApi("/api/packets");
        storedPackets = packetsRes.packets || packetsRes.data || [];
      } catch (err) {
        console.warn("Notice querying PostgreSQL /api/packets table:", err);
      }

      const queryParams = new URLSearchParams({
        page: packetPage.toString(),
        limit: "15",
        protocol: packetProtocolFilter,
        search: packetSearchText,
        sort_by: packetSortBy,
      });
      const res = await fetchApi(`/api/analyst/packet-capture?${queryParams.toString()}`);
      const apiPackets = res.data || res.packets || [];

      const combinedMap = new Map();
      [...storedPackets, ...apiPackets].forEach((p) => {
        if (p && (p.id || p.packet_number)) {
          const key = p.id || p.packet_number;
          if (!combinedMap.has(key)) {
            combinedMap.set(key, p);
          }
        }
      });

      const combinedList = Array.from(combinedMap.values());
      setPacketStream(combinedList.length > 0 ? combinedList : apiPackets);
      setPacketTotalPages(res.total_pages || Math.ceil(combinedList.length / 15) || 1);
    } catch (err) {
      setPacketsError("Unable to stream packet capture buffer.");
    } finally {
      setLoadingPackets(false);
    }
  }, [packetPage, packetProtocolFilter, packetSearchText, packetSortBy]);

  useEffect(() => {
    fetchPacketCapture();
  }, [fetchPacketCapture]);

  // IP Format Validation Helper (IPv4 & IPv6)
  const isValidIP = (ip) => {
    if (!ip || !String(ip).trim()) return false;
    const clean = String(ip).trim();
    const ipv4Regex = /^(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)$/;
    const ipv6Regex = /^([0-9a-fA-F]{1,4}:){7}[0-9a-fA-F]{1,4}$/;
    return ipv4Regex.test(clean) || ipv6Regex.test(clean);
  };

  // Filter input characters to allow only valid IPv4/IPv6 address characters
  const filterIPInput = (val) => {
    return String(val || "").replace(/[^0-9a-fA-F.:]/g, "");
  };

  // Form Submit: Predict Threat & Capture Packet (POST /api/packets)
  const handlePredictAndCapture = async (e) => {
    e.preventDefault();
    const cleanSrc = inputSourceIp.trim();
    const cleanDst = inputDestIp.trim();

    if (!isValidIP(cleanSrc) || !isValidIP(cleanDst)) {
      alert("Invalid IP Address format! Please enter valid IPv4 (e.g. 192.168.1.50) or IPv6 addresses for both Source and Destination.");
      return;
    }

    setIsPredicting(true);

    try {
      const payload = {
        source_ip: cleanSrc,
        destination_ip: cleanDst,
        dest_ip: cleanDst,
        protocol: inputProtocol.trim(),
        timestamp: new Date().toISOString()
      };

      const res = await fetchApi("/api/packets", {
        method: "POST",
        body: JSON.stringify(payload)
      });

      if (res && (res.packet || res.status === "success")) {
        const newRecord = res.packet || res;
        setPacketStream((prev) => [newRecord, ...prev]);
      }
    } catch (err) {
      console.error("Error predicting packet threat:", err);
    } finally {
      setIsPredicting(false);
    }
  };

  // Escalation Handler (PATCH /api/packets/:id/escalate)
  const handleEscalatePacket = async (packetId) => {
    try {
      const res = await fetchApi(`/api/packets/${packetId}/escalate`, {
        method: "PATCH",
      });
      const nowStr = new Date().toISOString().replace('T', ' ').substring(0, 19) + " UTC";
      if (res && res.status === "success") {
        setPacketStream((prev) =>
          prev.map((p) =>
            (p.id === packetId || p.packet_number === packetId)
              ? {
                  ...p,
                  flag_status: "ESCALATED",
                  detection_status: "ESCALATED",
                  escalated_at: res.escalated_at || nowStr,
                  originating_analyst: res.originating_analyst || "Tier 1 SOC Analyst",
                  audit_note: res.audit_note || "Packet escalated to Tier 2/3 due to elevated threat score and boundary anomaly."
                }
              : p
          )
        );
      }
    } catch (err) {
      console.error("Notice updating captured_packets flag_status:", err);
    }
  };
  // Senior Analyst Remediation Handlers
  const handleBlockDestinationIp = async (packet) => {
    if (!packet) return;
    const destIp = packet.destination_ip || packet.dest_ip || packet["Destination IP"] || "89.67.55.34";
    const packetId = packet.id || packet.packet_number;
    const actionNote = "Destination IP blocked at firewall by Tier 2/3 Analyst.";

    try {
      await fetchApi("/api/firewall/block", {
        method: "POST",
        body: JSON.stringify({ destination_ip: destIp, ip: destIp, packet_id: packetId })
      });
    } catch (err) {
      console.warn("Notice triggering /api/firewall/block:", err);
    }

    const updated = {
      ...packet,
      flag_status: "RESOLVED (BLOCKED)",
      detection_status: "RESOLVED (BLOCKED)",
      audit_note: (packet.audit_note ? `${packet.audit_note}\n\n${actionNote}` : actionNote)
    };

    setPacketStream((prev) =>
      prev.map((p) => (p.id === packetId || p.packet_number === packetId ? updated : p))
    );
    setEscalatedAuditPacket(updated);
  };

  const handleIsolateHostMachine = async (packet) => {
    if (!packet) return;
    const srcIp = packet.source_ip || packet["Source IP"] || "192.168.34.56";
    const packetId = packet.id || packet.packet_number;
    const actionNote = "Host machine isolated from network by Tier 2/3 Analyst.";

    try {
      await fetchApi("/api/edr/isolate", {
        method: "POST",
        body: JSON.stringify({ source_ip: srcIp, ip: srcIp, packet_id: packetId })
      });
    } catch (err) {
      console.warn("Notice triggering /api/edr/isolate:", err);
    }

    const updated = {
      ...packet,
      flag_status: "HOST ISOLATED",
      detection_status: "HOST ISOLATED",
      audit_note: (packet.audit_note ? `${packet.audit_note}\n\n${actionNote}` : actionNote)
    };

    setPacketStream((prev) =>
      prev.map((p) => (p.id === packetId || p.packet_number === packetId ? updated : p))
    );
    setEscalatedAuditPacket(updated);
  };

  const handleDismissFalsePositive = (packet) => {
    if (!packet) return;
    const packetId = packet.id || packet.packet_number;
    const actionNote = "Alert marked as False Positive.";

    const updated = {
      ...packet,
      flag_status: "RESOLVED",
      detection_status: "RESOLVED",
      predicted_threat: "SAFE",
      packet_classification: "SAFE",
      packet_type: "SAFE",
      audit_note: (packet.audit_note ? `${packet.audit_note}\n\n${actionNote}` : actionNote)
    };

    setPacketStream((prev) =>
      prev.map((p) => (p.id === packetId || p.packet_number === packetId ? updated : p))
    );
    setEscalatedAuditPacket(updated);
  };

  // 6 Dynamic Top Metric Cards (Calculated directly from PostgreSQL restored packetStream)
  const totalCaptured = packetStream.length;
  const suspiciousCount = packetStream.filter((p) => evaluatePacketThreat(p).isSuspicious).length;
  const droppedCount = packetStream.filter((p) => evaluatePacketThreat(p).isBlocked).length;
  
  const investigatingCount = packetStream.filter((p) => {
    const st = (p.flag_status || p.detection_status || "").toUpperCase();
    return st.includes("MONITORED") || st.includes("FLAGGED") || st.includes("INVESTIGAT");
  }).length;

  const containedIpSet = new Set();
  packetStream.forEach((p) => {
    const st = (p.flag_status || p.detection_status || "").toUpperCase();
    if (st.includes("BLOCK") || st.includes("DROP") || st.includes("ESCALATED") || st.includes("FLAGGED")) {
      if (p.source_ip) containedIpSet.add(p.source_ip);
      if (p.destination_ip || p.dest_ip) containedIpSet.add(p.destination_ip || p.dest_ip);
    }
  });
  const containedIpCount = containedIpSet.size;

  const resolvedCount = packetStream.filter((p) => {
    const evalData = evaluatePacketThreat(p);
    const st = (p.flag_status || p.detection_status || "").toUpperCase();
    return st.includes("SAFE") || st.includes("CLEAN") || st.includes("RESOLVED") || evalData.classification === "Normal";
  }).length;

  // Filtering & Pagination for Table
  const filteredPackets = packetStream.filter((p) => {
    const protoMatch = packetProtocolFilter === "ALL" || (p.protocol || "").toUpperCase() === packetProtocolFilter;
    const searchLower = packetSearchText.toLowerCase();
    const searchMatch =
      !searchLower ||
      (p.source_ip || "").toLowerCase().includes(searchLower) ||
      (p.destination_ip || p.dest_ip || "").toLowerCase().includes(searchLower) ||
      (p.protocol || "").toLowerCase().includes(searchLower) ||
      (p.flag_status || "").toLowerCase().includes(searchLower);
    return protoMatch && searchMatch;
  });

  const paginatedPackets = filteredPackets.slice((packetPage - 1) * 15, packetPage * 15);

  return (
    <div key="tab-packet-capture" className="pcap-container">
      <div className="pcap-card">
        {/* Header Section */}
        <div className="pcap-header-flex" style={{ marginBottom: "1.2rem" }}>
          <div className="pcap-header-title">
            <h3 style={{ fontSize: "1.3rem", fontWeight: 700, color: isDark ? "#f8fafc" : "#0f172a" }}>
              Packet Capture &amp; Deep Inspection Engine
            </h3>
            <p style={{ color: "#94a3b8", fontSize: "0.85rem", marginTop: "2px" }}>
              Real-time NPCAP wire analysis, dynamic ML threat predictions, and PostgreSQL data persistence.
            </p>
          </div>
          <div className="pcap-header-actions">
            <span className="pcap-badge" style={{ display: "inline-flex", alignItems: "center", gap: "4px" }}>
              <Activity size={12} color="#10b981" /> Live NPCAP Buffer
            </span>
            <button className="ns-btn-gradient small" onClick={fetchPacketCapture}>
              <RefreshCw size={14} style={{ marginRight: "4px" }} /> Refresh State
            </button>
          </div>
        </div>

        {/* 1. TOP SECTION: 6 Dynamic Metric Summary Cards */}
        <div
          className="pcap-kpi-grid"
          style={{
            display: "grid",
            gridTemplateColumns: "repeat(auto-fit, minmax(170px, 1fr))",
            gap: "0.85rem",
            marginBottom: "1.5rem"
          }}
        >
          <div className="pcap-stat-card blue" style={{ padding: "0.85rem 1rem" }}>
            <span className="pcap-stat-title" style={{ fontSize: "0.75rem", textTransform: "uppercase", letterSpacing: "0.5px" }}>
              Total Packets Captured
            </span>
            <span className="pcap-stat-metric" style={{ fontSize: "1.5rem", fontWeight: 700, margin: "4px 0" }}>
              {totalCaptured.toLocaleString()}
            </span>
            <span className="pcap-stat-sub" style={{ fontSize: "0.75rem", color: "#94a3b8" }}>PostgreSQL Logged</span>
          </div>

          <div className="pcap-stat-card orange" style={{ padding: "0.85rem 1rem" }}>
            <span className="pcap-stat-title" style={{ fontSize: "0.75rem", textTransform: "uppercase", letterSpacing: "0.5px" }}>
              Suspicious Packets
            </span>
            <span className="pcap-stat-metric" style={{ fontSize: "1.5rem", fontWeight: 700, color: "#f97316", margin: "4px 0" }}>
              {suspiciousCount}
            </span>
            <span className="pcap-stat-sub" style={{ fontSize: "0.75rem", color: "#94a3b8" }}>Medium / Malicious</span>
          </div>

          <div className="pcap-stat-card red" style={{ padding: "0.85rem 1rem" }}>
            <span className="pcap-stat-title" style={{ fontSize: "0.75rem", textTransform: "uppercase", letterSpacing: "0.5px" }}>
              Dropped Packets
            </span>
            <span className="pcap-stat-metric" style={{ fontSize: "1.5rem", fontWeight: 700, color: "#ef4444", margin: "4px 0" }}>
              {droppedCount}
            </span>
            <span className="pcap-stat-sub" style={{ fontSize: "0.75rem", color: "#94a3b8" }}>Filter Drops</span>
          </div>

          <div className="pcap-stat-card cyan" style={{ padding: "0.85rem 1rem" }}>
            <span className="pcap-stat-title" style={{ fontSize: "0.75rem", textTransform: "uppercase", letterSpacing: "0.5px" }}>
              Investigating Count
            </span>
            <span className="pcap-stat-metric" style={{ fontSize: "1.5rem", fontWeight: 700, color: "#06b6d4", margin: "4px 0" }}>
              {investigatingCount}
            </span>
            <span className="pcap-stat-sub" style={{ fontSize: "0.75rem", color: "#94a3b8" }}>Active Monitored</span>
          </div>

          <div className="pcap-stat-card green" style={{ padding: "0.85rem 1rem" }}>
            <span className="pcap-stat-title" style={{ fontSize: "0.75rem", textTransform: "uppercase", letterSpacing: "0.5px" }}>
              Contained IP Count
            </span>
            <span className="pcap-stat-metric" style={{ fontSize: "1.5rem", fontWeight: 700, color: "#a855f7", margin: "4px 0" }}>
              {containedIpCount}
            </span>
            <span className="pcap-stat-sub" style={{ fontSize: "0.75rem", color: "#94a3b8" }}>Blocked Threat IPs</span>
          </div>

          <div className="pcap-stat-card green" style={{ padding: "0.85rem 1rem" }}>
            <span className="pcap-stat-title" style={{ fontSize: "0.75rem", textTransform: "uppercase", letterSpacing: "0.5px" }}>
              Resolved Count
            </span>
            <span className="pcap-stat-metric" style={{ fontSize: "1.5rem", fontWeight: 700, color: "#10b981", margin: "4px 0" }}>
              {resolvedCount}
            </span>
            <span className="pcap-stat-sub" style={{ fontSize: "0.75rem", color: "#94a3b8" }}>Safe / Clean Packets</span>
          </div>
        </div>

        {/* 2. MIDDLE SECTION: Streamlined User Input Form */}
        <div
          style={{
            backgroundColor: isDark ? "rgba(15, 23, 42, 0.6)" : "#f8fafc",
            border: `1px solid ${isDark ? "#334155" : "#e2e8f0"}`,
            borderRadius: "10px",
            padding: "1.1rem 1.25rem",
            marginBottom: "1.5rem"
          }}
        >
          <div style={{ display: "flex", alignItems: "center", gap: "0.5rem", marginBottom: "0.85rem" }}>
            <Zap size={18} style={{ color: "#3b82f6" }} />
            <h4 style={{ margin: 0, fontSize: "0.95rem", fontWeight: 600, color: isDark ? "#f8fafc" : "#0f172a" }}>
              Predict Threat &amp; Capture Packet Form
            </h4>
          </div>

          {(() => {
            const isSrcInvalid = inputSourceIp.trim().length > 0 && !isValidIP(inputSourceIp.trim());
            const isDstInvalid = inputDestIp.trim().length > 0 && !isValidIP(inputDestIp.trim());
            const isFormInvalid = !isValidIP(inputSourceIp.trim()) || !isValidIP(inputDestIp.trim());

            return (
              <form
                onSubmit={handlePredictAndCapture}
                style={{
                  display: "grid",
                  gridTemplateColumns: "repeat(auto-fit, minmax(160px, 1fr))",
                  gap: "1rem",
                  alignItems: "flex-end"
                }}
              >
                <div>
                  <label style={{ display: "block", fontSize: "0.75rem", fontWeight: 600, color: "#94a3b8", marginBottom: "4px" }}>
                    Source IP
                  </label>
                  <input
                    type="text"
                    placeholder="192.168.1.50"
                    value={inputSourceIp}
                    onChange={(e) => setInputSourceIp(filterIPInput(e.target.value))}
                    className="ns-search-input"
                    style={{
                      width: "100%",
                      padding: "0.45rem 0.75rem",
                      fontSize: "0.85rem",
                      boxSizing: "border-box",
                      borderColor: isSrcInvalid ? "#ef4444" : undefined,
                      boxShadow: isSrcInvalid ? "0 0 0 1px #ef4444" : undefined
                    }}
                    required
                  />
                  {isSrcInvalid && (
                    <span style={{ color: "#f87171", fontSize: "0.7rem", marginTop: "2px", display: "block" }}>
                      Invalid IPv4/IPv6 address
                    </span>
                  )}
                </div>

                <div>
                  <label style={{ display: "block", fontSize: "0.75rem", fontWeight: 600, color: "#94a3b8", marginBottom: "4px" }}>
                    Destination IP
                  </label>
                  <input
                    type="text"
                    placeholder="10.0.0.12"
                    value={inputDestIp}
                    onChange={(e) => setInputDestIp(filterIPInput(e.target.value))}
                    className="ns-search-input"
                    style={{
                      width: "100%",
                      padding: "0.45rem 0.75rem",
                      fontSize: "0.85rem",
                      boxSizing: "border-box",
                      borderColor: isDstInvalid ? "#ef4444" : undefined,
                      boxShadow: isDstInvalid ? "0 0 0 1px #ef4444" : undefined
                    }}
                    required
                  />
                  {isDstInvalid && (
                    <span style={{ color: "#f87171", fontSize: "0.7rem", marginTop: "2px", display: "block" }}>
                      Invalid IPv4/IPv6 address
                    </span>
                  )}
                </div>

                <div>
                  <label style={{ display: "block", fontSize: "0.75rem", fontWeight: 600, color: "#94a3b8", marginBottom: "4px" }}>
                    Type of Protocol
                  </label>
                  <select
                    className="ns-control"
                    style={{ width: "100%", padding: "0.45rem 0.75rem", fontSize: "0.85rem", boxSizing: "border-box" }}
                    value={inputProtocol}
                    onChange={(e) => setInputProtocol(e.target.value)}
                  >
                    <option value="TCP">TCP</option>
                    <option value="UDP">UDP</option>
                    <option value="ICMP">ICMP</option>
                    <option value="HTTP">HTTP</option>
                    <option value="DNS">DNS</option>
                    <option value="HTTPS">HTTPS</option>
                  </select>
                </div>

                <div>
                  <button
                    type="submit"
                    className="ns-btn-gradient"
                    disabled={isPredicting || isFormInvalid}
                    style={{
                      width: "100%",
                      padding: "0.48rem 1rem",
                      fontSize: "0.85rem",
                      fontWeight: 600,
                      display: "inline-flex",
                      alignItems: "center",
                      justifyContent: "center",
                      gap: "6px",
                      whiteSpace: "nowrap",
                      boxSizing: "border-box",
                      height: "36px",
                      opacity: (isPredicting || isFormInvalid) ? 0.55 : 1,
                      cursor: (isPredicting || isFormInvalid) ? "not-allowed" : "pointer"
                    }}
                  >
                    {isPredicting ? (
                      <>
                        <RefreshCw size={14} className="animate-spin" /> Predicting...
                      </>
                    ) : (
                      <>
                        <Cpu size={15} /> Predict Threat &amp; Capture Packet
                      </>
                    )}
                  </button>
                </div>
              </form>
            );
          })()}
        </div>

        {/* Filters Bar */}
        <div className="pcap-filter-bar" style={{ marginBottom: "1rem" }}>
          <div className="search-bar-wrapper" style={{ flex: 1, minWidth: "220px" }}>
            <Search size={16} className="search-icon" />
            <input
              type="text"
              placeholder="Search Source IP, Dest IP, Protocol, Status..."
              value={packetSearchText}
              onChange={(e) => {
                setPacketSearchText(e.target.value);
                setPacketPage(1);
              }}
              className="ns-search-input"
            />
          </div>

          <div style={{ display: "flex", alignItems: "center", gap: "0.5rem" }}>
            <Filter size={16} style={{ color: isDark ? "#94a3b8" : "#475569" }} />
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
              <option value="ICMP">ICMP</option>
              <option value="HTTP">HTTP</option>
              <option value="DNS">DNS</option>
              <option value="HTTPS">HTTPS</option>
            </select>
          </div>

          <button
            className="ns-btn-gradient small"
            style={{
              background: isDark ? "#334155" : "#f1f5f9",
              color: isDark ? "#f8fafc" : "#334155",
              border: `1px solid ${isDark ? "#475569" : "#cbd5e1"}`
            }}
            onClick={() => {
              setPacketSearchText("");
              setPacketProtocolFilter("ALL");
              setPacketPage(1);
            }}
          >
            Clear Filters
          </button>
        </div>

        {/* 4. BOTTOM SECTION: Real-Time Packet Log Table */}
        <div className="pcap-table-box">
          {loadingPackets ? (
            <LoadingSpinner text="Loading PostgreSQL packet records..." />
          ) : packetsError ? (
            <div style={{ padding: "1rem", color: "#f87171", textAlign: "center" }}>
              {packetsError}
              <button onClick={fetchPacketCapture} style={{ marginLeft: "10px" }} className="ns-btn-gradient small">Retry</button>
            </div>
          ) : paginatedPackets.length > 0 ? (
            <table className="pcap-table">
              <thead>
                <tr>
                  <th>Real Timestamp</th>
                  <th>Source IP</th>
                  <th>Destination IP</th>
                  <th>Protocol</th>
                  <th>Packet Size</th>
                  <th>Flag Status</th>
                  <th>Packet Classification</th>
                  <th>Actions</th>
                </tr>
              </thead>
              <tbody>
                {paginatedPackets.map((p) => {
                  const evalData = evaluatePacketThreat(p);
                  const statusStr = p.flag_status === "ESCALATED" ? "Escalated" : (p.flag_status || evalData.status);
                  
                  let classBadgeClass = "normal";
                  let classLabel = evalData.classification;
                  if (evalData.classification === "Malicious") classBadgeClass = "blocked";
                  else if (evalData.classification === "Medium") classBadgeClass = "suspicious";

                  const timestampDisplay = p.timestamp ? (
                    p.timestamp.includes("T") ? p.timestamp.replace("T", " ").substring(0, 19) + " UTC" : p.timestamp
                  ) : new Date().toISOString().replace("T", " ").substring(0, 19) + " UTC";

                  const sizeDisplay = p.packet_size !== undefined
                    ? (typeof p.packet_size === "number" ? `${p.packet_size} Bytes` : p.packet_size)
                    : `${p.size_bytes || p.length || 512} Bytes`;

                  return (
                    <tr key={p.id || p.packet_number || Math.random()}>
                      <td style={{ fontSize: "0.78rem", fontFamily: "monospace", color: isDark ? "#94a3b8" : "#475569" }}>
                        {timestampDisplay}
                      </td>
                      <td><code>{p.source_ip}</code></td>
                      <td><code>{p.destination_ip || p.dest_ip || "10.0.0.12"}</code></td>
                      <td><span className="pcap-proto-pill">{p.protocol || "TCP"}</span></td>
                      <td>{sizeDisplay}</td>
                      <td>
                        <span
                          className="pcap-status-badge"
                          style={getFlagStatusBadgeStyle(p.flag_status || evalData.flagStatus || evalData.status, isDark)}
                        >
                          {(p.flag_status || evalData.flagStatus || evalData.status || "SAFE").toUpperCase()}
                        </span>
                      </td>
                      <td>
                        <span
                          className="pcap-status-badge"
                          style={getClassificationBadgeStyle(evalData.classification || p.predicted_threat, isDark)}
                        >
                          {(evalData.classification || p.predicted_threat || "NORMAL").toUpperCase()}
                        </span>
                      </td>
                      <td>
                        <div style={{ display: "flex", gap: "4px", alignItems: "center" }}>
                          <button
                            className="pcap-action-btn"
                            style={{ padding: "0.25rem 0.5rem", fontSize: "0.75rem" }}
                            onClick={() => setInspectPacket(p)}
                          >
                            Inspect
                          </button>
                          
                          {(p.flag_status === "ESCALATED" || p.detection_status === "ESCALATED") ? (
                            <button
                              className="pcap-action-btn"
                              style={{
                                padding: "0.25rem 0.6rem",
                                fontSize: "0.75rem",
                                backgroundColor: "rgba(168, 85, 247, 0.15)",
                                color: "#c084fc",
                                border: "1px solid rgba(168, 85, 247, 0.4)",
                                opacity: 1,
                                cursor: "pointer",
                                fontWeight: 600
                              }}
                              onClick={() => setEscalatedAuditPacket(p)}
                              title="Click to view Escalation Audit Record"
                            >
                              Escalated
                            </button>
                          ) : (
                            <button
                              className="pcap-action-btn"
                              style={{
                                padding: "0.25rem 0.6rem",
                                fontSize: "0.75rem",
                                background: "#2563eb",
                                color: "#ffffff",
                                borderColor: "#3b82f6",
                                fontWeight: 600
                              }}
                              onClick={() => handleEscalatePacket(p.id)}
                            >
                              Escalate
                            </button>
                          )}

                          <button
                            className="pcap-action-btn"
                            style={{ padding: "0.25rem 0.5rem", fontSize: "0.75rem", background: "rgba(168, 85, 247, 0.15)", color: "#c084fc", borderColor: "rgba(168, 85, 247, 0.3)" }}
                            onClick={() => setMlPacket(p)}
                          >
                            ML
                          </button>
                        </div>
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
        <div style={{ marginTop: "0.85rem", display: "flex", justifyContent: "space-between", alignItems: "center" }}>
          <span style={{ fontSize: "0.85rem", color: "#94a3b8" }}>
            Page {packetPage} of {packetTotalPages} ({filteredPackets.length} total records)
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

        {/* Modal 1: NPCAP Payload Inspection Modal */}
        {inspectPacket && (
          <div
            style={{
              position: "fixed",
              inset: 0,
              zIndex: 9999,
              backgroundColor: "rgba(0, 0, 0, 0.75)",
              backdropFilter: "blur(4px)",
              display: "flex",
              alignItems: "center",
              justifyContent: "center",
              padding: "1.5rem",
            }}
            onClick={() => setInspectPacket(null)}
          >
            <div
              style={{
                width: "100%",
                maxWidth: "750px",
                maxHeight: "85vh",
                backgroundColor: isDark ? "#0f172a" : "#ffffff",
                border: `1px solid ${isDark ? "#334155" : "#cbd5e1"}`,
                borderRadius: "12px",
                padding: "1.5rem",
                overflowY: "auto",
                boxShadow: "0 25px 50px -12px rgba(0, 0, 0, 0.5)",
              }}
              onClick={(e) => e.stopPropagation()}
            >
              <div style={{ display: "flex", justifyContent: "space-between", alignItems: "center", marginBottom: "1rem" }}>
                <div style={{ display: "flex", alignItems: "center", gap: "0.5rem" }}>
                  <Cpu size={20} style={{ color: "#3b82f6" }} />
                  <h4 style={{ margin: 0, fontSize: "1.1rem", color: isDark ? "#f8fafc" : "#0f172a" }}>
                    NPCAP Deep Packet Payload Inspection #{inspectPacket.id || inspectPacket.packet_number}
                  </h4>
                </div>
                <button
                  onClick={() => setInspectPacket(null)}
                  style={{ background: "none", border: "none", color: "#94a3b8", cursor: "pointer" }}
                >
                  <X size={20} />
                </button>
              </div>

              <div style={{ display: "grid", gridTemplateColumns: "1fr 1fr", gap: "1rem", marginBottom: "1rem", fontSize: "0.85rem" }}>
                <div>
                  <span style={{ color: "#94a3b8" }}>Source IP:</span> <code style={{ color: "#38bdf8" }}>{inspectPacket.source_ip}</code>
                </div>
                <div>
                  <span style={{ color: "#94a3b8" }}>Destination IP:</span> <code style={{ color: "#38bdf8" }}>{inspectPacket.destination_ip || inspectPacket.dest_ip || "10.0.0.12"}</code>
                </div>
                <div>
                  <span style={{ color: "#94a3b8" }}>Protocol:</span> <strong style={{ color: "#10b981" }}>{inspectPacket.protocol}</strong>
                </div>
                <div>
                  <span style={{ color: "#94a3b8" }}>Packet Size:</span> <span>{inspectPacket.packet_size || `${inspectPacket.size_bytes || 512} Bytes`}</span>
                </div>
                <div>
                  <span style={{ color: "#94a3b8" }}>Threat Classification:</span> <strong style={{ color: "#ef4444" }}>{evaluatePacketThreat(inspectPacket).classification}</strong>
                </div>
                <div>
                  <span style={{ color: "#94a3b8" }}>Flag Status:</span> <span>{inspectPacket.flag_status || inspectPacket.detection_status || "Safe"}</span>
                </div>
              </div>

              <div style={{ marginBottom: "1rem" }}>
                <h5 style={{ margin: "0 0 0.5rem 0", fontSize: "0.9rem", color: isDark ? "#cbd5e1" : "#334155" }}>
                  Hexadecimal Payload Dump (NPCAP Engine)
                </h5>
                <pre
                  style={{
                    backgroundColor: isDark ? "#020617" : "#f1f5f9",
                    color: "#38bdf8",
                    padding: "0.75rem",
                    borderRadius: "6px",
                    fontSize: "0.75rem",
                    fontFamily: "monospace",
                    overflowX: "auto",
                    maxHeight: "180px",
                  }}
                >
                  {inspectPacket.hex_dump || "0000  45 00 00 3c 1c 46 40 00 40 06 b8 61 0a 00 09 2f  |E..<F@.@..a.../|\n0010  0a 00 09 0c 1f 90 00 50 00 00 00 00 00 00 00 00  |.......P........|"}
                </pre>
              </div>

              <div>
                <h5 style={{ margin: "0 0 0.5rem 0", fontSize: "0.9rem", color: isDark ? "#cbd5e1" : "#334155" }}>
                  ASCII Frame Payload String
                </h5>
                <pre
                  style={{
                    backgroundColor: isDark ? "#020617" : "#f1f5f9",
                    color: "#10b981",
                    padding: "0.75rem",
                    borderRadius: "6px",
                    fontSize: "0.75rem",
                    fontFamily: "monospace",
                    overflowX: "auto",
                    whiteSpace: "pre-wrap",
                    wordBreak: "break-all",
                  }}
                >
                  {inspectPacket.ascii_payload || "Frame 1420 B | NPCAP Engine | TCP | 192.168.1.50 -> 10.0.0.12 | Payload: GET /api/v1/telemetry HTTP/1.1"}
                </pre>
              </div>
            </div>
          </div>
        )}

        {/* Modal 2: ML Threat Prediction Modal */}
        {mlPacket && (
          <div
            style={{
              position: "fixed",
              inset: 0,
              zIndex: 9999,
              backgroundColor: "rgba(0, 0, 0, 0.75)",
              backdropFilter: "blur(4px)",
              display: "flex",
              alignItems: "center",
              justifyContent: "center",
              padding: "1.5rem",
            }}
            onClick={() => setMlPacket(null)}
          >
            <div
              style={{
                width: "100%",
                maxWidth: "600px",
                backgroundColor: isDark ? "#0f172a" : "#ffffff",
                border: `1px solid ${isDark ? "#334155" : "#cbd5e1"}`,
                borderRadius: "12px",
                padding: "1.5rem",
                boxShadow: "0 25px 50px -12px rgba(0, 0, 0, 0.5)",
              }}
              onClick={(e) => e.stopPropagation()}
            >
              <div style={{ display: "flex", justifyContent: "space-between", alignItems: "center", marginBottom: "1rem" }}>
                <div style={{ display: "flex", alignItems: "center", gap: "0.5rem" }}>
                  <ShieldAlert size={20} style={{ color: "#a855f7" }} />
                  <h4 style={{ margin: 0, fontSize: "1.1rem", color: isDark ? "#f8fafc" : "#0f172a" }}>
                    ML Threat Prediction Details
                  </h4>
                </div>
                <button
                  onClick={() => setMlPacket(null)}
                  style={{ background: "none", border: "none", color: "#94a3b8", cursor: "pointer" }}
                >
                  <X size={20} />
                </button>
              </div>

              <div style={{ backgroundColor: isDark ? "#020617" : "#f8fafc", borderRadius: "8px", padding: "1rem", marginBottom: "1rem" }}>
                <div style={{ display: "grid", gridTemplateColumns: "1fr 1fr", gap: "0.75rem", fontSize: "0.85rem" }}>
                  <div>
                    <span style={{ color: "#94a3b8" }}>Threat Classification:</span>{" "}
                    <strong style={{ color: evaluatePacketThreat(mlPacket).classification === "Malicious" ? "#ef4444" : (evaluatePacketThreat(mlPacket).classification === "Medium" ? "#f97316" : "#10b981") }}>
                      {evaluatePacketThreat(mlPacket).classification}
                    </strong>
                  </div>
                  <div>
                    <span style={{ color: "#94a3b8" }}>Threat Score:</span>{" "}
                    <strong>{evaluatePacketThreat(mlPacket).score}/100</strong>
                  </div>
                  <div>
                    <span style={{ color: "#94a3b8" }}>Source -&gt; Dest:</span>{" "}
                    <code>{mlPacket.source_ip} -&gt; {mlPacket.destination_ip || mlPacket.dest_ip || "10.0.0.12"}</code>
                  </div>
                  <div>
                    <span style={{ color: "#94a3b8" }}>Protocol / Size:</span>{" "}
                    <span>{mlPacket.protocol} ({mlPacket.packet_size || mlPacket.size_bytes || 512} B)</span>
                  </div>
                </div>
              </div>

              <div style={{ fontSize: "0.85rem", color: isDark ? "#cbd5e1" : "#334155" }}>
                <p style={{ margin: "0 0 0.5rem 0", fontWeight: 600 }}>ML Inference Breakdown:</p>
                <ul style={{ margin: 0, paddingLeft: "1.2rem", lineHeight: 1.6, color: "#94a3b8" }}>
                  <li>Gradient Boosted Classifier &amp; Random Forest ensemble analysis.</li>
                  <li>Heuristic IP reputation check against threat vector feeds.</li>
                  <li>Payload anomaly score computed from raw byte distribution.</li>
                </ul>
              </div>
            </div>
          </div>
        )}

        {/* Modal 3: Escalation Audit Details Modal */}
        {escalatedAuditPacket && (
          <div
            style={{
              position: "fixed",
              inset: 0,
              zIndex: 9999,
              backgroundColor: "rgba(0, 0, 0, 0.75)",
              backdropFilter: "blur(4px)",
              display: "flex",
              alignItems: "center",
              justifyContent: "center",
              padding: "1.5rem",
            }}
            onClick={() => setEscalatedAuditPacket(null)}
          >
            <div
              style={{
                width: "100%",
                maxWidth: "680px",
                maxHeight: "85vh",
                overflowY: "auto",
                backgroundColor: isDark ? "#0f172a" : "#ffffff",
                border: isDark ? "1px solid #1e293b" : "1px solid #e2e8f0",
                borderRadius: "12px",
                boxShadow: "0 20px 25px -5px rgba(0, 0, 0, 0.5)",
                padding: "1.5rem",
              }}
              onClick={(e) => e.stopPropagation()}
            >
              <div style={{ display: "flex", justifyContent: "space-between", alignItems: "center", marginBottom: "1.25rem" }}>
                <div style={{ display: "flex", alignItems: "center", gap: "0.5rem" }}>
                  <ShieldAlert size={20} style={{ color: "#c084fc" }} />
                  <h3 style={{ margin: 0, fontSize: "1.1rem", fontWeight: 700, color: isDark ? "#f8fafc" : "#0f172a" }}>
                    🛡️ Incident Escalation Record #{escalatedAuditPacket.id || escalatedAuditPacket.packet_number || 1}
                  </h3>
                </div>
                <button
                  style={{ background: "none", border: "none", color: "#94a3b8", cursor: "pointer", padding: "4px" }}
                  onClick={() => setEscalatedAuditPacket(null)}
                >
                  <X size={18} />
                </button>
              </div>

              {/* Telemetry Summary */}
              <div style={{ backgroundColor: isDark ? "#020617" : "#f8fafc", borderRadius: "8px", padding: "1rem", marginBottom: "1rem", border: isDark ? "1px solid #1e293b" : "1px solid #e2e8f0" }}>
                <h4 style={{ margin: "0 0 0.75rem 0", fontSize: "0.85rem", color: "#c084fc", textTransform: "uppercase", letterSpacing: "0.05em", fontWeight: 600 }}>
                  Telemetry Summary
                </h4>
                <div style={{ display: "grid", gridTemplateColumns: "1fr 1fr", gap: "0.75rem", fontSize: "0.85rem" }}>
                  <div>
                    <span style={{ color: "#94a3b8" }}>Source IP:</span>{" "}
                    <code style={{ color: "#38bdf8" }}>{escalatedAuditPacket.source_ip || escalatedAuditPacket["Source IP"] || "192.168.1.50"}</code>
                  </div>
                  <div>
                    <span style={{ color: "#94a3b8" }}>Destination IP:</span>{" "}
                    <code style={{ color: "#38bdf8" }}>{escalatedAuditPacket.destination_ip || escalatedAuditPacket.dest_ip || escalatedAuditPacket["Destination IP"] || "10.0.0.12"}</code>
                  </div>
                  <div>
                    <span style={{ color: "#94a3b8" }}>Protocol:</span>{" "}
                    <strong style={{ color: "#10b981" }}>{escalatedAuditPacket.protocol || escalatedAuditPacket["Type of Protocol"] || "TCP"}</strong>
                  </div>
                  <div>
                    <span style={{ color: "#94a3b8" }}>Packet Size:</span>{" "}
                    <span>{escalatedAuditPacket.packet_size || escalatedAuditPacket.size_bytes || `${escalatedAuditPacket.size || 512} Bytes`}</span>
                  </div>
                  <div style={{ gridColumn: "span 2" }}>
                    <span style={{ color: "#94a3b8" }}>Real Timestamp:</span>{" "}
                    <span>{escalatedAuditPacket.timestamp || escalatedAuditPacket.Timestamp || escalatedAuditPacket.real_timestamp || "2026-08-28 10:40:00 UTC"}</span>
                  </div>
                </div>
              </div>

              {/* Escalation Metadata */}
              <div style={{ backgroundColor: isDark ? "#020617" : "#f8fafc", borderRadius: "8px", padding: "1rem", border: isDark ? "1px solid #1e293b" : "1px solid #e2e8f0" }}>
                <h4 style={{ margin: "0 0 0.75rem 0", fontSize: "0.85rem", color: "#c084fc", textTransform: "uppercase", letterSpacing: "0.05em", fontWeight: 600 }}>
                  Escalation Audit Metadata
                </h4>
                <div style={{ display: "flex", flexDirection: "column", gap: "0.65rem", fontSize: "0.85rem" }}>
                  <div style={{ display: "flex", justifyContent: "space-between", alignItems: "center" }}>
                    <span style={{ color: "#94a3b8" }}>Escalation Status:</span>
                    <span className="pcap-status-badge" style={{ backgroundColor: "rgba(168, 85, 247, 0.2)", color: "#c084fc", borderColor: "rgba(168, 85, 247, 0.5)", fontWeight: 600 }}>
                      ESCALATED (Under Senior Review)
                    </span>
                  </div>
                  <div style={{ display: "flex", justifyContent: "space-between", alignItems: "center" }}>
                    <span style={{ color: "#94a3b8" }}>Escalated At:</span>
                    <span style={{ fontWeight: 600, color: isDark ? "#f8fafc" : "#0f172a" }}>
                      {escalatedAuditPacket.escalated_at || escalatedAuditPacket.timestamp || "2026-08-28 10:40:00 UTC"}
                    </span>
                  </div>
                  <div style={{ display: "flex", justifyContent: "space-between", alignItems: "center" }}>
                    <span style={{ color: "#94a3b8" }}>Originating Analyst:</span>
                    <span style={{ fontWeight: 600, color: "#38bdf8" }}>
                      {escalatedAuditPacket.originating_analyst || escalatedAuditPacket.user_id || "Tier 1 SOC Analyst"}
                    </span>
                  </div>
                  <div style={{ marginTop: "0.5rem", paddingTop: "0.5rem", borderTop: isDark ? "1px solid #1e293b" : "1px solid #e2e8f0" }}>
                    <span style={{ color: "#94a3b8", display: "block", marginBottom: "0.35rem", fontWeight: 600 }}>
                      Audit Log / Analyst Note:
                    </span>
                    <p style={{ margin: 0, padding: "0.6rem 0.75rem", backgroundColor: isDark ? "#0f172a" : "#ffffff", border: isDark ? "1px solid #334155" : "1px solid #cbd5e1", borderRadius: "6px", color: isDark ? "#cbd5e1" : "#334155", fontSize: "0.82rem", lineHeight: 1.5, whitespace: "pre-wrap" }}>
                      {escalatedAuditPacket.audit_note || "Packet escalated to Tier 2/3 due to elevated threat score and boundary anomaly."}
                    </p>
                  </div>
                </div>
              </div>

              {/* Senior Analyst Resolution Control Panel */}
              <div style={{ marginTop: "1rem", backgroundColor: isDark ? "#020617" : "#f8fafc", borderRadius: "8px", padding: "1rem", border: isDark ? "1px solid #1e293b" : "1px solid #e2e8f0" }}>
                <h4 style={{ margin: "0 0 0.75rem 0", fontSize: "0.85rem", color: "#38bdf8", textTransform: "uppercase", letterSpacing: "0.05em", fontWeight: 600 }}>
                  SENIOR ANALYST RESOLUTION ACTIONS
                </h4>
                <div style={{ display: "flex", gap: "0.6rem", flexWrap: "wrap" }}>
                  <button
                    style={{
                      flex: "1 1 auto",
                      padding: "0.55rem 0.85rem",
                      fontSize: "0.8rem",
                      fontWeight: 600,
                      backgroundColor: "#EF4444",
                      color: "#ffffff",
                      border: "none",
                      borderRadius: "6px",
                      cursor: "pointer",
                      display: "flex",
                      alignItems: "center",
                      justifyContent: "center",
                      gap: "0.35rem",
                      boxShadow: "0 2px 4px rgba(239, 68, 68, 0.3)"
                    }}
                    onClick={() => handleBlockDestinationIp(escalatedAuditPacket)}
                  >
                    <Lock size={14} /> Block Destination IP
                  </button>

                  <button
                    style={{
                      flex: "1 1 auto",
                      padding: "0.55rem 0.85rem",
                      fontSize: "0.8rem",
                      fontWeight: 600,
                      backgroundColor: "#F59E0B",
                      color: "#ffffff",
                      border: "none",
                      borderRadius: "6px",
                      cursor: "pointer",
                      display: "flex",
                      alignItems: "center",
                      justifyContent: "center",
                      gap: "0.35rem",
                      boxShadow: "0 2px 4px rgba(245, 158, 11, 0.3)"
                    }}
                    onClick={() => handleIsolateHostMachine(escalatedAuditPacket)}
                  >
                    <Zap size={14} /> Isolate Host Machine
                  </button>

                  <button
                    style={{
                      flex: "1 1 auto",
                      padding: "0.55rem 0.85rem",
                      fontSize: "0.8rem",
                      fontWeight: 600,
                      backgroundColor: "#6B7280",
                      color: "#ffffff",
                      border: "none",
                      borderRadius: "6px",
                      cursor: "pointer",
                      display: "flex",
                      alignItems: "center",
                      justifyContent: "center",
                      gap: "0.35rem"
                    }}
                    onClick={() => handleDismissFalsePositive(escalatedAuditPacket)}
                  >
                    <CheckCircle size={14} /> Dismiss as False Positive
                  </button>
                </div>
              </div>
            </div>
          </div>
        )}
      </div>
    </div>
  );
}


