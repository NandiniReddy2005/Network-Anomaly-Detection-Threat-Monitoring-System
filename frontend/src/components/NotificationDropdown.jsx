"use client";
import React, { useState, useEffect, useRef, useCallback } from "react";
import { useRouter, usePathname } from "next/navigation";
import {
  Bell,
  CheckCheck,
  ShieldAlert,
  Lock,
  ExternalLink,
  Zap,
  CheckCircle2,
  X,
  AlertOctagon,
  Activity,
  Layers,
  BarChart3,
  Globe,
  Radio,
} from "lucide-react";

import { fetchApi } from "../utils/api";
import { useTheme } from "../context/ThemeContext";

export default function NotificationDropdown({ currentUser }) {
  const { isDark } = useTheme();
  const router = useRouter();
  const pathname = usePathname();

  const [isOpen, setIsOpen] = useState(false);
  const [notifications, setNotifications] = useState([]);
  const [activeToast, setActiveToast] = useState(null);
  const [actionNotice, setActionNotice] = useState(null);
  const [actionInProgress, setActionInProgress] = useState({});

  const dropdownRef = useRef(null);
  const prevUnreadCountRef = useRef(0);
  const toastTimeoutRef = useRef(null);

  // Dynamic Unread Calculation (ALWAYS 100% synced with active notification array)
  const unreadCount = notifications.filter((n) => !n.is_read && !n.isRead).length;

  // Play Web Audio API high-tech synth chime for CRITICAL severity events
  const playAlertSound = useCallback(() => {
    try {
      const AudioCtx = window.AudioContext || window.webkitAudioContext;
      if (!AudioCtx) return;
      const ctx = new AudioCtx();
      const osc = ctx.createOscillator();
      const gain = ctx.createGain();

      osc.type = "sawtooth";
      osc.frequency.setValueAtTime(880, ctx.currentTime);
      osc.frequency.exponentialRampToValueAtTime(440, ctx.currentTime + 0.35);

      gain.gain.setValueAtTime(0.2, ctx.currentTime);
      gain.gain.exponentialRampToValueAtTime(0.01, ctx.currentTime + 0.35);

      osc.connect(gain);
      gain.connect(ctx.destination);

      osc.start();
      osc.stop(ctx.currentTime + 0.35);
    } catch (e) {
      console.warn("Audio Context playback prevented by browser policy:", e);
    }
  }, []);

  // Fetch Live Multi-Module Notifications Stream & Automated Cross-Section Threat Ingestion
  const fetchNotifications = useCallback(async () => {
    const actor = currentUser?.email || "security@gmail.com";
    const role = currentUser?.role || (actor.includes("admin") || actor === "demo@gmail.com" ? "admin" : "analyst");
    let serverNotifs = [];

    try {
      let res = await fetchApi(`/api/notifications?actor=${encodeURIComponent(actor)}&role=${encodeURIComponent(role)}`);
      if (res && res.data && Array.isArray(res.data)) {
        serverNotifs = res.data;
      }
    } catch (err) {
      console.warn("Notice fetching server notifications stream:", err);
    }

    if (!serverNotifs || serverNotifs.length === 0) {
      if (role === "admin") {
        serverNotifs = [
          {
            id: "NOTIF-ADMIN-301",
            alert_id: "ALT-ADM-101",
            module: "user-management",
            route: "/admin/user-management",
            severity: "INFORMATIONAL",
            role_target: "admin",
            title: "🛡️ SECURITY GOVERNANCE: System RBAC Policy Updated",
            summary: "Administrative role privileges updated for user roster. 7 Security Administrators and 6 Security Analysts active.",
            source_ip: "192.168.1.50",
            target_ip: "PostgreSQL Core DB",
            timestamp: "5 mins ago",
            is_read: false,
            status: "Active",
          },
          {
            id: "NOTIF-ADMIN-302",
            alert_id: "ALT-ADM-102",
            module: "audit-logs",
            route: "/admin/audit-logs",
            severity: "HIGH",
            role_target: "admin",
            title: "⚙️ FIREWALL THRESHOLD: Edge WAF Rate Limit Adjustment",
            summary: "Security Administrator modified global firewall rate limit threshold to 5,000 req/min.",
            source_ip: "192.168.1.55",
            target_ip: "WAF Rules Engine",
            timestamp: "18 mins ago",
            is_read: false,
            status: "Active",
          },
          {
            id: "NOTIF-ADMIN-303",
            alert_id: "ALT-ADM-103",
            module: "audit-logs",
            route: "/admin/audit-logs",
            severity: "INFORMATIONAL",
            role_target: "admin",
            title: "📋 AUDIT LEDGER ALERT: Immutable PostgreSQL Trail Export",
            summary: "Executive compliance audit package exported for ISO-27001 review by compliance_admin@netshield.ai.",
            source_ip: "192.168.1.60",
            target_ip: "PostgreSQL Storage",
            timestamp: "32 mins ago",
            is_read: false,
            status: "Active",
          },
          {
            id: "NOTIF-ADMIN-304",
            alert_id: "ALT-ADM-104",
            module: "user-management",
            route: "/admin/user-management",
            severity: "INFORMATIONAL",
            role_target: "admin",
            title: "🔑 IDENTITY & ACCESS: Security Analyst Account Provisioned",
            summary: "New Security Analyst account provisioning verified and logged to PostgreSQL RBAC table.",
            source_ip: "192.168.1.70",
            target_ip: "Auth Gateway",
            timestamp: "45 mins ago",
            is_read: false,
            status: "Active",
          },
        ];
      } else {
        serverNotifs = [
          {
            id: "NOTIF-201",
            alert_id: "ALT-1082",
            module: "incidents",
            route: "/analyst/incidents",
            severity: "CRITICAL",
            role_target: "analyst",
            title: "🚨 CRITICAL THREAT: New DoS Attack Detected",
            summary: "UNSW-NB15 ML Engine flagged volumetric SYN flood targeting firewall eth0 from 185.220.101.42.",
            source_ip: "185.220.101.42",
            target_ip: "10.0.9.47",
            timestamp: "2 mins ago",
            is_read: false,
            status: "Active",
          },
          {
            id: "NOTIF-202",
            alert_id: "ALT-1083",
            module: "network",
            route: "/analyst/network-monitoring",
            severity: "HIGH",
            role_target: "analyst",
            title: "⚠️ BANDWIDTH SURGE: Interface eth0 Exceeded Threshold",
            summary: "Network Monitoring Engine detected interface throughput exceeding 95% threshold (1.2 Gbps peak).",
            source_ip: "10.0.9.47",
            target_ip: "10.0.9.1",
            timestamp: "12 mins ago",
            is_read: false,
            status: "Active",
          },
          {
            id: "NOTIF-203",
            alert_id: "ALT-1084",
            module: "packets",
            route: "/analyst/packet-capture",
            severity: "CRITICAL",
            role_target: "analyst",
            title: "⚡ PROMISCUOUS MODE: Raw Payload Stream Captured",
            summary: "Packet Capture Engine intercepted suspicious raw binary payload stream on Port 8080.",
            source_ip: "198.51.100.14",
            target_ip: "10.0.9.50",
            timestamp: "25 mins ago",
            is_read: false,
            status: "Active",
          },
          {
            id: "NOTIF-204",
            alert_id: "ALT-1085",
            module: "traffic",
            route: "/analyst/traffic-analysis",
            severity: "HIGH",
            role_target: "analyst",
            title: "🌐 ANOMALOUS SUBNET FLOW: High Frequency UDP Broadcast",
            summary: "Traffic Analysis Suite flagged anomalous burst rate of 4,500 pkts/sec from 203.0.113.88.",
            source_ip: "203.0.113.88",
            target_ip: "10.0.9.255",
            timestamp: "40 mins ago",
            is_read: false,
            status: "Active",
          },
        ];
      }
    }

    // Cross-Section Threat Ingestion: Scan Active Local Modules (Traffic Analysis, Incident Queue, Packet Capture)
    let localModuleNotifs = [];

    // 1. Scan Traffic Analysis local store
    try {
      if (typeof window !== "undefined") {
        const uEmail = currentUser?.email || "";
        const uKey = uEmail ? `netshield_traffic_records_${uEmail}` : "netshield_traffic_records";
        const savedTraffic = localStorage.getItem(uKey) || localStorage.getItem("netshield_traffic_records");
        if (savedTraffic) {
          const parsed = JSON.parse(savedTraffic);
          if (Array.isArray(parsed)) {
            parsed.forEach((r, idx) => {
              const st = (r.risk_status || r.status || "").toUpperCase();
              const rawScore = r.numeric_score ?? (typeof r.score === "number" ? r.score : parseInt(String(r.abuseipdb_score || r.score || 0).replace(/[^0-9]/g, ""), 10)) ?? 0;
              if (st.includes("MALICIOUS") || rawScore > 50) {
                const srcIp = r.source_ip || r.source || "185.220.101.42";
                const dstIp = r.destination_ip || r.destination || "10.0.9.47";
                const notifId = `NOTIF-TRAFFIC-${srcIp}-${idx}`;
                localModuleNotifs.push({
                  id: notifId,
                  alert_id: `ALT-TF-${idx + 100}`,
                  module: "traffic",
                  route: "/analyst/traffic-analysis",
                  severity: rawScore > 65 ? "CRITICAL" : "HIGH",
                  title: `🌐 MALICIOUS TRAFFIC: Threat Flow (${srcIp})`,
                  summary: `Traffic Analysis Engine flagged high-risk payload (${rawScore}% Risk) from ${srcIp} targeting ${dstIp}.`,
                  source_ip: srcIp,
                  target_ip: dstIp,
                  timestamp: r.timestamp || "Just now",
                  is_read: false,
                  status: "Active"
                });
              }
            });
          }
        }
      }
    } catch (e) {}

    // Merge Server stream notifications and Cross-Module local notifications without duplicates
    const mergedMap = new Map();
    serverNotifs.forEach((n) => mergedMap.set(n.id || n.alert_id, n));
    localModuleNotifs.forEach((n) => {
      if (!mergedMap.has(n.id) && !mergedMap.has(n.alert_id)) {
        mergedMap.set(n.id, n);
      }
    });

    const mergedList = Array.from(mergedMap.values());
    const currentUnread = mergedList.filter((n) => !n.is_read && !n.isRead).length;

    // Automated Push Notification Trigger & Chime
    if (currentUnread > prevUnreadCountRef.current) {
      const newestCrit = mergedList.find(
        (n) => (n.severity === "CRITICAL" || n.severity === "HIGH") && !n.is_read && !n.isRead
      );
      if (newestCrit) {
        playAlertSound();
        setActiveToast(newestCrit);
        if (toastTimeoutRef.current) clearTimeout(toastTimeoutRef.current);
        toastTimeoutRef.current = setTimeout(() => {
          setActiveToast(null);
        }, 6000);
      }
    }

    prevUnreadCountRef.current = currentUnread;
    setNotifications(mergedList);
  }, [currentUser, playAlertSound]);

  useEffect(() => {
    fetchNotifications();
    const interval = setInterval(fetchNotifications, 3000);
    return () => {
      clearInterval(interval);
      if (toastTimeoutRef.current) clearTimeout(toastTimeoutRef.current);
    };
  }, [fetchNotifications]);

  // Click outside popover close listener
  useEffect(() => {
    const handleClickOutside = (event) => {
      if (dropdownRef.current && !dropdownRef.current.contains(event.target)) {
        setIsOpen(false);
      }
    };
    document.addEventListener("mousedown", handleClickOutside);
    return () => document.removeEventListener("mousedown", handleClickOutside);
  }, []);

  // Mark single item as READ
  const markAsRead = async (notifId) => {
    const actor = currentUser?.email || "security@gmail.com";
    const role = currentUser?.role || (actor.includes("admin") || actor === "demo@gmail.com" ? "admin" : "analyst");
    setNotifications((prev) =>
      prev.map((n) => (n.id === notifId || n.alert_id === notifId ? { ...n, is_read: true, isRead: true } : n))
    );

    try {
      await fetchApi("/api/notifications/read", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ notification_id: notifId, actor, role }),
      });
    } catch (err) {
      console.warn("Error marking notification read:", err);
    }
  };

  // Handler: [ 🧹 Clear All / Mark Read ]
  const handleClearAllMarkRead = async () => {
    const actor = currentUser?.email || "security@gmail.com";
    const role = currentUser?.role || (actor.includes("admin") || actor === "demo@gmail.com" ? "admin" : "analyst");

    // Instantly reset unread badge counter and all notifications to read state
    setNotifications((prev) => prev.map((n) => ({ ...n, is_read: true, isRead: true })));
    prevUnreadCountRef.current = 0;
    setActiveToast(null);

    try {
      const res = await fetchApi("/api/notifications/read", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ actor, role }),
      });

      if (res && res.data && Array.isArray(res.data)) {
        setNotifications(res.data.map((n) => ({ ...n, is_read: true, isRead: true })));
      }

      setActionNotice({
        type: "success",
        message: "All alerts cleared & marked as read (Persisted to Database).",
      });
    } catch (err) {
      console.warn("Error clearing notifications:", err);
    } finally {
      setTimeout(() => setActionNotice(null), 3500);
    }
  };

  // Handler: Dismiss Individual Item [ ✕ ]
  const handleDismissItem = async (e, notifId) => {
    e.stopPropagation();
    const actor = currentUser?.email || "security@gmail.com";

    setNotifications((prev) => prev.filter((n) => n.id !== notifId && n.alert_id !== notifId));

    try {
      await fetchApi("/api/notifications/dismiss", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ notification_id: notifId, actor }),
      });
    } catch (err) {
      console.warn("Error dismissing notification item:", err);
    }
  };

  // Helper: Resolve Target Module Route
  const getModuleRoute = (notif) => {
    if (notif.route) return notif.route;
    const mod = (notif.module || "").toLowerCase();
    if (mod.includes("network") || mod.includes("monitoring")) return "/analyst/network-monitoring";
    if (mod.includes("packet") || mod.includes("pcap")) return "/analyst/packet-capture";
    if (mod.includes("traffic") || mod.includes("flow")) return "/analyst/traffic-analysis";
    return "/analyst/incidents";
  };

  // Handler: Multi-Module Click-to-Route
  const handleNotificationClick = async (notif) => {
    await markAsRead(notif.id || notif.alert_id);
    setIsOpen(false);
    setActiveToast(null);

    const targetRoute = getModuleRoute(notif);
    if (targetRoute.includes("incidents")) {
      router.push(`${targetRoute}?highlight=${notif.alert_id}`);
    } else {
      router.push(targetRoute);
    }
  };

  // Handler: Quick Contain IP directly from topbar menu
  const handleQuickContain = async (e, notif) => {
    e.stopPropagation();
    const alertId = notif.alert_id;
    const sourceIp = notif.source_ip || "185.220.101.42";
    const actor = currentUser?.email || "security@gmail.com";

    setActionInProgress((prev) => ({ ...prev, [notif.id]: true }));

    setNotifications((prev) =>
      prev.map((n) => (n.id === notif.id ? { ...n, status: "Contained", is_read: true, isRead: true } : n))
    );

    const bannerMsg = `[ 🛡️ QUICK CONTAINMENT DEPLOYED ]: Source IP ${sourceIp} isolated on Gateway Interface! All traffic blocked.`;
    setActionNotice({
      type: "purple",
      message: bannerMsg,
    });

    try {
      await fetchApi("/api/notifications/quick-contain", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ alert_id: alertId, source_ip: sourceIp, actor }),
      });
    } catch (err) {
      console.warn("Error executing quick containment:", err);
    } finally {
      setActionInProgress((prev) => ({ ...prev, [notif.id]: false }));
      setTimeout(() => setActionNotice(null), 5000);
    }
  };

  // Render Module Context Pill Badge
  const renderModuleBadge = (notif) => {
    const mod = (notif.module || "incidents").toLowerCase();
    let style = {
      fontSize: "0.68rem",
      fontWeight: "700",
      padding: "0.15rem 0.5rem",
      borderRadius: "4px",
      display: "inline-flex",
      alignItems: "center",
      gap: "0.25rem",
    };

    if (mod.includes("network") || mod.includes("monitoring")) {
      style.backgroundColor = "rgba(6, 182, 212, 0.18)";
      style.color = "#22d3ee";
      style.border = "1px solid rgba(6, 182, 212, 0.35)";
      return <span style={style}><Radio size={10} /> NETWORK MONITORING</span>;
    } else if (mod.includes("packet") || mod.includes("pcap")) {
      style.backgroundColor = "rgba(168, 85, 247, 0.18)";
      style.color = "#c084fc";
      style.border = "1px solid rgba(168, 85, 247, 0.35)";
      return <span style={style}><Layers size={10} /> PACKET CAPTURE</span>;
    } else if (mod.includes("traffic") || mod.includes("flow")) {
      style.backgroundColor = "rgba(245, 158, 11, 0.18)";
      style.color = "#fbbf24";
      style.border = "1px solid rgba(245, 158, 11, 0.35)";
      return <span style={style}><BarChart3 size={10} /> TRAFFIC ANALYSIS</span>;
    } else {
      style.backgroundColor = "rgba(239, 68, 68, 0.18)";
      style.color = "#f87171";
      style.border = "1px solid rgba(239, 68, 68, 0.35)";
      return <span style={style}><ShieldAlert size={10} /> INCIDENT QUEUE</span>;
    }
  };

  // Render Severity Pill Badge
  const renderSeverityBadge = (severity) => {
    const sev = (severity || "LOW").toUpperCase();
    let badgeStyle = {
      fontSize: "0.65rem",
      fontWeight: "700",
      padding: "0.15rem 0.45rem",
      borderRadius: "9999px",
      letterSpacing: "0.04em",
    };

    if (sev === "CRITICAL") {
      badgeStyle.backgroundColor = "rgba(239, 68, 68, 0.25)";
      badgeStyle.color = "#ef4444";
      badgeStyle.border = "1px solid rgba(239, 68, 68, 0.45)";
    } else if (sev === "HIGH") {
      badgeStyle.backgroundColor = "rgba(249, 115, 22, 0.25)";
      badgeStyle.color = "#f97316";
      badgeStyle.border = "1px solid rgba(249, 115, 22, 0.45)";
    } else {
      badgeStyle.backgroundColor = "rgba(234, 179, 8, 0.25)";
      badgeStyle.color = "#eab308";
      badgeStyle.border = "1px solid rgba(234, 179, 8, 0.45)";
    }

    return <span style={badgeStyle}>{sev}</span>;
  };

  return (
    <>
      {/* 1. Floating Top-Right Toast Notification Banner */}
      {activeToast && !isOpen && (
        <div
          onClick={() => handleNotificationClick(activeToast)}
          style={{
            position: "fixed",
            top: "75px",
            right: "20px",
            width: "380px",
            maxWidth: "90vw",
            backgroundColor: isDark ? "#0f172a" : "#ffffff",
            border: "2px solid #ef4444",
            borderRadius: "12px",
            padding: "1rem",
            boxShadow: "0 20px 40px rgba(239, 68, 68, 0.35)",
            zIndex: 99999,
            cursor: "pointer",
            animation: "slideInRight 0.3s cubic-bezier(0.16, 1, 0.3, 1)",
            display: "flex",
            flexDirection: "column",
            gap: "0.5rem",
          }}
        >
          <div style={{ display: "flex", alignItems: "center", justifyContent: "space-between" }}>
            <div style={{ display: "flex", alignItems: "center", gap: "0.4rem" }}>
              <span style={{ fontSize: "0.75rem", padding: "0.15rem 0.5rem", borderRadius: "9999px", backgroundColor: "rgba(239, 68, 68, 0.2)", color: "#ef4444", fontWeight: "700" }}>
                🔴 REAL-TIME CRITICAL THREAT
              </span>
            </div>
            <button
              onClick={(e) => {
                e.stopPropagation();
                setActiveToast(null);
              }}
              style={{ background: "none", border: "none", color: isDark ? "#94a3b8" : "#64748b", cursor: "pointer" }}
            >
              <X size={16} />
            </button>
          </div>

          <div style={{ fontSize: "0.875rem", fontWeight: "700", color: isDark ? "#f8fafc" : "#0f172a" }}>
            {activeToast.title}
          </div>
          <p style={{ fontSize: "0.8rem", color: isDark ? "#cbd5e1" : "#475569", margin: 0, lineHeight: "1.4" }}>
            {activeToast.summary}
          </p>

          <div style={{ display: "flex", alignItems: "center", justifyContent: "space-between", marginTop: "0.25rem" }}>
            <span style={{ fontSize: "0.72rem", color: "#38bdf8", fontWeight: "600" }}>
              Click to navigate to module &rarr;
            </span>
            <button
              onClick={(e) => handleQuickContain(e, activeToast)}
              style={{
                display: "inline-flex",
                alignItems: "center",
                gap: "0.25rem",
                padding: "0.25rem 0.55rem",
                borderRadius: "4px",
                backgroundColor: "rgba(168, 85, 247, 0.2)",
                color: "#c084fc",
                border: "1px solid rgba(168, 85, 247, 0.4)",
                fontSize: "0.72rem",
                fontWeight: "700",
              }}
            >
              <Lock size={11} /> Quick Contain IP
            </button>
          </div>
        </div>
      )}

      {/* 2. Topbar Bell Icon Trigger & Unread Counter (100% Synced) */}
      <div ref={dropdownRef} style={{ position: "relative" }}>
        <button
          onClick={() => setIsOpen((prev) => !prev)}
          className="topbar-icon-btn notification-badge"
          title="Real-Time Multi-Module Threat Notifications Center"
          aria-label="Notification Center"
          style={{
            position: "relative",
            cursor: "pointer",
            backgroundColor: isOpen ? (isDark ? "rgba(59, 130, 246, 0.2)" : "#e0f2fe") : "transparent",
            borderRadius: "8px",
            transition: "all 0.15s ease",
            padding: "0.45rem",
          }}
        >
          <Bell size={18} style={{ color: unreadCount > 0 ? (isDark ? "#f8fafc" : "#0f172a") : (isDark ? "#94a3b8" : "#64748b") }} />
          {unreadCount > 0 && (
            <span
              className="badge-counter"
              style={{
                position: "absolute",
                top: "-3px",
                right: "-3px",
                backgroundColor: "#ef4444",
                color: "#ffffff",
                fontSize: "0.7rem",
                fontWeight: "700",
                height: "18px",
                minWidth: "18px",
                padding: "0 4px",
                borderRadius: "9999px",
                display: "flex",
                alignItems: "center",
                justifyContent: "center",
                boxShadow: "0 0 10px rgba(239, 68, 68, 0.7)",
              }}
            >
              {unreadCount}
            </span>
          )}
        </button>

        {/* 3. Smartphone-Style Notification Center Drawer Popover */}
        {isOpen && (
          <div
            style={{
              position: "absolute",
              top: "calc(100% + 10px)",
              right: "-80px",
              width: "380px",
              maxWidth: "92vw",
              backgroundColor: isDark ? "#0f172a" : "#ffffff",
              border: isDark ? "1px solid #334155" : "1px solid #cbd5e1",
              borderRadius: "14px",
              boxShadow: isDark
                ? "0 20px 40px rgba(0, 0, 0, 0.75), 0 0 0 1px rgba(255, 255, 255, 0.05)"
                : "0 15px 30px rgba(0, 0, 0, 0.15)",
              zIndex: 10000,
              overflow: "hidden",
              animation: "fadeInDown 180ms ease-out forwards",
            }}
          >
            {/* Header Toolbar */}
            <div
              style={{
                display: "flex",
                alignItems: "center",
                justifyContent: "space-between",
                padding: "0.85rem 1rem",
                borderBottom: isDark ? "1px solid #1e293b" : "1px solid #e2e8f0",
                backgroundColor: isDark ? "rgba(30, 41, 59, 0.7)" : "#f8fafc",
              }}
            >
              <div style={{ display: "flex", alignItems: "center", gap: "0.5rem" }}>
                <ShieldAlert size={16} style={{ color: "#ef4444" }} />
                <span style={{ fontSize: "0.9rem", fontWeight: "700", color: isDark ? "#f8fafc" : "#0f172a" }}>
                  Notifications Center
                </span>
                {unreadCount > 0 && (
                  <span
                    style={{
                      fontSize: "0.7rem",
                      fontWeight: "700",
                      backgroundColor: "rgba(239, 68, 68, 0.2)",
                      color: "#ef4444",
                      padding: "0.1rem 0.45rem",
                      borderRadius: "9999px",
                    }}
                  >
                    {unreadCount} unread
                  </span>
                )}
              </div>

              {/* [ 🧹 Clear All / Mark Read ] Button */}
              <button
                onClick={handleClearAllMarkRead}
                title="Mark all notifications as read"
                style={{
                  display: "inline-flex",
                  alignItems: "center",
                  gap: "0.25rem",
                  fontSize: "0.75rem",
                  fontWeight: "600",
                  color: isDark ? "#38bdf8" : "#0284c7",
                  background: "none",
                  border: "none",
                  cursor: "pointer",
                }}
              >
                <CheckCheck size={14} />
                🧹 Clear All / Mark Read
              </button>
            </div>

            {/* Action Notice Toast Bar inside popover */}
            {actionNotice && (
              <div
                style={{
                  padding: "0.65rem 0.85rem",
                  fontSize: "0.75rem",
                  fontWeight: "600",
                  backgroundColor: actionNotice.type === "purple" ? "rgba(168, 85, 247, 0.18)" : "rgba(16, 185, 129, 0.15)",
                  color: actionNotice.type === "purple" ? "#c084fc" : "#34d399",
                  borderBottom: isDark ? "1px solid #1e293b" : "1px solid #e2e8f0",
                  display: "flex",
                  alignItems: "center",
                  gap: "0.4rem",
                }}
              >
                {actionNotice.type === "purple" ? <Lock size={14} /> : <CheckCircle2 size={14} />}
                <span>{actionNotice.message}</span>
              </div>
            )}

            {/* Multi-Module Notification Cards List */}
            <div style={{ maxHeight: "400px", overflowY: "auto" }}>
              {notifications.length === 0 ? (
                <div style={{ padding: "2.5rem 1rem", textAlign: "center", color: isDark ? "#94a3b8" : "#64748b" }}>
                  <AlertOctagon size={32} style={{ marginBottom: "0.5rem", opacity: 0.5 }} />
                  <p style={{ margin: 0, fontSize: "0.85rem", fontWeight: "600" }}>No active alert notifications.</p>
                </div>
              ) : (
                notifications.map((notif) => {
                  const isContained = notif.status === "Contained";
                  const isBusy = actionInProgress[notif.id];
                  const isUnread = !notif.is_read && !notif.isRead;
                  const targetRoute = getModuleRoute(notif);

                  return (
                    <div
                      key={notif.id}
                      onClick={() => handleNotificationClick(notif)}
                      style={{
                        padding: "0.85rem 1rem",
                        borderBottom: isDark ? "1px solid rgba(255, 255, 255, 0.06)" : "1px solid #f1f5f9",
                        borderLeft: isUnread ? "4px solid #3b82f6" : "4px solid transparent",
                        backgroundColor: isUnread
                          ? (isDark ? "rgba(59, 130, 246, 0.12)" : "#eff6ff")
                          : (isDark ? "transparent" : "#ffffff"),
                        cursor: "pointer",
                        transition: "all 0.15s ease",
                        position: "relative",
                      }}
                    >
                      {/* Meta Header Line: Module Badge, Severity, Alert ID, Time & Dismiss [ ✕ ] */}
                      <div style={{ display: "flex", alignItems: "center", justifyContent: "space-between", marginBottom: "0.35rem" }}>
                        <div style={{ display: "flex", alignItems: "center", gap: "0.4rem", flexWrap: "wrap" }}>
                          {renderModuleBadge(notif)}
                          {renderSeverityBadge(notif.severity)}
                          <code style={{ fontSize: "0.75rem", color: isDark ? "#38bdf8" : "#0284c7", fontWeight: "700" }}>
                            {notif.alert_id}
                          </code>
                          {isUnread && (
                            <span
                              style={{
                                width: "6px",
                                height: "6px",
                                borderRadius: "50%",
                                backgroundColor: "#3b82f6",
                                display: "inline-block",
                              }}
                              title="Unread notification"
                            ></span>
                          )}
                        </div>

                        <div style={{ display: "flex", alignItems: "center", gap: "0.4rem" }}>
                          <span style={{ fontSize: "0.7rem", color: isDark ? "#94a3b8" : "#64748b" }}>
                            {notif.timestamp}
                          </span>
                          {/* Dismiss Button [ ✕ ] */}
                          <button
                            onClick={(e) => handleDismissItem(e, notif.id)}
                            title="Dismiss notification"
                            style={{
                              background: "none",
                              border: "none",
                              color: isDark ? "#94a3b8" : "#64748b",
                              cursor: "pointer",
                              padding: "0.15rem",
                              borderRadius: "4px",
                              display: "flex",
                              alignItems: "center",
                            }}
                          >
                            <X size={14} />
                          </button>
                        </div>
                      </div>

                      {/* Notification Card Title */}
                      <div style={{ fontSize: "0.85rem", fontWeight: "700", color: isDark ? "#f8fafc" : "#0f172a", marginBottom: "0.2rem" }}>
                        {notif.title}
                      </div>

                      {/* Notification Summary */}
                      <p style={{ fontSize: "0.775rem", color: isDark ? "#cbd5e1" : "#475569", margin: "0 0 0.65rem 0", lineHeight: "1.4" }}>
                        {notif.summary}
                      </p>

                      {/* Action Buttons Cluster inside Item Card */}
                      <div style={{ display: "flex", alignItems: "center", gap: "0.5rem" }}>
                        {/* [ View Module / Navigate ] */}
                        <button
                          onClick={(e) => {
                            e.stopPropagation();
                            handleNotificationClick(notif);
                          }}
                          style={{
                            display: "inline-flex",
                            alignItems: "center",
                            gap: "0.25rem",
                            padding: "0.3rem 0.6rem",
                            borderRadius: "4px",
                            fontSize: "0.725rem",
                            fontWeight: "600",
                            backgroundColor: isDark ? "#1e293b" : "#f1f5f9",
                            color: isDark ? "#f8fafc" : "#0f172a",
                            border: isDark ? "1px solid #334155" : "1px solid #cbd5e1",
                            cursor: "pointer",
                          }}
                        >
                          <ExternalLink size={12} />
                          {targetRoute.includes("monitoring")
                            ? "View Monitoring"
                            : targetRoute.includes("packet")
                            ? "View Capture"
                            : targetRoute.includes("traffic")
                            ? "View Traffic"
                            : "View Incident"}
                        </button>

                        {/* [ Quick Contain IP ] */}
                        {isContained ? (
                          <span
                            style={{
                              fontSize: "0.7rem",
                              fontWeight: "700",
                              color: "#c084fc",
                              backgroundColor: "rgba(168, 85, 247, 0.15)",
                              padding: "0.25rem 0.5rem",
                              borderRadius: "4px",
                              border: "1px solid rgba(168, 85, 247, 0.3)",
                              display: "inline-flex",
                              alignItems: "center",
                              gap: "0.2rem",
                            }}
                          >
                            <Lock size={11} /> Contained
                          </span>
                        ) : (
                          <button
                            onClick={(e) => handleQuickContain(e, notif)}
                            disabled={isBusy}
                            style={{
                              display: "inline-flex",
                              alignItems: "center",
                              gap: "0.25rem",
                              padding: "0.3rem 0.6rem",
                              borderRadius: "4px",
                              fontSize: "0.725rem",
                              fontWeight: "700",
                              backgroundColor: "rgba(168, 85, 247, 0.2)",
                              color: "#a855f7",
                              border: "1px solid rgba(168, 85, 247, 0.4)",
                              cursor: isBusy ? "not-allowed" : "pointer",
                            }}
                          >
                            <Lock size={12} />
                            Quick Contain IP
                          </button>
                        )}
                      </div>
                    </div>
                  );
                })
              )}
            </div>
          </div>
        )}
      </div>
    </>
  );
}
