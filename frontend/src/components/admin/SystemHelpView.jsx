"use client";
import React, { useState, useEffect } from "react";
import {
  HelpCircle,
  FileText,
  Search,
  ChevronDown,
  ChevronUp,
  BookOpen,
  Mail,
  Zap,
  Download,
  Database,
  Sliders,
} from "lucide-react";

import { getFormattedUTCTime } from "../../utils/formatDate";
import { API_BASE_URL } from "../../utils/constants";
import { useTheme } from "../../context/ThemeContext";
import { querySystemHelp, sendSupportEmail } from "../../utils/api";

export default function SystemHelpView() {
  const { isDark } = useTheme();
  const [currentTime, setCurrentTime] = useState("");
  const [expandedFaq, setExpandedFaq] = useState(0);
  const [helpSearchQuery, setHelpSearchQuery] = useState("");
  const [helpToastMsg, setHelpToastMsg] = useState(null);

  const [activeAnswer, setActiveAnswer] = useState(null);
  const [isSearching, setIsSearching] = useState(false);
  const [searchError, setSearchError] = useState(null);

  const [activeModuleIndex, setActiveModuleIndex] = useState(null);
  const [hoveredDocIndex, setHoveredDocIndex] = useState(null);

  // Technical Support Email Modal state
  const [isEmailModalOpen, setIsEmailModalOpen] = useState(false);
  const [emailSubject, setEmailSubject] = useState("");
  const [emailCategory, setEmailCategory] = useState("Technical Support");
  const [emailMessage, setEmailMessage] = useState("");
  const [userContactEmail, setUserContactEmail] = useState("");
  const [isSubmittingEmail, setIsSubmittingEmail] = useState(false);
  const [emailError, setEmailError] = useState(null);

  const initialFaqs = [
    {
      id: 'faq-1',
      question: 'How does NetShield-AI calculate composite threat anomaly scores?',
      q: 'How does NetShield-AI calculate composite threat anomaly scores?',
      answer: 'NetShield-AI uses an integrated neural network classifier combined with Snort/Suricata heuristic signatures to evaluate incoming packet payloads. Scores above 75 trigger critical alerts.',
      a: 'NetShield-AI uses an integrated neural network classifier combined with Snort/Suricata heuristic signatures to evaluate incoming packet payloads. Scores above 75 trigger critical alerts.',
      category: 'Telemetry Analytics',
    },
    {
      id: 'faq-2',
      question: 'How do I configure automatic threat mitigation playbooks?',
      q: 'How do I configure automatic threat mitigation playbooks?',
      answer: 'Navigate to Critical Alerts, select an active threat, and choose Execute Containment Playbook to apply automated edge firewall rules.',
      a: 'Navigate to Critical Alerts, select an active threat, and choose Execute Containment Playbook to apply automated edge firewall rules.',
      category: 'Incident Response',
    },
    {
      id: 'faq-3',
      question: 'Where are system audit logs persisted?',
      q: 'Where are system audit logs persisted?',
      answer: 'All security events, user interactions, and ML inference logs are asynchronously written to PostgreSQL audit storage and exported via ml_verification_log.txt.',
      a: 'All security events, user interactions, and ML inference logs are asynchronously written to PostgreSQL audit storage and exported via ml_verification_log.txt.',
      category: 'Audit Logs & RBAC',
    },
    {
      id: 'faq-4',
      question: 'How do I manage user roles and Security Analyst roster access?',
      q: 'How do I manage user roles and Security Analyst roster access?',
      answer: 'Access the User Management tab to assign Role-Based Access Controls (RBAC) separating Security Analyst read/triage permissions from Security Administrator containment rights.',
      a: 'Access the User Management tab to assign Role-Based Access Controls (RBAC) separating Security Analyst read/triage permissions from Security Administrator containment rights.',
      category: 'User Management',
    }
  ];

  const [faqList, setFaqList] = useState(initialFaqs);

  useEffect(() => {
    setCurrentTime(getFormattedUTCTime());
    const timer = setInterval(() => setCurrentTime(getFormattedUTCTime()), 1000);
    return () => clearInterval(timer);
  }, []);

  const handleDownloadPdfGuide = () => {
    window.open(`${API_BASE_URL}/api/reports/pdf`, "_blank");
  };

  const docModules = [
    {
      title: "Architecture & Sensor Mesh Guide",
      category: "Architecture & Sensor Mesh",
      desc: "Detailed overview of FastAPI gateway nodes, PostgreSQL audit storage, and telemetry probes.",
      icon: Database,
      answer: "NetShield-AI Architecture consists of distributed FastAPI telemetry sensor gateway nodes processing network flow features, real-time Async Engine classification pipelines, and PostgreSQL immutable audit storage. Telemetry probes collect netflow stats and submit them via asynchronous RPC payloads for instantaneous ML inference.",
    },
    {
      title: "Threat Triage & Mitigation Playbooks",
      category: "Incident Response",
      desc: "Step-by-step procedures for handling DDoS spikes, WAF injection attempts, and port scans.",
      icon: Zap,
      answer: "Operational Triage Playbooks provide step-by-step containment procedures: P1 Emergency incidents trigger automated IPTables null-routing and source IP isolation; P2 High Risk triggers edge WAF rate limiting; P3/P4 standard incidents undergo DPI sampling and security analyst verification.",
    },
    {
      title: "RBAC & User Access Policy Manual",
      category: "Audit Logs & RBAC",
      desc: "Role permissions definition for Security Analyst vs Security Administrator credentials.",
      icon: Sliders,
      answer: "NetShield-AI enforces strict Role-Based Access Control (RBAC): Security Administrators hold full administrative authority (user provisioning, policy tuning, model retraining), while Security Analysts monitor real-time threat activity and execute manual containment playbooks. All access events are immutably logged.",
    },
    {
      title: "Compliance & Audit Export Guide",
      category: "Compliance & Reporting",
      desc: "Exporting ISO-27001 / SOC2 compliance packages in PDF, CSV, and JSON formats.",
      icon: FileText,
      answer: "Compliance export utilities allow SOC leads to generate ISO-27001, SOC2 Type II, and NIST SP 800-53 audit compliance packages in PDF, CSV, and JSON formats directly from the Reports portal or API endpoints.",
    },
  ];

  const handleModuleClick = (doc, idx) => {
    setActiveModuleIndex(idx);
    setActiveAnswer({
      query: doc.title,
      category: doc.category,
      answer: doc.answer,
    });
  };

  const toggleFaq = (index) => {
    setExpandedFaq(expandedFaq === index ? -1 : index);
  };

  const getLocalAnswer = (queryText) => {
    const raw = (queryText || "").trim();
    const q = raw.toLowerCase();

    let category = "SOC Knowledge Base";
    let answer = `NetShield-AI AI Assistant: I am here to help you navigate threat telemetry, critical alerts, audit logs, and security playbooks regarding '${raw}'. Consult the technical user manual or trigger an automated playbook from the Critical Alerts panel.`;

    if (
      q.includes("threat") ||
      q.includes("threats") ||
      q.includes("threat detection") ||
      q.includes("threat score") ||
      q.includes("threat scores") ||
      q.includes("anomaly score") ||
      q.includes("anomaly probability")
    ) {
      category = "Threat Detection & Analysis";
      answer = "The Threat Detection module continuously analyzes incoming network telemetry using dual neural network models (UNSW-NB15 & CICIDS2017). It calculates real-time threat scores (0–100) and composite anomaly probabilities. Payloads with scores exceeding 75 trigger critical alarms requiring immediate triage or automated playbook execution.";
    } else if (
      q.includes("critical alert") ||
      q.includes("critical alerts") ||
      q.includes("alert") ||
      q.includes("alerts") ||
      q.includes("alarm") ||
      q.includes("alarms") ||
      q.includes("critical threat alerts") ||
      q.includes("alert section") ||
      q.includes("alerts section")
    ) {
      category = "Critical Threat Alerts";
      answer = "The Critical Alerts section monitors real-time composite threat anomalies scored above 75. Security Analysts can inspect deep packet parameters, view AI threat probability vectors, acknowledge incidents, and execute automated containment playbooks (such as IP quarantine or firewall null-routing).";
    } else if (
      q.includes("activity security") ||
      q.includes("security scans") ||
      q.includes("prediction scans") ||
      q.includes("scan history") ||
      q.includes("scans today") ||
      q.includes("total scans") ||
      q.includes("scan") ||
      q.includes("scans")
    ) {
      category = "Activity Security & Threat Scans";
      answer = "The Activity Security portal tracks real-time threat detection metrics, cumulative prediction scans executed across the PostgreSQL historical audit database, daily scan counts, and the live Critical Threat Ratio across incoming network flows.";
    } else if (
      q.includes("audit log") ||
      q.includes("audit logs") ||
      q.includes("audit ledger") ||
      q.includes("audit log section") ||
      q.includes("audit log responsibilities") ||
      q.includes("audit logs responsibilities") ||
      q.includes("audit") ||
      q.includes("log") ||
      q.includes("logs")
    ) {
      category = "Audit Logs & Event Ledger";
      answer = "The Audit Logs section provides an immutable ledger of all system security events, user authentication attempts, RBAC permission changes, active containment playbook executions, and ML model inference calls. All logs are asynchronously written to PostgreSQL audit storage and can be exported in PDF, CSV, or JSON formats for ISO-27001 and SOC2 compliance.";
    } else if (
      q.includes("security analyst") ||
      q.includes("analyst responsibility") ||
      q.includes("analyst responsibilities") ||
      q.includes("analyst role") ||
      q.includes("analyst duties") ||
      q.includes("analyst duty") ||
      q.includes("analyst task") ||
      q.includes("analyst triage") ||
      q.includes("analyst") ||
      q.includes("analysts")
    ) {
      category = "Security Analyst Role";
      answer = "Security Analysts are responsible for real-time threat telemetry monitoring, incident triage, inspecting packet captures (PCAP), analyzing ML risk scores, acknowledging alerts, and executing authorized containment playbooks. Analysts hold read and triage permissions without full platform policy modification rights.";
    } else if (
      q.includes("security administrator") ||
      q.includes("admin responsibility") ||
      q.includes("admin responsibilities") ||
      q.includes("admin role") ||
      q.includes("administrator duties") ||
      q.includes("administrator duty") ||
      q.includes("admin rights") ||
      q.includes("system administrator") ||
      q.includes("administrator role") ||
      q.includes("admin") ||
      q.includes("admins") ||
      q.includes("administrator")
    ) {
      category = "Security Administrator Role";
      answer = "Security Administrators hold root administrative authority across NetShield-AI, including user provisioning, RBAC role assignment, firewall rate limit tuning, global threat intelligence configuration, ML model retraining, and system-wide security posture governance.";
    } else if (q.includes("source ip") || q.includes("src ip")) {
      category = "Network Fundamentals";
      answer = "Source IP represents the originating IPv4 address of the device sending network packets across the telemetry sensor mesh. In NetShield-AI, it is analyzed for threat vector attribution and potential IP quarantine.";
    } else if (q.includes("destination ip") || q.includes("target asset") || q.includes("dst ip") || q.includes("asset") || q.includes("assets")) {
      category = "Asset Protection";
      answer = "Destination IP (or Target Asset) refers to the internal infrastructure node, server, or core gateway receiving the incoming network traffic being inspected by the ML pipeline.";
    } else if (q.includes("triage") || q.includes("critical triage") || q.includes("containment") || q.includes("playbook") || q.includes("playbooks")) {
      category = "Incident Response";
      answer = "Triage is the immediate evaluation and prioritization of security incidents based on composite risk scores. High-priority incidents (P1 Emergency / P2 High Risk) trigger automated containment playbooks.";
    } else if (q.includes("dataset") || q.includes("unsw") || q.includes("cicids") || q.includes("model") || q.includes("machine learning") || q.includes("ml")) {
      category = "Machine Learning Analyzers";
      answer = "NetShield-AI features dual machine learning classification engines trained on UNSW-NB15 (186 features) and CICIDS2017 (78 features). Dynamic IPv4 octet parsing allows inference across any valid IPv4 address—even unseen or out-of-vocabulary IPs.";
    } else if (q.includes("report") || q.includes("reports") || q.includes("pdf") || q.includes("compliance") || q.includes("iso-27001") || q.includes("soc2")) {
      category = "Compliance & Reporting";
      answer = "Compliance export utilities allow SOC leads to generate ISO-27001, SOC2 Type II, and NIST SP 800-53 audit compliance packages in PDF, CSV, and JSON formats directly from the Reports portal or API endpoints.";
    } else if (q.includes("rbac") || q.includes("permission") || q.includes("permissions") || q.includes("role") || q.includes("user management")) {
      category = "Audit Logs & RBAC";
      answer = "NetShield-AI enforces strict Role-Based Access Control (RBAC): Security Administrators possess full system control (user management, policy changes, interactive ML vector analysis), while Security Analysts focus on real-time incident triage and telemetry monitoring. All administrative actions and login events are immutably logged to the PostgreSQL audit ledger.";
    }

    return {
      query: raw,
      category,
      answer
    };
  };

  const handleDispatchSupportEmail = async (e) => {
    if (e && e.preventDefault) e.preventDefault();
    if (!emailMessage.trim()) {
      setEmailError("Please enter your inquiry details before submitting.");
      return;
    }

    setIsSubmittingEmail(true);
    setEmailError(null);
    try {
      const payload = {
        subject: emailSubject.trim() || "Technical Support Inquiry",
        category: emailCategory,
        message: emailMessage.trim(),
        contact_email: userContactEmail.trim() || undefined,
      };
      const res = await sendSupportEmail(payload);
      const ticketId = res?.ticket_id || "TICKET-DISPATCHED";
      setIsEmailModalOpen(false);
      setEmailSubject("");
      setEmailMessage("");
      setUserContactEmail("");
      setEmailError(null);
      setHelpToastMsg(`Support Inquiry #${ticketId} dispatched to support@netshield-ai.com successfully!`);
      setTimeout(() => setHelpToastMsg(null), 5000);
    } catch (err) {
      console.error("Error dispatching support email:", err);
      setEmailError("Failed to dispatch support inquiry. Please try again or call the 24/7 hotline.");
    } finally {
      setIsSubmittingEmail(false);
    }
  };

  const handleExecuteHelpSearchWithQuery = async (searchStr) => {
    if (!searchStr || !searchStr.trim()) return;
    setHelpSearchQuery(searchStr);
    setIsSearching(true);
    setSearchError(null);
    try {
      const res = await querySystemHelp(searchStr.trim());
      if (res && res.answer) {
        setActiveAnswer(res);
      } else {
        setActiveAnswer(getLocalAnswer(searchStr.trim()));
      }
    } catch (err) {
      console.warn("Backend help query API fallback to local matcher:", err);
      setActiveAnswer(getLocalAnswer(searchStr.trim()));
    } finally {
      setIsSearching(false);
    }
  };

  const handleExecuteHelpSearch = async (e) => {
    if (e && e.preventDefault) e.preventDefault();
    await handleExecuteHelpSearchWithQuery(helpSearchQuery);
  };

  return (
    <div key="tab-admin-help" className="soc-help-container">
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
            <HelpCircle size={26} className="soc-dash-header-title-icon" style={{ color: "#38bdf8" }} />
            System Help &amp; Administrative Documentation
          </h2>
          <div className="soc-dash-header-sub">
            <span>SOC Knowledge Base, Operations Guide &amp; Technical Support</span>
            <span>•</span>
            <span className="soc-dash-clock">UTC Time: {currentTime || "Real-Time"}</span>
          </div>
        </div>

        <div className="soc-dash-header-right">
          <button onClick={handleDownloadPdfGuide} className="soc-dash-btn-refresh primary">
            <Download size={15} /> Download PDF Guide
          </button>
        </div>
      </div>

      {/* 2. Search Bar */}
      <form onSubmit={handleExecuteHelpSearch} className="soc-dash-card" style={{ padding: "1.25rem 1.5rem" }}>
        <div style={{ display: "flex", gap: "0.75rem", width: "100%" }}>
          <div className="soc-dash-table-search" style={{ maxWidth: "100%", flex: 1 }}>
            <Search size={18} style={{ color: "#94a3b8" }} />
            <input
              type="text"
              placeholder="Search documentation, FAQs, SOC playbooks, or system guides..."
              value={helpSearchQuery}
              onChange={(e) => setHelpSearchQuery(e.target.value)}
              onKeyDown={(e) => {
                if (e.key === "Enter") handleExecuteHelpSearch(e);
              }}
              style={{ fontSize: "0.95rem" }}
            />
          </div>
          <button
            type="submit"
            disabled={isSearching}
            className="ns-btn-gradient primary small"
            style={{ padding: "0.5rem 1.25rem", fontSize: "0.875rem", whiteSpace: "nowrap" }}
          >
            {isSearching ? "Searching..." : "Search Knowledge Base"}
          </button>
        </div>
      </form>

      {/* AI Search Result Card */}
      {activeAnswer && (
        <div
          style={{
            marginBottom: "1.5rem",
            padding: "1.25rem 1.5rem",
            borderRadius: "10px",
            backgroundColor: isDark ? "rgba(15, 23, 42, 0.9)" : "#ffffff",
            border: `1px solid ${isDark ? "rgba(56, 189, 248, 0.4)" : "#93c5fd"}`,
            boxShadow: isDark ? "0 4px 20px rgba(0, 0, 0, 0.4)" : "0 4px 20px rgba(0, 0, 0, 0.05)",
          }}
        >
          <div style={{ display: "flex", justifyContent: "space-between", alignItems: "center", marginBottom: "0.75rem" }}>
            <div style={{ display: "flex", alignItems: "center", gap: "0.5rem" }}>
              <Zap size={18} style={{ color: "#38bdf8" }} />
              <h4 style={{ margin: 0, fontSize: "0.95rem", color: isDark ? "#f8fafc" : "#0f172a" }}>
                AI Assistant Search Result
              </h4>
              <span className="soc-dash-badge" style={{ background: "rgba(56, 189, 248, 0.15)", color: "#38bdf8" }}>
                {activeAnswer.category || "Q&A Result"}
              </span>
            </div>
            <button
              onClick={() => {
                setActiveAnswer(null);
                setActiveModuleIndex(null);
              }}
              style={{ background: "none", border: "none", color: "#94a3b8", cursor: "pointer", fontSize: "1rem" }}
            >
              ✕
            </button>
          </div>

          <div style={{ marginBottom: "0.5rem", fontSize: "0.85rem", color: isDark ? "#94a3b8" : "#475569" }}>
            <strong>Query Asked:</strong> "{activeAnswer.query}"
          </div>

          {(activeAnswer.auto_corrected || activeAnswer.notice) && (
            <div
              style={{
                marginBottom: "0.85rem",
                padding: "0.6rem 0.85rem",
                borderRadius: "6px",
                background: isDark ? "rgba(56, 189, 248, 0.12)" : "#f0f9ff",
                border: `1px solid ${isDark ? "rgba(56, 189, 248, 0.35)" : "#bae6fd"}`,
                display: "flex",
                alignItems: "center",
                gap: "0.5rem",
                fontSize: "0.825rem",
                color: isDark ? "#38bdf8" : "#0284c7",
              }}
            >
              <span>✨ <strong>Auto-corrected query:</strong> "{activeAnswer.query}" → <strong>"{activeAnswer.suggested_query || activeAnswer.corrected_query}"</strong></span>
            </div>
          )}

          <div
            style={{
              padding: "0.85rem 1rem",
              borderRadius: "8px",
              background: isDark ? "rgba(30, 41, 59, 0.8)" : "#f8fafc",
              border: `1px solid ${isDark ? "rgba(56, 189, 248, 0.2)" : "#e2e8f0"}`,
              fontSize: "0.9rem",
              lineHeight: 1.6,
              color: isDark ? "#e2e8f0" : "#1e293b",
            }}
          >
            {activeAnswer.answer}
          </div>
        </div>
      )}

      {/* 3 & 4. Knowledge Base Categories & Operational Playbooks */}
      <div className="soc-dash-charts-dual-row">
        {/* Knowledge Base Categories */}
        <div className="soc-dash-card">
          <div className="soc-dash-card-header">
            <h3 className="soc-dash-card-title">
              <BookOpen size={18} style={{ color: "#38bdf8" }} />
              Documentation Modules
            </h3>
            <span className="soc-dash-badge">Core Docs</span>
          </div>

          <div style={{ display: "grid", gap: "1rem", paddingTop: "0.5rem" }}>
            {docModules.map((doc, idx) => {
              const DocIcon = doc.icon;
              const isSelected = activeModuleIndex === idx;
              const isHovered = hoveredDocIndex === idx;
              return (
                <div
                  key={idx}
                  onClick={() => handleModuleClick(doc, idx)}
                  onMouseEnter={() => setHoveredDocIndex(idx)}
                  onMouseLeave={() => setHoveredDocIndex(null)}
                  style={{
                    padding: "1rem",
                    borderRadius: "8px",
                    background: isSelected
                      ? (isDark ? "rgba(56, 189, 248, 0.15)" : "#e0f2fe")
                      : isHovered
                      ? (isDark ? "rgba(255, 255, 255, 0.06)" : "#f1f5f9")
                      : (isDark ? "rgba(255,255,255,0.03)" : "#f8fafc"),
                    border: isSelected
                      ? (isDark ? "1px solid rgba(56, 189, 248, 0.5)" : "1px solid #38bdf8")
                      : isHovered
                      ? (isDark ? "1px solid rgba(56, 189, 248, 0.3)" : "1px solid #93c5fd")
                      : (isDark ? "1px solid rgba(255,255,255,0.06)" : "1px solid #e2e8f0"),
                    display: "flex",
                    alignItems: "flex-start",
                    gap: "1rem",
                    cursor: "pointer",
                    transition: "all 0.2s ease-in-out",
                    boxShadow: isSelected
                      ? "0 0 12px rgba(56, 189, 248, 0.25)"
                      : isHovered
                      ? "0 2px 8px rgba(0, 0, 0, 0.1)"
                      : "none",
                  }}
                >
                  <div
                    style={{
                      padding: "0.6rem",
                      borderRadius: "8px",
                      background: isSelected || isHovered ? "rgba(56, 189, 248, 0.25)" : "rgba(56, 189, 248, 0.15)",
                      color: "#38bdf8",
                      transition: "all 0.2s ease-in-out",
                    }}
                  >
                    <DocIcon size={20} />
                  </div>
                  <div>
                    <h4 style={{ margin: "0 0 0.25rem 0", fontSize: "0.95rem", color: isDark ? "#f8fafc" : "#0f172a" }}>
                      {doc.title}
                    </h4>
                    <p style={{ margin: 0, fontSize: "0.825rem", color: isDark ? "#94a3b8" : "#64748b" }}>
                      {doc.desc}
                    </p>
                  </div>
                </div>
              );
            })}
          </div>
        </div>

        {/* FAQ Accordion Section */}
        <div className="soc-dash-card">
          <div className="soc-dash-card-header">
            <h3 className="soc-dash-card-title">
              <HelpCircle size={18} style={{ color: "#a855f7" }} />
              Frequently Asked Questions (FAQ)
            </h3>
            <span className="soc-dash-badge">Instant Answers</span>
          </div>

          <div style={{ display: "grid", gap: "0.75rem", paddingTop: "0.5rem" }}>
            {faqList && faqList.length > 0 ? (
              faqList.map((item, index) => {
                const isOpen = expandedFaq === index;
                const qText = item.question || item.q;
                const aText = item.answer || item.a;
                return (
                  <div
                    key={item.id || index}
                    style={{
                      borderRadius: "8px",
                      border: isDark ? "1px solid rgba(255,255,255,0.08)" : "1px solid #cbd5e1",
                      overflow: "hidden",
                      transition: "border-color 0.2s ease",
                    }}
                  >
                    <button
                      type="button"
                      onClick={() => toggleFaq(index)}
                      style={{
                        width: "100%",
                        padding: "0.85rem 1rem",
                        background: isDark
                          ? (isOpen ? "rgba(59,130,246,0.12)" : "rgba(255,255,255,0.02)")
                          : (isOpen ? "#eff6ff" : "#ffffff"),
                        border: "none",
                        color: isDark ? "#f8fafc" : "#0f172a",
                        fontSize: "0.9rem",
                        fontWeight: 600,
                        textAlign: "left",
                        display: "flex",
                        justifyContent: "space-between",
                        alignItems: "center",
                        cursor: "pointer",
                      }}
                    >
                      <span>{qText}</span>
                      <span style={{ fontSize: "0.85rem", color: isOpen ? "#38bdf8" : "#94a3b8", fontWeight: "bold" }}>
                        {isOpen ? "▲" : "▼"}
                      </span>
                    </button>

                    {isOpen && (
                      <div
                        style={{
                          padding: "0.85rem 1rem",
                          fontSize: "0.85rem",
                          lineHeight: 1.6,
                          color: isDark ? "#cbd5e1" : "#334155",
                          borderTop: isDark ? "1px solid rgba(255,255,255,0.06)" : "1px solid #e2e8f0",
                          background: isDark ? "rgba(0,0,0,0.2)" : "#f8fafc",
                        }}
                      >
                        {aText}
                      </div>
                    )}
                  </div>
                );
              })
            ) : (
              <p style={{ fontSize: "0.875rem", color: "#94a3b8" }}>Loading FAQs...</p>
            )}
          </div>
        </div>
      </div>

      {/* Support & Contact Quick Actions */}
      <div className="soc-dash-card">
        <div className="soc-dash-card-header">
          <h3 className="soc-dash-card-title">
            <Mail size={18} style={{ color: "#10b981" }} />
            Technical Support Channels
          </h3>
          <span className="soc-dash-badge">SOC Escalation</span>
        </div>
        <div className="admin-dash-quick-grid">
          <div
            className="admin-dash-quick-card"
            onClick={handleDownloadPdfGuide}
          >
            <div className="admin-dash-quick-icon">
              <Download size={20} />
            </div>
            <span className="admin-dash-quick-label">PDF User Guide</span>
          </div>

          <div
            className="admin-dash-quick-card"
            onClick={() => setIsEmailModalOpen(true)}
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

      {/* Interactive Technical Support Email Modal */}
      {isEmailModalOpen && (
        <div
          style={{
            position: "fixed",
            top: 0,
            left: 0,
            right: 0,
            bottom: 0,
            backgroundColor: "rgba(0, 0, 0, 0.75)",
            backdropFilter: "blur(6px)",
            display: "flex",
            alignItems: "center",
            justifyContent: "center",
            zIndex: 9999,
            padding: "1rem",
          }}
        >
          <div
            style={{
              width: "100%",
              maxWidth: "540px",
              backgroundColor: isDark ? "#0f172a" : "#ffffff",
              border: `1px solid ${isDark ? "rgba(56, 189, 248, 0.4)" : "#93c5fd"}`,
              borderRadius: "12px",
              boxShadow: isDark ? "0 20px 40px rgba(0, 0, 0, 0.6)" : "0 20px 40px rgba(0, 0, 0, 0.15)",
              overflow: "hidden",
            }}
          >
            {/* Modal Header */}
            <div
              style={{
                padding: "1.25rem 1.5rem",
                borderBottom: isDark ? "1px solid rgba(255, 255, 255, 0.1)" : "1px solid #e2e8f0",
                display: "flex",
                justifyContent: "space-between",
                alignItems: "center",
                background: isDark ? "rgba(30, 41, 59, 0.5)" : "#f8fafc",
              }}
            >
              <div style={{ display: "flex", alignItems: "center", gap: "0.6rem" }}>
                <div style={{ padding: "0.4rem", borderRadius: "6px", background: "rgba(56, 189, 248, 0.15)", color: "#38bdf8" }}>
                  <Mail size={20} />
                </div>
                <div>
                  <h3 style={{ margin: 0, fontSize: "1.05rem", fontWeight: 600, color: isDark ? "#f8fafc" : "#0f172a" }}>
                    Submit Technical Support Inquiry
                  </h3>
                  <span style={{ fontSize: "0.775rem", color: isDark ? "#94a3b8" : "#64748b" }}>
                    Direct dispatch to NetShield-AI Tier-3 SOC Escalation Team
                  </span>
                </div>
              </div>
              <button
                type="button"
                onClick={() => {
                  setIsEmailModalOpen(false);
                  setEmailError(null);
                }}
                style={{ background: "none", border: "none", color: "#94a3b8", cursor: "pointer", fontSize: "1.2rem", padding: "0.2rem" }}
              >
                ✕
              </button>
            </div>

            {/* Modal Form */}
            <form onSubmit={handleDispatchSupportEmail} style={{ padding: "1.5rem" }}>
              {emailError && (
                <div
                  style={{
                    marginBottom: "1rem",
                    padding: "0.75rem 1rem",
                    borderRadius: "6px",
                    background: "rgba(239, 68, 68, 0.15)",
                    border: "1px solid rgba(239, 68, 68, 0.35)",
                    color: "#f87171",
                    fontSize: "0.85rem",
                  }}
                >
                  ⚠️ {emailError}
                </div>
              )}

              <div style={{ marginBottom: "1rem" }}>
                <label style={{ display: "block", marginBottom: "0.35rem", fontSize: "0.825rem", fontWeight: 600, color: isDark ? "#cbd5e1" : "#334155" }}>
                  Inquiry Category
                </label>
                <select
                  value={emailCategory}
                  onChange={(e) => setEmailCategory(e.target.value)}
                  style={{
                    width: "100%",
                    padding: "0.6rem 0.85rem",
                    borderRadius: "6px",
                    background: isDark ? "#1e293b" : "#f8fafc",
                    border: isDark ? "1px solid rgba(255, 255, 255, 0.15)" : "1px solid #cbd5e1",
                    color: isDark ? "#f8fafc" : "#0f172a",
                    fontSize: "0.875rem",
                  }}
                >
                  <option value="Technical Support">Technical Support</option>
                  <option value="SOC Escalation">SOC Incident Escalation</option>
                  <option value="Feature Request">Feature / Integration Request</option>
                  <option value="General Inquiry">General Inquiry</option>
                </select>
              </div>

              <div style={{ marginBottom: "1rem" }}>
                <label style={{ display: "block", marginBottom: "0.35rem", fontSize: "0.825rem", fontWeight: 600, color: isDark ? "#cbd5e1" : "#334155" }}>
                  Subject / Title
                </label>
                <input
                  type="text"
                  placeholder="e.g. WAF Rate Limit Threshold Adjustment Request"
                  value={emailSubject}
                  onChange={(e) => setEmailSubject(e.target.value)}
                  style={{
                    width: "100%",
                    padding: "0.6rem 0.85rem",
                    borderRadius: "6px",
                    background: isDark ? "#1e293b" : "#f8fafc",
                    border: isDark ? "1px solid rgba(255, 255, 255, 0.15)" : "1px solid #cbd5e1",
                    color: isDark ? "#f8fafc" : "#0f172a",
                    fontSize: "0.875rem",
                  }}
                />
              </div>

              <div style={{ marginBottom: "1rem" }}>
                <label style={{ display: "block", marginBottom: "0.35rem", fontSize: "0.825rem", fontWeight: 600, color: isDark ? "#cbd5e1" : "#334155" }}>
                  Your Contact Email (Optional)
                </label>
                <input
                  type="email"
                  placeholder="analyst@company.com"
                  value={userContactEmail}
                  onChange={(e) => setUserContactEmail(e.target.value)}
                  style={{
                    width: "100%",
                    padding: "0.6rem 0.85rem",
                    borderRadius: "6px",
                    background: isDark ? "#1e293b" : "#f8fafc",
                    border: isDark ? "1px solid rgba(255, 255, 255, 0.15)" : "1px solid #cbd5e1",
                    color: isDark ? "#f8fafc" : "#0f172a",
                    fontSize: "0.875rem",
                  }}
                />
              </div>

              <div style={{ marginBottom: "1.25rem" }}>
                <label style={{ display: "block", marginBottom: "0.35rem", fontSize: "0.825rem", fontWeight: 600, color: isDark ? "#cbd5e1" : "#334155" }}>
                  Inquiry Details / Description *
                </label>
                <textarea
                  rows={4}
                  placeholder="Describe your inquiry, telemetry anomaly observation, or technical assistance needed..."
                  value={emailMessage}
                  onChange={(e) => setEmailMessage(e.target.value)}
                  required
                  style={{
                    width: "100%",
                    padding: "0.6rem 0.85rem",
                    borderRadius: "6px",
                    background: isDark ? "#1e293b" : "#f8fafc",
                    border: isDark ? "1px solid rgba(255, 255, 255, 0.15)" : "1px solid #cbd5e1",
                    color: isDark ? "#f8fafc" : "#0f172a",
                    fontSize: "0.875rem",
                    resize: "vertical",
                  }}
                />
              </div>

              {/* Modal Actions */}
              <div style={{ display: "flex", justifyContent: "flex-end", gap: "0.75rem" }}>
                <button
                  type="button"
                  onClick={() => {
                    setIsEmailModalOpen(false);
                    setEmailError(null);
                  }}
                  style={{
                    padding: "0.55rem 1.15rem",
                    borderRadius: "6px",
                    background: "transparent",
                    border: isDark ? "1px solid rgba(255,255,255,0.2)" : "1px solid #cbd5e1",
                    color: isDark ? "#cbd5e1" : "#475569",
                    fontSize: "0.85rem",
                    fontWeight: 600,
                    cursor: "pointer",
                  }}
                >
                  Cancel
                </button>
                <button
                  type="submit"
                  disabled={isSubmittingEmail}
                  className="ns-btn-gradient primary small"
                  style={{
                    padding: "0.55rem 1.25rem",
                    fontSize: "0.85rem",
                    display: "flex",
                    alignItems: "center",
                    gap: "0.4rem",
                  }}
                >
                  {isSubmittingEmail ? "Dispatching..." : "Dispatch Inquiry"}
                </button>
              </div>
            </form>
          </div>
        </div>
      )}
    </div>
  );
}
