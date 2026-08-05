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

export default function SystemHelpView() {
  const { isDark } = useTheme();
  const [currentTime, setCurrentTime] = useState("");
  const [openFaqIndex, setOpenFaqIndex] = useState(0);
  const [helpSearchQuery, setHelpSearchQuery] = useState("");
  const [helpToastMsg, setHelpToastMsg] = useState(null);

  useEffect(() => {
    setCurrentTime(getFormattedUTCTime());
    const timer = setInterval(() => setCurrentTime(getFormattedUTCTime()), 1000);
    return () => clearInterval(timer);
  }, []);

  const handleDownloadPdfGuide = () => {
    window.open(`${API_BASE_URL}/api/reports/pdf`, "_blank");
  };

  const faqList = [
    {
      q: "How does NetShield-AI calculate composite threat anomaly scores?",
      a: "NetShield-AI uses an integrated neural network classifier combined with Snort/Suricata heuristic signatures to evaluate incoming packet payloads. Scores above 75 trigger critical alerts.",
    },
    {
      q: "How do I configure automatic threat mitigation playbooks?",
      a: "Navigate to Platform Settings and configure the WAF & Rate Limiting thresholds. When a threat score exceeds the configured limit, IPTables rules are applied automatically.",
    },
    {
      q: "Where are system audit logs persisted?",
      a: "All administrative actions, login attempts, and policy changes are recorded in an immutable PostgreSQL audit ledger accessible from the Audit Logs tab.",
    },
    {
      q: "How do I manage user roles and Security Analyst roster access?",
      a: "Security Administrators can add, edit, or revoke user accounts and update RBAC privileges via the User Management tab.",
    },
    {
      q: "How frequently does real-time telemetry auto-refresh?",
      a: "By default, telemetry feeds refresh every 5 seconds. This interval can be adjusted to Real-time (1s) or Low Bandwidth (30s) under Settings.",
    },
  ];

  const filteredFaqs = faqList.filter(
    (faq) =>
      faq.q.toLowerCase().includes(helpSearchQuery.toLowerCase()) ||
      faq.a.toLowerCase().includes(helpSearchQuery.toLowerCase())
  );

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
      <div className="soc-dash-card" style={{ padding: "1.25rem 1.5rem" }}>
        <div className="soc-dash-table-search" style={{ maxWidth: "100%", width: "100%" }}>
          <Search size={18} style={{ color: "#94a3b8" }} />
          <input
            type="text"
            placeholder="Search documentation, FAQs, SOC playbooks, or system guides..."
            value={helpSearchQuery}
            onChange={(e) => setHelpSearchQuery(e.target.value)}
            style={{ fontSize: "0.95rem" }}
          />
        </div>
      </div>

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
            {[
              {
                title: "Architecture & Sensor Mesh Guide",
                desc: "Detailed overview of FastAPI gateway nodes, PostgreSQL audit storage, and telemetry probes.",
                icon: Database,
              },
              {
                title: "Threat Triage & Mitigation Playbooks",
                desc: "Step-by-step procedures for handling DDoS spikes, WAF injection attempts, and port scans.",
                icon: Zap,
              },
              {
                title: "RBAC & User Access Policy Manual",
                desc: "Role permissions definition for Security Analyst vs Security Administrator credentials.",
                icon: Sliders,
              },
              {
                title: "Compliance & Audit Export Guide",
                desc: "Exporting ISO-27001 / SOC2 compliance packages in PDF, CSV, and JSON formats.",
                icon: FileText,
              },
            ].map((doc, idx) => {
              const DocIcon = doc.icon;
              return (
                <div
                  key={idx}
                  style={{
                    padding: "1rem",
                    borderRadius: "8px",
                    background: isDark ? "rgba(255,255,255,0.03)" : "#f8fafc",
                    border: isDark ? "1px solid rgba(255,255,255,0.06)" : "1px solid #e2e8f0",
                    display: "flex",
                    alignItems: "flex-start",
                    gap: "1rem",
                  }}
                >
                  <div
                    style={{
                      padding: "0.6rem",
                      borderRadius: "8px",
                      background: "rgba(56, 189, 248, 0.15)",
                      color: "#38bdf8",
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
            {filteredFaqs.map((faq, idx) => {
              const isOpen = openFaqIndex === idx;
              return (
                <div
                  key={idx}
                  style={{
                    borderRadius: "8px",
                    border: isDark ? "1px solid rgba(255,255,255,0.08)" : "1px solid #cbd5e1",
                    overflow: "hidden",
                  }}
                >
                  <button
                    onClick={() => setOpenFaqIndex(isOpen ? -1 : idx)}
                    style={{
                      width: "100%",
                      padding: "0.85rem 1rem",
                      background: isDark ? (isOpen ? "rgba(59,130,246,0.12)" : "rgba(255,255,255,0.02)") : isOpen ? "#eff6ff" : "#ffffff",
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
                    <span>{faq.q}</span>
                    {isOpen ? <ChevronUp size={16} /> : <ChevronDown size={16} />}
                  </button>

                  {isOpen && (
                    <div
                      style={{
                        padding: "0.85rem 1rem",
                        fontSize: "0.85rem",
                        lineHeight: 1.5,
                        color: isDark ? "#cbd5e1" : "#334155",
                        borderTop: isDark ? "1px solid rgba(255,255,255,0.06)" : "1px solid #e2e8f0",
                        background: isDark ? "rgba(0,0,0,0.2)" : "#f8fafc",
                      }}
                    >
                      {faq.a}
                    </div>
                  )}
                </div>
              );
            })}
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
}
