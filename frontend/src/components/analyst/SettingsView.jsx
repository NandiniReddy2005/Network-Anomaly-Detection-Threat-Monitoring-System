"use client";
import React, { useState, useEffect, useCallback } from "react";
import {
  Sliders,
  Activity,
  ShieldCheck,
  Bell,
  Cpu,
  Save,
  CheckCircle2,
  AlertTriangle,
  RefreshCw,
  Info,
} from "lucide-react";

import LoadingSpinner from "../LoadingSpinner";
import { fetchApi } from "../../utils/api";
import { getCurrentUser } from "../../utils/authHelpers";
import { getFormattedUTCTime } from "../../utils/formatDate";

const SENSITIVITY_LEVELS = ["Low", "Medium", "High", "Aggressive"];

export default function SettingsView() {
  const [currentTime, setCurrentTime] = useState("");
  const [toastMsg, setToastMsg] = useState(null);

  const [loadingSettings, setLoadingSettings] = useState(true);
  const [settingsError, setSettingsError] = useState(null);
  const [savingSettings, setSavingSettings] = useState(false);

  // Settings State
  const [telemetryPollingInterval, setTelemetryPollingInterval] = useState("Standard (5 sec)");
  const [forensicLogRetention, setForensicLogRetention] = useState("365 Days (Compliant)");
  const [autoArchiveTelemetry, setAutoArchiveTelemetry] = useState(true);

  const [autoMitigateThreats, setAutoMitigateThreats] = useState(true);
  const [wafRateLimitThreshold, setWafRateLimitThreshold] = useState(1000);
  const [emergencyIpContainment, setEmergencyIpContainment] = useState(false);

  const [webhookUrl, setWebhookUrl] = useState("https://hooks.slack.com/services/T0000/B0000/XXXXX");
  const [emailDigestFrequency, setEmailDigestFrequency] = useState("Hourly Summary");
  const [pagerdutyAlertPush, setPagerdutyAlertPush] = useState(true);

  const [defaultPredictionModel, setDefaultPredictionModel] = useState("UNSW-NB15 (186 features)");
  const [anomalyDetectionSensitivity, setAnomalyDetectionSensitivity] = useState("High");

  const getLoggedInUserEmail = useCallback(() => {
    try {
      const user = getCurrentUser();
      if (user && user.email) return user.email;
      const stored =
        typeof window !== "undefined"
          ? localStorage.getItem("user") || localStorage.getItem("netshield_current_user")
          : null;
      if (stored) {
        const parsed = JSON.parse(stored);
        if (parsed && parsed.email) return parsed.email;
      }
    } catch (e) {}
    return "demo@gmail.com";
  }, []);

  useEffect(() => {
    setCurrentTime(getFormattedUTCTime());
    const timer = setInterval(() => setCurrentTime(getFormattedUTCTime()), 1000);
    return () => clearInterval(timer);
  }, []);

  const fetchSettings = useCallback(async () => {
    setLoadingSettings(true);
    setSettingsError(null);
    try {
      const res = await fetchApi("/api/settings");
      const data = res.data || res.settings || res || {};

      if (data.telemetry_polling_interval) setTelemetryPollingInterval(data.telemetry_polling_interval);
      if (data.forensic_log_retention) setForensicLogRetention(data.forensic_log_retention);
      if (data.auto_archive_telemetry !== undefined) {
        setAutoArchiveTelemetry(String(data.auto_archive_telemetry) === "true" || data.auto_archive_telemetry === true);
      }

      if (data.auto_mitigate_threats !== undefined) {
        setAutoMitigateThreats(String(data.auto_mitigate_threats) === "true" || data.auto_mitigate_threats === true);
      }
      if (data.waf_rate_limit_threshold !== undefined) {
        setWafRateLimitThreshold(Number(data.waf_rate_limit_threshold) || 1000);
      }
      if (data.emergency_ip_containment !== undefined) {
        setEmergencyIpContainment(String(data.emergency_ip_containment) === "true" || data.emergency_ip_containment === true);
      }

      if (data.webhook_url) setWebhookUrl(data.webhook_url);
      if (data.email_digest_frequency) setEmailDigestFrequency(data.email_digest_frequency);
      if (data.pagerduty_alert_push !== undefined) {
        setPagerdutyAlertPush(String(data.pagerduty_alert_push) === "true" || data.pagerduty_alert_push === true);
      }

      if (data.default_prediction_model) setDefaultPredictionModel(data.default_prediction_model);
      if (data.anomaly_detection_sensitivity) setAnomalyDetectionSensitivity(data.anomaly_detection_sensitivity);
    } catch (err) {
      console.warn("Notice: Using default SOC configuration state:", err);
    } finally {
      setLoadingSettings(false);
    }
  }, []);

  useEffect(() => {
    fetchSettings();
  }, [fetchSettings]);

  const handleSaveSettings = async () => {
    setSavingSettings(true);
    const actorEmail = getLoggedInUserEmail();

    const payload = {
      telemetry_polling_interval: telemetryPollingInterval,
      forensic_log_retention: forensicLogRetention,
      auto_archive_telemetry: autoArchiveTelemetry,
      auto_mitigate_threats: autoMitigateThreats,
      waf_rate_limit_threshold: wafRateLimitThreshold,
      emergency_ip_containment: emergencyIpContainment,
      webhook_url: webhookUrl,
      email_digest_frequency: emailDigestFrequency,
      pagerduty_alert_push: pagerdutyAlertPush,
      default_prediction_model: defaultPredictionModel,
      anomaly_detection_sensitivity: anomalyDetectionSensitivity,
      actor: actorEmail,
    };

    try {
      // 1. Issue POST /api/settings
      await fetchApi("/api/settings", {
        method: "POST",
        headers: {
          "X-User-Email": actorEmail,
        },
        body: JSON.stringify(payload),
      });

      // 2. Explicitly trigger log_audit_event endpoint to guarantee top audit entry
      await fetchApi("/api/audit-logs", {
        method: "POST",
        headers: {
          "X-User-Email": actorEmail,
        },
        body: JSON.stringify({
          actor: actorEmail,
          action: "Updated Platform & SOC Security Settings Configuration",
          module: "Settings",
          ip_origin: "192.168.1.50",
          status: "Success",
          severity: "Informational",
          details: `Platform Settings updated by ${actorEmail}: WAF threshold ${wafRateLimitThreshold} req/min, Model ${defaultPredictionModel}.`,
        }),
      });

      setToastMsg("Platform Settings Updated Successfully");
      setTimeout(() => setToastMsg(null), 4000);
    } catch (err) {
      console.error("Error saving settings:", err);
      alert("Failed to save settings to backend. Please retry.");
    } finally {
      setSavingSettings(false);
    }
  };

  const sensitivityIndex = Math.max(0, SENSITIVITY_LEVELS.indexOf(anomalyDetectionSensitivity));

  return (
    <div key="enterprise-soc-settings" className="soc-settings-container">
      {/* Toast Notification Badge */}
      {toastMsg && (
        <div
          style={{
            padding: "0.85rem 1.25rem",
            borderRadius: "8px",
            background: "rgba(16, 185, 129, 0.15)",
            border: "1px solid rgba(16, 185, 129, 0.4)",
            color: "#34d399",
            fontSize: "0.875rem",
            fontWeight: 600,
            display: "flex",
            alignItems: "center",
            justifyContent: "space-between",
            boxShadow: "0 4px 12px rgba(16, 185, 129, 0.2)",
          }}
        >
          <div style={{ display: "flex", alignItems: "center", gap: "0.5rem" }}>
            <CheckCircle2 size={18} style={{ color: "#34d399" }} />
            <span>{toastMsg}</span>
          </div>
          <button
            onClick={() => setToastMsg(null)}
            style={{ background: "none", border: "none", color: "#34d399", cursor: "pointer", fontSize: "1rem" }}
          >
            ✕
          </button>
        </div>
      )}

      {/* 1. Header */}
      <div className="soc-dash-header">
        <div className="soc-dash-header-left">
          <h2 className="soc-dash-header-title">
            <Sliders size={26} className="soc-dash-header-title-icon" style={{ color: "#3b82f6" }} />
            Enterprise SOC Settings &amp; Platform Control Panel
          </h2>
          <div className="soc-dash-header-sub">
            <span>Configure Telemetry Polling, WAF Rate Limits, Threat Mitigations &amp; ML Models</span>
            <span>•</span>
            <span className="soc-dash-clock">UTC Time: {currentTime || "Real-Time"}</span>
          </div>
        </div>

        <div className="soc-dash-header-right">
          <div className="soc-dash-status-badge">
            <span className="soc-dash-pulse-dot"></span>
            <span>PostgreSQL Config Synchronized</span>
          </div>
        </div>
      </div>

      {loadingSettings ? (
        <div className="soc-settings-card" style={{ padding: "3rem", textAlign: "center" }}>
          <LoadingSpinner text="Loading Enterprise SOC configuration parameters..." />
        </div>
      ) : settingsError ? (
        <div className="soc-settings-card" style={{ padding: "2rem", color: "#f87171", textAlign: "center" }}>
          <p>{settingsError}</p>
          <button onClick={fetchSettings} className="soc-dash-btn-refresh" style={{ marginTop: "1rem" }}>
            <RefreshCw size={14} /> Retry Loading
          </button>
        </div>
      ) : (
        <>
          {/* 2. 4 Configuration Cards Grid */}
          <div className="soc-settings-grid">

            {/* CARD 1: TELEMETRY & POLLING ENGINE */}
            <div className="soc-settings-card">
              <div className="soc-settings-card-header">
                <div className="soc-settings-card-title-group">
                  <div className="soc-settings-card-icon">
                    <Activity size={20} style={{ color: "#3b82f6" }} />
                  </div>
                  <div>
                    <h3 className="soc-settings-card-title">Telemetry &amp; Polling Engine</h3>
                    <p className="soc-settings-desc">Sensor sampling rates and log retention parameters</p>
                  </div>
                </div>
                <span className="soc-settings-badge">Core Pipeline</span>
              </div>

              <div className="soc-settings-form">
                {/* Field 1: Polling Interval */}
                <div className="soc-settings-field">
                  <label className="soc-settings-label">Telemetry Polling Interval</label>
                  <select
                    className="soc-settings-select"
                    value={telemetryPollingInterval}
                    onChange={(e) => setTelemetryPollingInterval(e.target.value)}
                  >
                    <option value="Real-Time (1 sec)">Real-Time (1 sec)</option>
                    <option value="Standard (5 sec)">Standard (5 sec)</option>
                    <option value="Extended (15 sec)">Extended (15 sec)</option>
                  </select>
                </div>

                {/* Field 2: Retention Policy */}
                <div className="soc-settings-field">
                  <label className="soc-settings-label">Forensic Log Retention Policy</label>
                  <select
                    className="soc-settings-select"
                    value={forensicLogRetention}
                    onChange={(e) => setForensicLogRetention(e.target.value)}
                  >
                    <option value="30 Days">30 Days</option>
                    <option value="90 Days">90 Days</option>
                    <option value="365 Days (Compliant)">365 Days (Compliant)</option>
                    <option value="Indefinite">Indefinite</option>
                  </select>
                </div>

                {/* Field 3: Auto-Archive Toggle */}
                <div className="soc-settings-field-row">
                  <div className="soc-settings-label-group">
                    <span className="soc-settings-label">Auto-Archive Telemetry Logs</span>
                    <span className="soc-settings-desc">Compress and move cold logs to PostgreSQL storage</span>
                  </div>
                  <label className="soc-toggle-switch">
                    <input
                      type="checkbox"
                      checked={autoArchiveTelemetry}
                      onChange={(e) => setAutoArchiveTelemetry(e.target.checked)}
                    />
                    <span className="soc-toggle-slider"></span>
                  </label>
                </div>
              </div>
            </div>

            {/* CARD 2: AUTOMATED THREAT DEFENSE & WAF RULES */}
            <div className="soc-settings-card">
              <div className="soc-settings-card-header">
                <div className="soc-settings-card-title-group">
                  <div className="soc-settings-card-icon" style={{ background: "rgba(16, 185, 129, 0.1)", borderColor: "rgba(16, 185, 129, 0.25)" }}>
                    <ShieldCheck size={20} style={{ color: "#10b981" }} />
                  </div>
                  <div>
                    <h3 className="soc-settings-card-title">Automated Threat Defense &amp; WAF Rules</h3>
                    <p className="soc-settings-desc">Edge firewall throttling and active mitigation rules</p>
                  </div>
                </div>
                <span className="soc-settings-badge" style={{ background: "rgba(16, 185, 129, 0.15)", color: "#34d399", borderColor: "rgba(16, 185, 129, 0.3)" }}>
                  Active Protection
                </span>
              </div>

              <div className="soc-settings-form">
                {/* Field 1: Auto-Mitigate Toggle */}
                <div className="soc-settings-field-row">
                  <div className="soc-settings-label-group">
                    <span className="soc-settings-label">Auto-Mitigate High Severity Threats</span>
                    <span className="soc-settings-desc">Execute IPTables null-routing on high-confidence vectors</span>
                  </div>
                  <label className="soc-toggle-switch">
                    <input
                      type="checkbox"
                      checked={autoMitigateThreats}
                      onChange={(e) => setAutoMitigateThreats(e.target.checked)}
                    />
                    <span className="soc-toggle-slider"></span>
                  </label>
                </div>

                {/* Field 2: WAF Rate Limiting Threshold */}
                <div className="soc-settings-field">
                  <div style={{ display: "flex", justifyContent: "space-between", alignItems: "center" }}>
                    <label className="soc-settings-label">WAF Rate Limiting Threshold</label>
                    <span className="soc-settings-slider-value">{wafRateLimitThreshold.toLocaleString()} req/min</span>
                  </div>
                  <input
                    type="range"
                    min="100"
                    max="5000"
                    step="50"
                    className="soc-settings-slider"
                    value={wafRateLimitThreshold}
                    onChange={(e) => setWafRateLimitThreshold(Number(e.target.value))}
                  />
                  <div style={{ display: "flex", justifyContent: "space-between", fontSize: "0.72rem", color: "#94a3b8" }}>
                    <span>100 req/min (Strict)</span>
                    <span>5,000 req/min (Permissive)</span>
                  </div>
                </div>

                {/* Field 3: Emergency IP Containment Mode */}
                <div className="soc-settings-field-row">
                  <div className="soc-settings-label-group">
                    <div style={{ display: "flex", alignItems: "center", gap: "0.5rem" }}>
                      <span className="soc-settings-label">Emergency IP Containment Mode</span>
                      {emergencyIpContainment && (
                        <span className="soc-warning-badge">
                          <AlertTriangle size={12} /> EMERGENCY LOCKDOWN ACTIVE
                        </span>
                      )}
                    </div>
                    <span className="soc-settings-desc">Immediately block untrusted source IP clusters</span>
                  </div>
                  <label className="soc-toggle-switch">
                    <input
                      type="checkbox"
                      checked={emergencyIpContainment}
                      onChange={(e) => setEmergencyIpContainment(e.target.checked)}
                    />
                    <span className="soc-toggle-slider warning-toggle"></span>
                  </label>
                </div>
              </div>
            </div>

            {/* CARD 3: SECURITY NOTIFICATIONS & WEBHOOKS */}
            <div className="soc-settings-card">
              <div className="soc-settings-card-header">
                <div className="soc-settings-card-title-group">
                  <div className="soc-settings-card-icon" style={{ background: "rgba(245, 158, 11, 0.1)", borderColor: "rgba(245, 158, 11, 0.25)" }}>
                    <Bell size={20} style={{ color: "#f59e0b" }} />
                  </div>
                  <div>
                    <h3 className="soc-settings-card-title">Security Notifications &amp; Webhooks</h3>
                    <p className="soc-settings-desc">Real-time alert dispatch to external Incident Response channels</p>
                  </div>
                </div>
                <span className="soc-settings-badge" style={{ background: "rgba(245, 158, 11, 0.15)", color: "#fbbf24", borderColor: "rgba(245, 158, 11, 0.3)" }}>
                  Alert Dispatch
                </span>
              </div>

              <div className="soc-settings-form">
                {/* Field 1: Slack / Discord Webhook */}
                <div className="soc-settings-field">
                  <label className="soc-settings-label">Slack / Discord Alert Webhook URL</label>
                  <input
                    type="text"
                    className="soc-settings-input"
                    placeholder="https://hooks.slack.com/services/..."
                    value={webhookUrl}
                    onChange={(e) => setWebhookUrl(e.target.value)}
                  />
                </div>

                {/* Field 2: Email Security Digest */}
                <div className="soc-settings-field">
                  <label className="soc-settings-label">Email Security Digest Frequency</label>
                  <select
                    className="soc-settings-select"
                    value={emailDigestFrequency}
                    onChange={(e) => setEmailDigestFrequency(e.target.value)}
                  >
                    <option value="Immediate">Immediate</option>
                    <option value="Hourly Summary">Hourly Summary</option>
                    <option value="Daily Digest">Daily Digest</option>
                  </select>
                </div>

                {/* Field 3: PagerDuty Alert Push */}
                <div className="soc-settings-field-row">
                  <div className="soc-settings-label-group">
                    <span className="soc-settings-label">Critical Alert PagerDuty Push</span>
                    <span className="soc-settings-desc">Push P1 Emergency incidents directly to active SOC rotas</span>
                  </div>
                  <label className="soc-toggle-switch">
                    <input
                      type="checkbox"
                      checked={pagerdutyAlertPush}
                      onChange={(e) => setPagerdutyAlertPush(e.target.checked)}
                    />
                    <span className="soc-toggle-slider"></span>
                  </label>
                </div>
              </div>
            </div>

            {/* CARD 4: ML MODEL ENGINE & ANOMALY DETECTION */}
            <div className="soc-settings-card">
              <div className="soc-settings-card-header">
                <div className="soc-settings-card-title-group">
                  <div className="soc-settings-card-icon" style={{ background: "rgba(168, 85, 247, 0.1)", borderColor: "rgba(168, 85, 247, 0.25)" }}>
                    <Cpu size={20} style={{ color: "#a855f7" }} />
                  </div>
                  <div>
                    <h3 className="soc-settings-card-title">ML Model Engine &amp; Anomaly Detection</h3>
                    <p className="soc-settings-desc">Neural inference pipeline and dataset thresholding</p>
                  </div>
                </div>
                <span className="soc-settings-badge" style={{ background: "rgba(168, 85, 247, 0.15)", color: "#c084fc", borderColor: "rgba(168, 85, 247, 0.3)" }}>
                  AI Inference
                </span>
              </div>

              <div className="soc-settings-form">
                {/* Field 1: Default Prediction Model */}
                <div className="soc-settings-field">
                  <label className="soc-settings-label">Default Prediction Model</label>
                  <select
                    className="soc-settings-select"
                    value={defaultPredictionModel}
                    onChange={(e) => setDefaultPredictionModel(e.target.value)}
                  >
                    <option value="UNSW-NB15 (186 features)">UNSW-NB15 (186 features)</option>
                    <option value="CICIDS2017 (78 features)">CICIDS2017 (78 features)</option>
                  </select>
                </div>

                {/* Field 2: Anomaly Detection Sensitivity Slider */}
                <div className="soc-settings-field">
                  <div className="soc-settings-slider-header">
                    <label className="soc-settings-label">Anomaly Detection Sensitivity</label>
                    <span className="soc-settings-slider-value" style={{ background: "rgba(168, 85, 247, 0.15)", color: "#c084fc", borderColor: "rgba(168, 85, 247, 0.3)" }}>
                      {anomalyDetectionSensitivity}
                    </span>
                  </div>
                  <input
                    type="range"
                    min="0"
                    max="3"
                    step="1"
                    className="soc-settings-slider"
                    value={sensitivityIndex}
                    onChange={(e) => setAnomalyDetectionSensitivity(SENSITIVITY_LEVELS[Number(e.target.value)])}
                  />
                  <div style={{ display: "flex", justifyContent: "space-between", fontSize: "0.72rem", color: "#94a3b8" }}>
                    {SENSITIVITY_LEVELS.map((level) => (
                      <span
                        key={level}
                        style={{
                          color: level === anomalyDetectionSensitivity ? "#c084fc" : "#94a3b8",
                          fontWeight: level === anomalyDetectionSensitivity ? 700 : 400,
                        }}
                      >
                        {level}
                      </span>
                    ))}
                  </div>
                </div>
              </div>
            </div>

          </div>

          {/* 3. Footer Bar with Save Button */}
          <div className="soc-settings-footer">
            <div className="soc-settings-footer-left">
              <Info size={16} style={{ color: "#3b82f6" }} />
              <span>All configuration updates automatically trigger an immutable entry in the PostgreSQL audit log ledger.</span>
            </div>

            <button
              onClick={handleSaveSettings}
              disabled={savingSettings}
              className="soc-settings-save-btn"
            >
              {savingSettings ? (
                <>
                  <RefreshCw size={18} className="animate-spin" />
                  Saving Configuration...
                </>
              ) : (
                <>
                  <Save size={18} />
                  Save Platform Configuration
                </>
              )}
            </button>
          </div>
        </>
      )}
    </div>
  );
}
