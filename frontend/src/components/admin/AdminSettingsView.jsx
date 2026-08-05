"use client";
import React, { useState, useEffect, useCallback } from "react";

import DashboardCard from "../DashboardCard";
import LoadingSpinner from "../LoadingSpinner";
import { fetchApi } from "../../utils/api";

export default function AdminSettingsView() {
  const [settings, setSettings] = useState({});
  const [loadingSettings, setLoadingSettings] = useState(true);
  const [settingsError, setSettingsError] = useState(null);
  const [savingSettings, setSavingSettings] = useState(false);
  const [settingsSuccess, setSettingsSuccess] = useState("");

  const fetchSettings = useCallback(async () => {
    setLoadingSettings(true);
    setSettingsError(null);
    try {
      const res = await fetchApi("/api/settings");
      setSettings(res.data || res.settings || {});
    } catch (err) {
      setSettingsError("Unable to load administrator settings.");
    } finally {
      setLoadingSettings(false);
    }
  }, []);

  useEffect(() => {
    fetchSettings();
  }, [fetchSettings]);

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
}
