"use client";
import React, { createContext, useContext, useState, useEffect, useCallback } from "react";
import { fetchApi } from "../utils/api";

const DEFAULT_INCIDENTS = [
  {
    alert_id: "ALT-1082",
    timestamp: "2026-08-22 09:47:00 UTC",
    source_ip: "185.220.101.42",
    sourceIp: "185.220.101.42",
    target_ip: "10.0.9.47",
    threat_vector: "UNSW-NB15 DoS / SYN Flood (Abuse Score: 96%)",
    threatType: "UNSW-NB15 DoS / SYN Flood (Abuse Score: 96%)",
    severity: "CRITICAL",
    threatSeverity: "CRITICAL",
    status: "Active",
    detection_source: "UNSW-NB15 Engine + AbuseIPDB API",
    abuse_score: 96,
    threatScore: "0.96 (96%)",
    details: "High-volume TCP SYN flood detected targeting core firewall eth0.",
    analyst_notes: "",
    packet_size: "1,420 Bytes",
    protocol: "TCP (SYN-ACK)",
    dest_port: "8080 / HTTP",
    isp: "Tor Exit Router Network",
    country: "RO",
    total_reports: 142,
    action_history: [],
  },
  {
    alert_id: "ALT-1083",
    timestamp: "2026-08-22 09:35:12 UTC",
    source_ip: "198.51.100.14",
    sourceIp: "198.51.100.14",
    target_ip: "10.0.9.50",
    threat_vector: "AbuseIPDB Known Malicious Tor Exit Node (Abuse Score: 88%)",
    threatType: "AbuseIPDB Known Malicious Tor Exit Node (Abuse Score: 88%)",
    severity: "HIGH",
    threatSeverity: "HIGH",
    status: "Active",
    detection_source: "AbuseIPDB Threat Intel",
    abuse_score: 88,
    threatScore: "0.88 (88%)",
    details: "Inbound connection request initiated from known malicious Tor exit relay.",
    analyst_notes: "",
    packet_size: "820 Bytes",
    protocol: "TCP (SYN)",
    dest_port: "22 / SSH",
    isp: "DigitalOcean LLC",
    country: "US",
    total_reports: 88,
    action_history: [],
  },
  {
    alert_id: "ALT-1084",
    timestamp: "2026-08-22 09:12:45 UTC",
    source_ip: "192.168.1.180",
    sourceIp: "192.168.1.180",
    target_ip: "10.0.9.47",
    threat_vector: "CICIDS2017 PortScan / Reconnaissance",
    threatType: "CICIDS2017 PortScan / Reconnaissance",
    severity: "MEDIUM",
    threatSeverity: "MEDIUM",
    status: "Contained",
    detection_source: "CICIDS2017 Engine + AbuseIPDB API",
    abuse_score: 54,
    threatScore: "0.54 (54%)",
    details: "Sequential TCP port probe across subnet range 10.0.9.0/24 intercepted.",
    analyst_notes: "Isolated IP on gateway interface.",
    packet_size: "64 Bytes",
    protocol: "TCP (ACK)",
    dest_port: "443 / HTTPS",
    isp: "Internal LAN Subnet",
    country: "LOCAL",
    total_reports: 12,
    action_history: [],
  },
  {
    alert_id: "ALT-1085",
    timestamp: "2026-08-22 08:50:30 UTC",
    source_ip: "203.0.113.88",
    sourceIp: "203.0.113.88",
    target_ip: "10.0.9.12",
    threat_vector: "CICIDS2017 Web Attack - Brute Force / XSS / SQLi",
    threatType: "CICIDS2017 Web Attack - Brute Force / XSS / SQLi",
    severity: "CRITICAL",
    threatSeverity: "CRITICAL",
    status: "Investigating",
    detection_source: "Dual Engine (UNSW + CICIDS2017)",
    abuse_score: 92,
    threatScore: "0.92 (92%)",
    details: "Remote code execution attempt via SQLi payload in HTTP GET parameters.",
    analyst_notes: "Inspected payload structure; matches SQL injection pattern.",
    packet_size: "2,150 Bytes",
    protocol: "HTTP (POST)",
    dest_port: "443 / HTTPS",
    isp: "Cloudflare Network",
    country: "DE",
    total_reports: 110,
    action_history: [],
  },
];

export const IncidentContext = createContext({
  incidents: DEFAULT_INCIDENTS,
  setIncidents: () => {},
  addIncident: () => {},
  fetchQueue: () => {},
  isLoading: false,
  isRefreshing: false,
});

export function IncidentProvider({ children }) {
  const [incidents, setIncidents] = useState(DEFAULT_INCIDENTS);
  const [isLoading, setIsLoading] = useState(false);
  const [isRefreshing, setIsRefreshing] = useState(false);

  // Helper to add a new threat incident directly to state
  const addIncident = useCallback((newIncident) => {
    setIncidents((prev) => [newIncident, ...prev]);
  }, []);

  // Fetch Live Incident Queue from FastAPI Backend (GET /api/incidents/queue)
  const fetchQueue = useCallback(async (severityFilter, statusFilter) => {
    setIsRefreshing(true);
    try {
      const queryParams = new URLSearchParams();
      if (severityFilter && severityFilter !== "ALL") queryParams.append("severity", severityFilter);
      if (statusFilter && statusFilter !== "ALL") queryParams.append("status", statusFilter);

      const url = `/api/incidents/queue?${queryParams.toString()}`;
      let res = await fetchApi(url).catch(() => null);

      if (!res) {
        res = await fetchApi(`/api/analyst/incidents/queue?${queryParams.toString()}`).catch(() => null);
      }

      const data = res?.data || res?.incidents || (Array.isArray(res) ? res : null);
      if (Array.isArray(data) && data.length > 0) {
        const datasetIncidentsOnly = data.filter((item) => {
          const type = (
            item?.threatType ||
            item?.threat_vector ||
            item?.threat_type ||
            item?.description ||
            item?.details ||
            item?.alert_id ||
            item?.id ||
            ""
          ).toLowerCase();
          return !type.includes("pcap");
        });
        if (datasetIncidentsOnly.length > 0) {
          setIncidents(datasetIncidentsOnly);
        }
      }
    } catch (err) {
      console.warn("Failed to fetch incident queue from FastAPI backend, retaining default dataset", err);
    } finally {
      setIsLoading(false);
      setIsRefreshing(false);
    }
  }, []);

  useEffect(() => {
    fetchQueue();
  }, [fetchQueue]);

  // Real-Time SSE Stream Listener (/api/incidents/stream)
  useEffect(() => {
    let eventSource = null;
    try {
      eventSource = new EventSource("/api/incidents/stream");
      eventSource.onmessage = (event) => {
        try {
          const parsed = JSON.parse(event.data);
          if (parsed && parsed.incidents) {
            const datasetIncidentsOnly = parsed.incidents.filter((item) => {
              const type = (
                item?.threatType ||
                item?.threat_vector ||
                item?.threat_type ||
                item?.description ||
                item?.details ||
                item?.alert_id ||
                item?.id ||
                ""
              ).toLowerCase();
              return !type.includes("pcap");
            });
            if (datasetIncidentsOnly.length > 0) {
              setIncidents(datasetIncidentsOnly);
            }
          }
        } catch (e) {
          console.warn("SSE parse notice:", e);
        }
      };
    } catch (e) {
      console.warn("SSE connection notice, polling active:", e);
    }

    return () => {
      if (eventSource) eventSource.close();
    };
  }, []);

  return (
    <IncidentContext.Provider
      value={{
        incidents,
        setIncidents,
        addIncident,
        fetchQueue,
        isLoading,
        isRefreshing,
      }}
    >
      {children}
    </IncidentContext.Provider>
  );
}

export function useIncidents() {
  return useContext(IncidentContext);
}
