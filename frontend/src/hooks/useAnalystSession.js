"use client";
import { useState, useEffect, useCallback } from "react";
import { getCurrentUser } from "../utils/authHelpers";
import { fetchApi } from "../utils/api";

/**
 * Custom React Hook: useAnalystSession
 * Manages user-specific action persistence, history restoration, and session preferences
 * in PostgreSQL for all logged-in Security Analysts (e.g., security@gmail.com or new accounts).
 */
export function useAnalystSession() {
  const [currentUser, setCurrentUser] = useState(null);
  const [history, setHistory] = useState([]);
  const [sessionSettings, setSessionSettings] = useState({
    bandwidthThresholdMbps: 1000,
    liveStreamActive: true,
    pinnedInterface: "eth0",
    customFilters: { severity: "ALL", protocol: "ALL", dataset: "CICIDS2017" },
  });
  const [isLoading, setIsLoading] = useState(true);
  const [isSyncing, setIsSyncing] = useState(false);
  const [error, setError] = useState(null);

  // Initialize Current User Context
  useEffect(() => {
    const user = getCurrentUser();
    if (user) {
      setCurrentUser(user);
    } else {
      // Fallback active session default
      setCurrentUser({ email: "security@gmail.com", role: "Security Analyst" });
    }
  }, []);

  const userEmail = currentUser?.email || "security@gmail.com";

  // 1. Fetch User Historical Activity Logs from PostgreSQL
  const fetchHistory = useCallback(async () => {
    if (!userEmail) return;
    setIsLoading(true);
    setError(null);
    try {
      const res = await fetchApi(`/api/analyst/history?user_email=${encodeURIComponent(userEmail)}`, {
        headers: {
          "X-User-Email": userEmail,
        },
      });
      const logData = res?.data || res || [];
      if (Array.isArray(logData)) {
        setHistory(logData);
      }
    } catch (err) {
      console.warn("Analyst history restoration fallback:", err);
      setError("Unable to restore remote action history from PostgreSQL.");
    } finally {
      setIsLoading(false);
    }
  }, [userEmail]);

  // 2. Restore User Local Preference Settings
  const restoreSessionSettings = useCallback(() => {
    if (typeof window === "undefined" || !userEmail) return;
    try {
      const savedKey = `netshield_session_${userEmail}`;
      const saved = localStorage.getItem(savedKey);
      if (saved) {
        setSessionSettings(JSON.parse(saved));
      }
    } catch (e) {
      console.warn("Failed to load local session settings:", e);
    }
  }, [userEmail]);

  // Trigger history & settings restoration whenever active user changes
  useEffect(() => {
    if (userEmail) {
      fetchHistory();
      restoreSessionSettings();
    }
  }, [userEmail, fetchHistory, restoreSessionSettings]);

  // 3. Persist New Analyst Action to PostgreSQL
  const logAction = useCallback(
    async (actionType, moduleName, details = null) => {
      if (!actionType || !moduleName) return null;
      setIsSyncing(true);

      const newActionRecord = {
        id: Date.now(),
        user_email: userEmail,
        user_role: currentUser?.role || "Security Analyst",
        action_type: actionType,
        module_name: moduleName,
        details: details || {},
        timestamp: new Date().toISOString().replace("T", " ").substring(0, 19) + " UTC",
      };

      // Optimistic state update (prepend to ongoing audit timeline instantly)
      setHistory((prev) => [newActionRecord, ...prev]);

      try {
        const payload = {
          action_type: actionType,
          module_name: moduleName,
          user_email: userEmail,
          user_role: currentUser?.role || "Security Analyst",
          details: details,
        };

        const res = await fetchApi("/api/analyst/action", {
          method: "POST",
          headers: {
            "Content-Type": "application/json",
            "X-User-Email": userEmail,
          },
          body: JSON.stringify(payload),
        });

        if (res && res.data) {
          // Replace optimistic record with canonical database record
          setHistory((prev) =>
            prev.map((item) => (item.id === newActionRecord.id ? res.data : item))
          );
        }
        return res?.data || newActionRecord;
      } catch (err) {
        console.error("Action persistence failed:", err);
        return newActionRecord;
      } finally {
        setIsSyncing(false);
      }
    },
    [userEmail, currentUser]
  );

  // 4. Save Session Preference Settings
  const saveSessionSettings = useCallback(
    (newSettings) => {
      setSessionSettings((prev) => {
        const updated = typeof newSettings === "function" ? newSettings(prev) : { ...prev, ...newSettings };
        if (typeof window !== "undefined" && userEmail) {
          try {
            localStorage.setItem(`netshield_session_${userEmail}`, JSON.stringify(updated));
          } catch (e) {}
        }
        return updated;
      });
    },
    [userEmail]
  );

  return {
    currentUser,
    userEmail,
    history,
    sessionSettings,
    isLoading,
    isSyncing,
    error,
    fetchHistory,
    logAction,
    saveSessionSettings,
  };
}

export default useAnalystSession;
