"use client";
import React, { useState, useEffect } from "react";
import { usePathname, useRouter } from "next/navigation";
import {
  BarChart3,
  Shield,
  ShieldAlert,
  AlertTriangle,
  HelpCircle,
  Users,
  FileText,
  Settings,
} from "lucide-react";

import ProtectedRoute from "../../components/ProtectedRoute";
import Navbar from "../../components/Navbar";
import Sidebar from "../../components/Sidebar";
import Footer from "../../components/Footer";

import { getCurrentUser, clearCurrentUser } from "../../utils/authHelpers";
import { getFormattedUTCTime } from "../../utils/formatDate";
import { fetchApi } from "../../utils/api";

const ROUTE_TO_TAB = {
  "/admin": "Dashboard",
  "/admin/dashboard": "Dashboard",
  "/admin/activity-security": "Activity Security",
  "/admin/threats": "Threats",
  "/admin/critical-alerts": "Critical Alerts",
  "/admin/system-help": "System Help",
  "/admin/system-health": "System Help",
  "/admin/user-management": "User Management",
  "/admin/audit-logs": "Audit Logs",
  "/admin/settings": "Settings",
};

const TAB_TO_ROUTE = {
  "Dashboard": "/admin/dashboard",
  "Activity Security": "/admin/activity-security",
  "Threats": "/admin/threats",
  "Critical Alerts": "/admin/critical-alerts",
  "System Help": "/admin/system-help",
  "User Management": "/admin/user-management",
  "Audit Logs": "/admin/audit-logs",
  "Settings": "/admin/settings",
};

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

export default function AdminLayout({ children }) {
  const router = useRouter();
  const pathname = usePathname();
  const [currentUser, setCurrentUser] = useState(null);
  const [sidebarCollapsed, setSidebarCollapsed] = useState(false);
  const [currentTime, setCurrentTime] = useState("");
  const [searchQuery, setSearchQuery] = useState("");
  const [notificationCount, setNotificationCount] = useState(3);

  const activeTab = ROUTE_TO_TAB[pathname] || "Dashboard";

  useEffect(() => {
    setCurrentTime(getFormattedUTCTime());
    const timer = setInterval(() => {
      setCurrentTime(getFormattedUTCTime());
    }, 1000);
    return () => clearInterval(timer);
  }, []);

  useEffect(() => {
    const user = getCurrentUser();
    if (user) {
      setCurrentUser(user);
    }
  }, []);

  useEffect(() => {
    async function loadStats() {
      try {
        const res = await fetchApi("/api/dashboard/stats");
        if (res?.stats?.critical_alerts) {
          setNotificationCount(parseInt(res.stats.critical_alerts));
        }
      } catch (err) {}
    }
    loadStats();
  }, []);

  const handleLogout = () => {
    clearCurrentUser();
    router.push("/login");
  };

  const handleSetActiveTab = (tabName) => {
    const targetRoute = TAB_TO_ROUTE[tabName];
    if (targetRoute) {
      router.push(targetRoute);
    }
  };

  return (
    <ProtectedRoute allowedRoles={["admin"]}>
      <div className="ns-soc-layout ns-admin-layout">
        <Sidebar
          sidebarCollapsed={sidebarCollapsed}
          setSidebarCollapsed={setSidebarCollapsed}
          menuItems={menuItems}
          activeTab={activeTab}
          setActiveTab={handleSetActiveTab}
          onLogout={handleLogout}
        />

        <main className="ns-soc-main">
          <Navbar
            currentUser={currentUser}
            searchQuery={searchQuery}
            setSearchQuery={setSearchQuery}
            currentTime={currentTime}
            notificationCount={notificationCount}
            onLogout={handleLogout}
          />

          <div className="ns-soc-content-container">
            {children}
            <Footer />
          </div>
        </main>
      </div>
    </ProtectedRoute>
  );
}
