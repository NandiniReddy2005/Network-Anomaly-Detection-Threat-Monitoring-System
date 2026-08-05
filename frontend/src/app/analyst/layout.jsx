"use client";
import React, { useState, useEffect } from "react";
import { usePathname, useRouter } from "next/navigation";
import {
  Globe,
  Radio,
  Activity,
  Shield,
  BarChart3,
  FileText,
  Settings,
} from "lucide-react";

import ProtectedRoute from "../../components/ProtectedRoute";
import Navbar from "../../components/Navbar";
import Sidebar from "../../components/Sidebar";
import Footer from "../../components/Footer";

import { getCurrentUser, clearCurrentUser } from "../../utils/authHelpers";
import { getFormattedUTCTime } from "../../utils/formatDate";

const ROUTE_TO_TAB = {
  "/analyst": "Dashboard",
  "/analyst/dashboard": "Dashboard",
  "/analyst/network-monitoring": "Network Monitoring",
  "/analyst/packet-capture": "Packet Capture",
  "/analyst/traffic-analysis": "Traffic Analysis",
  "/analyst/reports": "Reports",
  "/analyst/analytics": "Analytics",
  "/analyst/settings": "Settings",
};

const TAB_TO_ROUTE = {
  "Dashboard": "/analyst/dashboard",
  "Network Monitoring": "/analyst/network-monitoring",
  "Packet Capture": "/analyst/packet-capture",
  "Traffic Analysis": "/analyst/traffic-analysis",
  "Reports": "/analyst/reports",
  "Analytics": "/analyst/analytics",
  "Settings": "/analyst/settings",
};

const menuItems = [
  { name: "Dashboard", icon: <Globe size={18} /> },
  { name: "Network Monitoring", icon: <Radio size={18} /> },
  { name: "Packet Capture", icon: <Activity size={18} /> },
  { name: "Traffic Analysis", icon: <Shield size={18} /> },
  { name: "Reports", icon: <FileText size={18} /> },
  { name: "Analytics", icon: <BarChart3 size={18} /> },
  { name: "Settings", icon: <Settings size={18} /> },
];

export default function AnalystLayout({ children }) {
  const router = useRouter();
  const pathname = usePathname();
  const [currentUser, setCurrentUser] = useState(null);
  const [sidebarCollapsed, setSidebarCollapsed] = useState(false);
  const [currentTime, setCurrentTime] = useState("");
  const [searchQuery, setSearchQuery] = useState("");

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
    <ProtectedRoute allowedRoles={["analyst"]}>
      <div className="ns-soc-layout ns-analyst-layout">
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
            onLogout={handleLogout}
          />

          <div className="ns-soc-content-container">
            {children}
          </div>
          <Footer />
        </main>
      </div>
    </ProtectedRoute>
  );
}
