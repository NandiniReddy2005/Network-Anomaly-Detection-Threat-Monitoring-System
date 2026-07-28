"use client";
import React from "react";
import { Search, Bell, Sun, Moon } from "lucide-react";
import { useTheme } from "../context/ThemeContext";

export default function Navbar({ currentUser, searchQuery, setSearchQuery, currentTime, notificationCount }) {
  const { isDark, toggleTheme } = useTheme();
  const userInitial = currentUser?.email ? currentUser.email.charAt(0).toUpperCase() : "U";
  const userEmail = currentUser?.email || "user@gmail.com";
  const userRoleText = currentUser?.role === "analyst" ? "Security Analyst" : "Administrator";

  return (
    <header className="ns-topbar">
      <div className="topbar-left">
        <div className="search-bar-wrapper">
          <Search size={16} className="search-icon" />
          <input
            type="text"
            placeholder="Search IPs, events, or signatures..."
            value={searchQuery}
            onChange={(e) => setSearchQuery && setSearchQuery(e.target.value)}
            className="ns-search-input"
          />
        </div>
      </div>

      <div className="topbar-right">
        <div className="ticker-badge">
          <span className="live-dot"></span>
          <span className="ticker-time">{currentTime}</span>
        </div>

        <button
          onClick={toggleTheme}
          className="topbar-icon-btn theme-toggle-btn"
          title={isDark ? "Switch to Light Mode" : "Switch to Dark Mode"}
          aria-label="Toggle Theme"
        >
          {isDark ? <Sun size={18} style={{ color: "#fbbf24" }} /> : <Moon size={18} style={{ color: "#3b82f6" }} />}
        </button>

        <div className="topbar-icon-btn notification-badge">
          <Bell size={18} />
          <span className="badge-counter">{notificationCount !== undefined ? notificationCount : 3}</span>
        </div>

        <div className="user-profile-pill">
          <div className="user-avatar-circle">{userInitial}</div>
          <div className="user-meta">
            <span className="user-email-text">{userEmail}</span>
            <span className="user-role-text">{userRoleText}</span>
          </div>
        </div>
      </div>
    </header>
  );
}
