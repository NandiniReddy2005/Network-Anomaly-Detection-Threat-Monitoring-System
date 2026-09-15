"use client";
import React, { useState, useRef, useEffect } from "react";
import { useRouter } from "next/navigation";
import {
  Search,
  Bell,
  Sun,
  Moon,
  LogOut,
  ChevronDown,
  ShieldCheck,
  Shield,
  Key,
} from "lucide-react";

import { useTheme } from "../context/ThemeContext";
import { clearCurrentUser } from "../utils/authHelpers";
import NotificationDropdown from "./NotificationDropdown";

export default function Navbar({
  currentUser,
  searchQuery,
  setSearchQuery,
  currentTime,
  notificationCount,
  onLogout,
}) {
  const { isDark, toggleTheme } = useTheme();
  const router = useRouter();

  const [isOpen, setIsOpen] = useState(false);
  const dropdownRef = useRef(null);
  const hoverTimeoutRef = useRef(null);

  const userInitial = currentUser?.email
    ? currentUser.email.charAt(0).toUpperCase()
    : "U";
  const userEmail = currentUser?.email || "admin@gmail.com";
  const isAnalyst = currentUser?.role === "analyst";
  const userRoleText = isAnalyst ? "Security Analyst" : "Security Administrator";

  // Toggle or open dropdown
  const toggleDropdown = () => {
    setIsOpen((prev) => !prev);
  };

  const handleMouseEnter = () => {
    if (hoverTimeoutRef.current) clearTimeout(hoverTimeoutRef.current);
    setIsOpen(true);
  };

  const handleMouseLeave = () => {
    hoverTimeoutRef.current = setTimeout(() => {
      setIsOpen(false);
    }, 200);
  };

  // Close dropdown on click outside
  useEffect(() => {
    const handleClickOutside = (event) => {
      if (dropdownRef.current && !dropdownRef.current.contains(event.target)) {
        setIsOpen(false);
      }
    };

    const handleKeyDown = (event) => {
      if (event.key === "Escape") {
        setIsOpen(false);
      }
    };

    document.addEventListener("mousedown", handleClickOutside);
    document.addEventListener("keydown", handleKeyDown);

    return () => {
      document.removeEventListener("mousedown", handleClickOutside);
      document.removeEventListener("keydown", handleKeyDown);
      if (hoverTimeoutRef.current) clearTimeout(hoverTimeoutRef.current);
    };
  }, []);

  // Handle logout
  const handleLogoutAction = (e) => {
    e.stopPropagation();
    setIsOpen(false);
    clearCurrentUser();
    if (onLogout) {
      onLogout();
    } else {
      router.push("/login");
    }
  };

  return (
    <header className="ns-topbar">
      <div className="topbar-left">
        <div className="search-bar-wrapper">
          <Search size={16} className="search-icon" />
          <input
            type="text"
            placeholder="Search IPs, events, or signatures..."
            value={searchQuery || ""}
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
          {isDark ? (
            <Sun size={18} style={{ color: "#fbbf24" }} />
          ) : (
            <Moon size={18} style={{ color: "#3b82f6" }} />
          )}
        </button>

        {/* Dynamic Notification Center Dropdown */}
        <NotificationDropdown currentUser={currentUser} />

        {/* Interactive Profile Dropdown Container */}
        <div
          ref={dropdownRef}
          className="user-profile-wrapper"
          onMouseEnter={handleMouseEnter}
          onMouseLeave={handleMouseLeave}
          style={{ position: "relative" }}
        >
          <div
            className="user-profile-pill"
            onClick={toggleDropdown}
            style={{
              cursor: "pointer",
              userSelect: "none",
              display: "flex",
              alignItems: "center",
              gap: "0.5rem",
            }}
          >
            <div className="user-avatar-circle">{userInitial}</div>
            <div className="user-meta">
              <span className="user-email-text" style={{ color: isDark ? "#f8fafc" : "#1e293b" }}>{userEmail}</span>
              <span className="user-role-text" style={{ color: isDark ? "#94a3b8" : "#475569" }}>{userRoleText}</span>
            </div>
            <ChevronDown
              size={14}
              style={{
                marginLeft: "0.25rem",
                transition: "transform 200ms ease",
                transform: isOpen ? "rotate(180deg)" : "rotate(0deg)",
                color: isDark ? "#94a3b8" : "#64748b",
              }}
            />
          </div>

          {/* Dropdown Popover */}
          {isOpen && (
            <div
              style={{
                position: "absolute",
                top: "calc(100% + 8px)",
                right: 0,
                width: "260px",
                backgroundColor: isDark ? "#0f172a" : "#ffffff",
                border: isDark
                  ? "1px solid rgba(255, 255, 255, 0.12)"
                  : "1px solid #cbd5e1",
                borderRadius: "12px",
                boxShadow: isDark
                  ? "0 15px 35px rgba(0, 0, 0, 0.6), 0 0 0 1px rgba(255, 255, 255, 0.05)"
                  : "0 15px 30px rgba(0, 0, 0, 0.12)",
                padding: "0.75rem",
                zIndex: 1000,
                animation: "fadeInDown 180ms ease-out forwards",
              }}
            >
              {/* Dropdown Header User Info */}
              <div
                style={{
                  display: "flex",
                  alignItems: "center",
                  gap: "0.75rem",
                  paddingBottom: "0.75rem",
                  borderBottom: isDark
                    ? "1px solid rgba(255, 255, 255, 0.08)"
                    : "1px solid #e2e8f0",
                  marginBottom: "0.5rem",
                }}
              >
                <div
                  style={{
                    width: "40px",
                    height: "40px",
                    borderRadius: "50%",
                    backgroundColor: isAnalyst
                      ? isDark
                        ? "rgba(6, 182, 212, 0.2)"
                        : "#e0f2fe"
                      : isDark
                      ? "rgba(168, 85, 247, 0.2)"
                      : "#f3e8ff",
                    color: isAnalyst ? "#0284c7" : "#a855f7",
                    display: "flex",
                    alignItems: "center",
                    justifyContent: "center",
                    fontSize: "1.1rem",
                    fontWeight: 700,
                    border: `1px solid ${
                      isAnalyst
                        ? isDark
                          ? "rgba(6, 182, 212, 0.4)"
                          : "#7dd3fc"
                        : isDark
                        ? "rgba(168, 85, 247, 0.4)"
                        : "#d8b4fe"
                    }`,
                  }}
                >
                  {userInitial}
                </div>

                <div style={{ flex: 1, minWidth: 0 }}>
                  <div
                    style={{
                      fontSize: "0.85rem",
                      fontWeight: 700,
                      color: isDark ? "#f8fafc" : "#0f172a",
                      whiteSpace: "nowrap",
                      overflow: "hidden",
                      textOverflow: "ellipsis",
                    }}
                    title={userEmail}
                  >
                    {userEmail}
                  </div>

                  <div
                    style={{
                      display: "inline-flex",
                      alignItems: "center",
                      gap: "0.25rem",
                      marginTop: "0.2rem",
                      padding: "0.15rem 0.45rem",
                      borderRadius: "9999px",
                      fontSize: "0.7rem",
                      fontWeight: 600,
                      backgroundColor: isAnalyst
                        ? isDark
                          ? "rgba(6, 182, 212, 0.15)"
                          : "#ecfeff"
                        : isDark
                        ? "rgba(168, 85, 247, 0.15)"
                        : "#faf5ff",
                      color: isAnalyst
                        ? isDark
                          ? "#22d3ee"
                          : "#0369a1"
                        : isDark
                        ? "#c084fc"
                        : "#7e22ce",
                      border: `1px solid ${
                        isAnalyst
                          ? isDark
                            ? "rgba(6, 182, 212, 0.3)"
                            : "#a5f3fc"
                          : isDark
                          ? "rgba(168, 85, 247, 0.3)"
                          : "#e9d5ff"
                      }`,
                    }}
                  >
                    {isAnalyst ? <Shield size={10} /> : <ShieldCheck size={10} />}
                    {userRoleText}
                  </div>
                </div>
              </div>

              {/* Logout Button */}
              <button
                onClick={handleLogoutAction}
                style={{
                  width: "100%",
                  display: "flex",
                  alignItems: "center",
                  justifyContent: "center",
                  gap: "0.5rem",
                  padding: "0.55rem",
                  borderRadius: "6px",
                  border: isDark
                    ? "1px solid rgba(239, 68, 68, 0.25)"
                    : "1px solid #fca5a5",
                  backgroundColor: isDark
                    ? "rgba(239, 68, 68, 0.12)"
                    : "#fef2f2",
                  color: "#ef4444",
                  fontSize: "0.825rem",
                  fontWeight: 600,
                  cursor: "pointer",
                  transition: "all 150ms ease",
                }}
                onMouseEnter={(e) => {
                  e.currentTarget.style.backgroundColor = "#ef4444";
                  e.currentTarget.style.color = "#ffffff";
                }}
                onMouseLeave={(e) => {
                  e.currentTarget.style.backgroundColor = isDark
                    ? "rgba(239, 68, 68, 0.12)"
                    : "#fef2f2";
                  e.currentTarget.style.color = "#ef4444";
                }}
              >
                <LogOut size={15} />
                Log Out
              </button>
            </div>
          )}
        </div>
      </div>
    </header>
  );
}
