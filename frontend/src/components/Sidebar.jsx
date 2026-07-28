"use client";
import React from "react";
import { Shield, Menu, ChevronLeft, LogOut } from "lucide-react";

export default function Sidebar({
  sidebarCollapsed,
  setSidebarCollapsed,
  menuItems = [],
  activeTab,
  setActiveTab,
  onLogout,
}) {
  return (
    <aside className={`ns-sidebar ${sidebarCollapsed ? "collapsed" : ""}`}>
      <div className="ns-sidebar-brand">
        <Shield className="ns-brand-icon" size={24} />
        {!sidebarCollapsed && <span className="ns-brand-text">NetShield-AI</span>}
        <button
          className="ns-collapse-btn"
          onClick={() => setSidebarCollapsed(!sidebarCollapsed)}
          aria-label="Toggle Sidebar"
        >
          {sidebarCollapsed ? <Menu size={16} /> : <ChevronLeft size={16} />}
        </button>
      </div>

      <div className="ns-sidebar-menu">
        {menuItems.map((item) => (
          <div
            key={item.name}
            className={`ns-menu-item ${activeTab === item.name ? "active" : ""}`}
            onClick={() => setActiveTab(item.name)}
          >
            <span className="ns-menu-icon">{item.icon}</span>
            {!sidebarCollapsed && <span className="ns-menu-label">{item.name}</span>}
          </div>
        ))}
      </div>

      <div className="ns-sidebar-footer">
        <div className="ns-menu-item logout" onClick={onLogout}>
          <span className="ns-menu-icon">
            <LogOut size={18} />
          </span>
          {!sidebarCollapsed && <span className="ns-menu-label">Sign Out</span>}
        </div>
      </div>
    </aside>
  );
}
