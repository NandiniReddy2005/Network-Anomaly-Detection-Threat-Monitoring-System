"use client";
import React from "react";

export default function DashboardCard({
  title,
  badgeTag,
  badgeTagClass = "",
  className = "",
  headerExtra,
  children,
}) {
  return (
    <div className={`ns-card ${className}`}>
      {(title || badgeTag || headerExtra) && (
        <div className="card-header-flex">
          {title && <h3>{title}</h3>}
          {headerExtra}
          {badgeTag && <span className={`badge-tag ${badgeTagClass}`}>{badgeTag}</span>}
        </div>
      )}
      {children}
    </div>
  );
}
