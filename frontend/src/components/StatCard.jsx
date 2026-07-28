"use client";
import React from "react";

export default function StatCard({
  title,
  icon,
  metric,
  trendText,
  trendClass = "trend-up",
  progressWidth = "50%",
  colorVariant = "blue",
}) {
  return (
    <div className={`ns-kpi-card border-${colorVariant}`}>
      <div className="kpi-header">
        <span>{title}</span>
        {icon}
      </div>
      <h2 className="kpi-metric">{metric}</h2>
      <div className="kpi-footer">
        <span className={trendClass}>{trendText}</span>
        <div className="mini-progress">
          <div className={`fill ${colorVariant}`} style={{ width: progressWidth }}></div>
        </div>
      </div>
    </div>
  );
}
