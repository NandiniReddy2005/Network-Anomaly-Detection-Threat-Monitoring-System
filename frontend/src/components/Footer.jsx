"use client";
import React from "react";
import { useTheme } from "../context/ThemeContext";

export default function Footer() {
  const { isDark } = useTheme();

  return (
    <footer
      className="ns-footer text-center text-xs w-full"
      style={{
        width: "100%",
        marginTop: "auto",
        padding: "1.5rem 0 0.5rem 0",
        textAlign: "center",
        color: isDark ? "#64748b" : "#64748b",
        fontSize: "0.75rem",
        position: "relative",
        clear: "both",
        flexShrink: 0,
      }}
    >
      &copy; {new Date().getFullYear()} NetShield-AI Enterprise SOC Security Gateway. All rights reserved.
    </footer>
  );
}
