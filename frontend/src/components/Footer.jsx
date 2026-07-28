"use client";
import React from "react";

export default function Footer() {
  return (
    <footer
      className="ns-footer"
      style={{
        width: "100%",
        marginTop: "auto",
        padding: "1.5rem 0 0.5rem 0",
        textAlign: "center",
        color: "#64748b",
        fontSize: "0.85rem",
        position: "relative",
        zIndex: 1,
        clear: "both",
        flexShrink: 0,
      }}
    >
      &copy; {new Date().getFullYear()} NetShield-AI Enterprise SOC Security Gateway. All rights reserved.
    </footer>
  );
}
