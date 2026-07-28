"use client";
import React from "react";

export default function LoadingSpinner({ text = "Loading backend telemetry data..." }) {
  return (
    <div style={{ padding: "2rem", textAlign: "center" }}>
      <p style={{ color: "#94a3b8", fontSize: "0.95rem" }}>{text}</p>
    </div>
  );
}
