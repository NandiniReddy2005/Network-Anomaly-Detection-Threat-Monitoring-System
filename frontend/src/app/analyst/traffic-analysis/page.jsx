"use client";
import React, { useState, useEffect } from "react";
import dynamic from "next/dynamic";
import LoadingSpinner from "../../../components/LoadingSpinner";

// Dynamically import TrafficAnalysisView with ssr: false to prevent Next.js hydration mismatches & SSR crashes
const TrafficAnalysisView = dynamic(
  () => import("../../../components/analyst/TrafficAnalysisView"),
  {
    ssr: false,
    loading: () => (
      <div style={{ padding: "3rem", textAlign: "center", color: "#94a3b8" }}>
        <LoadingSpinner text="Initializing Traffic Analysis Telemetry Engine..." />
      </div>
    ),
  }
);

class ErrorBoundary extends React.Component {
  constructor(props) {
    super(props);
    this.state = { hasError: false, error: null };
  }

  static getDerivedStateFromError(error) {
    return { hasError: true, error };
  }

  componentDidCatch(error, errorInfo) {
    console.error("TrafficAnalysis Error Boundary caught error:", error, errorInfo);
  }

  render() {
    if (this.state.hasError) {
      return (
        <div style={{ padding: "2rem", backgroundColor: "rgba(239, 68, 68, 0.1)", border: "1px solid rgba(239, 68, 68, 0.3)", borderRadius: "8px", color: "#ef4444", margin: "1rem" }}>
          <h3 style={{ margin: "0 0 0.5rem 0", fontSize: "1.1rem" }}>Traffic Analysis Telemetry Notice</h3>
          <p style={{ margin: "0 0 1rem 0", fontSize: "0.85rem", color: "#94a3b8" }}>
            Telemetry Notice: {this.state.error?.message || "Render issue encountered"}. Showing standby layout.
          </p>
          <button
            onClick={() => this.setState({ hasError: false, error: null })}
            style={{ padding: "0.4rem 0.85rem", backgroundColor: "#3B82F6", color: "#fff", border: "none", borderRadius: "4px", cursor: "pointer", fontSize: "0.85rem" }}
          >
            Reload Traffic Analysis Engine
          </button>
        </div>
      );
    }

    return this.props.children;
  }
}

export default function TrafficAnalysisPage() {
  const [mounted, setMounted] = useState(false);

  useEffect(() => {
    setMounted(true);
  }, []);

  if (!mounted) {
    return (
      <div style={{ padding: "3rem", textAlign: "center", color: "#94a3b8" }}>
        <LoadingSpinner text="Loading traffic analysis telemetry..." />
      </div>
    );
  }

  return (
    <ErrorBoundary>
      <TrafficAnalysisView />
    </ErrorBoundary>
  );
}
