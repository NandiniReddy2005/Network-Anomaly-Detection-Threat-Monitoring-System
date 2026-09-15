"use client";
import React, { useState, useEffect } from "react";
import dynamic from "next/dynamic";
import LoadingSpinner from "../../components/LoadingSpinner";

const PacketCaptureView = dynamic(
  () => import("../../components/analyst/PacketCaptureView"),
  {
    ssr: false,
    loading: () => (
      <div style={{ padding: "3rem", textAlign: "center", color: "#94a3b8" }}>
        <LoadingSpinner text="Initializing Packet Capture Telemetry Engine..." />
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
    console.error("PacketCapture Error Boundary caught error:", error, errorInfo);
  }

  render() {
    if (this.state.hasError) {
      return (
        <div style={{ padding: "2rem", backgroundColor: "rgba(239, 68, 68, 0.1)", border: "1px solid rgba(239, 68, 68, 0.3)", borderRadius: "8px", color: "#ef4444", margin: "1rem" }}>
          <h3 style={{ margin: "0 0 0.5rem 0", fontSize: "1.1rem" }}>Packet Capture Connection Notice</h3>
          <p style={{ margin: "0 0 1rem 0", fontSize: "0.85rem", color: "#94a3b8" }}>
            Backend Connection Notice: {this.state.error?.message || "Render issue encountered"}. Showing standby layout for security@gmail.com.
          </p>
          <button
            onClick={() => this.setState({ hasError: false, error: null })}
            style={{ padding: "0.4rem 0.85rem", backgroundColor: "#3B82F6", color: "#fff", border: "none", borderRadius: "4px", cursor: "pointer", fontSize: "0.85rem" }}
          >
            Reload Packet Capture Engine
          </button>
        </div>
      );
    }

    return this.props.children;
  }
}

export default function PacketCaptureAliasPage() {
  const [mounted, setMounted] = useState(false);

  useEffect(() => {
    setMounted(true);
  }, []);

  if (!mounted) {
    return (
      <div style={{ padding: "3rem", textAlign: "center", color: "#94a3b8" }}>
        <LoadingSpinner text="Loading packet capture telemetry for security@gmail.com..." />
      </div>
    );
  }

  return (
    <ErrorBoundary>
      <PacketCaptureView />
    </ErrorBoundary>
  );
}
