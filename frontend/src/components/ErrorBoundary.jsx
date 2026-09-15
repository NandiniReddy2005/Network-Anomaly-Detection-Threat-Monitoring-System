"use client";
import React from "react";
import { AlertOctagon, RefreshCw } from "lucide-react";

class ErrorBoundary extends React.Component {
  constructor(props) {
    super(props);
    this.state = { hasError: false, error: null };
  }

  static getDerivedStateFromError(error) {
    return { hasError: true, error };
  }

  componentDidCatch(error, errorInfo) {
    console.error("ErrorBoundary caught an exception:", error, errorInfo);
  }

  render() {
    if (this.state.hasError) {
      if (this.props.fallback) {
        return this.props.fallback;
      }

      return (
        <div
          style={{
            padding: "2rem",
            margin: "1rem 0",
            borderRadius: "12px",
            backgroundColor: "rgba(239, 68, 68, 0.1)",
            border: "1px solid rgba(239, 68, 68, 0.3)",
            color: "#ef4444",
            display: "flex",
            flexDirection: "column",
            alignItems: "center",
            gap: "1rem",
            textAlign: "center",
          }}
        >
          <AlertOctagon size={48} />
          <div>
            <h3 style={{ fontSize: "1.25rem", fontWeight: "700", margin: "0 0 0.5rem 0", color: "#f87171" }}>
              Something went wrong loading this component
            </h3>
            <p style={{ fontSize: "0.875rem", margin: 0, color: "#94a3b8" }}>
              {this.state.error?.message || "An unexpected React runtime exception occurred."}
            </p>
          </div>
          <button
            onClick={() => {
              this.setState({ hasError: false, error: null });
              if (typeof window !== "undefined") window.location.reload();
            }}
            style={{
              display: "inline-flex",
              alignItems: "center",
              gap: "0.5rem",
              padding: "0.5rem 1rem",
              borderRadius: "6px",
              backgroundColor: "#ef4444",
              color: "#ffffff",
              border: "none",
              fontWeight: "600",
              cursor: "pointer",
            }}
          >
            <RefreshCw size={16} /> Reload Page
          </button>
        </div>
      );
    }

    return this.props.children;
  }
}

export default ErrorBoundary;
