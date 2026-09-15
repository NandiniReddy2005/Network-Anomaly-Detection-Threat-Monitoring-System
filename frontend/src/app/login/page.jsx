"use client";
import React, { useState } from "react";
import { useRouter } from "next/navigation";
import { Shield } from "lucide-react";
import { setCurrentUser } from "../../utils/authHelpers";
import { API_BASE_URL } from "../../utils/constants";

export default function LoginPage() {
  const router = useRouter();
  const [email, setEmail] = useState("");
  const [password, setPassword] = useState("");
  const [error, setError] = useState("");
  const [success, setSuccess] = useState("");
  const [loading, setLoading] = useState(false);

  const formatErrorMessage = (detail, status) => {
    if (status === 404 || (typeof detail === "string" && detail.includes("Account not found"))) {
      return "Account not found. Please register first.";
    }
    if (status === 401 || (typeof detail === "string" && detail.includes("Invalid password"))) {
      return "Invalid password.";
    }
    if (!detail) return "Authentication failed. Please check your credentials.";
    if (typeof detail === "string") return detail;
    if (Array.isArray(detail)) {
      return detail.map((err) => err.msg || JSON.stringify(err)).join(", ");
    }
    if (typeof detail === "object") {
      return detail.msg || JSON.stringify(detail);
    }
    return String(detail);
  };

  const handleLogin = async (e) => {
    e.preventDefault();
    setError("");
    setSuccess("");

    if (!email || !password) {
      setError("Please enter your Gmail and password.");
      return;
    }

    setLoading(true);

    try {
      const response = await fetch(`${API_BASE_URL}/api/auth/login`, {
        method: "POST",
        headers: {
          "Content-Type": "application/json",
        },
        body: JSON.stringify({ email: email.trim(), password }),
      });

      let data = {};
      try {
        data = await response.json();
      } catch (jsonErr) {
        console.error("Non-JSON response received:", jsonErr);
      }

      if (!response.ok) {
        setError(formatErrorMessage(data.detail, response.status));
        setLoading(false);
        return;
      }

      const user = data.user;
      setCurrentUser(user);
      setSuccess("Authentication successful! Loading dashboard...");
      setTimeout(() => {
        if (user.role === "analyst") {
          router.push("/analyst");
        } else {
          router.push("/admin");
        }
      }, 600);
    } catch (err) {
      console.error("Login network error:", err);
      setError("Unable to connect to security backend server. Please try again.");
      setLoading(false);
    }
  };

  return (
    <div className="ns-auth-wrapper">
      <div className="ns-auth-card">
        <div className="ns-auth-header">
          <Shield className="ns-auth-logo-icon" size={36} />
          <h1 className="ns-auth-title">NetShield-AI</h1>
          <p className="ns-auth-subtitle">Enterprise SOC Security Gateway</p>
        </div>

        {error && <div className="ns-alert-error">{error}</div>}
        {success && <div className="ns-alert-success">{success}</div>}

        <form onSubmit={handleLogin} className="ns-auth-form">
          <div className="ns-form-group">
            <label>Gmail Address</label>
            <input
              type="email"
              placeholder="analyst@gmail.com"
              value={email}
              onChange={(e) => setEmail(e.target.value)}
              className="ns-control"
              disabled={loading}
            />
          </div>

          <div className="ns-form-group">
            <label>Password</label>
            <input
              type="password"
              placeholder="••••••••"
              value={password}
              onChange={(e) => setPassword(e.target.value)}
              className="ns-control"
              disabled={loading}
            />
          </div>

          <button type="submit" className="ns-btn-gradient primary" disabled={loading}>
            {loading ? "Authenticating..." : "Sign In to SOC"}
          </button>
        </form>

        <p className="ns-auth-switch">
          <span>
            Don't have an account?{" "}
            <a onClick={() => router.push("/register")} style={{ cursor: "pointer" }}>
              Register first
            </a>
          </span>
        </p>
      </div>
    </div>
  );
}
