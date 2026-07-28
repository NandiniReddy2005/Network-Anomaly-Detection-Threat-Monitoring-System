"use client";
import React, { useState } from "react";
import { useRouter } from "next/navigation";
import { Shield } from "lucide-react";
import { API_BASE_URL } from "../../utils/constants";

export default function RegisterPage() {
  const router = useRouter();
  const [email, setEmail] = useState("");
  const [password, setPassword] = useState("");
  const [confirmPassword, setConfirmPassword] = useState("");
  const [role, setRole] = useState("analyst");
  const [error, setError] = useState("");
  const [success, setSuccess] = useState("");
  const [loading, setLoading] = useState(false);

  const formatErrorMessage = (detail) => {
    if (!detail) return "Registration failed. User with this email may already exist.";
    if (typeof detail === "string") return detail;
    if (Array.isArray(detail)) {
      return detail.map((err) => err.msg || JSON.stringify(err)).join(", ");
    }
    if (typeof detail === "object") {
      return detail.msg || JSON.stringify(detail);
    }
    return String(detail);
  };

  const handleRegister = async (e) => {
    e.preventDefault();
    setError("");
    setSuccess("");

    if (!email || !password || !confirmPassword) {
      setError("All fields are required.");
      return;
    }
    if (password !== confirmPassword) {
      setError("Passwords do not match.");
      return;
    }

    setLoading(true);

    try {
      const response = await fetch(`${API_BASE_URL}/api/auth/register`, {
        method: "POST",
        headers: {
          "Content-Type": "application/json",
        },
        body: JSON.stringify({ email: email.trim(), password, role }),
      });

      let data = {};
      try {
        data = await response.json();
      } catch (jsonErr) {
        console.error("Non-JSON response received:", jsonErr);
      }

      if (!response.ok) {
        setError(formatErrorMessage(data.detail));
        setLoading(false);
        return;
      }

      setSuccess("Registration successful! Redirecting to login...");
      setTimeout(() => {
        router.push("/login");
      }, 1200);
    } catch (err) {
      console.error("Register network error:", err);
      setError("Unable to connect to security backend server. Please try again.");
      setLoading(false);
    }
  };

  return (
    <div className="ns-auth-wrapper">
      <div className="ns-auth-card">
        <div className="ns-auth-header">
          <Shield className="ns-auth-logo-icon" size={36} />
          <h1 className="ns-auth-title">
            NetShield-AI <span className="ns-auth-tag">REGISTER</span>
          </h1>
          <p className="ns-auth-subtitle">Enterprise SOC Security Gateway</p>
        </div>

        {error && <div className="ns-alert-error">{error}</div>}
        {success && <div className="ns-alert-success">{success}</div>}

        <form onSubmit={handleRegister} className="ns-auth-form">
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

          <div className="ns-form-group">
            <label>Confirm Password</label>
            <input
              type="password"
              placeholder="••••••••"
              value={confirmPassword}
              onChange={(e) => setConfirmPassword(e.target.value)}
              className="ns-control"
              disabled={loading}
            />
          </div>

          <div className="ns-form-group">
            <label>Select Role</label>
            <select
              value={role}
              onChange={(e) => setRole(e.target.value)}
              className="ns-control"
              disabled={loading}
            >
              <option value="analyst">Security Analyst</option>
              <option value="admin">Security Administrator</option>
            </select>
          </div>

          <button type="submit" className="ns-btn-gradient primary" disabled={loading}>
            {loading ? "Creating Account..." : "Create Security Account"}
          </button>
        </form>

        <p className="ns-auth-switch">
          <span>
            Already have an account?{" "}
            <a onClick={() => router.push("/login")} style={{ cursor: "pointer" }}>
              Login here
            </a>
          </span>
        </p>
      </div>
    </div>
  );
}
