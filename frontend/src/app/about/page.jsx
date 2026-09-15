"use client";
import React, { useState, useEffect, useRef } from "react";
import { useRouter } from "next/navigation";
import { Shield } from "lucide-react";

export default function AboutPage() {
  const router = useRouter();
  const canvasRef = useRef(null);
  const [isHomeHovered, setIsHomeHovered] = useState(false);

  // Background Particles Animation
  useEffect(() => {
    const canvas = canvasRef.current;
    if (!canvas) return;
    const ctx = canvas.getContext("2d");
    let animationFrameId;

    let width = (canvas.width = window.innerWidth);
    let height = (canvas.height = window.innerHeight);

    const handleResize = () => {
      if (!canvas) return;
      width = canvas.width = window.innerWidth;
      height = canvas.height = window.innerHeight;
    };

    window.addEventListener("resize", handleResize);

    const particleCount = Math.min(Math.floor(width / 25), 60);
    const particles = [];

    for (let i = 0; i < particleCount; i++) {
      particles.push({
        x: Math.random() * width,
        y: Math.random() * height,
        vx: (Math.random() - 0.5) * 0.4,
        vy: (Math.random() - 0.5) * 0.4,
        radius: Math.random() * 2 + 1,
        alpha: Math.random() * 0.5 + 0.2,
      });
    }

    const render = () => {
      ctx.clearRect(0, 0, width, height);

      // Draw background grid lines subtle effect
      ctx.strokeStyle = "rgba(37, 99, 235, 0.03)";
      ctx.lineWidth = 1;
      const gridSize = 40;
      for (let x = 0; x < width; x += gridSize) {
        ctx.beginPath();
        ctx.moveTo(x, 0);
        ctx.lineTo(x, height);
        ctx.stroke();
      }
      for (let y = 0; y < height; y += gridSize) {
        ctx.beginPath();
        ctx.moveTo(0, y);
        ctx.lineTo(width, y);
        ctx.stroke();
      }

      // Update and draw particles
      particles.forEach((p, idx) => {
        p.x += p.vx;
        p.y += p.vy;

        if (p.x < 0) p.x = width;
        if (p.x > width) p.x = 0;
        if (p.y < 0) p.y = height;
        if (p.y > height) p.y = 0;

        ctx.beginPath();
        ctx.arc(p.x, p.y, p.radius, 0, Math.PI * 2);
        ctx.fillStyle = `rgba(59, 130, 246, ${p.alpha})`;
        ctx.shadowBlur = 8;
        ctx.shadowColor = "#3B82F6";
        ctx.fill();
        ctx.shadowBlur = 0;

        // Draw connections
        for (let j = idx + 1; j < particles.length; j++) {
          const p2 = particles[j];
          const dx = p.x - p2.x;
          const dy = p.y - p2.y;
          const dist = Math.sqrt(dx * dx + dy * dy);

          if (dist < 120) {
            ctx.beginPath();
            ctx.moveTo(p.x, p.y);
            ctx.lineTo(p2.x, p2.y);
            ctx.strokeStyle = `rgba(37, 99, 235, ${0.15 * (1 - dist / 120)})`;
            ctx.lineWidth = 0.8;
            ctx.stroke();
          }
        }
      });

      animationFrameId = requestAnimationFrame(render);
    };

    render();

    return () => {
      window.removeEventListener("resize", handleResize);
      cancelAnimationFrame(animationFrameId);
    };
  }, []);

  return (
    <div className="landing-root" style={{ minHeight: "100vh" }}>
      {/* Background Canvas Particles */}
      <canvas ref={canvasRef} className="landing-bg-canvas" />

      {/* Navigation Header */}
      <header className="landing-nav-header">
        <div className="landing-nav-container">
          <div className="landing-brand" onClick={() => router.push("/")} style={{ cursor: "pointer" }}>
            <div className="landing-logo-box">
              <Shield className="landing-logo-icon" size={28} />
            </div>
            <span className="landing-brand-text">NetShield-AI</span>
          </div>

          <nav className="landing-nav-menu">
            <a onClick={() => router.push("/")} className="landing-nav-link" style={{ cursor: "pointer" }}>Home</a>
            <a onClick={() => router.push("/about")} className="landing-nav-link active" style={{ cursor: "pointer" }}>About</a>
            <a onClick={() => router.push("/features")} className="landing-nav-link" style={{ cursor: "pointer" }}>Features</a>
          </nav>

          <div className="landing-nav-actions">
            <button 
              className="landing-btn landing-btn-secondary-nav"
              onClick={() => router.push("/login")}
            >
              Login
            </button>
            <button 
              className="landing-btn landing-btn-primary-nav"
              onClick={() => router.push("/register")}
            >
              Register
            </button>
          </div>
        </div>
      </header>

      {/* About Section View */}
      <section className="landing-about-section" style={{ paddingTop: "8rem", paddingBottom: "6rem" }}>
        <div className="landing-section-container">
          <div className="landing-about-card">
            <div className="landing-about-icon-wrapper">
              <Shield size={36} className="landing-about-icon" />
            </div>
            <h2 className="landing-about-title">About NetShield-AI</h2>
            <div className="landing-about-divider"></div>
            <p className="landing-about-text">
              NetShield-AI is an enterprise Security Operations Center platform developed to monitor network traffic, detect cyber attacks using AI, inspect packets, analyze threats, and provide secure role-based dashboards for Security Analysts and Security Administrators.
            </p>
          </div>

          {/* Icon-less Home Navigation Button outside card aligned to the left */}
          <div style={{ marginTop: "2.5rem", display: "flex", justifyContent: "flex-start" }}>
            <button
              type="button"
              className={`landing-btn landing-btn-secondary landing-home-btn ${isHomeHovered ? "hovered" : ""}`}
              onClick={() => router.push("/")}
              onMouseEnter={() => setIsHomeHovered(true)}
              onMouseLeave={() => setIsHomeHovered(false)}
              style={{ display: "inline-flex", alignItems: "center", justifyContent: "center" }}
            >
              <span>Home</span>
            </button>
          </div>
        </div>
      </section>

      {/* Footer */}
      <footer className="landing-footer">
        <div className="landing-footer-container">
          <div className="landing-footer-brand">
            <div className="landing-footer-logo-row">
              <Shield size={24} className="landing-footer-logo-icon" />
              <span className="landing-footer-title">NetShield-AI</span>
            </div>
            <p className="landing-footer-subtitle">Enterprise SOC Security Gateway</p>
          </div>
          <div className="landing-footer-copyright">
          </div>
        </div>
      </footer>
    </div>
  );
}
