"use client";
import React, { useEffect, useRef } from "react";
import { useRouter } from "next/navigation";
import { 
  Shield, 
  Cpu, 
  Activity, 
  FileText, 
  Users, 
  Search
} from "lucide-react";

export default function FeaturesPage() {
  const router = useRouter();
  const canvasRef = useRef(null);

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

  const featureCards = [
    {
      id: 1,
      title: "AI Intrusion Detection",
      description: "Detect malicious traffic using AI-powered IDS models.",
      icon: Cpu,
    },
    {
      id: 2,
      title: "Packet Capture",
      description: "Capture and inspect packets in real time.",
      icon: Search,
    },
    {
      id: 3,
      title: "Traffic Analysis",
      description: "Visualize live network traffic and protocol statistics.",
      icon: Activity,
    },
    {
      id: 4,
      title: "Threat Monitoring",
      description: "Monitor cyber attacks and suspicious activities.",
      icon: Shield,
    },
    {
      id: 5,
      title: "Role Based Access",
      description: "Separate dashboards for Security Analysts and Security Administrators.",
      icon: Users,
    },
    {
      id: 6,
      title: "Audit Logs",
      description: "Maintain complete security event history and administrative actions.",
      icon: FileText,
    },
  ];

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
            <a onClick={() => router.push("/#about")} className="landing-nav-link" style={{ cursor: "pointer" }}>About</a>
            <a onClick={() => router.push("/features")} className="landing-nav-link active" style={{ cursor: "pointer" }}>Features</a>
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

      {/* Main Features Content Section */}
      <section className="landing-features-section" style={{ paddingTop: "8rem", paddingBottom: "6rem" }}>
        <div className="landing-section-container">
          <div className="landing-section-header">
            <span className="landing-section-tag">CAPABILITIES</span>
            <h2 className="landing-section-title">Platform Features</h2>
            <p className="landing-section-subtitle">
              Advanced AI security tools designed for deep network traffic inspection, automated intrusion detection, and active threat monitoring.
            </p>
          </div>

          <div className="landing-features-grid">
            {featureCards.map((card) => {
              const IconComp = card.icon;
              return (
                <div key={card.id} className="landing-feature-card">
                  <div className="landing-card-glow"></div>
                  <div className="landing-card-icon-box">
                    <IconComp size={24} className="landing-card-icon" />
                  </div>
                  <h3 className="landing-card-title">{card.title}</h3>
                  <p className="landing-card-description">{card.description}</p>
                </div>
              );
            })}
          </div>

          {/* Platform Features Footer Navigation */}
          <div style={{ marginTop: "4rem", display: "flex", flexDirection: "row", justifyContent: "flex-start", alignItems: "center", gap: "1.25rem" }}>
            <button
              type="button"
              className="landing-btn landing-btn-secondary"
              onClick={() => router.push("/")}
              style={{ display: "inline-flex", alignItems: "center", justifyContent: "center" }}
            >
              <span>Home</span>
            </button>

            <button
              type="button"
              className="landing-btn landing-btn-primary"
              onClick={() => router.push("/#about")}
              style={{ display: "inline-flex", alignItems: "center", justifyContent: "center" }}
            >
              <span>About</span>
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
