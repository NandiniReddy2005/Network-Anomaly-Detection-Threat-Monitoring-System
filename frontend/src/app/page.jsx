"use client";
import React, { useState, useEffect, useRef } from "react";
import { useRouter } from "next/navigation";
import { 
  Shield, 
  Cpu, 
  Activity, 
  FileText, 
  Users, 
  ArrowRight, 
  Sparkles,
  Search,
  Zap,
  Home,
  Info
} from "lucide-react";

export default function LandingPage() {
  const router = useRouter();
  const canvasRef = useRef(null);
  const [isAboutHomeHovered, setIsAboutHomeHovered] = useState(false);

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

  const featureBadges = [
    "AI Intrusion Detection",
    "Packet Capture",
    "Traffic Analysis",
    "Security Analytics",
    "Role Based Access",
    "PostgreSQL Database",
  ];

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
    <div className="landing-root">
      {/* Background Canvas Particles */}
      <canvas ref={canvasRef} className="landing-bg-canvas" />

      {/* Navigation Bar */}
      <header className="landing-nav-header">
        <div className="landing-nav-container">
          <div className="landing-brand" onClick={() => router.push("/")}>
            <div className="landing-logo-box">
              <Shield className="landing-logo-icon" size={28} />
            </div>
            <span className="landing-brand-text">NetShield-AI</span>
          </div>

          <nav className="landing-nav-menu">
            <a href="#hero" className="landing-nav-link">Home</a>
            <a href="#about" className="landing-nav-link">About</a>
            <a href="#features" className="landing-nav-link">Features</a>
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

      {/* Hero Section */}
      <section id="hero" className="landing-hero-section">
        <div className="landing-hero-container">
          {/* Left Side */}
          <div className="landing-hero-left">
            <div className="landing-hero-badge">
              <Sparkles size={16} className="sparkle-icon" />
              <span>Enterprise SOC Security Gateway</span>
            </div>

            <div className="landing-hero-heading-group">
              <div className="landing-large-shield-wrapper">
                <Shield size={48} className="landing-large-shield-icon" />
              </div>
              <h1 className="landing-hero-title">NetShield-AI</h1>
            </div>

            <h2 className="landing-hero-subtitle">
              AI Powered Enterprise Network Intrusion Detection & Security Monitoring Platform
            </h2>

            <p className="landing-hero-description">
              NetShield-AI is an AI-powered Security Operations Center platform that provides packet inspection, intrusion detection, traffic analysis, role-based monitoring, threat visualization, and cybersecurity analytics for enterprise networks.
            </p>

            {/* Feature Badges */}
            <div className="landing-badges-grid">
              {featureBadges.map((badge, idx) => (
                <div key={idx} className="landing-badge-item">
                  <span className="landing-check-icon">✔</span>
                  <span className="landing-badge-text">{badge}</span>
                </div>
              ))}
            </div>

            {/* CTA Buttons */}
            <div className="landing-hero-buttons">
              <button 
                className="landing-btn landing-btn-primary"
                onClick={() => router.push("/login")}
              >
                <span>Login</span>
                <ArrowRight size={18} />
              </button>
              <button 
                className="landing-btn landing-btn-secondary"
                onClick={() => router.push("/register")}
              >
                <span>Register</span>
              </button>
            </div>
          </div>

          {/* Right Side: Modern Cybersecurity Illustration */}
          <div className="landing-hero-right">
            <div className="cyber-illustration-container">
              <div className="cyber-glow-bg"></div>
              
              {/* SVG Cyber Mesh & Shield */}
              <svg className="cyber-svg" viewBox="0 0 500 450" fill="none" xmlns="http://www.w3.org/2000/svg">
                <defs>
                  <linearGradient id="shieldGrad" x1="0%" y1="0%" x2="100%" y2="100%">
                    <stop offset="0%" stopColor="#3B82F6" stopOpacity="0.8" />
                    <stop offset="50%" stopColor="#2563EB" stopOpacity="0.6" />
                    <stop offset="100%" stopColor="#06B6D4" stopOpacity="0.9" />
                  </linearGradient>
                  <linearGradient id="cyberLineGrad" x1="0%" y1="0%" x2="100%" y2="0%">
                    <stop offset="0%" stopColor="#2563EB" stopOpacity="0.2" />
                    <stop offset="50%" stopColor="#3B82F6" stopOpacity="0.9" />
                    <stop offset="100%" stopColor="#06B6D4" stopOpacity="0.2" />
                  </linearGradient>
                  <filter id="neonGlow" x="-20%" y="-20%" width="140%" height="140%">
                    <feGaussianBlur stdDeviation="8" result="blur" />
                    <feComposite in="SourceGraphic" in2="blur" operator="over" />
                  </filter>
                </defs>

                {/* Hexagon & Grid Lines */}
                <path d="M250 40 L410 130 L410 310 L250 400 L90 310 L90 130 Z" stroke="rgba(59, 130, 246, 0.25)" strokeWidth="2" fill="rgba(15, 23, 42, 0.6)" />
                <path d="M250 65 L385 142 L385 298 L250 375 L115 298 L115 142 Z" stroke="rgba(37, 99, 235, 0.4)" strokeWidth="1.5" fill="rgba(17, 24, 39, 0.5)" />

                {/* Circuit Lines */}
                <line x1="90" y1="130" x2="250" y2="220" stroke="url(#cyberLineGrad)" strokeWidth="2" strokeDasharray="6 4" />
                <line x1="410" y1="130" x2="250" y2="220" stroke="url(#cyberLineGrad)" strokeWidth="2" strokeDasharray="6 4" />
                <line x1="250" y1="400" x2="250" y2="220" stroke="url(#cyberLineGrad)" strokeWidth="2" strokeDasharray="6 4" />

                {/* Central Shield Graphic */}
                <path 
                  d="M250 120 C290 120 330 135 330 180 C330 250 250 310 250 310 C250 310 170 250 170 180 C170 135 210 120 250 120 Z" 
                  fill="url(#shieldGrad)" 
                  stroke="#60A5FA" 
                  strokeWidth="3" 
                  filter="url(#neonGlow)"
                />

                {/* Inner AI Core */}
                <circle cx="250" cy="205" r="35" fill="rgba(15, 23, 42, 0.8)" stroke="#3B82F6" strokeWidth="2" />
                <path d="M240 195 L260 205 L240 215 Z" fill="#60A5FA" />
                <circle cx="250" cy="205" r="12" fill="none" stroke="#06B6D4" strokeWidth="2" strokeDasharray="3 3" />

                {/* Floating Node Circles */}
                <circle cx="120" cy="140" r="8" fill="#3B82F6" filter="url(#neonGlow)" />
                <circle cx="380" cy="140" r="8" fill="#06B6D4" filter="url(#neonGlow)" />
                <circle cx="250" cy="380" r="8" fill="#10B981" filter="url(#neonGlow)" />
                <circle cx="90" cy="310" r="6" fill="#3B82F6" />
                <circle cx="410" cy="310" r="6" fill="#3B82F6" />
              </svg>

              {/* Floating Glassmorphism Telemetry Cards */}
              <div className="cyber-card cyber-card-1">
                <div className="cyber-card-icon"><Zap size={18} color="#10B981" /></div>
                <div className="cyber-card-info">
                  <span className="cyber-card-title">AI IDS Engine</span>
                  <span className="cyber-card-status">ACTIVE • 99.8% ACCURACY</span>
                </div>
              </div>

              <div className="cyber-card cyber-card-2">
                <div className="cyber-card-icon"><Activity size={18} color="#3B82F6" /></div>
                <div className="cyber-card-info">
                  <span className="cyber-card-title">Live Packet Monitor</span>
                  <span className="cyber-card-status">INSPECTING TRAFFIC</span>
                </div>
              </div>

              <div className="cyber-card cyber-card-3">
                <div className="cyber-card-icon"><Shield size={18} color="#06B6D4" /></div>
                <div className="cyber-card-info">
                  <span className="cyber-card-title">SOC Firewall Gateway</span>
                  <span className="cyber-card-status">PROTECTED</span>
                </div>
              </div>
            </div>
          </div>
        </div>
      </section>

      {/* Features Section */}
      <section id="features" className="landing-features-section">
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

          {/* Features Section Footer Navigation */}
          <div style={{ marginTop: "3.5rem", display: "flex", flexDirection: "row", justifyContent: "flex-start", alignItems: "center", gap: "1.25rem" }}>
            <button
              type="button"
              className="landing-btn landing-btn-secondary"
              onClick={() => router.push("/#hero")}
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

      {/* About Section */}
      <section id="about" className="landing-about-section">
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
          <div style={{ marginTop: "2.5rem", display: "flex", justifyContent: "flex-start" }}>
            <button
              type="button"
              className={`landing-btn landing-btn-secondary landing-home-btn ${isAboutHomeHovered ? "hovered" : ""}`}
              onClick={() => router.push("/#hero")}
              onMouseEnter={() => setIsAboutHomeHovered(true)}
              onMouseLeave={() => setIsAboutHomeHovered(false)}
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