"""
Shared in-memory state store for NetShield-AI SIEM.
Houses INCIDENT_QUEUE and NOTIFICATION_STORE to prevent circular imports between routers.
"""

from typing import List, Dict, Any

# Initial Seed Incidents Queue
INITIAL_INCIDENTS: List[Dict[str, Any]] = [
    {
        "alert_id": "ALT-1082",
        "timestamp": "2026-08-22 09:47:00 UTC",
        "source_ip": "185.220.101.42",
        "target_ip": "10.0.9.47",
        "threat_vector": "UNSW-NB15 DoS / SYN Flood (Abuse Score: 96%)",
        "severity": "CRITICAL",
        "status": "Active",
        "detection_source": "UNSW-NB15 Engine + AbuseIPDB API",
        "abuse_score": 96,
        "model_confidence": 98.4,
        "details": "High-volume TCP SYN flood detected targeting core firewall eth0. Threat score 96/100.",
        "analyst_notes": "",
        "packet_size": "1,420 Bytes",
        "protocol": "TCP (SYN-ACK)",
        "dest_port": "8080 / HTTP",
        "isp": "Tor Exit Router Network",
        "country": "RO",
        "total_reports": 142
    },
    {
        "alert_id": "ALT-1083",
        "timestamp": "2026-08-22 09:35:12 UTC",
        "source_ip": "198.51.100.14",
        "target_ip": "10.0.9.50",
        "threat_vector": "AbuseIPDB Known Malicious Tor Exit Node (Abuse Score: 88%)",
        "severity": "HIGH",
        "status": "Active",
        "detection_source": "AbuseIPDB Threat Intel",
        "abuse_score": 88,
        "model_confidence": 92.1,
        "details": "Inbound connection request initiated from known malicious Tor exit relay.",
        "analyst_notes": "",
        "packet_size": "820 Bytes",
        "protocol": "TCP (SYN)",
        "dest_port": "22 / SSH",
        "isp": "DigitalOcean LLC",
        "country": "US",
        "total_reports": 88
    },
    {
        "alert_id": "ALT-1084",
        "timestamp": "2026-08-22 09:12:45 UTC",
        "source_ip": "192.168.1.180",
        "target_ip": "10.0.9.47",
        "threat_vector": "CICIDS2017 PortScan / Reconnaissance",
        "severity": "MEDIUM",
        "status": "Contained",
        "detection_source": "CICIDS2017 Neural Classifier",
        "abuse_score": 35,
        "model_confidence": 88.5,
        "details": "Internal subnet port sweep detected targeting ports 1-1024.",
        "analyst_notes": "Isolated IP on gateway interface.",
        "packet_size": "64 Bytes",
        "protocol": "TCP (SYN)",
        "dest_port": "1-1024 / Multi",
        "isp": "Internal LAN Subnet",
        "country": "LOCAL",
        "total_reports": 0
    },
    {
        "alert_id": "ALT-1085",
        "timestamp": "2026-08-22 08:50:30 UTC",
        "source_ip": "203.0.113.88",
        "target_ip": "10.0.9.12",
        "threat_vector": "Web Attack - SQL Injection & XSS Payload",
        "severity": "CRITICAL",
        "status": "Investigating",
        "detection_source": "Dual Engine (UNSW + CICIDS2017)",
        "abuse_score": 92,
        "model_confidence": 99.1,
        "details": "Remote code execution attempt via SQLi payload in HTTP GET parameters.",
        "analyst_notes": "Inspected payload structure; matches SQL injection pattern.",
        "packet_size": "2,150 Bytes",
        "protocol": "HTTP (POST)",
        "dest_port": "443 / HTTPS",
        "isp": "Cloudflare Network",
        "country": "DE",
        "total_reports": 110
    }
]

INCIDENT_QUEUE: List[Dict[str, Any]] = [dict(item) for item in INITIAL_INCIDENTS]

# Initial Seed Notifications Store for Security Analysts
INITIAL_ANALYST_NOTIFICATIONS: List[Dict[str, Any]] = [
    {
        "id": "NOTIF-201",
        "alert_id": "ALT-1082",
        "module": "incidents",
        "route": "/analyst/incidents",
        "severity": "CRITICAL",
        "role_target": "analyst",
        "title": "🚨 CRITICAL THREAT: New DoS Attack Detected",
        "summary": "UNSW-NB15 ML Engine flagged volumetric SYN flood targeting firewall eth0 from 185.220.101.42.",
        "source_ip": "185.220.101.42",
        "target_ip": "10.0.9.47",
        "timestamp": "2 mins ago",
        "raw_utc": "2026-08-22 09:47:00 UTC",
        "is_read": False,
        "status": "Active"
    },
    {
        "id": "NOTIF-202",
        "alert_id": "ALT-1083",
        "module": "network",
        "route": "/analyst/network-monitoring",
        "severity": "HIGH",
        "role_target": "analyst",
        "title": "⚠️ BANDWIDTH SURGE: Interface eth0 Exceeded Threshold",
        "summary": "Network Monitoring Engine detected interface throughput exceeding 95% threshold (1.2 Gbps peak).",
        "source_ip": "10.0.9.47",
        "target_ip": "10.0.9.1",
        "timestamp": "12 mins ago",
        "raw_utc": "2026-08-22 09:35:12 UTC",
        "is_read": False,
        "status": "Active"
    },
    {
        "id": "NOTIF-203",
        "alert_id": "ALT-1084",
        "module": "packets",
        "route": "/analyst/packet-capture",
        "severity": "CRITICAL",
        "role_target": "analyst",
        "title": "⚡ PROMISCUOUS MODE: Raw Payload Stream Captured",
        "summary": "Packet Capture Engine intercepted suspicious raw binary payload stream on Port 8080.",
        "source_ip": "198.51.100.14",
        "target_ip": "10.0.9.50",
        "timestamp": "25 mins ago",
        "raw_utc": "2026-08-22 09:10:00 UTC",
        "is_read": False,
        "status": "Active"
    },
    {
        "id": "NOTIF-204",
        "alert_id": "ALT-1085",
        "module": "traffic",
        "route": "/analyst/traffic-analysis",
        "severity": "HIGH",
        "role_target": "analyst",
        "title": "🌐 ANOMALOUS SUBNET FLOW: High Frequency UDP Broadcast",
        "summary": "Traffic Analysis Suite flagged anomalous burst rate of 4,500 pkts/sec from 203.0.113.88.",
        "source_ip": "203.0.113.88",
        "target_ip": "10.0.9.255",
        "timestamp": "40 mins ago",
        "raw_utc": "2026-08-22 08:45:00 UTC",
        "is_read": False,
        "status": "Active"
    }
]

# Initial Seed Notifications Store for Security Administrators
INITIAL_ADMIN_NOTIFICATIONS: List[Dict[str, Any]] = [
    {
        "id": "NOTIF-ADMIN-301",
        "alert_id": "ALT-ADM-101",
        "module": "user-management",
        "route": "/admin/user-management",
        "severity": "INFORMATIONAL",
        "role_target": "admin",
        "title": "🛡️ SECURITY GOVERNANCE: System RBAC Policy Updated",
        "summary": "Administrative role privileges updated for user roster. 7 Security Administrators and 6 Security Analysts active.",
        "source_ip": "192.168.1.50",
        "target_ip": "PostgreSQL Core DB",
        "timestamp": "5 mins ago",
        "raw_utc": "2026-09-15 10:45:00 UTC",
        "is_read": False,
        "status": "Active"
    },
    {
        "id": "NOTIF-ADMIN-302",
        "alert_id": "ALT-ADM-102",
        "module": "audit-logs",
        "route": "/admin/audit-logs",
        "severity": "HIGH",
        "role_target": "admin",
        "title": "⚙️ FIREWALL THRESHOLD: Edge WAF Rate Limit Adjustment",
        "summary": "Security Administrator modified global firewall rate limit threshold to 5,000 req/min.",
        "source_ip": "192.168.1.55",
        "target_ip": "WAF Rules Engine",
        "timestamp": "18 mins ago",
        "raw_utc": "2026-09-15 10:32:15 UTC",
        "is_read": False,
        "status": "Active"
    },
    {
        "id": "NOTIF-ADMIN-303",
        "alert_id": "ALT-ADM-103",
        "module": "audit-logs",
        "route": "/admin/audit-logs",
        "severity": "INFORMATIONAL",
        "role_target": "admin",
        "title": "📋 AUDIT LEDGER ALERT: Immutable PostgreSQL Trail Export",
        "summary": "Executive compliance audit package exported for ISO-27001 review by compliance_admin@netshield.ai.",
        "source_ip": "192.168.1.60",
        "target_ip": "PostgreSQL Storage",
        "timestamp": "32 mins ago",
        "raw_utc": "2026-09-15 10:18:40 UTC",
        "is_read": False,
        "status": "Active"
    },
    {
        "id": "NOTIF-ADMIN-304",
        "alert_id": "ALT-ADM-104",
        "module": "user-management",
        "route": "/admin/user-management",
        "severity": "INFORMATIONAL",
        "role_target": "admin",
        "title": "🔑 IDENTITY & ACCESS: Security Analyst Account Provisioned",
        "summary": "New Security Analyst account provisioning verified and logged to PostgreSQL RBAC table.",
        "source_ip": "192.168.1.70",
        "target_ip": "Auth Gateway",
        "timestamp": "45 mins ago",
        "raw_utc": "2026-09-15 10:05:00 UTC",
        "is_read": False,
        "status": "Active"
    }
]

# Standardized Role-Segregated Stores
INITIAL_NOTIFICATIONS: List[Dict[str, Any]] = INITIAL_ANALYST_NOTIFICATIONS
ANALYST_NOTIFICATION_STORE: List[Dict[str, Any]] = [dict(item) for item in INITIAL_ANALYST_NOTIFICATIONS]
ADMIN_NOTIFICATION_STORE: List[Dict[str, Any]] = [dict(item) for item in INITIAL_ADMIN_NOTIFICATIONS]
NOTIFICATION_STORE: List[Dict[str, Any]] = ANALYST_NOTIFICATION_STORE

def sync_notification_status(alert_id: str, source_ip: str, new_status: str, is_read: bool = True):
    """
    Synchronizes incident status changes into both role notification stores.
    """
    for store in (ANALYST_NOTIFICATION_STORE, ADMIN_NOTIFICATION_STORE):
        for n in store:
            if (alert_id and str(n.get("alert_id")).upper() == str(alert_id).upper()) or (source_ip and n.get("source_ip") == source_ip):
                n["status"] = new_status
                if is_read:
                    n["is_read"] = True
                    n["isRead"] = True

def dispatch_threat_notification(
    module: str,
    source_ip: str,
    target_ip: str = "10.0.9.47",
    severity: str = "CRITICAL",
    title: str = "🚨 THREAT DETECTED",
    summary: str = "Malicious network activity flagged.",
    route: str = "/analyst/traffic-analysis",
    alert_id: str = None,
    target_role: str = "analyst"
) -> dict:
    """
    Automated Cross-Section Threat Notification Dispatcher.
    Pushes a push-style notification payload into the specified role notification store.
    """
    target_store = ADMIN_NOTIFICATION_STORE if target_role == "admin" else ANALYST_NOTIFICATION_STORE

    for notif in target_store:
        if notif.get("source_ip") == source_ip and notif.get("title") == title:
            return notif

    if not alert_id:
        alert_id = f"ALT-{1080 + len(target_store) + 1}"

    notif_id = f"NOTIF-ROLE-{300 if target_role == 'admin' else 200}+{len(target_store) + 1}"

    new_notif = {
        "id": notif_id,
        "alert_id": alert_id,
        "module": module,
        "route": route,
        "severity": severity.upper(),
        "role_target": target_role,
        "title": title,
        "summary": summary,
        "source_ip": source_ip,
        "target_ip": target_ip,
        "timestamp": "Just now",
        "raw_utc": datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC") if 'datetime' in globals() else "2026-08-30 UTC",
        "is_read": False,
        "status": "Active"
    }

    target_store.insert(0, new_notif)
    return new_notif
