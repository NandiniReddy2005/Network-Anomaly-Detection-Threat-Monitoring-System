from fastapi import APIRouter, Depends, Query, Response
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.future import select
import os
import json
import math
from typing import Optional

try:
    from app.database import get_db
    from app.models import TrafficMetric, SecurityLog, TrustedDevice
except ImportError:
    from backend.app.database import get_db
    from backend.app.models import TrafficMetric, SecurityLog, TrustedDevice

router = APIRouter(prefix="/api/analyst", tags=["Security Analyst"])

@router.get("/network-monitoring")
async def get_network_monitoring(db: AsyncSession = Depends(get_db)):
    result_metrics = await db.execute(select(TrafficMetric))
    metrics = result_metrics.scalars().all()
    
    total_packets = sum(m.packet_count for m in metrics) if metrics else 84200000
    avg_anomaly = (sum(m.anomaly_score for m in metrics) / len(metrics)) if metrics else 12.4
    
    interfaces = [
        {
            "name": "eth0 (Primary Gateway)",
            "status": "UP",
            "rx_bandwidth": "1.2 Gbps",
            "tx_bandwidth": "850 Mbps",
            "packet_rate": f"{int(total_packets / 600):,} pps",
            "throughput": "2.05 Gbps",
            "error_count": 0,
            "dropped_packets": 12,
            "utilization": "68%",
            "last_updated": "Just now"
        },
        {
            "name": "eth1 (Internal LAN Subnet)",
            "status": "UP",
            "rx_bandwidth": "450 Mbps",
            "tx_bandwidth": "320 Mbps",
            "packet_rate": f"{int(total_packets / 1800):,} pps",
            "throughput": "770 Mbps",
            "error_count": 0,
            "dropped_packets": 0,
            "utilization": "32%",
            "last_updated": "Just now"
        },
        {
            "name": "wlan0 (Wireless Sensor Mesh)",
            "status": "UP",
            "rx_bandwidth": "120 Mbps",
            "tx_bandwidth": "45 Mbps",
            "packet_rate": f"{int(total_packets / 4500):,} pps",
            "throughput": "165 Mbps",
            "error_count": 1,
            "dropped_packets": 3,
            "utilization": "15%",
            "last_updated": "Just now"
        },
        {
            "name": "tun0 (Encrypted SOC Tunnel)",
            "status": "UP",
            "rx_bandwidth": "85 Mbps",
            "tx_bandwidth": "80 Mbps",
            "packet_rate": "8,400 pps",
            "throughput": "165 Mbps",
            "error_count": 0,
            "dropped_packets": 0,
            "utilization": "10%",
            "last_updated": "Just now"
        }
    ]

    summary = {
        "active_interfaces": len(interfaces),
        "rx_bandwidth": "1.855 Gbps",
        "tx_bandwidth": "1.295 Gbps",
        "packet_rate": f"{int(total_packets / 400):,} pps",
        "throughput": "3.15 Gbps",
        "error_count": 1,
        "dropped_packets": 15,
        "utilization": "41.2%",
        "last_updated": "Just now"
    }

    return {
        "status": "success",
        "data": {
            "interfaces": interfaces,
            "summary": summary
        }
    }

@router.get("/packet-capture")
async def get_packet_capture(
    search: Optional[str] = None,
    protocol: Optional[str] = None,
    page: int = 1,
    limit: int = 10,
    sort_by: Optional[str] = "timestamp",
    sort_order: Optional[str] = "desc"
):
    # Sample raw packet capture stream
    raw_packets = [
        {"id": 1, "timestamp": "19:42:01.102", "source_ip": "192.168.1.105", "destination_ip": "10.0.0.5", "src_port": 54210, "dst_port": 443, "protocol": "TCP", "packet_size": "1,420 B", "threat_score": 15, "detection_status": "Normal"},
        {"id": 2, "timestamp": "19:42:01.085", "source_ip": "198.51.100.42", "destination_ip": "192.168.1.1", "src_port": 38920, "dst_port": 80, "protocol": "HTTP", "packet_size": "840 B", "threat_score": 88, "detection_status": "Flagged"},
        {"id": 3, "timestamp": "19:42:00.950", "source_ip": "10.0.0.12", "destination_ip": "8.8.8.8", "src_port": 61200, "dst_port": 53, "protocol": "UDP", "packet_size": "128 B", "threat_score": 5, "detection_status": "Normal"},
        {"id": 4, "timestamp": "19:42:00.812", "source_ip": "192.168.1.50", "destination_ip": "10.0.0.25", "src_port": 44300, "dst_port": 22, "protocol": "SSH", "packet_size": "512 B", "threat_score": 35, "detection_status": "Normal"},
        {"id": 5, "timestamp": "19:42:00.640", "source_ip": "203.0.113.99", "destination_ip": "192.168.1.100", "src_port": 12044, "dst_port": 8080, "protocol": "TCP", "packet_size": "1,500 B", "threat_score": 92, "detection_status": "Blocked"},
        {"id": 6, "timestamp": "19:42:00.420", "source_ip": "192.168.1.105", "destination_ip": "10.0.0.5", "src_port": 54212, "dst_port": 443, "protocol": "TCP", "packet_size": "1,420 B", "threat_score": 12, "detection_status": "Normal"},
        {"id": 7, "timestamp": "19:42:00.210", "source_ip": "172.16.0.4", "destination_ip": "10.0.0.50", "src_port": 5001, "dst_port": 5001, "protocol": "UDP", "packet_size": "2,048 B", "threat_score": 78, "detection_status": "Warning"},
        {"id": 8, "timestamp": "19:41:59.980", "source_ip": "192.168.1.110", "destination_ip": "1.1.1.1", "src_port": 58912, "dst_port": 53, "protocol": "DNS", "packet_size": "96 B", "threat_score": 8, "detection_status": "Normal"},
        {"id": 9, "timestamp": "19:41:59.750", "source_ip": "198.51.100.88", "destination_ip": "192.168.1.1", "src_port": 40102, "dst_port": 80, "protocol": "HTTP", "packet_size": "1,024 B", "threat_score": 95, "detection_status": "Blocked"},
        {"id": 10, "timestamp": "19:41:59.500", "source_ip": "10.0.0.15", "destination_ip": "10.0.0.5", "src_port": 33890, "dst_port": 3389, "protocol": "RDP", "packet_size": "2,560 B", "threat_score": 22, "detection_status": "Normal"},
        {"id": 11, "timestamp": "19:41:59.200", "source_ip": "192.168.1.120", "destination_ip": "10.0.0.5", "src_port": 49200, "dst_port": 443, "protocol": "TCP", "packet_size": "1,200 B", "threat_score": 10, "detection_status": "Normal"},
        {"id": 12, "timestamp": "19:41:58.900", "source_ip": "198.51.100.90", "destination_ip": "192.168.1.1", "src_port": 31000, "dst_port": 443, "protocol": "TCP", "packet_size": "1,440 B", "threat_score": 85, "detection_status": "Flagged"}
    ]

    filtered = raw_packets
    if search:
        q = search.toLowerCase() if hasattr(search, "toLowerCase") else str(search).lower()
        filtered = [
            p for p in filtered
            if q in p["source_ip"].lower()
            or q in p["destination_ip"].lower()
            or q in p["protocol"].lower()
            or q in p["detection_status"].lower()
            or q in str(p["src_port"])
            or q in str(p["dst_port"])
        ]

    if protocol and protocol.upper() != "ALL":
        filtered = [p for p in filtered if p["protocol"].upper() == protocol.upper()]

    total_count = len(filtered)
    total_pages = max(1, math.ceil(total_count / limit))
    start_idx = (page - 1) * limit
    end_idx = start_idx + limit
    paginated_data = filtered[start_idx:end_idx]

    return {
        "status": "success",
        "count": total_count,
        "page": page,
        "total_pages": total_pages,
        "limit": limit,
        "data": paginated_data
    }

@router.get("/traffic-analysis")
async def get_traffic_analysis(db: AsyncSession = Depends(get_db)):
    result_metrics = await db.execute(select(TrafficMetric))
    metrics = result_metrics.scalars().all()

    protocol_distribution = [
        {"name": "TCP", "value": 62, "percentage": "62%"},
        {"name": "UDP", "value": 25, "percentage": "25%"},
        {"name": "ICMP", "value": 8, "percentage": "8%"},
        {"name": "HTTP/S", "value": 5, "percentage": "5%"}
    ]

    top_source_ips = [
        {"ip": "192.168.1.105", "packets": "1,420,500", "percentage": "28.4%", "risk": "Low"},
        {"ip": "198.51.100.42", "packets": "980,120", "percentage": "19.6%", "risk": "High"},
        {"ip": "10.0.0.12", "packets": "750,400", "percentage": "15.0%", "risk": "Low"},
        {"ip": "203.0.113.99", "packets": "620,000", "percentage": "12.4%", "risk": "Critical"},
        {"ip": "172.16.0.4", "packets": "410,200", "percentage": "8.2%", "risk": "Medium"}
    ]

    top_destination_ips = [
        {"ip": "10.0.0.5 (Primary DB)", "packets": "2,100,000", "percentage": "42.0%"},
        {"ip": "192.168.1.1 (Gateway)", "packets": "1,540,000", "percentage": "30.8%"},
        {"ip": "10.0.0.25 (SSH Server)", "packets": "680,000", "percentage": "13.6%"},
        {"ip": "8.8.8.8 (External DNS)", "packets": "420,000", "percentage": "8.4%"}
    ]

    timeline_chart = [
        {"time": "00:00", "volume": 45, "throughput": "1.2 Gbps"},
        {"time": "04:00", "volume": 30, "throughput": "0.8 Gbps"},
        {"time": "08:00", "volume": 85, "throughput": "2.8 Gbps"},
        {"time": "12:00", "volume": 92, "throughput": "3.1 Gbps"},
        {"time": "16:00", "volume": 78, "throughput": "2.4 Gbps"},
        {"time": "20:00", "volume": 65, "throughput": "1.9 Gbps"}
    ]

    stats = {
        "incoming_traffic": "1.85 Gbps",
        "outgoing_traffic": "1.21 Gbps",
        "traffic_volume": "42.8 TB / 24h",
        "active_sessions": "14,892",
        "suspicious_traffic_percentage": "4.2%",
        "peak_bandwidth": "3.4 Gbps",
        "protocol_distribution": protocol_distribution,
        "top_source_ips": top_source_ips,
        "top_destination_ips": top_destination_ips,
        "timeline_chart": timeline_chart
    }

    return {
        "status": "success",
        "data": stats
    }

@router.get("/reports")
async def get_analyst_reports(
    search: Optional[str] = None,
    report_type: Optional[str] = None,
    page: int = 1,
    limit: int = 10
):
    reports = [
        {
            "id": "REP-2026-001",
            "name": "ISO-27001 Security Posture Assessment",
            "type": "Compliance Audit",
            "generated_time": "2026-07-27 18:30 UTC",
            "generated_by": "analyst@gmail.com",
            "status": "Completed"
        },
        {
            "id": "REP-2026-002",
            "name": "Deep Packet Inspection & Payload Analysis",
            "type": "Technical Audit",
            "generated_time": "2026-07-27 15:10 UTC",
            "generated_by": "analyst@gmail.com",
            "status": "Completed"
        },
        {
            "id": "REP-2026-003",
            "name": "DDoS Volumetric Anomaly Mitigation Log",
            "type": "Incident Summary",
            "generated_time": "2026-07-27 11:45 UTC",
            "generated_by": "sec_admin@gmail.com",
            "status": "Completed"
        },
        {
            "id": "REP-2026-004",
            "name": "SOC2 Type II Protocol & Subnet Review",
            "type": "Compliance Audit",
            "generated_time": "2026-07-26 22:00 UTC",
            "generated_by": "analyst@gmail.com",
            "status": "Completed"
        }
    ]

    filtered = reports
    if search:
        q = search.lower()
        filtered = [
            r for r in filtered
            if q in r["name"].lower()
            or q in r["type"].lower()
            or q in r["generated_by"].lower()
            or q in r["id"].lower()
        ]

    if report_type and report_type.upper() != "ALL":
        filtered = [r for r in filtered if r["type"].lower() == report_type.lower()]

    total_count = len(filtered)
    total_pages = max(1, math.ceil(total_count / limit))
    start_idx = (page - 1) * limit
    end_idx = start_idx + limit
    paginated = filtered[start_idx:end_idx]

    return {
        "status": "success",
        "count": total_count,
        "page": page,
        "total_pages": total_pages,
        "limit": limit,
        "data": paginated
    }

@router.get("/reports/pdf")
async def download_analyst_pdf_report():
    pdf_content = b"%PDF-1.4 NetShield-AI Security Analyst Technical Audit & Telemetry Report\n1 0 obj << /Type /Catalog /Pages 2 0 R >> endobj\ntrailer << /Root 1 0 R >> %%EOF"
    return Response(
        content=pdf_content,
        media_type="application/pdf",
        headers={"Content-Disposition": "attachment; filename=netshield_analyst_report.pdf"}
    )

@router.get("/reports/csv")
async def download_analyst_csv_report():
    csv_content = "Report_ID,Report_Name,Report_Type,Generated_Time,Generated_By,Status\nREP-2026-001,ISO-27001 Security Posture Assessment,Compliance Audit,2026-07-27 18:30 UTC,analyst@gmail.com,Completed\nREP-2026-002,Deep Packet Inspection,Technical Audit,2026-07-27 15:10 UTC,analyst@gmail.com,Completed\n".encode("utf-8")
    return Response(
        content=csv_content,
        media_type="text/csv",
        headers={"Content-Disposition": "attachment; filename=netshield_analyst_report.csv"}
    )

@router.get("/analytics")
async def get_analyst_analytics(db: AsyncSession = Depends(get_db)):
    result_sec = await db.execute(select(SecurityLog))
    sec_logs = result_sec.scalars().all()
    
    analytics_data = {
        "daily_attacks": 142,
        "weekly_attacks": 890,
        "monthly_attacks": 3420,
        "detection_accuracy": "99.4%",
        "risk_score": "Medium (42/100)",
        "security_health_summary": "Optimal Heuristics Active",
        "threat_trend_chart": [
            {"day": "Mon", "attacks": 110, "score": 35},
            {"day": "Tue", "attacks": 145, "score": 42},
            {"day": "Wed", "attacks": 95, "score": 28},
            {"day": "Thu", "attacks": 180, "score": 65},
            {"day": "Fri", "attacks": 142, "score": 42},
            {"day": "Sat", "attacks": 80, "score": 20},
            {"day": "Sun", "attacks": 65, "score": 15}
        ],
        "top_attack_categories": [
            {"category": "DDoS Volumetric", "count": 48, "percentage": "33.8%"},
            {"category": "ARP Spoofing", "count": 32, "percentage": "22.5%"},
            {"category": "SYN Flood", "count": 24, "percentage": "16.9%"},
            {"category": "DNS Tunneling", "count": 18, "percentage": "12.6%"},
            {"category": "Port Scanning", "count": 20, "percentage": "14.1%"}
        ],
        "top_targeted_assets": [
            {"asset": "Gateway Firewall eth0", "ip": "192.168.1.1", "threats_intercepted": 85},
            {"asset": "Primary DB Cluster", "ip": "10.0.0.5", "threats_intercepted": 42},
            {"asset": "Analyst Workstation Node", "ip": "192.168.1.100", "threats_intercepted": 15}
        ],
        "detection_statistics": {
            "total_scanned_packets": "84,200,000",
            "threats_blocked": 1420,
            "false_positives": 3,
            "neural_confidence": "98.8%"
        }
    }

    return {
        "status": "success",
        "data": analytics_data
    }
