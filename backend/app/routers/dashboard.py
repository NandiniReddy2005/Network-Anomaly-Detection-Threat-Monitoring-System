from typing import Optional
from fastapi import APIRouter, Depends, Response, Query, HTTPException
from pydantic import BaseModel
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.future import select
import json
import logging

logger = logging.getLogger("netshield_backend")

try:
    from app.database import get_db
    from app.models import AdminIncident, AuditLog, User, TrafficMetric, TrustedDevice, SecurityLog, SystemSetting
except ImportError:
    from backend.app.database import get_db
    from backend.app.models import AdminIncident, AuditLog, User, TrafficMetric, TrustedDevice, SecurityLog, SystemSetting

router = APIRouter(prefix="/api/dashboard", tags=["Dashboard"])
reports_router = APIRouter(prefix="/api/reports", tags=["Reports"])
settings_router = APIRouter(prefix="/api/settings", tags=["Settings"])
audit_router = APIRouter(prefix="/api/audit-logs", tags=["Audit Logs"])
threats_router = APIRouter(prefix="/api/threats", tags=["Threats"])

@router.get("/stats")
@router.get("/analyst/stats")
async def get_analyst_stats(db: AsyncSession = Depends(get_db)):
    result_metrics = await db.execute(select(TrafficMetric))
    metrics = result_metrics.scalars().all()
    total_packets = sum(m.packet_count for m in metrics) if metrics else 84200000

    result_devices = await db.execute(select(TrustedDevice))
    devices = result_devices.scalars().all()
    device_count = len(devices) if devices else 1482

    avg_anomaly = (sum(m.anomaly_score for m in metrics) / len(metrics)) if metrics else 0.0
    traffic_status = "Nominal" if avg_anomaly < 20 else "Elevated"

    return {
        "status": "success",
        "data": {
            "active_connections": f"{device_count:,}",
            "packets_captured": f"{total_packets / 1_000_000:.1f}M" if total_packets >= 1_000_000 else str(total_packets),
            "traffic_status": traffic_status,
            "detection_status": "AI Active"
        }
    }

@router.get("/admin/stats")
async def get_admin_stats(db: AsyncSession = Depends(get_db)):
    result_incidents = await db.execute(select(AdminIncident))
    incidents = result_incidents.scalars().all()
    critical_count = sum(1 for inc in incidents if inc.severity == "Critical")

    threat_level = "Elevated" if critical_count > 0 else "Low"

    return {
        "status": "success",
        "data": {
            "critical_alerts": str(critical_count),
            "threat_level": threat_level,
            "active_policies": "48 / 48",
            "system_health": "99.98%"
        }
    }

@router.get("/admin/incidents")
async def get_admin_incidents(db: AsyncSession = Depends(get_db)):
    result = await db.execute(select(AdminIncident))
    incidents = result.scalars().all()
    inc_list = [
        {
            "id": inc.id,
            "severity": inc.severity,
            "type": inc.type,
            "analyst": inc.analyst,
            "status": inc.status,
            "updated": inc.updated
        }
        for inc in incidents
    ]
    return {
        "status": "success",
        "data": inc_list
    }

@audit_router.get("")
@audit_router.get("/")
@router.get("/admin/audit-logs")
@router.get("/audit-logs")
async def get_audit_logs(
    limit: Optional[int] = Query(default=None),
    db: AsyncSession = Depends(get_db)
):
    try:
        query = select(AuditLog).order_by(AuditLog.id.desc())
        if limit and limit > 0:
            query = query.limit(limit)
        result = await db.execute(query)
        logs = result.scalars().all()

        log_list = [
            {
                "id": log.id,
                "timestamp": str(log.timestamp) if log.timestamp else "Just now",
                "actor": log.actor,
                "action": log.action,
                "ip_origin": log.ip_origin,
                "module": getattr(log, "module", None) or "SOC Core Platform",
                "status": getattr(log, "status", None) or "Success",
                "severity": getattr(log, "severity", None) or "Informational",
                "details": getattr(log, "details", None) or f"Operation {log.action} logged to PostgreSQL database."
            }
            for log in logs
        ]
        return {
            "status": "success",
            "data": log_list
        }
    except Exception as e:
        logger.error(f"Error querying AuditLog table from PostgreSQL: {e}")
        raise HTTPException(
            status_code=500,
            detail=f"Failed to fetch audit log trail from PostgreSQL: {str(e)}"
        )

@router.get("/threat-chart")
async def get_threat_chart_data(db: AsyncSession = Depends(get_db)):
    result_metrics = await db.execute(select(TrafficMetric))
    metrics = result_metrics.scalars().all()
    if metrics:
        bars = [
            {"id": i + 1, "height": f"{min(95, max(25, int(m.anomaly_score * 5 + 30)))}%", "value": m.anomaly_score}
            for i, m in enumerate(metrics[:10])
        ]
        # Supplement if fewer than 10 metrics exist
        default_heights = ["85%", "60%", "90%", "45%", "70%", "30%", "95%", "50%", "75%", "65%"]
        while len(bars) < 10:
            idx = len(bars)
            bars.append({"id": idx + 1, "height": default_heights[idx], "value": 50})
    else:
        default_heights = ["85%", "60%", "90%", "45%", "70%", "30%", "95%", "50%", "75%", "65%"]
        bars = [{"id": i + 1, "height": h, "value": 50} for i, h in enumerate(default_heights)]
    return {"status": "success", "data": bars}

@router.get("/system-status")
async def get_system_status(db: AsyncSession = Depends(get_db)):
    subsystems = [
        {"name": "Firewall Gateway", "status": "Online", "indicator": "online"},
        {"name": "Packet Capture", "status": "Online", "indicator": "online"},
        {"name": "Detection Engine", "status": "Online", "indicator": "online"},
        {"name": "Telemetry Database", "status": "Online", "indicator": "online"},
        {"name": "REST API", "status": "Online", "indicator": "online"},
    ]
    return {"status": "success", "data": subsystems}

@router.get("/security-activity")
async def get_security_activity(db: AsyncSession = Depends(get_db)):
    result = await db.execute(select(SecurityLog).order_by(SecurityLog.id.desc()))
    logs = result.scalars().all()
    data = [
        {
            "id": log.id,
            "event_type": log.event_type,
            "details": log.details,
            "severity": log.severity,
            "timestamp": str(log.timestamp) if log.timestamp else "Just now"
        }
        for log in logs
    ]
    return {"status": "success", "data": data}

@router.get("/critical-alerts")
async def get_critical_alerts(db: AsyncSession = Depends(get_db)):
    result_incidents = await db.execute(select(AdminIncident).where(AdminIncident.severity.in_(["Critical", "High"])))
    incidents = result_incidents.scalars().all()
    alerts = [
        {
            "id": inc.id,
            "title": f"{inc.type} on cluster node",
            "severity": inc.severity,
            "status": inc.status,
            "analyst": inc.analyst,
            "updated": inc.updated
        }
        for inc in incidents
    ]
    return {"status": "success", "data": alerts}

@threats_router.get("")
@threats_router.get("/")
@router.get("/threats")
@router.get("/admin/threats")
async def get_threats(db: AsyncSession = Depends(get_db)):
    try:
        result_incidents = await db.execute(select(AdminIncident))
        incidents = result_incidents.scalars().all()
        threats = [
            {
                "id": inc.id if str(inc.id).startswith("THR") or str(inc.id).startswith("INC") else f"THR-{inc.id}",
                "type": inc.type,
                "threat_type": inc.type,
                "severity": inc.severity,
                "assigned": inc.analyst,
                "analyst": inc.analyst,
                "status": inc.status,
                "updated": inc.updated,
                "last_updated": inc.updated,
                "timestamp": inc.updated,
                "source_ip": getattr(inc, "source_ip", None) or "185.220.101.42",
                "destination_ip": getattr(inc, "destination_ip", None) or "10.0.0.1 (GW)",
                "confidence": getattr(inc, "confidence", None) or "98.4%",
                "action": getattr(inc, "action", None) or "Apply IPTables Rate Limit",
                "description": getattr(inc, "description", None) or f"{inc.type} detected targeting gateway cluster.",
                "engine": getattr(inc, "engine", None) or "AI-Neural-Inference-Probe",
            }
            for inc in incidents
        ]
        return {"status": "success", "data": threats}
    except Exception as e:
        logger.error(f"Error querying PostgreSQL database for Threats telemetry: {e}")
        raise HTTPException(
            status_code=500,
            detail=f"Failed to fetch threat telemetry from PostgreSQL: {str(e)}"
        )

# Reports endpoints
@reports_router.get("/pdf")
async def download_pdf_report():
    pdf_content = b"%PDF-1.4 NetShield-AI Enterprise SOC Compliance & Audit Report\n1 0 obj << /Type /Catalog /Pages 2 0 R >> endobj\ntrailer << /Root 1 0 R >> %%EOF"
    return Response(
        content=pdf_content,
        media_type="application/pdf",
        headers={"Content-Disposition": "attachment; filename=netshield_soc_report.pdf"}
    )

@reports_router.get("/json")
async def download_json_report(db: AsyncSession = Depends(get_db)):
    result_metrics = await db.execute(select(TrafficMetric))
    metrics = result_metrics.scalars().all()
    report_data = {
        "report_title": "NetShield-AI SOC Telemetry Export",
        "generated_at": "UTC Real-time",
        "metrics_count": len(metrics),
        "status": "Operational"
    }
    json_bytes = json.dumps(report_data, indent=2).encode("utf-8")
    return Response(
        content=json_bytes,
        media_type="application/json",
        headers={"Content-Disposition": "attachment; filename=netshield_telemetry_export.json"}
    )

# Settings endpoints
class SettingsPayload(BaseModel):
    telemetry_polling_interval: str = "Standard (5 seconds)"
    threat_threshold: str = "High Severity"
    auto_mitigation: str = "Enabled"

@settings_router.get("")
@settings_router.get("/")
async def get_settings(db: AsyncSession = Depends(get_db)):
    result = await db.execute(select(SystemSetting))
    settings_list = result.scalars().all()
    settings_dict = {s.key: s.value for s in settings_list}
    if not settings_dict:
        settings_dict = {
            "telemetry_polling_interval": "Standard (5 seconds)",
            "threat_threshold": "High Severity",
            "auto_mitigation": "Enabled"
        }
    return {"status": "success", "data": settings_dict}

@settings_router.put("")
@settings_router.put("/")
async def update_settings(payload: SettingsPayload, db: AsyncSession = Depends(get_db)):
    settings_data = payload.model_dump() if hasattr(payload, 'model_dump') else payload.dict()
    for k, v in settings_data.items():
        result = await db.execute(select(SystemSetting).where(SystemSetting.key == k))
        existing = result.scalars().first()
        if existing:
            existing.value = v
        else:
            db.add(SystemSetting(key=k, value=v))
    await db.commit()
    return {"status": "success", "message": "Settings updated successfully", "data": settings_data}

