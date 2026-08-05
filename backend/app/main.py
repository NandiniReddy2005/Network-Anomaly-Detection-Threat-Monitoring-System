from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from contextlib import asynccontextmanager
import os
import logging

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger("netshield_backend")

try:
    from app.database import engine, Base, AsyncSessionLocal
    from app.models import User, AdminIncident, AuditLog, TrafficMetric, TrustedDevice, SecurityLog, SystemSetting
    from app.auth import hash_password
    from app.routers import telemetry, auth_routes, dashboard, analyst
except ImportError:
    from backend.app.database import engine, Base, AsyncSessionLocal
    from backend.app.models import User, AdminIncident, AuditLog, TrafficMetric, TrustedDevice, SecurityLog, SystemSetting
    from backend.app.auth import hash_password
    from backend.app.routers import telemetry, auth_routes, dashboard, analyst
from sqlalchemy.future import select

@asynccontextmanager
async def lifespan(app: FastAPI):
    # Startup: create tables if they do not exist
    try:
        async with engine.begin() as conn:
            await conn.run_sync(Base.metadata.create_all)
        
        # Seed initial users & incidents if database is empty
        async with AsyncSessionLocal() as session:
            result_users = await session.execute(select(User))
            users = result_users.scalars().all()
            if not users:
                default_users = [
                    User(email="sec_admin@gmail.com", password_hash=hash_password("admin123"), role="admin"),
                    User(email="admin_lead@netshield.io", password_hash=hash_password("admin123"), role="admin"),
                    User(email="sec_director@netshield.io", password_hash=hash_password("admin123"), role="admin"),
                    User(email="sys_admin2@netshield.io", password_hash=hash_password("admin123"), role="admin"),
                    User(email="analyst@gmail.com", password_hash=hash_password("analyst123"), role="analyst"),
                    User(email="newuser@gmail.com", password_hash=hash_password("analyst123"), role="analyst"),
                    User(email="tier2_analyst@netshield.io", password_hash=hash_password("analyst123"), role="analyst"),
                    User(email="soc_analyst1@netshield.io", password_hash=hash_password("analyst123"), role="analyst"),
                ]
                session.add_all(default_users)
                await session.commit()

            result_incidents = await session.execute(select(AdminIncident))
            incidents = result_incidents.scalars().all()
            if not incidents:
                default_incidents = [
                    AdminIncident(id="INC-901", severity="Critical", type="DDoS Volumetric Spike", analyst="Unassigned", status="Open", updated="2 mins ago"),
                    AdminIncident(id="INC-902", severity="High", type="ARP Spoofing Attempt", analyst="analyst@gmail.com", status="Investigating", updated="15 mins ago"),
                    AdminIncident(id="INC-903", severity="Medium", type="Unauthorized Port Scan", analyst="sec_admin@gmail.com", status="Resolved", updated="1 hour ago"),
                ]
                session.add_all(default_incidents)
                await session.commit()

            result_logs = await session.execute(select(AuditLog))
            logs = result_logs.scalars().all()
            if not logs:
                default_logs = [
                    AuditLog(timestamp="11:42:01 UTC", actor="sec_admin@gmail.com", action="Updated Firewall Rate Limit Threshold", ip_origin="192.168.1.50")
                ]
                session.add_all(default_logs)
                await session.commit()

            result_metrics = await session.execute(select(TrafficMetric))
            metrics = result_metrics.scalars().all()
            if not metrics:
                default_metrics = [
                    TrafficMetric(packet_count=84200000, bytes_transferred=51200000000, anomaly_score=12.4),
                    TrafficMetric(packet_count=1482000, bytes_transferred=1024000000, anomaly_score=5.2)
                ]
                session.add_all(default_metrics)
                await session.commit()

            result_devices = await session.execute(select(TrustedDevice))
            devices = result_devices.scalars().all()
            if not devices:
                default_devices = [
                    TrustedDevice(ip_address="192.168.1.50", mac_address="00:1A:2B:3C:4D:5E", device_name="Gateway Firewall", is_blocked=False),
                    TrustedDevice(ip_address="192.168.1.100", mac_address="00:1A:2B:3C:4D:5F", device_name="Analyst Workstation", is_blocked=False)
                ]
                session.add_all(default_devices)
                await session.commit()

            result_sec_logs = await session.execute(select(SecurityLog))
            sec_logs = result_sec_logs.scalars().all()
            if not sec_logs:
                default_sec_logs = [
                    SecurityLog(event_type="ARP_SPOOF", details="Gratuitous ARP flood intercepted on eth0 sensor cluster", severity="HIGH"),
                    SecurityLog(event_type="DDOS_ANOMALY", details="Volumetric UDP flood anomaly score elevated to 88/100", severity="CRITICAL"),
                    SecurityLog(event_type="PORT_SCAN", details="Horizontal SYN scan detected from external IP 198.51.100.42", severity="MEDIUM"),
                    SecurityLog(event_type="AUTH_FAIL", details="Multiple failed authentication attempts for admin role", severity="WARNING"),
                ]
                session.add_all(default_sec_logs)
                await session.commit()

            result_settings = await session.execute(select(SystemSetting))
            settings = result_settings.scalars().all()
            if not settings:
                default_settings = [
                    SystemSetting(key="telemetry_polling_interval", value="Standard (5 seconds)"),
                    SystemSetting(key="threat_threshold", value="High Severity"),
                    SystemSetting(key="auto_mitigation", value="Enabled"),
                ]
                session.add_all(default_settings)
                await session.commit()

            logger.info("PostgreSQL Database initialized and seeded successfully.")
    except Exception as e:
        logger.warning(f"Database initialization warning: {e}")

    yield
    # Shutdown: Dispose engine connection pool cleanly
    try:
        await engine.dispose()
    except Exception:
        pass

app = FastAPI(title="NetShield-AI Backend", version="1.0.0", lifespan=lifespan)

# Enable CORS for Next.js Frontend communication
app.add_middleware(
    CORSMiddleware,
    allow_origins=[
        "http://localhost:3000",
        "http://127.0.0.1:3000",
        "http://localhost:8000",
        "http://127.0.0.1:8000",
    ],
    allow_origin_regex=r"http://(localhost|127\.0\.0\.1)(:[0-9]+)?",
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Include routers
app.include_router(telemetry.router)
app.include_router(telemetry.logs_router)
app.include_router(telemetry.events_router)
app.include_router(auth_routes.router)
app.include_router(dashboard.router)
app.include_router(dashboard.reports_router)
app.include_router(dashboard.settings_router)
app.include_router(dashboard.audit_router)
app.include_router(dashboard.threats_router)
app.include_router(analyst.router)

@app.get("/")
async def root():
    return {
        "status": "online",
        "message": "NetShield-AI Engine Operational",
        "database": "PostgreSQL Connected"
    }

if __name__ == "__main__":
    import uvicorn
    uvicorn.run("main:app", host="0.0.0.0", port=8000, reload=True)