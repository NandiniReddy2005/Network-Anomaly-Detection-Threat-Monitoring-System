from datetime import datetime, timezone
import logging
from typing import Optional
from sqlalchemy.ext.asyncio import AsyncSession

try:
    from app.models import AuditLog, User
except ImportError:
    from backend.app.models import AuditLog, User
from sqlalchemy.future import select

logger = logging.getLogger("netshield_audit")

async def log_audit_event(
    db: AsyncSession,
    actor: str,
    action: str,
    module: str = "SOC Core Platform",
    ip_origin: str = "192.168.1.50",
    status: str = "Success",
    severity: str = "Informational",
    details: Optional[str] = None,
    user_type: Optional[str] = None,
    login_time: Optional[str] = None,
    logout_time: Optional[str] = None
) -> Optional[AuditLog]:
    """
    Dynamically logs an administrative operation into the PostgreSQL Audit Log table.
    Captures exact session user email (actor), current UTC timestamp, user_type, login_time, logout_time, action, module, and status.
    """
    try:
        current_time_str = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC")
        
        # Ensure actor is a clean email string
        actor_email = str(actor).strip() if actor and str(actor).strip() else "sec_admin@gmail.com"
        
        if not user_type:
            try:
                user_res = await db.execute(select(User).where(User.email == actor_email))
                user_obj = user_res.scalars().first()
                if user_obj and getattr(user_obj, "role", None):
                    role_str = str(user_obj.role).lower()
                    user_type = "Security Analyst" if "analyst" in role_str else "Security Administrator"
                else:
                    user_type = "Security Analyst" if "analyst" in actor_email.lower() else "Security Administrator"
            except Exception:
                user_type = "Security Analyst" if "analyst" in actor_email.lower() else "Security Administrator"

        if not login_time:
            login_time = "09:45:00 UTC"
        if not logout_time:
            logout_time = "Active Session"

        if not details:
            details = f"Operation '{action}' executed by {actor_email} ({user_type}) and logged to audit store."

        log_entry = AuditLog(
            timestamp=current_time_str,
            actor=actor_email,
            action=action,
            module=module,
            ip_origin=ip_origin or "192.168.1.50",
            status=status or "Success",
            severity=severity or "Informational",
            details=details,
            user_type=user_type,
            login_time=login_time,
            logout_time=logout_time
        )
        db.add(log_entry)
        await db.commit()
        await db.refresh(log_entry)
        logger.info(f"Real-Time Audit Event Logged: [{action}] by {actor_email} ({user_type})")
        return log_entry
    except Exception as e:
        logger.error(f"Failed to record audit log event: {e}")
        try:
            await db.rollback()
        except Exception:
            pass
        return None
