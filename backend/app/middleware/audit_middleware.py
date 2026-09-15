from starlette.middleware.base import BaseHTTPMiddleware
from starlette.requests import Request
from starlette.responses import Response
import logging
import asyncio

try:
    from app.database import AsyncSessionLocal
    from app.services.audit import log_audit_event
except ImportError:
    from backend.app.database import AsyncSessionLocal
    from backend.app.services.audit import log_audit_event

logger = logging.getLogger("netshield_audit_middleware")

class AuditLoggingMiddleware(BaseHTTPMiddleware):
    async def dispatch(self, request: Request, call_next):
        response = await call_next(request)

        method = request.method.upper()
        path = request.url.path.lower()

        # Exclude GET read operations (such as fetching audit logs, metrics, or telemetry)
        if method == "GET":
            return response

        # Intercept state-changing operations
        if method in ["POST", "PUT", "DELETE", "PATCH"]:
            actor_email = request.headers.get("x-user-email") or request.headers.get("user-email")
            
            # Map path to module & descriptive action across all user roles
            module = "SOC Core Platform"
            if "auth" in path:
                module = "Auth Gateway"
                if "login" in path:
                    action = "User Authentication (Login)"
                elif "logout" in path:
                    action = "User Session Logout"
                else:
                    action = "New User Account Registration"
            elif "user" in path:
                module = "User Management"
                action = "Modified User Account Roles & Access Scopes"
            elif "waf" in path or "setting" in path:
                module = "WAF & Rules"
                action = "Updated WAF Policy & Rate Limit Thresholds"
            elif "threat" in path or "ml" in path or "predict" in path or "anomaly" in path:
                if "/predict" in path:
                    return response
                module = "Threat Management"
                action = "Executed Threat Prediction & Isolation Rule"
            elif "audit" in path:
                module = "System Administration"
                action = "Recorded Audit Event"
            elif "alert" in path:
                module = "Automated Defense"
                action = "Triaged Critical Security Alert"
            elif "report" in path or "analytic" in path:
                module = "Reports Engine"
                action = "Generated Security Analytics Package"
            else:
                action = f"Executed {method} {request.url.path}"

            client_ip = request.client.host if request.client else "192.168.1.50"
            status_str = "Success" if response.status_code < 400 else "Denied"
            severity_str = "Informational" if response.status_code < 400 else "High"

            if actor_email:
                asyncio.create_task(
                    self._persist_audit_log(
                        actor=actor_email,
                        action=action,
                        module=module,
                        ip_origin=client_ip,
                        status=status_str,
                        severity=severity_str,
                        details=f"Operation {action} executed by {actor_email} [HTTP {method} {request.url.path} - Status {response.status_code}]"
                    )
                )

        return response

    async def _persist_audit_log(self, actor, action, module, ip_origin, status, severity, details):
        try:
            async with AsyncSessionLocal() as session:
                await log_audit_event(
                    db=session,
                    actor=actor,
                    action=action,
                    module=module,
                    ip_origin=ip_origin,
                    status=status,
                    severity=severity,
                    details=details
                )
        except Exception as e:
            logger.warning(f"Middleware failed to log audit event: {e}")
