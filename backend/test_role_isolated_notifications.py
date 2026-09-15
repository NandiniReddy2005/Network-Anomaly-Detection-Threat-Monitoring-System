import sys
import os
import asyncio

sys.path.insert(0, os.path.abspath(os.path.dirname(__file__)))
if hasattr(sys.stdout, 'reconfigure'):
    sys.stdout.reconfigure(encoding='utf-8')

from app.routers.notifications import get_notifications, mark_notifications_read, notification_quick_contain

class MockDB:
    def add(self, obj):
        pass
    async def commit(self):
        pass
    async def refresh(self, obj):
        pass
    async def rollback(self):
        pass

async def run_role_isolation_tests():
    print("==================================================", flush=True)
    print(" Testing Role-Based Notification Isolation Stream  ", flush=True)
    print("==================================================", flush=True)

    # 1. Test GET /api/notifications for Security Administrator
    res_admin = await get_notifications(actor="sec_admin@gmail.com", role="admin")
    print(f"\n1. GET /api/notifications (Role: admin) -> status: {res_admin.get('status')}", flush=True)
    assert res_admin.get("status") == "success"
    admin_notifs = res_admin.get("data", [])
    print(f"   Fetched {len(admin_notifs)} Security Administrator notifications.", flush=True)
    for n in admin_notifs:
        print(f"   - [ADMIN NOTIF] ID: {n.get('id')} | Title: {n.get('title')}", flush=True)
        assert "ADMIN" in str(n.get("id")) or "GOVERNANCE" in str(n.get("title")) or "FIREWALL" in str(n.get("title")) or "AUDIT" in str(n.get("title")) or "IDENTITY" in str(n.get("title"))

    # 2. Test GET /api/notifications for Security Analyst
    res_analyst = await get_notifications(actor="analyst@gmail.com", role="analyst")
    print(f"\n2. GET /api/notifications (Role: analyst) -> status: {res_analyst.get('status')}", flush=True)
    assert res_analyst.get("status") == "success"
    analyst_notifs = res_analyst.get("data", [])
    print(f"   Fetched {len(analyst_notifs)} Security Analyst notifications.", flush=True)
    for n in analyst_notifs:
        print(f"   - [ANALYST NOTIF] ID: {n.get('id')} | Title: {n.get('title')}", flush=True)

    # 3. Verify ZERO cross-contamination between admin and analyst notifications
    admin_ids = set(n.get("id") for n in admin_notifs)
    analyst_ids = set(n.get("id") for n in analyst_notifs)
    overlap = admin_ids.intersection(analyst_ids)
    print(f"\n3. Cross-Contamination Check:", flush=True)
    print(f"   Admin IDs Count: {len(admin_ids)} | Analyst IDs Count: {len(analyst_ids)} | Overlap: {len(overlap)}", flush=True)
    assert len(overlap) == 0, f"Cross-contamination detected! Overlapping IDs: {overlap}"

    # 4. Test Role-Isolated Mark Read for Administrator
    res_read_admin = await mark_notifications_read(payload={"actor": "sec_admin@gmail.com", "role": "admin"})
    print(f"\n4. POST /api/notifications/read (Role: admin) -> Admin Unread Count: {res_read_admin.get('unread_count')}", flush=True)
    assert res_read_admin.get("unread_count") == 0

    # 5. Verify Analyst unread count is STILL untouched
    res_analyst_check = await get_notifications(actor="analyst@gmail.com", role="analyst")
    analyst_unread = res_analyst_check.get("unread_count", 0)
    print(f"   Analyst Unread Count after Admin Mark Read: {analyst_unread} (Isolated)", flush=True)
    assert analyst_unread > 0

    # 6. Test Role-Isolated Mark Read for Analyst
    res_read_analyst = await mark_notifications_read(payload={"actor": "analyst@gmail.com", "role": "analyst"})
    print(f"\n5. POST /api/notifications/read (Role: analyst) -> Analyst Unread Count: {res_read_analyst.get('unread_count')}", flush=True)
    assert res_read_analyst.get("unread_count") == 0

    print("\n[SUCCESS] Role-Based Notification Isolation & Segregation Tests PASSED!\n", flush=True)

if __name__ == "__main__":
    asyncio.run(run_role_isolation_tests())
