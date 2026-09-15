import sys
import os
import asyncio

sys.path.insert(0, os.path.abspath(os.path.dirname(__file__)))
if hasattr(sys.stdout, 'reconfigure'):
    sys.stdout.reconfigure(encoding='utf-8')

from app.routers.notifications import get_notifications, mark_notifications_read, notification_quick_contain, NOTIFICATION_STORE

class MockDB:
    def add(self, obj):
        pass
    async def commit(self):
        pass
    async def refresh(self, obj):
        pass
    async def rollback(self):
        pass

async def run_tests():
    print("==================================================", flush=True)
    print(" Testing Real-Time Notification Stream & Containment ", flush=True)
    print("==================================================", flush=True)

    # 1. Test GET /api/notifications
    res = await get_notifications(actor="security@gmail.com")
    print(f"\n1. GET /api/notifications -> status: {res.get('status')}", flush=True)
    assert res.get("status") == "success"
    notifs = res.get("data", [])
    unread = res.get("unread_count", 0)
    print(f"   Fetched {len(notifs)} notifications ({unread} unread).", flush=True)
    assert unread >= 0

    # 2. Test POST /api/notifications/quick-contain
    mock_db = MockDB()
    contain_payload = {
        "alert_id": "ALT-1082",
        "source_ip": "185.220.101.42",
        "actor": "security@gmail.com"
    }
    res_contain = await notification_quick_contain(payload=contain_payload, db=mock_db)
    print(f"\n2. POST /api/notifications/quick-contain Result:", flush=True)
    print(f"   - Message: {res_contain.get('message')}")
    print(f"   - New Status: {res_contain.get('new_status')}")
    assert res_contain.get("new_status") == "Contained"
    assert "QUICK CONTAINMENT DEPLOYED" in res_contain.get("message")

    # 3. Test POST /api/notifications/read
    read_payload = {"actor": "security@gmail.com"}
    res_read = await mark_notifications_read(payload=read_payload)
    print(f"\n3. POST /api/notifications/read Result:", flush=True)
    print(f"   - Message: {res_read.get('message')}")
    print(f"   - Unread Count: {res_read.get('unread_count')}")
    assert res_read.get("unread_count") == 0

    print("\n[SUCCESS] Real-Time Notification Stream & Quick Containment PASSED!\n", flush=True)

if __name__ == "__main__":
    asyncio.run(run_tests())
