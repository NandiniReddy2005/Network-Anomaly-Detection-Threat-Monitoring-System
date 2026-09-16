import os
import socket
from sqlalchemy.ext.asyncio import create_async_engine, async_sessionmaker, AsyncAttrs
from sqlalchemy.orm import DeclarativeBase

try:
    from core.config import settings
except ImportError:
    from app.core.config import settings

PG_DATABASE_URL = settings.DATABASE_URL

SQLITE_DATABASE_URL = "sqlite+aiosqlite:///d:/NetShield-AI/backend/netshield_ai.db"

def is_postgres_available():
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(1.5)
        res = s.connect_ex(("127.0.0.1", 5432))
        s.close()
        return res == 0
    except Exception:
        return False

if is_postgres_available():
    DATABASE_URL = PG_DATABASE_URL
    engine = create_async_engine(
        DATABASE_URL, 
        echo=False,
        pool_size=5,
        max_overflow=10,
        pool_pre_ping=True,
        pool_recycle=3600,
        connect_args={"ssl": False, "timeout": 5}
    )
else:
    DATABASE_URL = SQLITE_DATABASE_URL
    engine = create_async_engine(
        DATABASE_URL,
        echo=False
    )

AsyncSessionLocal = async_sessionmaker(engine, expire_on_commit=False)

class Base(DeclarativeBase, AsyncAttrs):
    pass

async def get_db():
    async with AsyncSessionLocal() as session:
        try:
            yield session
        finally:
            await session.close()
