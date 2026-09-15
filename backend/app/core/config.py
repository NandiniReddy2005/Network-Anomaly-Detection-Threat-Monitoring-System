import os
from pathlib import Path
from pydantic_settings import BaseSettings, SettingsConfigDict

# Determine directory paths to locate .env file reliably
CORE_DIR = Path(__file__).resolve().parent
APP_DIR = CORE_DIR.parent
BACKEND_DIR = APP_DIR.parent
PROJECT_ROOT = BACKEND_DIR.parent

class Settings(BaseSettings):
    ABUSEIPDB_API_KEY: str = ""
    DATABASE_URL: str = "postgresql+asyncpg://postgres:postgres@127.0.0.1:5432/netshield_ai"

    model_config = SettingsConfigDict(
        env_file=(
            str(BACKEND_DIR / ".env"),
            str(PROJECT_ROOT / ".env"),
            ".env"
        ),
        env_file_encoding="utf-8",
        extra="ignore",
        case_sensitive=True
    )

settings = Settings()
