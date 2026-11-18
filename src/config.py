"""Validated runtime configuration."""
from __future__ import annotations
import os
from dataclasses import dataclass

def _positive_int(name: str, default: int) -> int:
    try:
        value = int(os.getenv(name, str(default)))
    except ValueError as exc:
        raise ValueError(f"{name} must be an integer") from exc
    if value <= 0:
        raise ValueError(f"{name} must be greater than zero")
    return value

@dataclass(frozen=True)
class Settings:
    app_env: str
    host: str
    port: int
    database_path: str
    event_retention_days: int

    @classmethod
    def from_env(cls) -> "Settings":
        return cls(
            app_env=os.getenv("APP_ENV", "development").strip().lower(),
            host=os.getenv("HOST", "127.0.0.1").strip(),
            port=_positive_int("PORT", 5000),
            database_path=os.getenv("IOT_SECURITY_DB", "iot_security.db"),
            event_retention_days=_positive_int("EVENT_RETENTION_DAYS", 90),
        )

settings = Settings.from_env()
