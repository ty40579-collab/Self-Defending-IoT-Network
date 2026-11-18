"""Persistent JSON-backed application configuration helpers."""
from __future__ import annotations
import json
from typing import Any
from src.database import get_connection, utc_now

def set_config(key: str, value: Any, *, description: str = "") -> None:
    if not isinstance(key, str) or not key.strip():
        raise ValueError("config key is required")
    if not isinstance(description, str):
        raise ValueError("description must be a string")
    encoded = json.dumps(value, sort_keys=True)
    with get_connection() as conn:
        conn.execute("""INSERT INTO system_config(config_key,config_value,description,updated_at)
            VALUES (?,?,?,?)
            ON CONFLICT(config_key) DO UPDATE SET
            config_value=excluded.config_value,
            description=excluded.description,
            updated_at=excluded.updated_at""",
            (key.strip(), encoded, description, utc_now()))

def get_config(key: str, default: Any = None) -> Any:
    with get_connection() as conn:
        row = conn.execute("SELECT config_value FROM system_config WHERE config_key=?",
                           (key,)).fetchone()
    return json.loads(row["config_value"]) if row else default

def list_config() -> list[dict[str, Any]]:
    with get_connection() as conn:
        rows = conn.execute("""SELECT config_key,config_value,description,updated_at
            FROM system_config ORDER BY config_key""").fetchall()
    return [{"key": r["config_key"], "value": json.loads(r["config_value"]),
             "description": r["description"], "updated_at": r["updated_at"]}
            for r in rows]
