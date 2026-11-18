"""Structured persistent system event logging."""
from __future__ import annotations

import json
import sqlite3
from typing import Any

from src.database import get_connection, utc_now

ALLOWED_SEVERITIES = {"debug", "info", "warning", "error", "critical"}


def log_event(
    event_type: str,
    message: str,
    *,
    severity: str = "info",
    source: str = "system",
    device_uid: str | None = None,
    details: dict[str, Any] | None = None,
    connection: sqlite3.Connection | None = None,
) -> int:
    """Write an event, optionally inside a caller-owned transaction."""
    if not isinstance(event_type, str) or not event_type.strip():
        raise ValueError("event_type is required")
    if not isinstance(message, str) or not message.strip():
        raise ValueError("message is required")
    if not isinstance(severity, str) or severity not in ALLOWED_SEVERITIES:
        raise ValueError(f"severity must be one of {sorted(ALLOWED_SEVERITIES)}")
    if not isinstance(source, str):
        raise ValueError("source must be a string")
    if device_uid is not None and (
        not isinstance(device_uid, str) or not device_uid.strip()
    ):
        raise ValueError("device_uid must be a non-empty string")
    if details is not None and not isinstance(details, dict):
        raise ValueError("details must be a JSON object")

    try:
        details_json = json.dumps(details or {}, sort_keys=True)
    except (TypeError, ValueError) as exc:
        raise ValueError(
            "details must contain JSON-serializable values"
        ) from exc

    values = (
        event_type.strip(),
        severity,
        source.strip() or "system",
        device_uid.strip() if device_uid is not None else None,
        message.strip(),
        details_json,
        utc_now(),
    )

    def insert_event(conn: sqlite3.Connection) -> int:
        cur = conn.execute(
            """INSERT INTO system_events
               (event_type,severity,source,device_uid,message,details_json,created_at)
               VALUES (?,?,?,?,?,?,?)""",
            values,
        )
        return int(cur.lastrowid)

    if connection is not None:
        return insert_event(connection)

    with get_connection() as conn:
        return insert_event(conn)


def list_events(
    *,
    limit: int = 100,
    device_uid: str | None = None,
) -> list[dict[str, Any]]:
    if not isinstance(limit, int) or not 1 <= limit <= 500:
        raise ValueError("limit must be between 1 and 500")

    sql, params = "SELECT * FROM system_events", []
    if device_uid:
        sql += " WHERE device_uid = ?"
        params.append(device_uid)

    sql += " ORDER BY id DESC LIMIT ?"
    params.append(limit)

    with get_connection() as conn:
        rows = conn.execute(sql, params).fetchall()

    output = []
    for row in rows:
        item = dict(row)
        item["details"] = json.loads(item.pop("details_json") or "{}")
        output.append(item)

    return output
