"""Persistent per-device MQTT monitoring and telemetry queries."""

from __future__ import annotations

import json
import math
from typing import Any

from src.database import get_connection, utc_now


MAX_PAYLOAD_BYTES = 16 * 1024


def record_telemetry(
    device_uid: str,
    topic: str,
    payload: dict[str, Any],
    payload_bytes: int,
) -> int:
    if not isinstance(device_uid, str) or not device_uid.strip():
        raise ValueError("device_uid is required")

    if not isinstance(topic, str) or not topic:
        raise ValueError("topic is required")

    if not isinstance(payload, dict):
        raise ValueError("payload must be a JSON object")

    if not isinstance(payload_bytes, int) or not 0 <= payload_bytes <= MAX_PAYLOAD_BYTES:
        raise ValueError("Invalid payload size")

    encoded = json.dumps(payload, sort_keys=True, allow_nan=False)

    numeric = {}
    for key, value in payload.items():
        if (
            isinstance(key, str)
            and isinstance(value, (int, float))
            and not isinstance(value, bool)
            and math.isfinite(value)
        ):
            numeric[key] = value

    numeric_encoded = json.dumps(
        numeric, sort_keys=True, allow_nan=False
    )

    now = utc_now()

    with get_connection() as conn:
        device = conn.execute(
            "SELECT device_uid FROM devices WHERE device_uid=?",
            (device_uid.strip(),),
        ).fetchone()

        if device is None:
            raise LookupError("Unknown device")

        cursor = conn.execute(
            """INSERT INTO mqtt_telemetry
               (device_uid,topic,received_at,payload_json,
                payload_bytes,numeric_features_json)
               VALUES (?,?,?,?,?,?)""",
            (
                device_uid.strip(),
                topic,
                now,
                encoded,
                payload_bytes,
                numeric_encoded,
            ),
        )

        conn.execute(
            """UPDATE devices
               SET last_seen_at=?,updated_at=?
               WHERE device_uid=?""",
            (now, now, device_uid.strip()),
        )

        return int(cursor.lastrowid)


def get_monitoring_summary() -> dict:
    with get_connection() as conn:
        totals = conn.execute(
            """SELECT COUNT(*) AS total_messages,
                      COUNT(DISTINCT device_uid) AS monitored_devices,
                      MAX(received_at) AS last_received_at
               FROM mqtt_telemetry"""
        ).fetchone()

        devices = conn.execute(
            """SELECT d.device_uid,d.name,d.status,d.last_seen_at,
                      COUNT(t.id) AS message_count,
                      COALESCE(SUM(t.payload_bytes),0) AS total_bytes
               FROM devices d
               LEFT JOIN mqtt_telemetry t
                   ON t.device_uid=d.device_uid
               GROUP BY d.device_uid
               ORDER BY d.device_uid"""
        ).fetchall()

    return {
        "total_messages": totals["total_messages"],
        "monitored_devices": totals["monitored_devices"],
        "last_received_at": totals["last_received_at"],
        "devices": [dict(row) for row in devices],
    }


def get_device_monitoring(
    device_uid: str,
    limit: int = 50,
) -> dict | None:
    if not isinstance(limit, int) or not 1 <= limit <= 500:
        raise ValueError("limit must be between 1 and 500")

    with get_connection() as conn:
        device = conn.execute(
            """SELECT device_uid,name,status,last_seen_at
               FROM devices WHERE device_uid=?""",
            (device_uid,),
        ).fetchone()

        if device is None:
            return None

        totals = conn.execute(
            """SELECT COUNT(*) AS message_count,
                      COALESCE(SUM(payload_bytes),0) AS total_bytes,
                      MAX(received_at) AS last_received_at
               FROM mqtt_telemetry WHERE device_uid=?""",
            (device_uid,),
        ).fetchone()

        rows = conn.execute(
            """SELECT id,topic,received_at,payload_json,
                      payload_bytes,numeric_features_json
               FROM mqtt_telemetry
               WHERE device_uid=?
               ORDER BY id DESC LIMIT ?""",
            (device_uid, limit),
        ).fetchall()

    messages = []
    for row in rows:
        item = dict(row)
        item["payload"] = json.loads(item.pop("payload_json"))
        item["numeric_features"] = json.loads(
            item.pop("numeric_features_json")
        )
        messages.append(item)

    return {
        "device": dict(device),
        "statistics": dict(totals),
        "messages": messages,
    }
