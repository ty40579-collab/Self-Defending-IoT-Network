"""Device registry and guarded lifecycle transitions; no network enforcement."""
from __future__ import annotations

import json
import re
from typing import Any

from src.database import get_connection, utc_now
from src.event_logger import log_event

DEVICE_STATUSES = {"registered", "active", "inactive", "isolated", "recovering"}

ALLOWED_TRANSITIONS = {
    "registered": {"active", "inactive"},
    "active": {"inactive", "isolated"},
    "inactive": {"active", "isolated"},
    "isolated": {"recovering"},
    "recovering": {"active", "isolated"},
}

MAC_RE = re.compile(r"^(?:[0-9A-Fa-f]{2}[:-]){5}[0-9A-Fa-f]{2}$")


def _normalize_mac(mac_address: str | None) -> str | None:
    if mac_address is None:
        return None

    candidate = mac_address.strip()
    if not MAC_RE.fullmatch(candidate):
        raise ValueError("mac_address must be a valid six-octet MAC address")

    # Store every accepted MAC in lowercase colon-separated form.
    return candidate.replace("-", ":").lower()


def _serialize(row: Any) -> dict[str, Any]:
    item = dict(row)
    item["trusted"] = bool(item["trusted"])
    item["metadata"] = json.loads(item.pop("metadata_json") or "{}")
    return item


def register_device(
    device_uid: str,
    name: str,
    *,
    device_type: str = "unknown",
    ip_address: str | None = None,
    mac_address: str | None = None,
    communication_type: str = "unknown",
    endpoint: str | None = None,
    trusted: bool = False,
    metadata: dict[str, Any] | None = None,
) -> dict[str, Any]:
    required = {
        "device_uid": device_uid,
        "name": name,
        "device_type": device_type,
        "communication_type": communication_type,
    }
    for field, value in required.items():
        if not isinstance(value, str) or not value.strip():
            raise ValueError(f"{field} is required")

    for field, value in {
        "ip_address": ip_address,
        "mac_address": mac_address,
        "endpoint": endpoint,
    }.items():
        if value is not None and not isinstance(value, str):
            raise ValueError(f"{field} must be a string")

    normalized_mac = _normalize_mac(mac_address)

    if metadata is not None and not isinstance(metadata, dict):
        raise ValueError("metadata must be a JSON object")
    if not isinstance(trusted, bool):
        raise ValueError("trusted must be a boolean")

    try:
        metadata_json = json.dumps(metadata or {}, sort_keys=True)
    except (TypeError, ValueError) as exc:
        raise ValueError(
            "metadata must contain JSON-serializable values"
        ) from exc

    now = utc_now()
    uid = device_uid.strip()
    clean_name = name.strip()

    # Device creation and its audit event are one transaction.
    with get_connection() as conn:
        conn.execute(
            """INSERT INTO devices
               (device_uid,name,device_type,ip_address,mac_address,
                communication_type,endpoint,status,trusted,metadata_json,
                created_at,updated_at)
               VALUES (?,?,?,?,?,?,?,'registered',?,?,?,?)""",
            (
                uid,
                clean_name,
                device_type.strip(),
                ip_address.strip() if ip_address else None,
                normalized_mac,
                communication_type.strip(),
                endpoint.strip() if endpoint else None,
                int(trusted),
                metadata_json,
                now,
                now,
            ),
        )

        log_event(
            "device.registered",
            f"Device '{clean_name}' registered",
            source="device_manager",
            device_uid=uid,
            connection=conn,
        )

        row = conn.execute(
            "SELECT * FROM devices WHERE device_uid=?", (uid,)
        ).fetchone()

    return _serialize(row)


def get_device(device_uid: str) -> dict[str, Any] | None:
    if not isinstance(device_uid, str):
        return None

    with get_connection() as conn:
        row = conn.execute(
            "SELECT * FROM devices WHERE device_uid=?",
            (device_uid.strip(),),
        ).fetchone()

    return _serialize(row) if row else None


def list_devices(*, status: str | None = None) -> list[dict[str, Any]]:
    if status and status not in DEVICE_STATUSES:
        raise ValueError(f"status must be one of {sorted(DEVICE_STATUSES)}")

    with get_connection() as conn:
        if status:
            rows = conn.execute(
                "SELECT * FROM devices WHERE status=? ORDER BY id",
                (status,),
            ).fetchall()
        else:
            rows = conn.execute(
                "SELECT * FROM devices ORDER BY id"
            ).fetchall()

    return [_serialize(row) for row in rows]


def update_device_status(
    device_uid: str,
    new_status: str,
) -> dict[str, Any]:
    if not isinstance(device_uid, str) or not device_uid.strip():
        raise ValueError("device_uid is required")
    if not isinstance(new_status, str) or new_status not in DEVICE_STATUSES:
        raise ValueError(f"status must be one of {sorted(DEVICE_STATUSES)}")

    uid = device_uid.strip()

    # Status change and audit event are one transaction.
    with get_connection() as conn:
        row = conn.execute(
            "SELECT * FROM devices WHERE device_uid=?",
            (uid,),
        ).fetchone()

        if row is None:
            raise LookupError("device not found")

        old_status = row["status"]

        if new_status == old_status:
            return _serialize(row)

        if new_status not in ALLOWED_TRANSITIONS[old_status]:
            raise ValueError(
                f"invalid device status transition: {old_status} -> {new_status}"
            )

        conn.execute(
            "UPDATE devices SET status=?,updated_at=? WHERE device_uid=?",
            (new_status, utc_now(), uid),
        )

        log_event(
            "device.status_changed",
            f"Device status changed: {old_status} -> {new_status}",
            source="device_manager",
            device_uid=uid,
            details={
                "previous_status": old_status,
                "new_status": new_status,
            },
            connection=conn,
        )

        updated = conn.execute(
            "SELECT * FROM devices WHERE device_uid=?",
            (uid,),
        ).fetchone()

    return _serialize(updated)


def mark_device_seen(device_uid: str) -> None:
    if not isinstance(device_uid, str) or not device_uid.strip():
        raise ValueError("device_uid is required")

    now = utc_now()
    with get_connection() as conn:
        cur = conn.execute(
            """UPDATE devices
               SET last_seen_at=?,updated_at=?
               WHERE device_uid=?""",
            (now, now, device_uid.strip()),
        )
        if cur.rowcount == 0:
            raise LookupError("device not found")
