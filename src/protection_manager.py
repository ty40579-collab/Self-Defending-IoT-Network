"""Confirmed network isolation and release operations."""

from __future__ import annotations

import json
import os
from datetime import datetime, timedelta, timezone
from typing import Any

from src.database import get_connection, utc_now
from src.event_logger import log_event
from src.network_firewall import (
    FirewallBackend,
    FirewallError,
    FirewallResult,
    NftablesBackend,
    normalize_ip,
)


def _require_enabled() -> None:
    if os.environ.get("IOT_ENFORCEMENT_ENABLED", "false").lower() != "true":
        raise PermissionError("Network enforcement is disabled")


def _get_backend(backend: FirewallBackend | None) -> FirewallBackend:
    return backend if backend is not None else NftablesBackend()


def _record_action(
    conn,
    *,
    device_uid: str,
    action: str,
    status: str,
    ip_address: str,
    backend_name: str,
    reason: str,
    details: dict[str, Any] | None = None,
) -> None:
    conn.execute(
        """INSERT INTO network_protection_actions
           (device_uid,action,status,ip_address,backend,reason,details_json,created_at)
           VALUES (?,?,?,?,?,?,?,?)""",
        (
            device_uid, action, status, ip_address, backend_name,
            reason, json.dumps(details or {}, sort_keys=True), utc_now(),
        ),
    )


def isolate_device(
    device_uid: str,
    reason: str = "Manual isolation",
    *,
    backend: FirewallBackend | None = None,
) -> dict[str, Any]:
    """Isolate a device only after the firewall confirms the rule."""
    _require_enabled()

    if not isinstance(device_uid, str) or not device_uid.strip():
        raise ValueError("device_uid is required")
    if not isinstance(reason, str) or not reason.strip() or len(reason) > 500:
        raise ValueError("reason must contain 1 to 500 characters")

    uid = device_uid.strip()

    firewall = _get_backend(backend)
    backend_name = getattr(firewall, "name", "nftables")
    try:
        with get_connection() as conn:
            # Serialize protection transitions across threads and processes.
            # The firewall command has a five-second timeout, below SQLite's
            # configured ten-second busy timeout.
            conn.execute("BEGIN IMMEDIATE")
            device = conn.execute(
                "SELECT * FROM devices WHERE device_uid=?", (uid,)
            ).fetchone()
            if device is None:
                raise LookupError("device not found")

            existing = conn.execute(
                """SELECT * FROM network_protections
                   WHERE device_uid=? AND status='active'""",
                (uid,),
            ).fetchone()
            if existing:
                return {
                    "device_uid": uid,
                    "status": "isolated",
                    "ip_address": existing["ip_address"],
                    "already_isolated": True,
                }

            if device["trusted"]:
                raise PermissionError("Trusted devices cannot be isolated")
            if device["status"] not in {"active", "inactive"}:
                raise ValueError("Only active or inactive devices can be isolated")

            address = normalize_ip(device["ip_address"])
            # Keep the transaction open across the external operation so a
            # concurrent trust, lifecycle, or address change cannot invalidate
            # the decision between validation and persistence.
            result = firewall.isolate(address)
            if not result.success:
                raise FirewallError("Firewall did not confirm isolation")

            current = conn.execute(
                "SELECT * FROM devices WHERE device_uid=?", (uid,)
            ).fetchone()
            if (
                current is None
                or current["trusted"]
                or current["status"] not in {"active", "inactive"}
                or normalize_ip(current["ip_address"]) != address
            ):
                raise ValueError("Device eligibility changed during isolation")

            now = utc_now()
            conn.execute(
                """INSERT INTO network_protections
                   (device_uid,ip_address,backend,status,reason,isolated_at,released_at)
                   VALUES (?,?,?,'active',?,?,NULL)
                   ON CONFLICT(device_uid) DO UPDATE SET
                     ip_address=excluded.ip_address,
                     backend=excluded.backend,
                     status='active', reason=excluded.reason,
                     isolated_at=excluded.isolated_at, released_at=NULL""",
                (uid, address, backend_name, reason.strip(), now),
            )
            conn.execute(
                "UPDATE devices SET status='isolated',updated_at=? WHERE device_uid=?",
                (now, uid),
            )
            _record_action(
                conn, device_uid=uid, action="isolate", status="success",
                ip_address=address, backend_name=backend_name,
                reason=reason.strip(), details={"changed": bool(result.changed)},
            )
            log_event(
                "protection.device_isolated",
                "Firewall confirmed device network isolation",
                severity="warning", source="protection_manager",
                device_uid=uid,
                details={"ip_address": address, "backend": backend_name},
                connection=conn,
            )
    except Exception:
        if "address" in locals() and (
            "result" not in locals() or not result.success
        ):
            try:
                with get_connection() as conn:
                    _record_action(
                        conn, device_uid=uid, action="isolate", status="failed",
                        ip_address=address, backend_name=backend_name,
                        reason=reason.strip(),
                        details={"error": "FirewallError"},
                    )
                    log_event(
                        "protection.isolation_failed",
                        "Network isolation was not confirmed by the firewall",
                        severity="error", source="protection_manager",
                        device_uid=uid,
                        details={"ip_address": address}, connection=conn,
                    )
            except Exception:
                # Preserve the original firewall failure. The caller still
                # receives a failure and no isolation is reported as active.
                pass
        # Persistence or revalidation failed after a confirmed firewall
        # change. Do not claim compensation unless the backend confirms it.
        if "result" in locals() and result.success and result.changed:
            try:
                compensation = firewall.release(address)
                if not compensation.success:
                    raise FirewallError("Firewall rejected isolation compensation")
            except Exception as compensation_error:
                try:
                    with get_connection() as conn:
                        log_event(
                            "protection.compensation_failed",
                            "Firewall isolation compensation could not be confirmed",
                            severity="critical", source="protection_manager",
                            device_uid=uid,
                            details={"operation": "release", "ip_address": address},
                            connection=conn,
                        )
                finally:
                    raise FirewallError(
                        "Protection persistence failed and firewall compensation was not confirmed"
                    ) from compensation_error
        raise

    return {
        "device_uid": uid,
        "status": "isolated",
        "ip_address": address,
        "backend": backend_name,
        "already_isolated": False,
    }


def release_device(
    device_uid: str,
    reason: str = "Manual release",
    *,
    backend: FirewallBackend | None = None,
) -> dict[str, Any]:
    """Release a device only after the firewall confirms rule removal."""
    _require_enabled()

    if not isinstance(device_uid, str) or not device_uid.strip():
        raise ValueError("device_uid is required")
    if not isinstance(reason, str) or not reason.strip() or len(reason) > 500:
        raise ValueError("reason must contain 1 to 500 characters")

    uid = device_uid.strip()

    firewall = _get_backend(backend)
    try:
        with get_connection() as conn:
            conn.execute("BEGIN IMMEDIATE")
            protection = conn.execute(
                """SELECT * FROM network_protections
                   WHERE device_uid=? AND status='active'""",
                (uid,),
            ).fetchone()
            if protection is None:
                raise LookupError("No active network protection exists")

            device = conn.execute(
                "SELECT status FROM devices WHERE device_uid=?", (uid,)
            ).fetchone()
            if device is None:
                raise LookupError("device not found")

            address = normalize_ip(protection["ip_address"])
            backend_name = getattr(firewall, "name", protection["backend"])
            other_reference = conn.execute(
                """SELECT 1 FROM network_protections
                   WHERE status='active' AND ip_address=? AND device_uid<>?
                   LIMIT 1""",
                (address, uid),
            ).fetchone()

            # Keep the shared address blocked until its final active owner is
            # released. Device B may use the same address as device A.
            if other_reference is not None:
                result = FirewallResult(
                    True, "release", address, backend_name, changed=False
                )
            else:
                result = firewall.release(address)
                if not result.success:
                    raise FirewallError("Firewall did not confirm release")

            current = conn.execute(
                """SELECT status,ip_address FROM network_protections
                   WHERE device_uid=?""",
                (uid,),
            ).fetchone()
            if (
                current is None
                or current["status"] != "active"
                or normalize_ip(current["ip_address"]) != address
            ):
                raise ValueError("Protection state changed during release")

            now = utc_now()
            conn.execute(
                """UPDATE network_protections SET status='released',released_at=?
                   WHERE device_uid=? AND status='active'""",
                (now, uid),
            )
            conn.execute(
                """UPDATE devices SET status='recovering',updated_at=?
                   WHERE device_uid=? AND status='isolated'""",
                (now, uid),
            )
            _record_action(
                conn, device_uid=uid, action="release", status="success",
                ip_address=address, backend_name=backend_name,
                reason=reason.strip(),
                details={"changed": bool(result.changed),
                         "shared_address_retained": other_reference is not None},
            )
            log_event(
                "protection.device_released",
                "Device protection was released; shared firewall addresses are retained",
                source="protection_manager", device_uid=uid,
                details={"ip_address": address, "backend": backend_name,
                         "shared_address_retained": other_reference is not None},
                connection=conn,
            )
    except Exception:
        if "address" in locals() and (
            "result" not in locals() or not result.success
        ):
            try:
                with get_connection() as conn:
                    _record_action(
                        conn, device_uid=uid, action="release", status="failed",
                        ip_address=address,
                        backend_name=locals().get("backend_name", "nftables"),
                        reason=reason.strip(),
                        details={"error": "FirewallError"},
                    )
                    log_event(
                        "protection.release_failed",
                        "Firewall did not confirm removal of the isolation rule",
                        severity="error", source="protection_manager",
                        device_uid=uid,
                        details={"ip_address": address}, connection=conn,
                    )
            except Exception:
                pass
        if "result" in locals() and result.success and result.changed:
            try:
                compensation = firewall.isolate(address)
                if not compensation.success:
                    raise FirewallError("Firewall rejected release compensation")
            except Exception as compensation_error:
                try:
                    with get_connection() as conn:
                        log_event(
                            "protection.compensation_failed",
                            "Firewall re-isolation compensation could not be confirmed",
                            severity="critical", source="protection_manager",
                            device_uid=uid,
                            details={"operation": "isolate", "ip_address": address},
                            connection=conn,
                        )
                finally:
                    raise FirewallError(
                        "Protection persistence failed and firewall compensation was not confirmed"
                    ) from compensation_error
        raise

    return {
        "device_uid": uid,
        "status": "recovering",
        "ip_address": address,
        "backend": backend_name,
    }


def get_protection_status() -> dict[str, Any]:
    with get_connection() as conn:
        active = conn.execute(
            "SELECT COUNT(*) FROM network_protections WHERE status='active'"
        ).fetchone()[0]
        total_actions = conn.execute(
            "SELECT COUNT(*) FROM network_protection_actions"
        ).fetchone()[0]
        rows = conn.execute(
            """SELECT device_uid,ip_address,backend,status,reason,
                      isolated_at,released_at
               FROM network_protections ORDER BY isolated_at DESC"""
        ).fetchall()

    return {
        "enabled": os.environ.get(
            "IOT_ENFORCEMENT_ENABLED", "false"
        ).lower() == "true",
        "active_isolations": active,
        "total_actions": total_actions,
        "protections": [dict(row) for row in rows],
    }


def get_protection_history(device_uid: str, limit: int = 50) -> list[dict]:
    if not isinstance(limit, int) or not 1 <= limit <= 500:
        raise ValueError("limit must be between 1 and 500")

    with get_connection() as conn:
        rows = conn.execute(
            """SELECT * FROM network_protection_actions
               WHERE device_uid=? ORDER BY id DESC LIMIT ?""",
            (device_uid, limit),
        ).fetchall()

    result = []
    for row in rows:
        item = dict(row)
        item["details"] = json.loads(item.pop("details_json"))
        result.append(item)
    return result


AUTO_ISOLATION_ASSESSMENTS_REQUIRED = 3
AUTO_ISOLATION_WINDOW_MINUTES = 5
AUTO_ISOLATION_MIN_SCORE = 95.0


def maybe_auto_isolate(
    assessment: dict[str, Any] | None,
    *,
    backend: FirewallBackend | None = None,
) -> dict[str, Any]:
    """Apply strict, opt-in automatic isolation after repeated critical findings.

    The latest three persisted assessments must all be anomalous, critical,
    score >= 95, and no older than five minutes. The current assessment must
    also be the newest persisted assessment for this device.
    """
    if os.environ.get("IOT_AUTO_ISOLATION_ENABLED", "false").lower() != "true":
        return {"isolated": False, "reason": "automatic_isolation_disabled"}

    if os.environ.get("IOT_ENFORCEMENT_ENABLED", "false").lower() != "true":
        return {"isolated": False, "reason": "network_enforcement_disabled"}

    if not isinstance(assessment, dict) or assessment.get("skipped"):
        return {"isolated": False, "reason": "assessment_unavailable"}

    device_uid = assessment.get("device_uid")
    telemetry_id = assessment.get("telemetry_id")
    if (
        not isinstance(device_uid, str)
        or not device_uid.strip()
        or not isinstance(telemetry_id, int)
        or isinstance(telemetry_id, bool)
    ):
        return {"isolated": False, "reason": "invalid_assessment_reference"}

    with get_connection() as conn:
        device = conn.execute(
            "SELECT trusted,status FROM devices WHERE device_uid=?",
            (device_uid.strip(),),
        ).fetchone()

        if device is None:
            return {"isolated": False, "reason": "device_not_found"}

        if device["trusted"]:
            return {"isolated": False, "reason": "trusted_device"}

        if device["status"] not in {"active", "inactive"}:
            return {"isolated": False, "reason": "device_not_eligible"}

        rows = conn.execute(
            """SELECT telemetry_id,assessed_at,anomaly,anomaly_score,severity
               FROM threat_assessments
               WHERE device_uid=?
               ORDER BY id DESC LIMIT ?""",
            (device_uid.strip(), AUTO_ISOLATION_ASSESSMENTS_REQUIRED),
        ).fetchall()

    if len(rows) != AUTO_ISOLATION_ASSESSMENTS_REQUIRED:
        return {"isolated": False, "reason": "insufficient_assessments"}

    # Ignore a stale callback if a newer assessment has already been saved.
    if rows[0]["telemetry_id"] != telemetry_id:
        return {"isolated": False, "reason": "assessment_is_not_latest"}

    now = datetime.now(timezone.utc)
    cutoff = now - timedelta(minutes=AUTO_ISOLATION_WINDOW_MINUTES)

    for row in rows:
        if (
            row["anomaly"] != 1
            or row["severity"] != "critical"
            or row["anomaly_score"] < AUTO_ISOLATION_MIN_SCORE
        ):
            return {"isolated": False, "reason": "critical_threshold_not_met"}

        try:
            assessed_at = datetime.fromisoformat(row["assessed_at"])
            if assessed_at.tzinfo is None:
                assessed_at = assessed_at.replace(tzinfo=timezone.utc)
            assessed_at = assessed_at.astimezone(timezone.utc)
        except (TypeError, ValueError):
            return {"isolated": False, "reason": "invalid_assessment_timestamp"}

        if assessed_at < cutoff or assessed_at > now + timedelta(seconds=30):
            return {"isolated": False, "reason": "assessments_outside_time_window"}

    result = isolate_device(
        device_uid.strip(),
        reason=(
            "Automatic isolation: three consecutive critical anomaly "
            "assessments (score >= 95) within five minutes"
        ),
        backend=backend,
    )

    return {
        "isolated": result.get("status") == "isolated",
        "reason": "repeated_critical_anomalies",
        "protection": result,
    }
