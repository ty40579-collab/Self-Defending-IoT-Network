"""Read-only health checks for application persistence and registries."""
from __future__ import annotations
from datetime import datetime, timezone
from src.database import get_connection

def get_system_health() -> dict:
    checks = {}
    try:
        with get_connection() as conn:
            conn.execute("SELECT 1").fetchone()
            counts = {row["status"]: row["count"] for row in conn.execute(
                "SELECT status,COUNT(*) AS count FROM devices GROUP BY status")}
            event_count = conn.execute("SELECT COUNT(*) FROM system_events").fetchone()[0]
            alert_count = conn.execute("SELECT COUNT(*) FROM alerts").fetchone()[0]
        checks = {"database": {"status": "ok"},
                  "registry": {"status": "ok", "devices_by_status": counts},
                  "event_log": {"status": "ok", "total_events": event_count},
                  "alerts": {"status": "ok", "total_alerts": alert_count}}
        overall = "ok"
    except Exception:
        checks["database"] = {
            "status": "error",
            "message": "Database health check failed"
        }
        overall = "degraded"
    return {"status": overall,
            "checked_at": datetime.now(timezone.utc).isoformat(timespec="seconds"),
            "checks": checks}
