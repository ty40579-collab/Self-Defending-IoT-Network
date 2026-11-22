"""Transactional cleanup of expired system audit events."""
from __future__ import annotations

import json
from datetime import datetime, timedelta, timezone

from src.database import get_connection
from src.event_logger import log_event


def purge_expired_events(
    retention_days: int,
    *,
    now: datetime | None = None,
) -> dict:
    """Delete expired system events and record the cleanup atomically."""
    if isinstance(retention_days, bool) or not isinstance(retention_days, int):
        raise ValueError("retention_days must be a positive integer")
    if retention_days <= 0:
        raise ValueError("retention_days must be a positive integer")

    current = now or datetime.now(timezone.utc)
    if current.tzinfo is None or current.utcoffset() is None:
        raise ValueError("now must be timezone-aware")
    current = current.astimezone(timezone.utc).replace(microsecond=0)
    cutoff = (current - timedelta(days=retention_days)).isoformat(
        timespec="seconds"
    )
    current_text = current.isoformat(timespec="seconds")

    with get_connection() as conn:
        cursor = conn.execute(
            "DELETE FROM system_events WHERE created_at < ?",
            (cutoff,),
        )
        deleted_count = cursor.rowcount

        log_event(
            "event_retention.cleanup",
            "Expired system events cleanup completed",
            severity="info",
            source="maintenance",
            details={
                "retention_days": retention_days,
                "deleted_count": deleted_count,
                "cutoff_utc": cutoff,
            },
            connection=conn,
        )

    return {
        "status": "ok",
        "retention_days": retention_days,
        "deleted_count": deleted_count,
        "cutoff_utc": cutoff,
        "completed_at": current_text,
    }


def main() -> int:
    from src.config import settings

    result = purge_expired_events(settings.event_retention_days)
    print(json.dumps(result, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
