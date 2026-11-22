import os
import tempfile
import unittest
from datetime import datetime, timezone
from pathlib import Path
from unittest.mock import patch

from src import database
from src.event_logger import list_events, log_event
from src.event_retention import purge_expired_events


class EventRetentionTests(unittest.TestCase):
    def setUp(self):
        self.temp_dir = tempfile.TemporaryDirectory()
        self.old_db = os.environ.get("IOT_SECURITY_DB")
        os.environ["IOT_SECURITY_DB"] = str(
            Path(self.temp_dir.name) / "retention.db"
        )
        database.create_database()

    def tearDown(self):
        if self.old_db is None:
            os.environ.pop("IOT_SECURITY_DB", None)
        else:
            os.environ["IOT_SECURITY_DB"] = self.old_db
        self.temp_dir.cleanup()

    def test_deletes_only_expired_events_and_records_cleanup(self):
        fixed_now = datetime(2026, 11, 22, 12, 0, tzinfo=timezone.utc)
        log_event("test.old", "Expired event")
        log_event("test.recent", "Recent event")

        with database.get_connection() as conn:
            conn.execute(
                "UPDATE system_events SET created_at=? WHERE event_type=?",
                ("2026-10-01T00:00:00+00:00", "test.old"),
            )
            conn.execute(
                "UPDATE system_events SET created_at=? WHERE event_type=?",
                ("2026-11-20T00:00:00+00:00", "test.recent"),
            )
            conn.execute(
                "INSERT INTO alerts(timestamp,attack_type,severity,action) "
                "VALUES(?,?,?,?)",
                ("2026-01-01T00:00:00Z", "test", "Low", "none"),
            )

        result = purge_expired_events(30, now=fixed_now)

        self.assertEqual(result["deleted_count"], 1)
        events = list_events(limit=20)
        event_types = {event["event_type"] for event in events}
        self.assertNotIn("test.old", event_types)
        self.assertIn("test.recent", event_types)
        self.assertIn("event_retention.cleanup", event_types)

        cleanup = next(
            event for event in events
            if event["event_type"] == "event_retention.cleanup"
        )
        self.assertEqual(cleanup["details"]["deleted_count"], 1)
        self.assertEqual(cleanup["details"]["retention_days"], 30)

        with database.get_connection() as conn:
            self.assertEqual(
                conn.execute("SELECT COUNT(*) FROM alerts").fetchone()[0],
                1,
            )

    def test_event_exactly_at_cutoff_is_retained(self):
        fixed_now = datetime(2026, 11, 22, 12, 0, tzinfo=timezone.utc)
        log_event("test.at_cutoff", "Event exactly at cutoff")
        log_event("test.before_cutoff", "Event one second before cutoff")

        with database.get_connection() as conn:
            conn.execute(
                "UPDATE system_events SET created_at=? WHERE event_type=?",
                ("2026-10-23T12:00:00+00:00", "test.at_cutoff"),
            )
            conn.execute(
                "UPDATE system_events SET created_at=? WHERE event_type=?",
                ("2026-10-23T11:59:59+00:00", "test.before_cutoff"),
            )

        result = purge_expired_events(30, now=fixed_now)

        self.assertEqual(result["deleted_count"], 1)
        event_types = {
            event["event_type"] for event in list_events(limit=20)
        }
        self.assertIn("test.at_cutoff", event_types)
        self.assertNotIn("test.before_cutoff", event_types)

    def test_audit_failure_rolls_back_event_deletion(self):
        log_event("test.expired", "Expired event")

        with database.get_connection() as conn:
            conn.execute(
                "UPDATE system_events SET created_at=? WHERE event_type=?",
                ("2026-01-01T00:00:00+00:00", "test.expired"),
            )

        with patch(
            "src.event_retention.log_event",
            side_effect=RuntimeError("simulated audit failure"),
        ):
            with self.assertRaisesRegex(RuntimeError, "simulated audit failure"):
                purge_expired_events(
                    30,
                    now=datetime(2026, 11, 22, 12, 0, tzinfo=timezone.utc),
                )

        events = list_events(limit=20)
        self.assertIn(
            "test.expired",
            {event["event_type"] for event in events},
        )
        self.assertNotIn(
            "event_retention.cleanup",
            {event["event_type"] for event in events},
        )

    def test_zero_expired_events_still_records_cleanup(self):
        result = purge_expired_events(
            90,
            now=datetime(2026, 11, 22, tzinfo=timezone.utc),
        )
        self.assertEqual(result["deleted_count"], 0)
        self.assertEqual(
            list_events(limit=5)[0]["event_type"],
            "event_retention.cleanup",
        )

    def test_invalid_retention_period_is_rejected(self):
        for value in (0, -1, True, 1.5, "30"):
            with self.subTest(value=value):
                with self.assertRaises(ValueError):
                    purge_expired_events(value)

    def test_naive_datetime_is_rejected(self):
        with self.assertRaisesRegex(ValueError, "timezone-aware"):
            purge_expired_events(
                30,
                now=datetime(2026, 11, 22, 12, 0),
            )


if __name__ == "__main__":
    unittest.main()
