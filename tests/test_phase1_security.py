import importlib
import io
import os
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from src import database
from src.device_manager import register_device, update_device_status, get_device
from src.event_logger import log_event
from src.health_checker import get_system_health


class PhaseOneSecurityTests(unittest.TestCase):
    def setUp(self):
        self.temp_dir = tempfile.TemporaryDirectory()
        self.old_db = os.environ.get("IOT_SECURITY_DB")
        os.environ["IOT_SECURITY_DB"] = str(
            Path(self.temp_dir.name) / "security_test.db"
        )
        database.create_database()

    def tearDown(self):
        if self.old_db is None:
            os.environ.pop("IOT_SECURITY_DB", None)
        else:
            os.environ["IOT_SECURITY_DB"] = self.old_db
        self.temp_dir.cleanup()

    def test_non_json_device_metadata_rejected(self):
        with self.assertRaisesRegex(ValueError, "JSON-serializable"):
            register_device(
                "bad-metadata",
                "Bad Metadata",
                metadata={"invalid": object()},
            )

    def test_invalid_event_severity_rejected(self):
        with self.assertRaises(ValueError):
            log_event("test.event", "test", severity=[])

    def test_invalid_event_source_rejected(self):
        with self.assertRaises(ValueError):
            log_event("test.event", "test", source=None)

    def test_invalid_event_device_uid_rejected(self):
        with self.assertRaises(ValueError):
            log_event("test.event", "test", device_uid="   ")

    def test_non_json_event_details_rejected(self):
        with self.assertRaisesRegex(ValueError, "JSON-serializable"):
            log_event(
                "test.event",
                "test",
                details={"invalid": object()},
            )

    def test_database_health_error_does_not_leak_details(self):
        with patch(
            "src.health_checker.get_connection",
            side_effect=RuntimeError("SECRET_DATABASE_PATH"),
        ):
            health = get_system_health()

        self.assertEqual(health["status"], "degraded")
        self.assertEqual(
            health["checks"]["database"]["message"],
            "Database health check failed",
        )
        self.assertNotIn("SECRET_DATABASE_PATH", str(health))

    def test_csv_failure_does_not_leak_exception_details(self):
        app_module = importlib.import_module("app")
        app_module.app.config["TESTING"] = True

        with patch.object(
            app_module,
            "predict_file",
            side_effect=RuntimeError("SECRET_INTERNAL_ERROR"),
        ):
            response = app_module.app.test_client().post(
                "/upload",
                data={
                    "file": (
                        io.BytesIO(b"column1,column2\n1,2\n"),
                        "security_test.csv",
                    )
                },
                content_type="multipart/form-data",
            )

        self.assertEqual(response.status_code, 500)
        self.assertIn(
            b"CSV analysis failed. Check the server logs for details.",
            response.data,
        )
        self.assertNotIn(b"SECRET_INTERNAL_ERROR", response.data)


    def test_registration_and_audit_are_atomic(self):
        with patch(
            "src.device_manager.log_event",
            side_effect=RuntimeError("SIMULATED_AUDIT_FAILURE"),
        ):
            with self.assertRaisesRegex(RuntimeError, "SIMULATED_AUDIT_FAILURE"):
                register_device("atomic-registration", "Atomic Sensor")

        with database.get_connection() as conn:
            count = conn.execute(
                "SELECT COUNT(*) FROM devices WHERE device_uid=?",
                ("atomic-registration",),
            ).fetchone()[0]

        self.assertEqual(count, 0)

    def test_status_change_and_audit_are_atomic(self):
        register_device("atomic-status", "Atomic Status Sensor")

        with patch(
            "src.device_manager.log_event",
            side_effect=RuntimeError("SIMULATED_AUDIT_FAILURE"),
        ):
            with self.assertRaisesRegex(RuntimeError, "SIMULATED_AUDIT_FAILURE"):
                update_device_status("atomic-status", "active")

        self.assertEqual(get_device("atomic-status")["status"], "registered")

    def test_hyphenated_mac_is_stored_canonically(self):
        device = register_device(
            "canonical-mac",
            "Canonical MAC Sensor",
            mac_address="AA-BB-CC-DD-EE-FF",
        )

        self.assertEqual(
            device["mac_address"],
            "aa:bb:cc:dd:ee:ff",
        )


if __name__ == "__main__":
    unittest.main()
