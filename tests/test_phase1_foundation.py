import os, sqlite3, tempfile, unittest
from pathlib import Path
from src import database
from src.device_manager import (get_device, register_device, update_device_status,
                                mark_device_seen)
from src.event_logger import list_events, log_event
from src.health_checker import get_system_health
from src.config_manager import get_config, list_config, set_config

class PhaseOneFoundationTests(unittest.TestCase):
    def setUp(self):
        self.temp_dir = tempfile.TemporaryDirectory()
        self.old_db = os.environ.get("IOT_SECURITY_DB")
        os.environ["IOT_SECURITY_DB"] = str(Path(self.temp_dir.name) / "test.db")
        database.create_database()

    def tearDown(self):
        if self.old_db is None: os.environ.pop("IOT_SECURITY_DB", None)
        else: os.environ["IOT_SECURITY_DB"] = self.old_db
        self.temp_dir.cleanup()

    def test_schema_is_idempotent_and_preserves_alerts(self):
        database.insert_alert("2026-01-01T00:00:00Z", "test", "Low", "none")
        database.create_database()
        with database.get_connection() as conn:
            self.assertEqual(conn.execute("SELECT COUNT(*) FROM alerts").fetchone()[0], 1)
            tables = {r["name"] for r in conn.execute("SELECT name FROM sqlite_master WHERE type='table'")}
        self.assertTrue({"devices","system_events","system_config","schema_migrations"} <= tables)

    def test_device_registration_and_normalized_mac(self):
        d = register_device("sensor-1", "Temperature", device_type="sensor",
                            mac_address="AA:BB:CC:DD:EE:FF", communication_type="mqtt",
                            metadata={"room":"lab"})
        self.assertEqual(d["status"], "registered")
        self.assertEqual(d["mac_address"], "aa:bb:cc:dd:ee:ff")
        self.assertEqual(get_device("sensor-1")["metadata"]["room"], "lab")

    def test_duplicate_uid_and_mac_rejected(self):
        register_device("sensor-1", "Sensor", mac_address="AA:BB:CC:DD:EE:FF")
        with self.assertRaises(sqlite3.IntegrityError): register_device("sensor-1", "Duplicate")
        with self.assertRaises(sqlite3.IntegrityError):
            register_device(
                "sensor-2",
                "Duplicate MAC",
                mac_address="AA-BB-CC-DD-EE-FF",
            )

    def test_lifecycle_guards_and_audit(self):
        register_device("sensor-1", "Sensor")
        update_device_status("sensor-1", "active")
        update_device_status("sensor-1", "isolated")
        with self.assertRaises(ValueError): update_device_status("sensor-1", "active")
        update_device_status("sensor-1", "recovering")
        with self.assertRaises(ValueError):
            update_device_status("sensor-1", "active")
        self.assertEqual(get_device("sensor-1")["status"], "recovering")
        self.assertGreaterEqual(len(list_events(device_uid="sensor-1")), 4)

    def test_unknown_device_and_invalid_mac(self):
        with self.assertRaises(LookupError): update_device_status("missing", "active")
        with self.assertRaises(ValueError): register_device("bad", "Bad", mac_address="invalid")

    def test_seen_timestamp_and_health(self):
        register_device("sensor-1", "Sensor")
        mark_device_seen("sensor-1")
        self.assertIsNotNone(get_device("sensor-1")["last_seen_at"])
        self.assertEqual(get_system_health()["status"], "ok")

    def test_persistent_configuration_round_trip(self):
        set_config("monitoring.interval_seconds", 5, description="Polling interval")
        self.assertEqual(get_config("monitoring.interval_seconds"), 5)
        self.assertEqual(get_config("missing", "fallback"), "fallback")
        self.assertEqual(list_config()[0]["description"], "Polling interval")
        set_config("monitoring.interval_seconds", 10)
        self.assertEqual(get_config("monitoring.interval_seconds"), 10)

    def test_event_validation(self):
        with self.assertRaises(ValueError): log_event("", "invalid")
        log_event("test.event", "test", details={"number": 1})
        self.assertEqual(list_events(limit=5)[0]["details"]["number"], 1)
        with self.assertRaises(ValueError): list_events(limit=501)

if __name__ == "__main__": unittest.main()
