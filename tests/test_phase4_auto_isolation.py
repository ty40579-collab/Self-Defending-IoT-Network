
import os
import tempfile
import unittest
from datetime import datetime, timedelta, timezone
from pathlib import Path
from unittest.mock import patch

from src import database
from src.database import utc_now
from src.device_manager import register_device, update_device_status, get_device
from src.monitoring_manager import record_telemetry
from src.protection_manager import maybe_auto_isolate
from src.network_firewall import FirewallResult


class FakeFirewall:
    name = "fake-auto-firewall"

    def __init__(self):
        self.blocked = set()

    def isolate(self, ip_address):
        changed = ip_address not in self.blocked
        self.blocked.add(ip_address)
        return FirewallResult(
            True, "isolate", ip_address, self.name, changed
        )

    def release(self, ip_address):
        changed = ip_address in self.blocked
        self.blocked.discard(ip_address)
        return FirewallResult(
            True, "release", ip_address, self.name, changed
        )


class AutomaticIsolationTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.old_db = os.environ.get("IOT_SECURITY_DB")
        os.environ["IOT_SECURITY_DB"] = str(
            Path(self.temp.name) / "auto-isolation.db"
        )
        self.old_auto = os.environ.get("IOT_AUTO_ISOLATION_ENABLED")
        self.old_enforcement = os.environ.get("IOT_ENFORCEMENT_ENABLED")

        os.environ["IOT_AUTO_ISOLATION_ENABLED"] = "true"
        os.environ["IOT_ENFORCEMENT_ENABLED"] = "true"

        database.create_database()
        register_device(
            "auto-sensor",
            "Automatic Isolation Sensor",
            ip_address="8.8.8.8",
            communication_type="mqtt",
        )
        update_device_status("auto-sensor", "active")
        self.firewall = FakeFirewall()

    def tearDown(self):
        if self.old_db is None:
            os.environ.pop("IOT_SECURITY_DB", None)
        else:
            os.environ["IOT_SECURITY_DB"] = self.old_db

        if self.old_auto is None:
            os.environ.pop("IOT_AUTO_ISOLATION_ENABLED", None)
        else:
            os.environ["IOT_AUTO_ISOLATION_ENABLED"] = self.old_auto

        if self.old_enforcement is None:
            os.environ.pop("IOT_ENFORCEMENT_ENABLED", None)
        else:
            os.environ["IOT_ENFORCEMENT_ENABLED"] = self.old_enforcement

        self.temp.cleanup()

    def add_assessments(self, values, age_seconds=0):
        latest_telemetry_id = None
        for anomaly, score, severity in values:
            telemetry_id = record_telemetry(
                "auto-sensor",
                "iot/auto-sensor/telemetry",
                {"temperature_c": 25.0},
                20,
            )
            latest_telemetry_id = telemetry_id
            assessed = (
                datetime.now(timezone.utc)
                - timedelta(seconds=age_seconds)
            ).isoformat()

            with database.get_connection() as conn:
                conn.execute(
                    """INSERT INTO threat_assessments
                       (telemetry_id,device_uid,assessed_at,anomaly,
                        anomaly_score,confidence,severity,ml_prediction,
                        reasons_json,model_version)
                       VALUES (?,?,?,?,?,?,?,?,?,?)""",
                    (
                        telemetry_id, "auto-sensor", assessed,
                        int(anomaly), score, min(score / 100, 1.0),
                        severity, -1 if anomaly else 1,
                        '["test_assessment"]', "test-model",
                    ),
                )

        return {
            "device_uid": "auto-sensor",
            "telemetry_id": latest_telemetry_id,
            "anomaly": True,
            "anomaly_score": 99.0,
            "severity": "critical",
        }

    def qualifying_values(self, count=3):
        return [(True, 99.0, "critical")] * count

    def test_three_consecutive_critical_assessments_isolate_device(self):
        assessment = self.add_assessments(self.qualifying_values())

        result = maybe_auto_isolate(
            assessment, backend=self.firewall
        )

        self.assertTrue(result["isolated"])
        self.assertEqual(get_device("auto-sensor")["status"], "isolated")
        self.assertIn("8.8.8.8", self.firewall.blocked)

    def test_automatic_isolation_is_disabled_by_default(self):
        os.environ.pop("IOT_AUTO_ISOLATION_ENABLED", None)
        assessment = self.add_assessments(self.qualifying_values())

        result = maybe_auto_isolate(
            assessment, backend=self.firewall
        )

        self.assertFalse(result["isolated"])
        self.assertEqual(
            result["reason"], "automatic_isolation_disabled"
        )
        self.assertEqual(self.firewall.blocked, set())

    def test_enforcement_must_also_be_enabled(self):
        os.environ["IOT_ENFORCEMENT_ENABLED"] = "false"
        assessment = self.add_assessments(self.qualifying_values())

        result = maybe_auto_isolate(
            assessment, backend=self.firewall
        )

        self.assertFalse(result["isolated"])
        self.assertEqual(
            result["reason"], "network_enforcement_disabled"
        )
        self.assertEqual(self.firewall.blocked, set())

    def test_two_assessments_are_not_enough(self):
        assessment = self.add_assessments(self.qualifying_values(2))

        result = maybe_auto_isolate(
            assessment, backend=self.firewall
        )

        self.assertFalse(result["isolated"])
        self.assertEqual(result["reason"], "insufficient_assessments")

    def test_normal_assessment_breaks_consecutive_sequence(self):
        values = [
            (True, 99.0, "critical"),
            (False, 0.0, "low"),
            (True, 99.0, "critical"),
        ]
        assessment = self.add_assessments(values)

        result = maybe_auto_isolate(
            assessment, backend=self.firewall
        )

        self.assertFalse(result["isolated"])
        self.assertEqual(
            result["reason"], "critical_threshold_not_met"
        )

    def test_score_below_95_does_not_isolate(self):
        values = [
            (True, 99.0, "critical"),
            (True, 94.99, "critical"),
            (True, 99.0, "critical"),
        ]
        assessment = self.add_assessments(values)

        result = maybe_auto_isolate(
            assessment, backend=self.firewall
        )

        self.assertFalse(result["isolated"])
        self.assertEqual(
            result["reason"], "critical_threshold_not_met"
        )

    def test_old_assessments_do_not_trigger_isolation(self):
        assessment = self.add_assessments(
            self.qualifying_values(), age_seconds=301
        )

        result = maybe_auto_isolate(
            assessment, backend=self.firewall
        )

        self.assertFalse(result["isolated"])
        self.assertEqual(
            result["reason"], "assessments_outside_time_window"
        )

    def test_trusted_device_is_never_automatically_isolated(self):
        with database.get_connection() as conn:
            conn.execute(
                "UPDATE devices SET trusted=1 WHERE device_uid=?",
                ("auto-sensor",),
            )

        assessment = self.add_assessments(self.qualifying_values())
        result = maybe_auto_isolate(
            assessment, backend=self.firewall
        )

        self.assertFalse(result["isolated"])
        self.assertEqual(result["reason"], "trusted_device")
        self.assertEqual(self.firewall.blocked, set())

    def test_stale_assessment_callback_is_ignored(self):
        assessment = self.add_assessments(self.qualifying_values())
        assessment["telemetry_id"] -= 1

        result = maybe_auto_isolate(
            assessment, backend=self.firewall
        )

        self.assertFalse(result["isolated"])
        self.assertEqual(
            result["reason"], "assessment_is_not_latest"
        )
        self.assertEqual(self.firewall.blocked, set())

    def test_skipped_assessment_is_ignored(self):
        result = maybe_auto_isolate({
            "device_uid": "auto-sensor",
            "telemetry_id": 1,
            "skipped": True,
        }, backend=self.firewall)

        self.assertFalse(result["isolated"])
        self.assertEqual(result["reason"], "assessment_unavailable")

    def test_policy_failure_does_not_break_telemetry_collection(self):
        from src.intelligence_manager import assess_telemetry
        from src.protection_manager import maybe_auto_isolate as policy

        assessment = {
            "device_uid": "auto-sensor",
            "telemetry_id": 999,
            "anomaly": True,
            "anomaly_score": 99.0,
            "severity": "critical",
        }

        with patch(
            "src.intelligence_manager.assess_telemetry",
            return_value=assessment,
        ), patch(
            "src.protection_manager.maybe_auto_isolate",
            side_effect=RuntimeError("simulated policy failure"),
        ):
            telemetry_id = record_telemetry(
                "auto-sensor",
                "iot/auto-sensor/telemetry",
                {"temperature_c": 26.0},
                20,
            )

        self.assertIsInstance(telemetry_id, int)
        with database.get_connection() as conn:
            count = conn.execute(
                "SELECT COUNT(*) FROM mqtt_telemetry WHERE device_uid=?",
                ("auto-sensor",),
            ).fetchone()[0]
        self.assertEqual(count, 1)


if __name__ == "__main__":
    unittest.main()
