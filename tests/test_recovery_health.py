
import json
import os
import tempfile
import unittest
from datetime import datetime, timedelta, timezone
from pathlib import Path
from unittest.mock import patch

from src import database
from src.database import get_connection
from src.device_manager import register_device, update_device_status, get_device
from src.protection_manager import get_recovery_status, complete_device_recovery


class RecoveryHealthTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.old_db = os.environ.get("IOT_SECURITY_DB")
        self.old_required = os.environ.get("IOT_RECOVERY_REQUIRED_ASSESSMENTS")
        self.old_age = os.environ.get("IOT_RECOVERY_TELEMETRY_MAX_AGE_SECONDS")
        os.environ["IOT_SECURITY_DB"] = str(Path(self.temp.name) / "recovery.db")
        os.environ["IOT_RECOVERY_REQUIRED_ASSESSMENTS"] = "3"
        os.environ["IOT_RECOVERY_TELEMETRY_MAX_AGE_SECONDS"] = "300"
        database.create_database()

        register_device("recovery-sensor", "Recovery Sensor",
                        ip_address="192.0.2.80")
        update_device_status("recovery-sensor", "active")
        update_device_status("recovery-sensor", "isolated")
        update_device_status("recovery-sensor", "recovering")

        self.release_time = datetime.now(timezone.utc) - timedelta(seconds=60)
        self.release_text = self.release_time.isoformat(timespec="seconds")
        with get_connection() as conn:
            conn.execute(
                """INSERT INTO network_protections
                   (device_uid,ip_address,backend,status,reason,isolated_at,released_at)
                   VALUES (?,?,?,?,?,?,?)""",
                ("recovery-sensor", "192.0.2.80", "test", "released",
                 "test recovery", self.release_text, self.release_text),
            )

    def tearDown(self):
        for key, value in (
            ("IOT_SECURITY_DB", self.old_db),
            ("IOT_RECOVERY_REQUIRED_ASSESSMENTS", self.old_required),
            ("IOT_RECOVERY_TELEMETRY_MAX_AGE_SECONDS", self.old_age),
        ):
            if value is None:
                os.environ.pop(key, None)
            else:
                os.environ[key] = value
        self.temp.cleanup()

    def add_baseline(self):
        with get_connection() as conn:
            conn.execute(
                """INSERT INTO intelligence_baselines
                   (device_uid,feature_names_json,samples_json,statistics_json,
                    model_version,sample_count,trained_at)
                   VALUES (?,?,?,?,?,?,?)""",
                ("recovery-sensor", '["temperature"]', "[[20]]",
                 '{"temperature":{"median":20,"mad":1}}',
                 "test-model", 20, self.release_text),
            )

    def add_observations(self, *, count=3, assessments=3, anomaly_at=None,
                         stale=False):
        now = datetime.now(timezone.utc)
        with get_connection() as conn:
            for i in range(count):
                observed = now - timedelta(seconds=(400 if stale else 10-i))
                observed_text = observed.isoformat(timespec="seconds")
                cur = conn.execute(
                    """INSERT INTO mqtt_telemetry
                       (device_uid,topic,received_at,payload_json,
                        payload_bytes,numeric_features_json)
                       VALUES (?,?,?,?,?,?)""",
                    ("recovery-sensor", "test/topic", observed_text,
                     '{"temperature":20}', 18, '{"temperature":20}'),
                )
                if i < assessments:
                    anomaly = 1 if anomaly_at == i else 0
                    conn.execute(
                        """INSERT INTO threat_assessments
                           (telemetry_id,device_uid,assessed_at,anomaly,
                            anomaly_score,confidence,severity,ml_prediction,
                            reasons_json,model_version)
                           VALUES (?,?,?,?,?,?,?,?,?,?)""",
                        (cur.lastrowid, "recovery-sensor", observed_text,
                         anomaly, 0.0 if not anomaly else 90.0, 0.95,
                         "low" if not anomaly else "high",
                         1 if not anomaly else -1, "[]", "test-model"),
                    )

    def test_missing_baseline_blocks_recovery(self):
        report = get_recovery_status("recovery-sensor")
        self.assertFalse(report["eligible"])
        self.assertFalse(report["checks"]["trained_baseline_exists"])

    def test_insufficient_telemetry_blocks_recovery(self):
        self.add_baseline()
        self.add_observations(count=2)
        report = get_recovery_status("recovery-sensor")
        self.assertFalse(report["eligible"])
        self.assertFalse(report["checks"]["enough_fresh_telemetry"])

    def test_missing_assessment_blocks_recovery(self):
        self.add_baseline()
        self.add_observations(assessments=2)
        self.assertFalse(get_recovery_status("recovery-sensor")["eligible"])

    def test_anomalous_assessment_blocks_recovery(self):
        self.add_baseline()
        self.add_observations(anomaly_at=1)
        report = get_recovery_status("recovery-sensor")
        self.assertFalse(report["eligible"])
        self.assertFalse(report["checks"]["all_assessments_are_clean"])

    def test_stale_telemetry_blocks_recovery(self):
        self.add_baseline()
        __import__("os").environ["IOT_RECOVERY_TELEMETRY_MAX_AGE_SECONDS"] = "5"
        self.add_observations()
        self.assertFalse(get_recovery_status("recovery-sensor")["eligible"])

    def test_shared_ip_active_protection_blocks_recovery(self):
        self.add_baseline()
        self.add_observations()
        register_device("shared-sensor", "Shared Sensor",
                        ip_address="192.0.2.80")
        with get_connection() as conn:
            conn.execute(
                """INSERT INTO network_protections
                   (device_uid,ip_address,backend,status,reason,isolated_at)
                   VALUES (?,?,?,?,?,?)""",
                ("shared-sensor", "192.0.2.80", "test", "active",
                 "shared protection", self.release_text),
            )
        report = get_recovery_status("recovery-sensor")
        self.assertFalse(report["eligible"])
        self.assertFalse(report["checks"]["shared_ip_is_unblocked"])

    def test_successful_recovery_requires_all_checks(self):
        self.add_baseline()
        self.add_observations()
        result = complete_device_recovery("recovery-sensor")
        self.assertTrue(result["completed"])
        self.assertEqual(get_device("recovery-sensor")["status"], "active")
        with get_connection() as conn:
            event = conn.execute(
                """SELECT 1 FROM system_events
                   WHERE device_uid=? AND event_type=?""",
                ("recovery-sensor", "protection.device_recovery_completed"),
            ).fetchone()
        self.assertIsNotNone(event)

    def test_ineligible_recovery_never_activates_device(self):
        result = complete_device_recovery("recovery-sensor")
        self.assertFalse(result["completed"])
        self.assertEqual(get_device("recovery-sensor")["status"], "recovering")


class RecoveryApiTests(unittest.TestCase):
    def setUp(self):
        import app as app_module
        self.app_module = app_module
        self.client = app_module.app.test_client()
        self.env = patch.dict(os.environ, {
            "IOT_ENFORCEMENT_API_TOKEN": "test-secret-token",
        })
        self.env.start()
        self.headers = {"Authorization": "Bearer test-secret-token"}

    def tearDown(self):
        self.env.stop()

    def test_recovery_get_requires_authentication(self):
        response = self.client.get(
            "/api/protection/devices/sensor-1/recovery")
        self.assertEqual(response.status_code, 401)

    def test_recovery_post_requires_authentication(self):
        response = self.client.post(
            "/api/protection/devices/sensor-1/recover")
        self.assertEqual(response.status_code, 401)

    def test_recovery_get_returns_report(self):
        report = {"device_uid": "sensor-1", "eligible": False,
                  "checks": {}, "reasons": ["test"]}
        with patch("src.protection_manager.get_recovery_status",
                   return_value=report):
            response = self.client.get(
                "/api/protection/devices/sensor-1/recovery",
                headers=self.headers)
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.get_json(), report)

    def test_recovery_post_returns_conflict_when_ineligible(self):
        result = {"completed": False, "recovery": {"eligible": False}}
        with patch("src.protection_manager.complete_device_recovery",
                   return_value=result):
            response = self.client.post(
                "/api/protection/devices/sensor-1/recover",
                headers=self.headers)
        self.assertEqual(response.status_code, 409)
        self.assertFalse(response.get_json()["completed"])


if __name__ == "__main__":
    unittest.main()
