import json
import os
import tempfile
import unittest
from unittest.mock import patch
from pathlib import Path

from src import database
from src.device_manager import register_device
from src.monitoring_manager import record_telemetry
from src.intelligence_manager import (
    train_device_baseline, get_device_threats, get_threat_summary
)
from src.event_logger import list_events


class PhaseThreeIntelligenceTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.old_db = os.environ.get("IOT_SECURITY_DB")
        os.environ["IOT_SECURITY_DB"] = str(Path(self.temp.name) / "phase3.db")
        database.create_database()
        register_device("phase3-sensor", "Phase 3 Sensor", communication_type="mqtt")

    def tearDown(self):
        if self.old_db is None:
            os.environ.pop("IOT_SECURITY_DB", None)
        else:
            os.environ["IOT_SECURITY_DB"] = self.old_db
        self.temp.cleanup()

    def add_samples(self, count=30):
        for i in range(count):
            record_telemetry(
                "phase3-sensor", "iot/phase3-sensor/telemetry",
                {"temperature_c": 24 + (i % 5) * 0.1,
                 "humidity_percent": 50 + (i % 7) * 0.2},
                50,
            )

    def test_baseline_requires_minimum_samples(self):
        self.add_samples(19)
        with self.assertRaises(ValueError):
            train_device_baseline("phase3-sensor")

    def test_baseline_training_and_assessment(self):
        self.add_samples()
        result = train_device_baseline("phase3-sensor")
        self.assertEqual(result["sample_count"], 30)
        record_telemetry(
            "phase3-sensor", "iot/phase3-sensor/telemetry",
            {"temperature_c": 24.2, "humidity_percent": 50.4}, 50
        )
        detail = get_device_threats("phase3-sensor")
        self.assertIsNotNone(detail["baseline"])
        self.assertEqual(len(detail["assessments"]), 1)
        self.assertIn("anomaly_score", detail["assessments"][0])
        self.assertIn("confidence", detail["assessments"][0])

    def test_extreme_outlier_is_recorded(self):
        self.add_samples()
        train_device_baseline("phase3-sensor")
        record_telemetry(
            "phase3-sensor", "iot/phase3-sensor/telemetry",
            {"temperature_c": 500.0, "humidity_percent": 99.0}, 50
        )
        result = get_device_threats("phase3-sensor")
        self.assertTrue(result["assessments"][0]["anomaly"])
        self.assertGreaterEqual(result["assessments"][0]["anomaly_score"], 50)
        self.assertTrue(any(
            e["event_type"] == "intelligence.anomaly_detected"
            for e in list_events(device_uid="phase3-sensor")
        ))

    def test_untrained_device_has_no_false_assessment(self):
        record_telemetry(
            "phase3-sensor", "iot/phase3-sensor/telemetry",
            {"temperature_c": 22.0}, 20
        )
        self.assertEqual(get_device_threats("phase3-sensor")["assessments"], [])

    def test_baseline_training_unknown_device(self):
        with self.assertRaises(LookupError):
            train_device_baseline("missing-device")

    def test_threat_summary(self):
        self.add_samples()
        train_device_baseline("phase3-sensor")
        record_telemetry(
            "phase3-sensor", "iot/phase3-sensor/telemetry",
            {"temperature_c": 24.2, "humidity_percent": 50.4}, 50
        )
        summary = get_threat_summary()
        self.assertEqual(summary["trained_baselines"], 1)
        self.assertEqual(summary["assessments"], 1)

    def test_flask_intelligence_routes(self):
        import app as flask_app
        flask_app.app.config["TESTING"] = True
        client = flask_app.app.test_client()
        self.assertEqual(client.get("/api/intelligence/summary").status_code, 200)
        self.assertEqual(
            client.get("/api/intelligence/devices/missing/threats").status_code,
            404,
        )
        self.assertEqual(
            client.post(
                "/api/intelligence/devices/phase3-sensor/baseline",
                json={"unknown": 1},
            ).status_code,
            400,
        )


    def test_baseline_keeps_features_present_in_at_least_80_percent(self):
        for i in range(30):
            payload = {"temperature_c": 24 + (i % 5) * 0.1}
            if i < 25:
                payload["humidity_percent"] = 50 + (i % 7) * 0.2
            record_telemetry(
                "phase3-sensor", "iot/phase3-sensor/telemetry",
                payload, 40
            )

        result = train_device_baseline("phase3-sensor")
        self.assertIn("temperature_c", result["features"])
        self.assertIn("humidity_percent", result["features"])
        self.assertEqual(result["sample_count"], 30)

    def test_missing_inference_feature_skips_assessment(self):
        self.add_samples()
        train_device_baseline("phase3-sensor")

        telemetry_id = record_telemetry(
            "phase3-sensor", "iot/phase3-sensor/telemetry",
            {"temperature_c": 24.2}, 20
        )

        detail = get_device_threats("phase3-sensor")
        self.assertEqual(detail["assessments"], [])
        self.assertTrue(any(
            event["event_type"] == "intelligence.assessment_skipped"
            for event in list_events(device_uid="phase3-sensor")
        ))


    def test_assessment_history_retains_newest_records(self):
        import src.intelligence_manager as intelligence_manager

        self.add_samples()
        train_device_baseline("phase3-sensor")

        telemetry_ids = []
        with patch.object(intelligence_manager, "MAX_HISTORY", 2):
            for i in range(4):
                telemetry_id = record_telemetry(
                    "phase3-sensor",
                    "iot/phase3-sensor/telemetry",
                    {
                        "temperature_c": 24.1 + i * 0.1,
                        "humidity_percent": 50.2 + i * 0.2,
                    },
                    50,
                )
                telemetry_ids.append(telemetry_id)

        detail = get_device_threats("phase3-sensor", limit=10)
        retained_ids = [
            item["telemetry_id"] for item in detail["assessments"]
        ]

        self.assertEqual(len(retained_ids), 2)
        self.assertEqual(retained_ids, telemetry_ids[-2:][::-1])


if __name__ == "__main__":
    unittest.main()
