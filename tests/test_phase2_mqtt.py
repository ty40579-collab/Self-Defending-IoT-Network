import json
import os
import shutil
import socket
import subprocess
import tempfile
import time
import unittest
from pathlib import Path

import paho.mqtt.client as mqtt

from src import database
from src.device_manager import register_device
from src.mqtt_collector import MQTTCollector
from src.monitoring_manager import (
    get_device_monitoring,
    get_monitoring_summary,
)


class PhaseTwoMQTTIntegrationTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        if shutil.which("mosquitto") is None:
            raise unittest.SkipTest("Mosquitto broker is not installed")

    def setUp(self):
        self.temp_dir = tempfile.TemporaryDirectory()
        self.old_db = os.environ.get("IOT_SECURITY_DB")
        os.environ["IOT_SECURITY_DB"] = str(
            Path(self.temp_dir.name) / "phase2_test.db"
        )
        database.create_database()

        sock = socket.socket()
        sock.bind(("127.0.0.1", 0))
        self.port = sock.getsockname()[1]
        sock.close()

        self.broker = subprocess.Popen(
            [
                "mosquitto",
                "-p",
                str(self.port),
                "-v",
            ],
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
        )

        deadline = time.time() + 8
        while time.time() < deadline:
            if self.broker.poll() is not None:
                self.fail("Mosquitto broker exited unexpectedly")

            try:
                probe = socket.create_connection(
                    ("127.0.0.1", self.port),
                    timeout=0.2,
                )
                probe.close()
                break
            except OSError:
                time.sleep(0.1)
        else:
            self.fail("Mosquitto broker did not start")

        register_device(
            "phase2-sensor-1",
            "Phase 2 Temperature Sensor",
            communication_type="mqtt",
        )

        self.collector = MQTTCollector(port=self.port)
        self.collector.start()

        self.publisher = mqtt.Client(
            mqtt.CallbackAPIVersion.VERSION2,
            protocol=mqtt.MQTTv311,
        )
        self.publisher.connect("127.0.0.1", self.port, 10)
        self.publisher.loop_start()

    def tearDown(self):
        if hasattr(self, "publisher"):
            self.publisher.disconnect()
            self.publisher.loop_stop()

        if hasattr(self, "collector"):
            self.collector.stop()

        if hasattr(self, "broker"):
            self.broker.terminate()
            try:
                self.broker.wait(timeout=3)
            except subprocess.TimeoutExpired:
                self.broker.kill()
                self.broker.wait()

        if self.old_db is None:
            os.environ.pop("IOT_SECURITY_DB", None)
        else:
            os.environ["IOT_SECURITY_DB"] = self.old_db

        self.temp_dir.cleanup()

    def publish(self, topic, payload):
        result = self.publisher.publish(topic, payload, qos=1)
        result.wait_for_publish()
        self.assertEqual(result.rc, mqtt.MQTT_ERR_SUCCESS)

    def wait_for_count(self, expected, timeout=5):
        deadline = time.time() + timeout
        while time.time() < deadline:
            summary = get_monitoring_summary()
            if summary["total_messages"] >= expected:
                return summary
            time.sleep(0.05)
        self.fail(f"Expected at least {expected} persisted messages")

    def test_real_mqtt_publish_subscribe_and_persistence(self):
        payload = {
            "temperature_c": 24.5,
            "humidity_percent": 51.2,
            "sequence": 1,
        }

        self.publish(
            "iot/phase2-sensor-1/telemetry",
            json.dumps(payload),
        )

        summary = self.wait_for_count(1)

        self.assertEqual(summary["total_messages"], 1)
        self.assertEqual(summary["monitored_devices"], 1)

        detail = get_device_monitoring("phase2-sensor-1")

        self.assertEqual(detail["statistics"]["message_count"], 1)
        self.assertEqual(
            detail["messages"][0]["payload"]["temperature_c"],
            24.5,
        )
        self.assertEqual(
            detail["messages"][0]["numeric_features"]["humidity_percent"],
            51.2,
        )

    def test_unknown_device_is_rejected(self):
        before = get_monitoring_summary()["total_messages"]

        self.publish(
            "iot/unknown-sensor/telemetry",
            json.dumps({"temperature_c": 20}),
        )

        time.sleep(0.4)

        self.assertEqual(
            get_monitoring_summary()["total_messages"],
            before,
        )
        self.assertGreater(self.collector.rejected_messages, 0)

    def test_invalid_json_is_rejected(self):
        self.publish(
            "iot/phase2-sensor-1/telemetry",
            b"{invalid-json",
        )

        time.sleep(0.4)

        self.assertEqual(
            get_monitoring_summary()["total_messages"],
            0,
        )
        self.assertGreater(self.collector.rejected_messages, 0)

    def test_non_object_json_is_rejected(self):
        self.publish(
            "iot/phase2-sensor-1/telemetry",
            b"[1,2,3]",
        )

        time.sleep(0.4)

        self.assertEqual(
            get_monitoring_summary()["total_messages"],
            0,
        )

    def test_oversized_payload_is_rejected(self):
        payload = json.dumps(
            {"data": "x" * (16 * 1024 + 100)}
        )

        self.publish(
            "iot/phase2-sensor-1/telemetry",
            payload,
        )

        time.sleep(0.4)

        self.assertEqual(
            get_monitoring_summary()["total_messages"],
            0,
        )

    def test_malformed_topic_is_rejected_by_validator(self):
        accepted = self.collector.process_message(
            "invalid/topic",
            b'{"temperature_c":20}',
        )
        self.assertFalse(accepted)

    def test_nan_values_are_rejected(self):
        accepted = self.collector.process_message(
            "iot/phase2-sensor-1/telemetry",
            b'{"temperature_c":NaN}',
        )
        self.assertFalse(accepted)

    def test_device_monitoring_unknown_device(self):
        self.assertIsNone(
            get_device_monitoring("does-not-exist")
        )

    def test_monitoring_limit_validation(self):
        with self.assertRaises(ValueError):
            get_device_monitoring("phase2-sensor-1", 501)

    def test_broker_connection_is_established(self):
        self.assertTrue(self.collector.connected.is_set())


    def test_collector_reconnects_after_broker_restart(self):
        # Stop the broker and verify that the collector detects disconnection.
        self.broker.terminate()
        self.broker.wait(timeout=3)

        deadline = time.monotonic() + 6
        while self.collector.connected.is_set() and time.monotonic() < deadline:
            time.sleep(0.05)

        self.assertFalse(
            self.collector.connected.is_set(),
            "Collector did not detect the broker disconnect",
        )

        # Restart Mosquitto on the same port.
        self.broker = subprocess.Popen(
            ["mosquitto", "-p", str(self.port), "-v"],
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
        )

        deadline = time.monotonic() + 8
        broker_ready = False

        while time.monotonic() < deadline:
            if self.broker.poll() is not None:
                self.fail("Restarted Mosquitto broker exited unexpectedly")

            try:
                probe = socket.create_connection(
                    ("127.0.0.1", self.port),
                    timeout=0.2,
                )
                probe.close()
                broker_ready = True
                break
            except OSError:
                time.sleep(0.1)

        self.assertTrue(broker_ready, "Mosquitto did not restart")

        # The collector must reconnect and its on_connect callback must
        # subscribe again before it can receive telemetry.
        self.assertTrue(
            self.collector.connected.wait(timeout=15),
            f"Collector failed to reconnect: {self.collector.last_error}",
        )

        publisher = mqtt.Client(
            mqtt.CallbackAPIVersion.VERSION2,
            protocol=mqtt.MQTTv311,
        )
        publisher.connect("127.0.0.1", self.port, 10)
        publisher.loop_start()

        try:
            payload = json.dumps({
                "temperature_c": 26.0,
                "sequence": 99,
            })
            result = publisher.publish(
                "iot/phase2-sensor-1/telemetry",
                payload,
                qos=1,
            )
            result.wait_for_publish()
            self.assertEqual(result.rc, mqtt.MQTT_ERR_SUCCESS)
        finally:
            publisher.disconnect()
            publisher.loop_stop()

        summary = self.wait_for_count(1)
        self.assertEqual(summary["total_messages"], 1)

        # The database commit happens before the collector increments its
        # accepted counter (record_telemetry also runs threat assessment).
        # Wait for the complete MQTT callback instead of racing that work.
        deadline = time.monotonic() + 10
        while (
            self.collector.accepted_messages < 1
            and time.monotonic() < deadline
        ):
            time.sleep(0.02)

        self.assertEqual(self.collector.accepted_messages, 1)

    def test_monitoring_api_routes(self):
        import app as flask_app

        flask_app.app.config["TESTING"] = True
        client = flask_app.app.test_client()

        summary = client.get("/api/monitoring/summary")
        self.assertEqual(summary.status_code, 200)
        self.assertEqual(summary.get_json()["total_messages"], 0)

        detail = client.get(
            "/api/monitoring/devices/phase2-sensor-1"
        )
        self.assertEqual(detail.status_code, 200)
        self.assertEqual(
            detail.get_json()["device"]["device_uid"],
            "phase2-sensor-1",
        )

        missing = client.get(
            "/api/monitoring/devices/does-not-exist"
        )
        self.assertEqual(missing.status_code, 404)

        invalid_limit = client.get(
            "/api/monitoring/devices/phase2-sensor-1?limit=abc"
        )
        self.assertEqual(invalid_limit.status_code, 400)

        excessive_limit = client.get(
            "/api/monitoring/devices/phase2-sensor-1?limit=501"
        )
        self.assertEqual(excessive_limit.status_code, 400)


if __name__ == "__main__":
    unittest.main()
