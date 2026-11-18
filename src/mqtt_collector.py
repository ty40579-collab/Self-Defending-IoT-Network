"""MQTT telemetry collector with validation and reconnect support."""

from __future__ import annotations

import json
import logging
import os
import threading
import time
import uuid

import paho.mqtt.client as mqtt

from src.event_logger import log_event
from src.monitoring_manager import (
    MAX_PAYLOAD_BYTES,
    record_telemetry,
)

logger = logging.getLogger(__name__)


class MQTTCollector:
    def __init__(
        self,
        host: str = "127.0.0.1",
        port: int = 1883,
        keepalive: int = 30,
    ):
        if not isinstance(host, str) or not host.strip():
            raise ValueError("MQTT host is required")

        if not isinstance(port, int) or not 1 <= port <= 65535:
            raise ValueError("Invalid MQTT port")

        self.host = host
        self.port = port
        self.keepalive = keepalive
        self.connected = threading.Event()
        self.last_error = None
        self.accepted_messages = 0
        self.rejected_messages = 0
        self._lock = threading.Lock()

        self.client = mqtt.Client(
            mqtt.CallbackAPIVersion.VERSION2,
            client_id=f"iot-monitor-{uuid.uuid4().hex[:12]}",
            protocol=mqtt.MQTTv311,
        )

        self.client.on_connect = self._on_connect
        self.client.on_disconnect = self._on_disconnect
        self.client.on_message = self._on_message

    def _on_connect(
        self, client, userdata, flags, reason_code, properties
    ):
        if reason_code.is_failure:
            self.last_error = str(reason_code)
            logger.error("MQTT connection rejected: %s", reason_code)
            return

        result, _ = client.subscribe("iot/+/telemetry", qos=1)

        if result != mqtt.MQTT_ERR_SUCCESS:
            self.last_error = f"Subscription failed: {result}"
            logger.error(self.last_error)
            return

        self.connected.set()
        self.last_error = None
        logger.info("Connected to MQTT broker and subscribed.")

    def _on_disconnect(
        self, client, userdata, disconnect_flags, reason_code, properties
    ):
        self.connected.clear()
        logger.warning("MQTT disconnected: %s", reason_code)

    def _on_message(self, client, userdata, message):
        self.process_message(message.topic, message.payload)

    def _reject(self, reason: str, topic: str) -> bool:
        with self._lock:
            self.rejected_messages += 1

        logger.warning("Rejected MQTT message: %s", reason)

        try:
            log_event(
                "mqtt.message_rejected",
                "MQTT telemetry message rejected",
                severity="warning",
                source="mqtt_collector",
                details={
                    "reason": reason,
                    "topic": topic[:256],
                },
            )
        except Exception:
            logger.exception("Could not persist MQTT rejection event")

        return False

    def process_message(self, topic: str, raw_payload: bytes) -> bool:
        if not isinstance(topic, str):
            return self._reject("Invalid topic", "")

        parts = topic.split("/")

        if (
            len(parts) != 3
            or parts[0] != "iot"
            or not parts[1]
            or parts[2] != "telemetry"
        ):
            return self._reject("Invalid topic format", topic)

        if not isinstance(raw_payload, bytes):
            return self._reject("Payload must be bytes", topic)

        if len(raw_payload) > MAX_PAYLOAD_BYTES:
            return self._reject("Payload exceeds size limit", topic)

        try:
            payload = json.loads(raw_payload.decode("utf-8"))
        except (UnicodeDecodeError, json.JSONDecodeError):
            return self._reject("Invalid JSON payload", topic)

        if not isinstance(payload, dict):
            return self._reject("Payload must be a JSON object", topic)

        try:
            record_telemetry(
                parts[1],
                topic,
                payload,
                len(raw_payload),
            )
        except LookupError:
            return self._reject("Unknown device", topic)
        except (ValueError, TypeError):
            return self._reject("Invalid telemetry data", topic)
        except Exception:
            logger.exception("MQTT telemetry persistence failed")
            return self._reject("Persistence failure", topic)

        with self._lock:
            self.accepted_messages += 1

        return True

    def start(self, timeout: float = 8.0):
        self.client.connect(
            self.host,
            self.port,
            self.keepalive,
        )
        self.client.loop_start()

        if not self.connected.wait(timeout):
            self.client.loop_stop()
            self.client.disconnect()
            raise ConnectionError(
                f"MQTT broker connection failed: {self.last_error or 'timeout'}"
            )

        return self

    def stop(self):
        try:
            self.client.disconnect()
        finally:
            self.client.loop_stop()
            self.connected.clear()

    def run_forever(self):
        self.start()
        logger.info("MQTT collector running.")
        try:
            while True:
                time.sleep(1)
        except KeyboardInterrupt:
            logger.info("Stopping MQTT collector.")
        finally:
            self.stop()


def main():
    logging.basicConfig(
        level=logging.INFO,
        format="%(asctime)s %(levelname)s %(name)s: %(message)s",
    )

    host = os.getenv("MQTT_HOST", "127.0.0.1")
    port = int(os.getenv("MQTT_PORT", "1883"))

    collector = MQTTCollector(host, port)
    collector.run_forever()


if __name__ == "__main__":
    main()
