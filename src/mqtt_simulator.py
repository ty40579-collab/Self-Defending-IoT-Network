"""Publish simulated IoT sensor telemetry to an MQTT broker."""

from __future__ import annotations

import argparse
import json
import random
import time
from datetime import datetime, timezone

import paho.mqtt.client as mqtt


def main():
    parser = argparse.ArgumentParser(
        description="Simulate an MQTT temperature and humidity sensor."
    )
    parser.add_argument("--device", required=True)
    parser.add_argument("--host", default="127.0.0.1")
    parser.add_argument("--port", type=int, default=1883)
    parser.add_argument("--interval", type=float, default=2.0)
    parser.add_argument("--count", type=int, default=0)
    args = parser.parse_args()

    if not args.device or "/" in args.device:
        parser.error("Device ID must be non-empty and cannot contain '/'.")

    if args.interval <= 0 or args.count < 0:
        parser.error("Interval must be positive and count cannot be negative.")

    client = mqtt.Client(
        mqtt.CallbackAPIVersion.VERSION2,
        client_id=f"iot-simulator-{args.device}",
        protocol=mqtt.MQTTv311,
    )

    client.connect(args.host, args.port, 30)
    client.loop_start()

    topic = f"iot/{args.device}/telemetry"
    sequence = 0

    try:
        while args.count == 0 or sequence < args.count:
            sequence += 1

            payload = {
                "sequence": sequence,
                "temperature_c": round(random.uniform(18, 32), 2),
                "humidity_percent": round(random.uniform(30, 75), 2),
                "timestamp": datetime.now(timezone.utc).isoformat(),
            }

            result = client.publish(
                topic,
                json.dumps(payload),
                qos=1,
            )
            result.wait_for_publish()

            if result.rc != mqtt.MQTT_ERR_SUCCESS:
                raise RuntimeError("MQTT publish failed")

            print(f"Published {sequence}: {payload}")

            if args.count == 0 or sequence < args.count:
                time.sleep(args.interval)

    except KeyboardInterrupt:
        print("Simulator stopped.")
    finally:
        client.disconnect()
        client.loop_stop()


if __name__ == "__main__":
    main()
