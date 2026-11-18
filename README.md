# Self-Defending IoT Network

## Project overview

This repository contains an IoT network security application. The existing application provides a Flask web interface, CSV-based traffic analysis, and a machine-learning classification component.

The implementation is being extended in phases toward device-aware monitoring, threat assessment, response, and recovery.

## Phase 1 — Core foundation

Phase 1 establishes the backend foundation:

- Persistent SQLite device registry.
- Unique device identifiers and normalized MAC addresses.
- Guarded device lifecycle transitions.
- Structured, persistent system audit events.
- Atomic device registration/status changes and their audit events.
- Persistent JSON-backed configuration helpers.
- Database and registry health checks.
- JSON API endpoints.
- Automated unit/security tests and GitHub Actions CI.

### Device lifecycle

Supported states:

- `registered`
- `active`
- `inactive`
- `isolated`
- `recovering`

Allowed transitions:

| Current state | Allowed next states |
|---|---|
| registered | active, inactive |
| active | inactive, isolated |
| inactive | active, isolated |
| isolated | recovering |
| recovering | active, isolated |

These are application lifecycle records. They do not, by themselves, block network traffic or disconnect a device.

### Atomic audit history

Device registration and status changes write their corresponding audit events using the same SQLite transaction. If either database operation fails, the transaction is rolled back.

### Database

The database path defaults to `iot_security.db` in the repository root. Override it with:

```bash
export IOT_SECURITY_DB=/path/to/iot_security.db
```

The database layer enables foreign-key checks, a busy timeout, and SQLite WAL journaling. Schema initialization is idempotent and preserves existing alert records.

### Configuration

The validated environment settings are defined in `src/config.py`. Persistent JSON configuration helpers are provided in `src/config_manager.py`.

The environment `Settings` object is not yet wired into every Flask runtime setting. Event-retention configuration is defined but automatic event cleanup is not implemented in this phase.

## API reference

### Health

`GET /api/health`

Returns database, device registry, event-log, and alert-store health information.

### Devices

`GET /api/devices`

Lists registered devices.

Optional filter:

`GET /api/devices?status=active`

`POST /api/devices`

Registers a device. Example JSON body:

```json
{
  "device_uid": "sensor-001",
  "name": "Temperature Sensor",
  "device_type": "sensor",
  "ip_address": "192.168.1.20",
  "mac_address": "AA-BB-CC-DD-EE-FF",
  "communication_type": "mqtt",
  "trusted": false,
  "metadata": {
    "location": "lab"
  }
}
```

`GET /api/devices/<device_uid>`

Returns one device.

`PATCH /api/devices/<device_uid>/status`

Example JSON body:

```json
{
  "status": "active"
}
```

Only allowed lifecycle transitions are accepted.

`POST /api/devices/<device_uid>/seen`

Updates the device's last-seen timestamp.

### System events

`GET /api/system/events?limit=100`

Returns recent audit events. The limit must be between 1 and 500.

Optional device filter:

`GET /api/system/events?device_uid=sensor-001`

## Installation and local execution

Use Python 3.12 or a compatible supported Python version.

Create and activate a virtual environment:

```bash
python3 -m venv .venv
source .venv/bin/activate
python -m pip install --upgrade pip
python -m pip install -r requirements.txt
```

Start the Flask application using the repository's configured entry point:

```bash
python app.py
```

Do not expose a development Flask server directly to an untrusted network.

## Validation

Run syntax compilation:

```bash
python -m compileall -q app.py src tests
```

Run all unit and security tests:

```bash
python -m unittest discover -s tests -v
```

The Phase 1 GitHub Actions workflow performs compilation and runs the test suite on pushes and pull requests targeting `main`.

## Existing application and limitations

The existing CSV classification workflow and website routes are retained.

The existing Random Forest model has a specific feature schema and classification scope. It must not be interpreted as a general-purpose detector for every IoT attack.

### Important: Existing dashboard and response limitations

The following existing application values are demonstration or legacy behavior,
not verified live security measurements:

- Dashboard traffic totals and traffic breakdowns are hard-coded demonstration figures.
- Model-performance percentages are demonstration values; they are not calculated
  from a current, independently verified evaluation.
- The dashboard's isolation count is derived from the number of critical alerts.
  It does not count devices confirmed as isolated by a network enforcement point.
- The dashboard's `Protected` security-status label does not establish that the
  network is currently protected.
- The CSV-analysis response action labelled `SIMULATION: Device isolated` is
  a simulation only. It does not block, disconnect, or isolate a real device.

The Phase 1 device lifecycle status records application state only. In particular,
a database status of `isolated` is not evidence of network-level isolation.
These legacy dashboard and response behaviors must not be interpreted as
operational proof of protection. They require replacement or integration with
verified monitoring and enforcement in later phases.

Phase 1 does not yet implement:

- Continuous live IoT traffic collection.
- Per-device behavioral baseline learning.
- A complete multi-signal threat assessment engine.
- Actual network-level device isolation.
- Verified device recovery and safe reconnection.
- Automated event-retention cleanup.

Actual isolation requires integration with a real enforcement point, such as a controlled MQTT broker or a Linux gateway firewall. Changing a database status is not network enforcement.

## Planned implementation phases

1. Core backend foundation.
2. Live device and traffic monitoring.
3. Device baselines, anomaly detection, and threat assessment.
4. Automated response and verified network isolation.
5. Recovery checks and controlled reconnection.
6. End-to-end integration, security, performance, and failure testing.

## Phase 2 - MQTT live monitoring

Phase 2 adds an MQTT telemetry collection and monitoring foundation.

### Components

- Mosquitto is used as the MQTT broker.
- Paho MQTT is used by the Python collector and simulator.
- The collector subscribes to `iot/+/telemetry`.
- A message is associated with an existing registered device.
- Telemetry is validated and persisted in SQLite.
- Per-device message counts, payload sizes, numeric features and
  last-seen timestamps are available through monitoring APIs.

### Install and start the broker

On Ubuntu or WSL:

```bash
sudo apt-get update
sudo apt-get install -y mosquitto
```

Start Mosquitto:

```bash
sudo systemctl start mosquitto
```

If systemd is unavailable in WSL, start it in a terminal:

```bash
mosquitto -p 1883 -v
```

### Register a simulated device

Start the Flask application once to initialize its database, then register:

```bash
curl -X POST http://127.0.0.1:5000/api/devices \
  -H 'Content-Type: application/json' \
  -d '{"device_uid":"sensor-1","name":"Temperature Sensor","communication_type":"mqtt"}'
```

### Start the collector

In another terminal:

```bash
cd ~/Self-Defending-IoT-Network-GitHub
./.venv/bin/python -m src.mqtt_collector
```

### Publish simulated sensor data

```bash
./.venv/bin/python -m src.mqtt_simulator \
  --device sensor-1 --count 10 --interval 1
```

Use `--count 0` to publish continuously until interrupted.

### Monitoring endpoints

- `GET /api/monitoring/summary`
- `GET /api/monitoring/devices/<device_uid>`
- `GET /api/monitoring/devices/<device_uid>?limit=100`

### MQTT topic and payload

Expected topic:

```text
iot/<device_uid>/telemetry
```

Expected payload: a JSON object. Numeric properties are extracted as
candidate monitoring features. Maximum payload size is 16 KiB.

### Scope and limitations

This phase collects MQTT messages from devices registered in the
application. It does not yet provide anomaly detection, malicious-device
classification, network firewall enforcement, or verified device isolation.

The MQTT broker in this initial configuration is intended for local
development and testing. It does not configure production authentication,
TLS, access-control lists, or hardened network exposure. Do not expose
this development broker to an untrusted network.
