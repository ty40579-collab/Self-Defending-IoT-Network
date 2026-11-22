# Self-Defending IoT Network

## Project overview

This repository contains a Flask application for IoT device registration, MQTT telemetry collection, device-specific anomaly assessment, and opt-in network isolation through a Linux nftables gateway. SQLite stores device state, telemetry, assessments, protection actions, and audit events. The original CSV classification workflow remains available as a separate legacy feature.

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

The environment `Settings` object is not wired into every Flask runtime setting. `EVENT_RETENTION_DAYS` is defined, but automatic event cleanup is not implemented.

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

Create a virtual environment and install dependencies:

```bash
python3 -m venv .venv
./.venv/bin/python -m pip install --upgrade pip
./.venv/bin/python -m pip install -r requirements.txt
```

Start the Flask application using the repository's configured entry point:

```bash
./.venv/bin/python app.py
```

Do not expose a development Flask server directly to an untrusted network.

## Validation

Run syntax compilation:

```bash
./.venv/bin/python -m compileall -q app.py src tests
```

Run all unit and security tests:

```bash
./.venv/bin/python -m unittest discover -s tests -v
```

GitHub Actions performs compilation and runs the complete unittest suite, including the Mosquitto integration tests, on pushes to the Phase 4 branch and on pull requests targeting `main`.

## Existing CSV feature and dashboard data

The existing CSV classification workflow and website routes are retained.

The existing Random Forest model has a specific feature schema and classification scope. It must not be interpreted as a general-purpose detector for every IoT attack.

### Important: Existing dashboard and response limitations

The CSV classification workflow and its routes are retained. Its Random Forest
model has a specific feature schema and classification scope, and it must not be
treated as a general-purpose detector for every IoT attack. The dashboard still
contains legacy hard-coded traffic totals and distribution values; those values
are not computed from current MQTT telemetry. Threat totals come from the legacy
alerts table. The isolation count comes from active protection records.

- Model-performance percentages shown in the legacy interface are demonstration
  values, not a current, independently verified evaluation.
- The CSV-analysis response action labelled `SIMULATION: Device isolated` is a
  simulation only. It does not block, disconnect, or isolate a real device.

Lifecycle state by itself is not proof of network-level isolation. The Phase 4
protection manager records a device as isolated only after the firewall backend
reports success, but the dashboard cannot prove live packet blocking at the
gateway.

The application does not currently perform recovery health checks before
reconnection or automated event-retention cleanup.

## Implemented phases and acceptance limits

1. **Phase 1:** Device registry, lifecycle state, database, configuration, health checks, and audit events.
2. **Phase 2:** MQTT telemetry validation, persistence, monitoring APIs, and reconnect behavior.
3. **Phase 3:** Explicit device baseline training, anomaly detection, severity classification, and assessment history.
4. **Phase 4:** Authenticated protection APIs, nftables forwarding rules, protection history, and opt-in automatic isolation.

Unit and integration tests validate application behavior; they do not
establish packet blocking by themselves. Separate controlled validation in an
isolated VMware lab verified real bidirectional IPv4 packet blocking and
restoration for two endpoints; see the
[gateway validation results](docs/gateway-validation-results.md).
This lab result does not establish production readiness. A production
deployment still requires environment-specific validation and recovery
procedures described below.

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


## Phase 3 — Device intelligence and threat assessment

Phase 3 adds a separate device-specific intelligence pipeline for MQTT telemetry.
The existing uploaded-CSV Random Forest prediction path is unchanged.

### Behaviour baselines

A baseline is explicitly trained from historical telemetry for one registered
device. At least 20 usable samples are required. The selected training period
must represent known-normal behaviour; the software cannot independently prove
that historical samples are benign. Incoming telemetry is never automatically
added to a baseline.

### Detection and assessment

The engine uses a reproducible Isolation Forest model together with robust
median/MAD deviation checks. It preserves the baseline feature order, records
the model version, and stores anomaly score, confidence, severity, and reasons.
Assessment is skipped until a device has a trained baseline. Baseline
features present in at least 80% of training samples are retained, and missing
training values are median-imputed. If incoming telemetry lacks a required
baseline feature, its threat assessment is skipped and an audit event records
the missing fields; missing data alone is not classified as an attack.
Assessment history retains the newest 500 records per device.

This is an unsupervised anomaly detector, not a supervised attack-family
classifier. Scores are detector outputs, not calibrated probabilities or
measured real-world accuracy. Thresholds require evaluation against representative
benign and attack traffic before production use.

### APIs

Train a baseline from the latest 200 samples (minimum 20):

```bash
curl -X POST http://127.0.0.1:5000/api/intelligence/devices/sensor-1/baseline \
  -H 'Content-Type: application/json' -d '{"limit":200}'
```

View the system summary:

`GET /api/intelligence/summary`

View one device's baseline and assessments:

`GET /api/intelligence/devices/sensor-1/threats?limit=50`

### Scope boundary

Phase 3 records threat assessments and audit events. It does not itself isolate
devices, block MQTT clients, or claim that a device is safe. Phase 4 consumes
persisted assessments for its optional network-isolation policy.


## Phase 4 — Network protection and isolation

Phase 4 connects threat monitoring to an opt-in nftables backend. Isolation
records are written only after the backend reports success. Protection actions
and failures are retained in the database for review.

### Secure defaults and environment settings

The application does not enable firewall enforcement or automatic isolation by
default. Configure these settings in the process environment before starting the
application:

| Variable | Default | Purpose |
|---|---|---|
| `IOT_SECURITY_DB` | `iot_security.db` | SQLite database path |
| `MQTT_HOST` | `127.0.0.1` | MQTT broker host for the collector |
| `MQTT_PORT` | `1883` | MQTT broker port |
| `IOT_ENFORCEMENT_ENABLED` | `false` | Allow authenticated protection operations and firewall changes |
| `IOT_AUTO_ISOLATION_ENABLED` | `false` | Enable the automatic-isolation policy; enforcement must also be enabled |
| `IOT_ENFORCEMENT_API_TOKEN` | unset | Bearer token required by protection APIs |
| `HOST` | `127.0.0.1` | Flask bind address |
| `PORT` | `5000` | Flask port |
| `APP_ENV` | `development` | Flask debug mode is enabled only for `development` |

Example for an explicitly configured gateway deployment (replace the token
with a securely generated value and keep it out of source control):

```bash
export IOT_ENFORCEMENT_ENABLED=true
export IOT_AUTO_ISOLATION_ENABLED=false
export IOT_ENFORCEMENT_API_TOKEN='replace-with-a-long-random-secret'
./.venv/bin/python app.py
```

Do not enable enforcement until the deployment has been checked on its actual
Linux gateway. Keep the token in a protected secret store or service environment.

### Automatic-isolation policy

When explicitly enabled, the policy requires three consecutive persisted
critical assessments, each with an anomaly score of at least 95, within five
minutes. The latest assessment must match the telemetry callback being handled.
Trusted devices and skipped assessments are excluded. A normal assessment breaks
the sequence. Anomaly scores are detector outputs, not calibrated probabilities
or a guarantee that a device is compromised.

### Protection APIs

All protection endpoints require `Authorization: Bearer <token>`. The token must
be configured or the API returns service unavailable. The enforcement setting
must also be enabled for isolation and release operations.

```text
GET  /api/protection/status
GET  /api/protection/devices/<device_uid>/history?limit=50
POST /api/protection/devices/<device_uid>/isolate
POST /api/protection/devices/<device_uid>/release
```

Example manual isolation request:

```bash
curl -X POST http://127.0.0.1:5000/api/protection/devices/sensor-1/isolate \
  -H "Authorization: Bearer $IOT_ENFORCEMENT_API_TOKEN" \
  -H 'Content-Type: application/json' \
  -d '{"reason":"administrator review"}'
```

The status and history endpoints expose current protection records and audit
actions. Releasing one device retains a firewall address while another active
protection record references that address. A released device moves to
`recovering`; an administrator must evaluate it before ordinary reactivation.

### Linux gateway requirements and limits

The nftables backend requires Linux, the `nft` executable, and sufficient
network-administration privileges to manage the dedicated `inet`
`self_defending_iot` table. It creates and validates its ownership marker,
forwarding chain, address sets, and IPv4/IPv6 source and destination drop rules.
It refuses to modify a same-named table without the exact application ownership
marker and never flushes the global ruleset.

The dedicated `forward` chain only handles packets traversing this gateway.
Devices can bypass it if another route exists. Traffic to or from the gateway
itself is not necessarily covered by a forwarding chain. Installing `nft` does
not establish that the rules exist, that the application has permission, that
the gateway routes the devices, or that packets are actually blocked.

The dashboard reports **Configured — live enforcement unverified** when the
setting is enabled and nftables is installed. Mock firewall tests validate the
application's decisions and command construction; they do not send packets
through a real firewall. Production use requires controlled verification of the
real table, chain priority and policy, sets, directional rules, test-address
insertion and removal, packet behavior through the gateway, and preservation of
unrelated firewall rules. Follow the [controlled gateway validation runbook](docs/gateway-validation.md)
in an isolated test network with a safe recovery path.

Real bidirectional IPv4 packet blocking and restoration were verified for two
endpoints in an isolated VMware lab; see [gateway validation results](docs/gateway-validation-results.md).
This does not establish production deployment. Routed IPv6 and all possible
failure scenarios remain unverified.

### Complete test suite

Install Mosquitto and Python requirements, then run:

```bash
./.venv/bin/python -m compileall -q app.py src tests
./.venv/bin/python -m unittest discover -s tests -v
git diff --check
```

The MQTT tests start a local broker and therefore require local socket access.
Firewall unit tests use mocks and do not require root or change the host firewall.
