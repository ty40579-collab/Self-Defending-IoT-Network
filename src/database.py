"""SQLite persistence and idempotent schema initialization."""
from __future__ import annotations
import json, os, sqlite3
from contextlib import contextmanager
from datetime import datetime, timezone
from pathlib import Path
from typing import Iterator, Any

DEFAULT_DB_PATH = Path(__file__).resolve().parent.parent / "iot_security.db"

def utc_now() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="seconds")

def get_db_path() -> Path:
    return Path(os.environ.get("IOT_SECURITY_DB", str(DEFAULT_DB_PATH))).expanduser()

@contextmanager
def get_connection() -> Iterator[sqlite3.Connection]:
    path = get_db_path()
    path.parent.mkdir(parents=True, exist_ok=True)
    conn = sqlite3.connect(str(path), timeout=10)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA foreign_keys = ON")
    conn.execute("PRAGMA busy_timeout = 10000")
    try:
        yield conn
        conn.commit()
    except Exception:
        conn.rollback()
        raise
    finally:
        conn.close()

def create_database() -> None:
    """Create/upgrade tables without deleting existing alert history."""
    with get_connection() as conn:
        conn.execute("PRAGMA journal_mode = WAL")
        conn.execute("""CREATE TABLE IF NOT EXISTS alerts (
            id INTEGER PRIMARY KEY AUTOINCREMENT, timestamp TEXT,
            attack_type TEXT, severity TEXT, action TEXT)""")
        conn.execute("""CREATE TABLE IF NOT EXISTS devices (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            device_uid TEXT NOT NULL UNIQUE, name TEXT NOT NULL,
            device_type TEXT NOT NULL DEFAULT 'unknown',
            ip_address TEXT, mac_address TEXT,
            communication_type TEXT NOT NULL DEFAULT 'unknown',
            endpoint TEXT,
            status TEXT NOT NULL DEFAULT 'registered'
              CHECK(status IN ('registered','active','inactive','isolated','recovering')),
            trusted INTEGER NOT NULL DEFAULT 0 CHECK(trusted IN (0,1)),
            metadata_json TEXT NOT NULL DEFAULT '{}',
            created_at TEXT NOT NULL, updated_at TEXT NOT NULL, last_seen_at TEXT)""")
        conn.execute("""CREATE UNIQUE INDEX IF NOT EXISTS ux_devices_mac
            ON devices(mac_address)
            WHERE mac_address IS NOT NULL AND mac_address <> ''""")
        conn.execute("CREATE INDEX IF NOT EXISTS ix_devices_status ON devices(status)")
        conn.execute("""CREATE TABLE IF NOT EXISTS system_events (
            id INTEGER PRIMARY KEY AUTOINCREMENT, event_type TEXT NOT NULL,
            severity TEXT NOT NULL DEFAULT 'info'
              CHECK(severity IN ('debug','info','warning','error','critical')),
            source TEXT NOT NULL DEFAULT 'system', device_uid TEXT,
            message TEXT NOT NULL, details_json TEXT NOT NULL DEFAULT '{}',
            created_at TEXT NOT NULL,
            FOREIGN KEY(device_uid) REFERENCES devices(device_uid) ON DELETE SET NULL)""")
        conn.execute("CREATE INDEX IF NOT EXISTS ix_events_created ON system_events(created_at DESC)")
        conn.execute("CREATE INDEX IF NOT EXISTS ix_events_device ON system_events(device_uid, created_at DESC)")
        conn.execute("""CREATE TABLE IF NOT EXISTS system_config (
            config_key TEXT PRIMARY KEY, config_value TEXT NOT NULL,
            description TEXT NOT NULL DEFAULT '', updated_at TEXT NOT NULL)""")
        conn.execute("""CREATE TABLE IF NOT EXISTS schema_migrations (
            version INTEGER PRIMARY KEY, applied_at TEXT NOT NULL)""")

        conn.execute("""CREATE TABLE IF NOT EXISTS mqtt_telemetry (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            device_uid TEXT NOT NULL,
            topic TEXT NOT NULL,
            received_at TEXT NOT NULL,
            payload_json TEXT NOT NULL,
            payload_bytes INTEGER NOT NULL CHECK(payload_bytes >= 0),
            numeric_features_json TEXT NOT NULL DEFAULT '{}',
            FOREIGN KEY(device_uid) REFERENCES devices(device_uid)
                ON DELETE CASCADE
        )""")
        conn.execute("""CREATE INDEX IF NOT EXISTS ix_mqtt_device_received
            ON mqtt_telemetry(device_uid, received_at DESC)""")
        conn.execute("""CREATE INDEX IF NOT EXISTS ix_mqtt_received
            ON mqtt_telemetry(received_at DESC)""")

        conn.execute("""CREATE TABLE IF NOT EXISTS intelligence_baselines (
            device_uid TEXT PRIMARY KEY,
            feature_names_json TEXT NOT NULL,
            samples_json TEXT NOT NULL,
            statistics_json TEXT NOT NULL,
            model_version TEXT NOT NULL,
            sample_count INTEGER NOT NULL CHECK(sample_count >= 20),
            trained_at TEXT NOT NULL,
            FOREIGN KEY(device_uid) REFERENCES devices(device_uid) ON DELETE CASCADE
        )""")
        conn.execute("""CREATE TABLE IF NOT EXISTS threat_assessments (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            telemetry_id INTEGER NOT NULL,
            device_uid TEXT NOT NULL,
            assessed_at TEXT NOT NULL,
            anomaly INTEGER NOT NULL CHECK(anomaly IN (0,1)),
            anomaly_score REAL NOT NULL CHECK(anomaly_score >= 0 AND anomaly_score <= 100),
            confidence REAL NOT NULL CHECK(confidence >= 0 AND confidence <= 1),
            severity TEXT NOT NULL CHECK(severity IN ('low','medium','high','critical')),
            ml_prediction INTEGER NOT NULL CHECK(ml_prediction IN (-1,1)),
            reasons_json TEXT NOT NULL,
            model_version TEXT NOT NULL,
            FOREIGN KEY(telemetry_id) REFERENCES mqtt_telemetry(id) ON DELETE CASCADE,
            FOREIGN KEY(device_uid) REFERENCES devices(device_uid) ON DELETE CASCADE
        )""")
        conn.execute("CREATE INDEX IF NOT EXISTS ix_threat_device_id ON threat_assessments(device_uid,id DESC)")
        conn.execute("CREATE INDEX IF NOT EXISTS ix_threat_anomaly_id ON threat_assessments(anomaly,id DESC)")

        conn.execute("INSERT OR IGNORE INTO schema_migrations(version, applied_at) VALUES (?, ?)",
                     (1, utc_now()))

def insert_alert(timestamp: str, attack_type: str, severity: str, action: str) -> int:
    with get_connection() as conn:
        cur = conn.execute("""INSERT INTO alerts(timestamp,attack_type,severity,action)
            VALUES (?,?,?,?)""", (timestamp, attack_type, severity, action))
        return int(cur.lastrowid)

def json_object(value: str | None) -> dict[str, Any]:
    if not value:
        return {}
    try:
        result = json.loads(value)
        return result if isinstance(result, dict) else {}
    except (TypeError, json.JSONDecodeError):
        return {}
