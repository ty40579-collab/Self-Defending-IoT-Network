"""Device-specific IoT baselines and explainable anomaly assessments."""
from __future__ import annotations

import json
import math
from typing import Any

import numpy as np
from sklearn.ensemble import IsolationForest

from src.database import get_connection, utc_now
from src.event_logger import log_event

MODEL_VERSION = "iot-isolation-forest-mad-v1"
MIN_BASELINE_SAMPLES = 20
MAX_BASELINE_SAMPLES = 1000
MAX_HISTORY = 500


def _finite_features(features: dict[str, Any]) -> dict[str, float]:
    if not isinstance(features, dict):
        raise ValueError("numeric features must be an object")
    result = {}
    for key, value in features.items():
        if (isinstance(key, str) and key and isinstance(value, (int, float))
                and not isinstance(value, bool) and math.isfinite(value)):
            result[key] = float(value)
    return result


def _matrix(rows, names):
    matrix = []
    for row in rows:
        matrix.append([
            float(row[name]) if name in row and math.isfinite(float(row[name])) else np.nan
            for name in names
        ])
    array = np.asarray(matrix, dtype=float)
    if array.ndim != 2 or array.shape[1] == 0:
        raise ValueError("No usable numeric telemetry features")
    medians = np.nanmedian(array, axis=0)
    medians = np.where(np.isfinite(medians), medians, 0.0)
    array = np.where(np.isfinite(array), array, medians)
    return np.clip(array, -1e10, 1e10), medians


def train_device_baseline(device_uid: str, limit: int = 200) -> dict:
    if not isinstance(device_uid, str) or not device_uid.strip():
        raise ValueError("device_uid is required")
    if not isinstance(limit, int) or not MIN_BASELINE_SAMPLES <= limit <= MAX_BASELINE_SAMPLES:
        raise ValueError(f"limit must be between {MIN_BASELINE_SAMPLES} and {MAX_BASELINE_SAMPLES}")

    uid = device_uid.strip()
    with get_connection() as conn:
        device = conn.execute(
            "SELECT device_uid FROM devices WHERE device_uid=?", (uid,)
        ).fetchone()
        if device is None:
            raise LookupError("Device not found")
        rows = conn.execute(
            """SELECT numeric_features_json FROM mqtt_telemetry
               WHERE device_uid=? ORDER BY id DESC LIMIT ?""",
            (uid, limit),
        ).fetchall()

    samples = []
    for row in reversed(rows):
        try:
            item = json.loads(row["numeric_features_json"] or "{}")
            clean = _finite_features(item)
            if clean:
                samples.append(clean)
        except (ValueError, TypeError, json.JSONDecodeError):
            continue

    if len(samples) < MIN_BASELINE_SAMPLES:
        raise ValueError(
            f"At least {MIN_BASELINE_SAMPLES} valid telemetry samples are required; found {len(samples)}"
        )

    # Keep features present in at least 80% of valid baseline samples.
    # _matrix() imputes missing training values using each feature's median.
    required_count = math.ceil(0.80 * len(samples))
    feature_counts = {}
    for sample in samples:
        for name in sample:
            feature_counts[name] = feature_counts.get(name, 0) + 1

    keys = sorted(
        name for name, count in feature_counts.items()
        if count >= required_count
    )
    if not keys:
        raise ValueError(
            "No numeric feature is present in at least 80% of baseline samples"
        )

    matrix, medians = _matrix(samples, keys)
    if len(matrix) < MIN_BASELINE_SAMPLES:
        raise ValueError("Insufficient baseline samples")

    # Reject a constant/degenerate feature set only if every feature is constant.
    if not np.any(np.std(matrix, axis=0) > 1e-12):
        raise ValueError("Baseline features have no measurable variation")

    stats = {}
    for index, name in enumerate(keys):
        column = matrix[:, index]
        center = float(np.median(column))
        mad = float(np.median(np.abs(column - center)))
        stats[name] = {
            "median": center,
            "mad": mad,
            "scale": max(1.4826 * mad, float(np.std(column)) * 0.05, 1e-9),
            "minimum": float(np.min(column)),
            "maximum": float(np.max(column)),
        }

    # Persist only the validated baseline samples; inference is reproducible.
    with get_connection() as conn:
        conn.execute(
            """INSERT INTO intelligence_baselines
               (device_uid,feature_names_json,samples_json,statistics_json,
                model_version,sample_count,trained_at)
               VALUES (?,?,?,?,?,?,?)
               ON CONFLICT(device_uid) DO UPDATE SET
                 feature_names_json=excluded.feature_names_json,
                 samples_json=excluded.samples_json,
                 statistics_json=excluded.statistics_json,
                 model_version=excluded.model_version,
                 sample_count=excluded.sample_count,
                 trained_at=excluded.trained_at""",
            (uid, json.dumps(keys), json.dumps(matrix.tolist()),
             json.dumps(stats, sort_keys=True), MODEL_VERSION,
             len(matrix), utc_now()),
        )
        log_event(
            "intelligence.baseline_trained",
            "Device behaviour baseline trained from selected historical telemetry",
            source="intelligence_manager",
            device_uid=uid,
            details={"sample_count": len(matrix), "features": keys,
                     "model_version": MODEL_VERSION},
            connection=conn,
        )

    return {
        "device_uid": uid,
        "sample_count": len(matrix),
        "features": keys,
        "model_version": MODEL_VERSION,
        "trained_at": utc_now(),
        "training_data_warning": "Use a known-normal training period. Training samples are selected from historical telemetry and are not independently verified as benign.",
    }


def assess_telemetry(device_uid: str, telemetry_id: int, features: dict) -> dict | None:
    clean = _finite_features(features)
    if not clean:
        return None

    with get_connection() as conn:
        baseline = conn.execute(
            "SELECT * FROM intelligence_baselines WHERE device_uid=?",
            (device_uid,),
        ).fetchone()

    if baseline is None:
        return None

    names = json.loads(baseline["feature_names_json"])
    samples = json.loads(baseline["samples_json"])
    stats = json.loads(baseline["statistics_json"])

    # Missing required fields are incomplete telemetry, not proof of an attack.
    missing = [name for name in names if name not in clean]
    if missing:
        log_event(
            "intelligence.assessment_skipped",
            "Threat assessment skipped because telemetry lacked baseline features",
            severity="warning",
            source="intelligence_manager",
            device_uid=device_uid,
            details={
                "telemetry_id": telemetry_id,
                "missing_features": missing,
                "model_version": MODEL_VERSION,
            },
        )
        return {
            "telemetry_id": telemetry_id,
            "device_uid": device_uid,
            "skipped": True,
            "skip_reason": "missing_baseline_features",
            "missing_features": missing,
            "model_version": MODEL_VERSION,
        }

    # Preserve the trained feature order and never train on incoming observations.
    vector = np.asarray([[clean[name] for name in names]], dtype=float)
    vector = np.clip(vector, -1e10, 1e10)
    train = np.asarray(samples, dtype=float)
    model = IsolationForest(
        n_estimators=150, contamination=0.05,
        random_state=42, n_jobs=1
    )
    model.fit(train)
    ml_prediction = int(model.predict(vector)[0])
    decision = float(model.decision_function(vector)[0])

    z_values = {
        name: abs(clean[name] - stats[name]["median"]) / stats[name]["scale"]
        for name in names
    }
    max_z = max(z_values.values(), default=0.0)
    statistical_score = min(100.0, max_z * 12.5)
    reasons = []
    for name, z in z_values.items():
        if z >= 4.0:
            reasons.append(f"{name}:robust_deviation_{z:.2f}MAD")
    if ml_prediction == -1:
        reasons.append("isolation_forest_outlier")
    if decision < 0:
        statistical_score = max(
            statistical_score, min(100.0, abs(decision) * 200.0)
        )
    if not reasons:
        reasons.append("within_learned_baseline")

    anomaly = bool(ml_prediction == -1 or max_z >= 4.0)
    score = round(min(100.0, max(statistical_score, 70.0 if ml_prediction == -1 else 0.0)), 2)
    confidence = round(min(1.0, max(0.0, score / 100.0)), 3)
    severity = (
        "critical" if anomaly and score >= 90 else
        "high" if anomaly and score >= 75 else
        "medium" if anomaly else "low"
    )

    with get_connection() as conn:
        conn.execute(
            """INSERT INTO threat_assessments
               (telemetry_id,device_uid,assessed_at,anomaly,anomaly_score,
                confidence,severity,ml_prediction,reasons_json,model_version)
               VALUES (?,?,?,?,?,?,?,?,?,?)""",
            (telemetry_id, device_uid, utc_now(), int(anomaly), score,
             confidence, severity, ml_prediction, json.dumps(reasons),
             MODEL_VERSION),
        )

        # Retain only the newest MAX_HISTORY assessments for each device.
        conn.execute(
            """DELETE FROM threat_assessments
               WHERE device_uid=?
                 AND id NOT IN (
                     SELECT id FROM threat_assessments
                     WHERE device_uid=?
                     ORDER BY id DESC LIMIT ?
                 )""",
            (device_uid, device_uid, MAX_HISTORY),
        )

        if anomaly:
            log_event(
                "intelligence.anomaly_detected",
                "IoT telemetry deviated from the trained device baseline",
                severity="critical" if severity == "critical" else "warning",
                source="intelligence_manager",
                device_uid=device_uid,
                details={"telemetry_id": telemetry_id, "score": score,
                         "confidence": confidence, "severity": severity,
                         "reasons": reasons, "model_version": MODEL_VERSION},
                connection=conn,
            )

    return {
        "telemetry_id": telemetry_id,
        "device_uid": device_uid,
        "anomaly": anomaly,
        "anomaly_score": score,
        "confidence": confidence,
        "severity": severity,
        "ml_prediction": ml_prediction,
        "reasons": reasons,
        "model_version": MODEL_VERSION,
    }


def get_device_threats(device_uid: str, limit: int = 50) -> dict | None:
    if not isinstance(limit, int) or not 1 <= limit <= 500:
        raise ValueError("limit must be between 1 and 500")
    with get_connection() as conn:
        device = conn.execute(
            "SELECT device_uid,name FROM devices WHERE device_uid=?", (device_uid,)
        ).fetchone()
        if device is None:
            return None
        baseline = conn.execute(
            "SELECT sample_count,model_version,trained_at FROM intelligence_baselines WHERE device_uid=?",
            (device_uid,),
        ).fetchone()
        rows = conn.execute(
            """SELECT * FROM threat_assessments WHERE device_uid=?
               ORDER BY id DESC LIMIT ?""", (device_uid, limit)
        ).fetchall()
    items = []
    for row in rows:
        item = dict(row)
        item["anomaly"] = bool(item["anomaly"])
        item["reasons"] = json.loads(item.pop("reasons_json"))
        items.append(item)
    return {"device": dict(device), "baseline": dict(baseline) if baseline else None,
            "assessments": items}


def get_threat_summary() -> dict:
    with get_connection() as conn:
        totals = conn.execute(
            """SELECT COUNT(*) AS assessments,
                      SUM(anomaly) AS anomalies,
                      COUNT(DISTINCT device_uid) AS assessed_devices
               FROM threat_assessments"""
        ).fetchone()
        severity = conn.execute(
            """SELECT severity,COUNT(*) AS count FROM threat_assessments
               WHERE anomaly=1 GROUP BY severity"""
        ).fetchall()
        baselines = conn.execute(
            "SELECT COUNT(*) FROM intelligence_baselines"
        ).fetchone()[0]
    return {"assessments": totals["assessments"],
            "anomalies": totals["anomalies"] or 0,
            "assessed_devices": totals["assessed_devices"] or 0,
            "trained_baselines": baselines,
            "anomalies_by_severity": {r["severity"]: r["count"] for r in severity}}
