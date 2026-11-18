import os
import logging
import sqlite3
from datetime import datetime, timezone
from pathlib import Path

from flask import Flask, jsonify, render_template, request

from src.database import create_database, get_connection
from src.device_manager import get_device, list_devices, mark_device_seen, register_device, update_device_status
from src.event_logger import list_events
from src.health_checker import get_system_health
from src.prediction import predict_file

app = Flask(__name__)
logger = logging.getLogger(__name__)
app.config["MAX_CONTENT_LENGTH"] = 50 * 1024 * 1024
create_database()

def _error(message, status):
    return jsonify({"error": message}), status

def get_dashboard_data():
    with get_connection() as conn:
        total_alerts = conn.execute("SELECT COUNT(*) FROM alerts").fetchone()[0]
        critical_alerts = conn.execute("SELECT COUNT(*) FROM alerts WHERE severity='Critical'").fetchone()[0]
    return {"total_traffic": 628385, "normal_traffic": 362361, "training_attack": 266024,
            "detected_threats": total_alerts, "critical_threats": critical_alerts,
            "isolations": critical_alerts, "security_status": "Protected"}

@app.route("/")
def home():
    return render_template("index.html", data=get_dashboard_data(),
                           latest_alert=get_latest_alert(), severity_data=get_threat_statistics())

@app.route("/api/dashboard")
def dashboard():
    return jsonify(get_dashboard_data())

@app.route("/api/health")
def api_health():
    health = get_system_health()
    return jsonify(health), (200 if health["status"] == "ok" else 503)

@app.route("/api/devices", methods=["GET", "POST"])
def api_devices():
    if request.method == "GET":
        try:
            return jsonify({"devices": list_devices(status=request.args.get("status"))})
        except ValueError as exc:
            return _error(str(exc), 400)
    payload = request.get_json(silent=True)
    if not isinstance(payload, dict):
        return _error("Request body must be a JSON object", 400)
    allowed = {"device_uid","name","device_type","ip_address","mac_address",
               "communication_type","endpoint","trusted","metadata"}
    unknown = set(payload) - allowed
    if unknown:
        return _error("Unknown fields: " + ", ".join(sorted(unknown)), 400)
    try:
        device = register_device(**payload)
    except ValueError as exc:
        return _error(str(exc), 400)
    except sqlite3.IntegrityError:
        return _error("Device ID or MAC address already exists", 409)
    return jsonify({"device": device}), 201

@app.route("/api/devices/<device_uid>")
def api_device_detail(device_uid):
    device = get_device(device_uid)
    return (jsonify({"device": device}), 200) if device else _error("Device not found", 404)

@app.route("/api/devices/<device_uid>/status", methods=["PATCH"])
def api_device_status(device_uid):
    payload = request.get_json(silent=True)
    if not isinstance(payload, dict) or set(payload) != {"status"}:
        return _error('Request body must contain only "status"', 400)
    try:
        return jsonify({"device": update_device_status(device_uid, payload["status"])}), 200
    except LookupError:
        return _error("Device not found", 404)
    except (ValueError, TypeError) as exc:
        return _error(str(exc), 400)

@app.route("/api/devices/<device_uid>/seen", methods=["POST"])
def api_device_seen(device_uid):
    try:
        mark_device_seen(device_uid)
        return jsonify({"message": "Last-seen timestamp updated"})
    except LookupError:
        return _error("Device not found", 404)

@app.route("/api/system/events")
def api_system_events():
    try:
        return jsonify({"events": list_events(
            limit=int(request.args.get("limit", "100")),
            device_uid=request.args.get("device_uid"))})
    except ValueError as exc:
        return _error(str(exc), 400)

@app.route("/monitoring")
def monitoring(): return render_template("monitoring.html")
@app.route("/traffic")
def traffic(): return render_template("traffic_analysis.html")
@app.route("/threats")
def threats():
    with get_connection() as conn:
        alert = conn.execute("SELECT * FROM alerts ORDER BY id DESC LIMIT 1").fetchone()
    return render_template("threats.html", alert=tuple(alert) if alert else None)
@app.route("/devices")
def devices(): return render_template("devices.html")
@app.route("/response")
def response(): return render_template("response.html")
@app.route("/performance")
def performance():
    return render_template("model_performance.html",
        metrics={"accuracy":100.0,"precision":100.0,"recall":100.0,"f1_score":100.0})
@app.route("/alerts")
def alerts():
    with get_connection() as conn:
        rows = conn.execute("SELECT * FROM alerts").fetchall()
    return render_template("alerts.html", alerts=[tuple(row) for row in rows])
@app.route("/about")
def about(): return render_template("about_project.html")
@app.route("/settings")
def settings_page(): return render_template("settings.html")
@app.route("/upload", methods=["GET"])
def upload_page(): return render_template("upload.html")

@app.route("/upload", methods=["POST"])
def upload_file():
    csv_file = request.files.get("file")
    if csv_file is None or not csv_file.filename:
        return _error("A CSV file is required", 400)
    if not csv_file.filename.lower().endswith(".csv"):
        return _error("Only .csv files are accepted", 400)
    upload_dir = Path("data/raw")
    upload_dir.mkdir(parents=True, exist_ok=True)
    save_path = upload_dir / ("upload_" + datetime.now(timezone.utc).strftime("%Y%m%d%H%M%S%f") + ".csv")
    csv_file.save(save_path)
    try:
        result = predict_file(str(save_path))
        with get_connection() as conn:
            conn.execute("""INSERT INTO alerts(timestamp,attack_type,severity,action)
                VALUES (?,?,?,?)""",
                (datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S"),
                 "Uploaded CSV Analysis",
                 "Critical" if result["attack_records"] > 0 else "Low",
                 "SIMULATION: Device isolated" if result["attack_records"] > 0 else "No action required"))
        return render_template("analysis_result.html", result=result)
    except Exception:
        logger.exception("CSV analysis failed")
        return _error(
            "CSV analysis failed. Check the server logs for details.",
            500
        )
    finally:
        try: save_path.unlink(missing_ok=True)
        except OSError: pass

def get_latest_alert():
    with get_connection() as conn:
        row = conn.execute("SELECT * FROM alerts ORDER BY id DESC LIMIT 1").fetchone()
    return tuple(row) if row else None

def get_threat_statistics():
    with get_connection() as conn:
        rows = conn.execute("SELECT severity,COUNT(*) FROM alerts GROUP BY severity").fetchall()
    stats = {"Critical":0,"High":0,"Medium":0,"Low":0}
    for severity, count in rows:
        if severity in stats: stats[severity] = count
    return stats

if __name__ == "__main__":
    app.run(host=os.getenv("HOST","127.0.0.1"),
            port=int(os.getenv("PORT","5000")),
            debug=os.getenv("APP_ENV","development").lower() == "development")
