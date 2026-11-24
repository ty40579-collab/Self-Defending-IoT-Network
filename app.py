import os
import hmac
import logging
import sqlite3
import shutil
from datetime import datetime, timezone
from pathlib import Path

from flask import Flask, jsonify, render_template, request

from src.database import create_database, get_connection
from src.device_manager import get_device, list_devices, mark_device_seen, register_device, update_device_status
from src.event_logger import list_events
from src.health_checker import get_system_health
from src.prediction import predict_file
from src.intelligence_manager import (
    train_device_baseline,
    get_device_threats,
    get_threat_summary,
)
from src.monitoring_manager import (
    get_device_monitoring,
    get_monitoring_summary,
)
from src.protection_manager import (
    get_protection_status,
    get_protection_history,
    isolate_device,
    release_device,
)
from src.network_firewall import FirewallError, NftablesBackend

app = Flask(__name__)
logger = logging.getLogger(__name__)
app.config["MAX_CONTENT_LENGTH"] = 50 * 1024 * 1024
create_database()

# Initialize only the project's owned firewall rules when enforcement is enabled.
if get_protection_status()["enabled"]:
    try:
        NftablesBackend()._ensure_rules()
        logger.info("Self-Defending IoT firewall initialized and verified")
    except Exception:
        logger.exception("Self-Defending IoT firewall startup initialization failed")
        raise

def _error(message, status):
    return jsonify({"error": message}), status

def get_dashboard_data():
    with get_connection() as conn:
        total_alerts = conn.execute(
            "SELECT COUNT(*) FROM alerts"
        ).fetchone()[0]
        critical_alerts = conn.execute(
            "SELECT COUNT(*) FROM alerts WHERE severity='Critical'"
        ).fetchone()[0]

    protection = get_protection_status()
    enforcement_enabled = protection["enabled"]
    nft_available = shutil.which("nft") is not None

    if not enforcement_enabled:
        security_status = "Protection disabled"
        security_detail = (
            "Network enforcement is disabled. Monitoring and threat "
            "assessment can continue without firewall changes."
        )
    elif not nft_available:
        security_status = "Monitoring only"
        security_detail = (
            "Enforcement is configured, but the nftables executable is "
            "unavailable on this host."
        )
    else:
        security_status = "Configured — live enforcement unverified"
        security_detail = (
            "Enforcement is enabled and nftables is installed, but live packet "
            "blocking is unverified. Gateway routing, forwarding, permissions "
            "and firewall rules still require validation on the actual Linux gateway."
        )

    return {
        "total_traffic": 628385,
        "normal_traffic": 362361,
        "training_attack": 266024,
        "detected_threats": total_alerts,
        "critical_threats": critical_alerts,
        "isolations": protection["active_isolations"],
        "security_status": security_status,
        "security_status_detail": security_detail,
        "automatic_isolation_enabled": (
            os.environ.get("IOT_AUTO_ISOLATION_ENABLED", "false").lower()
            == "true"
        ),
    }

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

    if not isinstance(payload["status"], str):
        return _error('"status" must be a string', 400)

    if payload["status"] in {"isolated", "recovering"}:
        return _error(
            "This status can only be changed through confirmed network "
            "protection operations",
            409,
        )

    try:
        return jsonify({"device": update_device_status(device_uid, payload["status"])}), 200
    except LookupError:
        return _error("Device not found", 404)
    except (ValueError, TypeError) as exc:
        return _error(str(exc), 400)


def _protection_api_authorized():
    """Return an HTTP error response unless a configured bearer token matches."""
    expected = os.environ.get("IOT_ENFORCEMENT_API_TOKEN", "").strip()
    if not expected:
        return _error("Protection API is disabled: API token is not configured", 503)

    authorization = request.headers.get("Authorization", "")
    scheme, separator, supplied = authorization.partition(" ")

    if (
        not separator
        or scheme.lower() != "bearer"
        or not supplied
        or not hmac.compare_digest(supplied, expected)
    ):
        return _error("A valid bearer token is required", 401)

    return None


@app.route("/api/protection/status", methods=["GET"])
def api_protection_status():
    auth_error = _protection_api_authorized()
    if auth_error is not None:
        return auth_error
    return jsonify(get_protection_status())


@app.route("/api/protection/devices/<device_uid>/history", methods=["GET"])
def api_protection_history(device_uid):
    auth_error = _protection_api_authorized()
    if auth_error is not None:
        return auth_error

    try:
        limit = int(request.args.get("limit", "50"))
        return jsonify({
            "device_uid": device_uid,
            "history": get_protection_history(device_uid, limit=limit),
        })
    except ValueError as exc:
        return _error(str(exc), 400)


@app.route("/api/protection/devices/<device_uid>/isolate", methods=["POST"])
def api_protection_isolate(device_uid):
    auth_error = _protection_api_authorized()
    if auth_error is not None:
        return auth_error

    payload = request.get_json(silent=True)
    if payload is None:
        payload = {}
    if not isinstance(payload, dict) or set(payload) - {"reason"}:
        return _error('Request body may contain only "reason"', 400)

    reason = payload.get("reason", "Manual isolation")
    try:
        result = isolate_device(device_uid, reason=reason)
        return jsonify({"result": result}), 200
    except LookupError as exc:
        return _error(str(exc), 404)
    except PermissionError as exc:
        return _error(str(exc), 403)
    except ValueError as exc:
        return _error(str(exc), 400)
    except FirewallError as exc:
        logger.exception("Firewall isolation operation failed")
        return _error(str(exc), 502)


@app.route("/api/protection/devices/<device_uid>/release", methods=["POST"])
def api_protection_release(device_uid):
    auth_error = _protection_api_authorized()
    if auth_error is not None:
        return auth_error

    payload = request.get_json(silent=True)
    if payload is None:
        payload = {}
    if not isinstance(payload, dict) or set(payload) - {"reason"}:
        return _error('Request body may contain only "reason"', 400)

    reason = payload.get("reason", "Manual release")
    try:
        result = release_device(device_uid, reason=reason)
        return jsonify({"result": result}), 200
    except LookupError as exc:
        return _error(str(exc), 404)
    except PermissionError as exc:
        return _error(str(exc), 403)
    except ValueError as exc:
        return _error(str(exc), 400)
    except FirewallError as exc:
        logger.exception("Firewall release operation failed")
        return _error(str(exc), 502)


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


@app.route("/api/monitoring/summary")
def api_monitoring_summary():
    return jsonify(get_monitoring_summary())


@app.route("/api/monitoring/devices/<device_uid>")
def api_device_monitoring(device_uid):
    try:
        limit = int(request.args.get("limit", "50"))
        result = get_device_monitoring(device_uid, limit=limit)
    except ValueError as exc:
        return _error(str(exc), 400)

    if result is None:
        return _error("Device not found", 404)

    return jsonify(result)

@app.route("/api/intelligence/summary")
def api_intelligence_summary():
    return jsonify(get_threat_summary())


@app.route("/api/intelligence/devices/<device_uid>/baseline", methods=["POST"])
def api_train_device_baseline(device_uid):
    payload = request.get_json(silent=True) or {}
    if not isinstance(payload, dict) or set(payload) - {"limit"}:
        return _error('Request body may contain only "limit"', 400)
    try:
        limit = int(payload.get("limit", 200))
        result = train_device_baseline(device_uid, limit)
        return jsonify({"baseline": result}), 201
    except LookupError:
        return _error("Device not found", 404)
    except (ValueError, TypeError) as exc:
        return _error(str(exc), 400)


@app.route("/api/intelligence/devices/<device_uid>/threats")
def api_device_threats(device_uid):
    try:
        result = get_device_threats(
            device_uid, int(request.args.get("limit", "50"))
        )
    except ValueError as exc:
        return _error(str(exc), 400)
    if result is None:
        return _error("Device not found", 404)
    return jsonify(result)




def _recovery_api_authorized():
    import hmac
    import os
    from flask import jsonify, request

    expected = os.environ.get("IOT_ENFORCEMENT_API_TOKEN")
    if not expected:
        return jsonify({"error": "Protection API token is not configured"}), 503
    supplied = request.headers.get("Authorization", "")
    if not hmac.compare_digest(supplied, f"Bearer {expected}"):
        return jsonify({"error": "Unauthorized"}), 401
    return None


@app.route("/api/protection/devices/<device_uid>/recovery", methods=["GET"])
def api_device_recovery_status(device_uid):
    from flask import jsonify
    from src.protection_manager import get_recovery_status

    denied = _recovery_api_authorized()
    if denied is not None:
        return denied
    try:
        return jsonify(get_recovery_status(device_uid)), 200
    except LookupError:
        return jsonify({"error": "Device not found"}), 404
    except ValueError as exc:
        return jsonify({"error": str(exc)}), 400


@app.route("/api/protection/devices/<device_uid>/recover", methods=["POST"])
def api_complete_device_recovery(device_uid):
    from flask import jsonify
    from src.protection_manager import complete_device_recovery

    denied = _recovery_api_authorized()
    if denied is not None:
        return denied
    try:
        result = complete_device_recovery(device_uid)
        return jsonify(result), 200 if result["completed"] else 409
    except LookupError:
        return jsonify({"error": "Device not found"}), 404
    except ValueError as exc:
        return jsonify({"error": str(exc)}), 400

if __name__ == "__main__":
    app.run(host=os.getenv("HOST","127.0.0.1"),
            port=int(os.getenv("PORT","5000")),
            debug=os.getenv("APP_ENV","development").lower() == "development")
