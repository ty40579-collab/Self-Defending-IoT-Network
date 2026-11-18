import sqlite3

from flask import Flask
from flask import render_template
from flask import jsonify
from flask import request
from src.prediction import predict_file
from datetime import datetime


def get_dashboard_data():

    conn = sqlite3.connect(
        "iot_security.db"
    )

    cursor = conn.cursor()

    cursor.execute(
        "SELECT COUNT(*) FROM alerts"
    )

    total_alerts = cursor.fetchone()[0]

    cursor.execute("""
    SELECT COUNT(*)
    FROM alerts
    WHERE severity='Critical'
    """)

    critical_alerts = cursor.fetchone()[0]

    conn.close()

    return {
        "total_traffic": 628385,
        "normal_traffic": 362361,

        # Training dataset attack count
        "training_attack": 266024,

        # Live security monitoring
        "detected_threats": total_alerts,
        "critical_threats": critical_alerts,

        "isolations": critical_alerts,
        "security_status": "Protected"
     }


from src.database import create_database

app = Flask(__name__)
create_database()



@app.route("/")
def home():

    data = get_dashboard_data()

    latest_alert = get_latest_alert()

    severity_data = get_threat_statistics()

    return render_template(
        "index.html",
        data=data,
        latest_alert=latest_alert,
        severity_data=severity_data
    )


@app.route("/api/dashboard")
def dashboard():
    return jsonify(
        get_dashboard_data()
        )


@app.route("/monitoring")
def monitoring():
    return render_template("monitoring.html")


@app.route("/traffic")
def traffic():
    return render_template("traffic_analysis.html")


@app.route("/threats")
def threats():

    conn = sqlite3.connect(
        "iot_security.db"
    )

    cursor = conn.cursor()

    cursor.execute("""
        SELECT *
        FROM alerts
        ORDER BY id DESC
        LIMIT 1
    """)

    latest_alert = cursor.fetchone()

    conn.close()

    return render_template(
        "threats.html",
        alert=latest_alert
    )

@app.route("/devices")
def devices():
    return render_template("devices.html")


@app.route("/response")
def response():
    return render_template("response.html")


@app.route("/performance")
def performance():

    metrics = {
        "accuracy": 100.0,
        "precision": 100.0,
        "recall": 100.0,
        "f1_score": 100.0
    }

    return render_template(
        "model_performance.html",
        metrics=metrics
    )


@app.route("/alerts")
def alerts():

    conn = sqlite3.connect(
        "iot_security.db"
    )

    cursor = conn.cursor()

    cursor.execute(
        "SELECT * FROM alerts"
    )

    alerts = cursor.fetchall()

    conn.close()

    return render_template(
        "alerts.html",
        alerts=alerts
    )

@app.route("/about")
def about():
    return render_template(
        "about_project.html"
    )
    
@app.route("/settings")
def settings():
    return render_template("settings.html")

@app.route("/upload")
def upload_page():
    return render_template(
        "upload.html"
    )
    
@app.route(
    "/upload",
    methods=["POST"]
)
def upload_file():

    csv_file = request.files["file"]

    save_path = (
        "data/raw/" +
        csv_file.filename
    )

    csv_file.save(save_path)

    try:

        result = predict_file(
            save_path
        )
        
        conn = sqlite3.connect(
            "iot_security.db"
        )

        cursor = conn.cursor()

        cursor.execute(
            """
            INSERT INTO alerts
            (timestamp, attack_type, severity, action)
            VALUES (?, ?, ?, ?)
            """,
            (
             datetime.now().strftime(
                "%Y-%m-%d %H:%M:%S"
                ),
                "Uploaded CSV Analysis",
                "Critical"
                    if result["attack_records"] > 0
                    else "Low",
                "SIMULATION: Device isolated"
                    if result["attack_records"] > 0
                    else "No action required"
            )
        )

        conn.commit()
        conn.close()
        return render_template(
            "analysis_result.html",
            result=result
        )

    except Exception as e:

        return f"Error: {e}"

def get_latest_alert():

    conn = sqlite3.connect(
        "iot_security.db"
    )

    cursor = conn.cursor()

    cursor.execute("""
        SELECT *
        FROM alerts
        ORDER BY id DESC
        LIMIT 1
    """)

    alert = cursor.fetchone()

    conn.close()

    return alert

def get_threat_statistics():

    conn = sqlite3.connect(
        "iot_security.db"
    )

    cursor = conn.cursor()

    cursor.execute("""
        SELECT severity, COUNT(*)
        FROM alerts
        GROUP BY severity
    """)

    rows = cursor.fetchall()

    conn.close()

    stats = {
        "Critical": 0,
        "High": 0,
        "Medium": 0,
        "Low": 0
    }

    for severity, count in rows:
        stats[severity] = count

    return stats

if __name__ == "__main__":
    app.run(debug=True)