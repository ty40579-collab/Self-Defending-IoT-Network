import sqlite3

DB_NAME = "iot_security.db"


def create_database():

    conn = sqlite3.connect(DB_NAME)

    cursor = conn.cursor()

    cursor.execute("""
    CREATE TABLE IF NOT EXISTS alerts (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        timestamp TEXT,
        attack_type TEXT,
        severity TEXT,
        action TEXT
    )
    """)

    conn.commit()
    conn.close()


def insert_alert(
    timestamp,
    attack_type,
    severity,
    action
):

    conn = sqlite3.connect(DB_NAME)

    cursor = conn.cursor()

    cursor.execute("""
    INSERT INTO alerts
    (
        timestamp,
        attack_type,
        severity,
        action
    )
    VALUES (?, ?, ?, ?)
    """,
    (
        timestamp,
        attack_type,
        severity,
        action
    ))

    conn.commit()
    conn.close()


if __name__ == "__main__":

    create_database()

    insert_alert(
        timestamp="2026-11-14 11:34:48",
        attack_type="DDoS-SYN_Flood",
        severity="Critical",
        action="SIMULATION: Device isolated"
    )

    print("Test alert inserted")