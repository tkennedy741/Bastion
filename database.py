import sqlite3

DB_NAME = "alert.db"

def get_connection():
    return sqlite3.connect(DB_NAME)

def initialize_database():
    conn = get_connection()
    cursor = conn.cursor()
    # Events table
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS events (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            event_record_id INTEGER,
            event_id INTEGER,
            timestamp TEXT,
            hostname TEXT,
            raw_XML TEXT
        )""")
    # Alerts Table
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS alerts (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            timestamp TEXT NOT NULL,
            severity TEXT,
            rule_name TEXT,
            description TEXT
        )""")

def log_event(
        event_record_id,
        event_id,
        timestamp,
        hostname,
        xml
):
    initialize_database()
    conn = get_connection()
    cursor = conn.cursor()

    cursor.execute("""
        INSERT INTO events
        (
            event_record_id,
            event_id,
            timestamp,
            hostname,
            raw_XML
        )
        VALUES (?, ?, ?, ?, ?)
    """, (
        event_record_id,
        event_id,
        timestamp,
        hostname,
        xml
    ))

    conn.commit()
    conn.close()