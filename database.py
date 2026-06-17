import sqlite3

DB_NAME = "alert.db"

def get_connection():
    return sqlite3.connect(DB_NAME)

def initialize_database():
    conn = get_connection()
    cursor = conn.cursor()

    cursor.execute("""
        CREATE TABLE IF NOT EXISTS process_events (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            timestamp TEXT NOT NULL,
            pid INTEGER,
            ppid INTEGER,
            process_name TEXT,
            command_line TEXT,
            username TEXT
        )""")

    cursor.execute("""
        CREATE TABLE IF NOT EXISTS alerts (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            timestamp TEXT NOT NULL,
            severity TEXT,
            rule_name TEXT,
            description TEXT
        )""")

def log_process_event(
        timestamp,
        pid,
        ppid,
        process_name,
        command_line,
        username
):
    conn = get_connection()
    cursor = conn.cursor()

    cursor.execute("""
        INSERT INTO process_events
        (
            timestamp,
            pid,
            ppid,
            process_name,
            command_line,
            username
        )
        VALUES (?, ?, ?, ?, ?, ?)
    """, (
        timestamp,
        pid,
        ppid,
        process_name,
        command_line,
        username
    ))

    conn.commit()
    conn.close()