import sqlite3
from datetime import datetime

def init_db(name):
    conn = sqlite3.connect(name)
    c = conn.cursor()
    c.execute('''
        CREATE TABLE IF NOT EXISTS events (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            timestamp TEXT,
            event_type TEXT,
            message TEXT
        )
    ''')
    conn.commit()
    conn.close()

def log_event(name, event_type, message):
    conn = sqlite3.connect(name)
    c = conn.cursor()
    c.execute("INSERT INTO events (timestamp, event_type, message) VALUES (?, ?, ?)",
              (datetime.now().strftime("%Y-%m-%d %H:%M:%S"), event_type, message))
    conn.commit()
    conn.close()