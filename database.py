import sqlite3
import datetime
import os

DB_PATH = os.path.join(os.path.dirname(__file__), 'idps.db')

def init_db():
    conn = sqlite3.connect(DB_PATH)
    c = conn.cursor()
    c.execute('''
        CREATE TABLE IF NOT EXISTS attacks (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            timestamp DATETIME DEFAULT CURRENT_TIMESTAMP,
            src_ip TEXT,
            dst_ip TEXT,
            protocol TEXT,
            attack_type TEXT,
            confidence REAL,
            action_taken TEXT
        )
    ''')
    conn.commit()
    conn.close()

def log_attack(src_ip, dst_ip, protocol, attack_type, confidence, action):
    conn = sqlite3.connect(DB_PATH)
    c = conn.cursor()
    c.execute('''
        INSERT INTO attacks (src_ip, dst_ip, protocol, attack_type, confidence, action_taken)
        VALUES (?, ?, ?, ?, ?, ?)
    ''', (src_ip, dst_ip, protocol, attack_type, float(confidence), action))
    conn.commit()
    conn.close()

def get_recent_alerts(limit=10):
    conn = sqlite3.connect(DB_PATH)
    c = conn.cursor()
    c.execute('SELECT * FROM attacks ORDER BY id DESC LIMIT ?', (limit,))
    rows = c.fetchall()
    conn.close()
    return rows

def get_stats():
    conn = sqlite3.connect(DB_PATH)
    c = conn.cursor()
    c.execute('SELECT count(*) FROM attacks')
    total_attacks = c.fetchone()[0]
    
    # Group by attack type
    c.execute('SELECT attack_type, count(*) FROM attacks GROUP BY attack_type')
    types = c.fetchall()
    
    conn.close()
    return total_attacks, dict(types)

def clear_all_logs():
    conn = sqlite3.connect(DB_PATH, timeout=10)
    c = conn.cursor()
    c.execute('DELETE FROM attacks')
    conn.commit()
    conn.close()

# Initialize on module load
if not os.path.exists(DB_PATH):
    init_db()
