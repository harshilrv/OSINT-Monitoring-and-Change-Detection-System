import sqlite3
import os
from typing import List
from datetime import datetime

from core.models import Finding


# =====================================
# Safe absolute DB path
# =====================================

BASE_DIR = os.path.dirname(os.path.dirname(__file__))
DB_PATH = os.path.join(BASE_DIR, "osint_engine.db")


# =====================================
# Initialize database
# =====================================

def init_db():

    conn = sqlite3.connect(DB_PATH)
    cur = conn.cursor()

    cur.execute("""
        CREATE TABLE IF NOT EXISTS findings (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            timestamp TEXT,
            type TEXT,
            value TEXT,
            target TEXT,
            sources TEXT,
            confidence REAL,
            verified INTEGER
        )
    """)

    conn.commit()
    conn.close()


# =====================================
# Save scan results
# =====================================

def save_findings(findings: List[Finding]):

    init_db()

    conn = sqlite3.connect(DB_PATH)
    cur = conn.cursor()

    timestamp = datetime.utcnow().isoformat()

    for f in findings:

        # Clean source list
        sources_list = f.metadata.get("sources")

        if isinstance(sources_list, list):
            sources = ",".join(sorted(sources_list))
        else:
            sources = f.source

        verified = 1 if f.metadata.get("verified") else 0

        cur.execute("""
            INSERT INTO findings 
            (timestamp, type, value, target, sources, confidence, verified)
            VALUES (?, ?, ?, ?, ?, ?, ?)
        """, (
            timestamp,
            f.type,
            f.value,
            f.target,
            sources,
            f.confidence,
            verified
        ))

    conn.commit()
    conn.close()


# =====================================
# Load last scan (for change detection)
# =====================================

def load_last_scan(target: str):

    init_db()

    conn = sqlite3.connect(DB_PATH)
    cur = conn.cursor()

    # Get latest timestamp for target
    cur.execute("""
        SELECT MAX(timestamp) FROM findings WHERE target=?
    """, (target,))

    row = cur.fetchone()

    if not row or not row[0]:
        conn.close()
        return []

    last_time = row[0]

    cur.execute("""
        SELECT value, sources, confidence, verified
        FROM findings
        WHERE timestamp=? AND target=?
    """, (last_time, target))

    results = cur.fetchall()
    conn.close()

    return results
