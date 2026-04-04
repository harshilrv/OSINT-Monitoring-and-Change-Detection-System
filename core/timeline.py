import sqlite3
from collections import defaultdict
from datetime import datetime
from typing import Dict, List

DB_PATH = "osint_engine.db"


def parse_day(ts: str) -> str:
    """
    Normalize timestamp to YYYY-MM-DD
    """
    return ts.split("T")[0]


def get_timeline(target: str, limit_days: int = 30) -> Dict[str, Dict]:
    """
    Build a timeline of findings grouped by day
    """

    conn = sqlite3.connect(DB_PATH)
    cur = conn.cursor()

    cur.execute("""
        SELECT timestamp, value, confidence
        FROM findings
        WHERE target=?
        ORDER BY timestamp ASC
    """, (target,))

    rows = cur.fetchall()
    conn.close()

    timeline = defaultdict(lambda: {
        "added": set(),
        "confidence_avg": 0.0,
        "count": 0
    })

    for ts, value, confidence in rows:
        day = parse_day(ts)
        timeline[day]["added"].add(value)
        timeline[day]["confidence_avg"] += confidence
        timeline[day]["count"] += 1

    # finalize averages
    for day in timeline:
        if timeline[day]["count"]:
            timeline[day]["confidence_avg"] = round(
                timeline[day]["confidence_avg"] / timeline[day]["count"], 2
            )

    return dict(timeline)


def print_timeline_report(target: str, days: int = 30):
    """
    Pretty CLI output
    """
    timeline = get_timeline(target, days)

    if not timeline:
        print("\n[!] No historical data available\n")
        return

    print("\n========= TIMELINE REPORT =========\n")
    print(f"Target: {target}\n")

    for day in sorted(timeline.keys()):
        entry = timeline[day]
        print(f"{day}")
        print(f"  + Subdomains discovered: {len(entry['added'])}")
        print(f"  ~ Avg confidence: {entry['confidence_avg']}")
        print()

    print("==================================\n")
