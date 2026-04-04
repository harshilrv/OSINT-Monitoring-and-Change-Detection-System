import sqlite3
from collections import defaultdict
from typing import Dict

DB_PATH = "osint_engine.db"


def get_daily_subdomain_counts(target: str) -> Dict[str, int]:
    conn = sqlite3.connect(DB_PATH)
    cur = conn.cursor()

    cur.execute("""
        SELECT timestamp, COUNT(DISTINCT value)
        FROM findings
        WHERE target=?
        GROUP BY timestamp
        ORDER BY timestamp ASC
    """, (target,))

    rows = cur.fetchall()
    conn.close()

    daily = defaultdict(int)

    for ts, count in rows:
        day = ts.split("T")[0]
        daily[day] = max(daily[day], count)

    return dict(daily)


def calculate_trend_metrics(target: str):
    daily = get_daily_subdomain_counts(target)

    if len(daily) < 2:
        return {
            "subdomain_volatility": "UNKNOWN",
            "growth_rate": 0.0,
            "stability_score": 1.0
        }

    counts = list(daily.values())
    changes = [
        abs(counts[i] - counts[i - 1])
        for i in range(1, len(counts))
    ]

    avg_change = sum(changes) / len(changes)
    avg_count = sum(counts) / len(counts)

    growth_rate = round((counts[-1] - counts[0]) / max(avg_count, 1), 2)

    if avg_change == 0:
        volatility = "VERY LOW"
    elif avg_change <= 1:
        volatility = "LOW"
    elif avg_change <= 3:
        volatility = "MEDIUM"
    else:
        volatility = "HIGH"

    stability_score = round(
        max(0.0, 1.0 - (avg_change / max(avg_count, 1))),
        2
    )

    return {
        "subdomain_volatility": volatility,
        "growth_rate": growth_rate,
        "stability_score": stability_score
    }


def print_trend_report(target: str):
    metrics = calculate_trend_metrics(target)

    print("\n========= TREND ANALYSIS =========\n")
    print(f"Target: {target}\n")

    print(f"Subdomain volatility : {metrics['subdomain_volatility']}")
    print(f"Growth rate          : {metrics['growth_rate']}")
    print(f"Stability score      : {metrics['stability_score']}")

    print("\n=================================\n")
