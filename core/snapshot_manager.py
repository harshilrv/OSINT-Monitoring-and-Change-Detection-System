import os
import requests
from datetime import datetime


BASE_DIR = "snapshots"


def get_target_dir(target: str):
    path = os.path.join(BASE_DIR, target)
    os.makedirs(path, exist_ok=True)
    return path


def save_snapshot(target: str, html: str):

    folder = get_target_dir(target)

    timestamp = datetime.utcnow().strftime("%Y-%m-%d_%H-%M-%S")

    file_path = os.path.join(folder, f"{timestamp}.html")

    with open(file_path, "w", encoding="utf-8", errors="ignore") as f:
        f.write(html)

    return file_path


def load_latest_snapshot(target: str):

    folder = get_target_dir(target)

    files = sorted(
        [f for f in os.listdir(folder) if f.endswith(".html")]
    )

    if not files:
        return None

    latest = files[-1]

    path = os.path.join(folder, latest)

    with open(path, "r", encoding="utf-8", errors="ignore") as f:
        return f.read()


def fetch_current_html(url: str):

    try:
        r = requests.get(url, timeout=15)
        return r.text
    except Exception:
        return ""
