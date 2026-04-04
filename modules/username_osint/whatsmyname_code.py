import requests
from tqdm import tqdm

WIMN_DATA_URL = "https://raw.githubusercontent.com/WebBreacher/WhatsMyName/main/wmn-data.json"

headers = {
    "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64)"
}


# ---------------------------
# Load site database
# ---------------------------
def load_wimn_data():
    try:
        r = requests.get(WIMN_DATA_URL, timeout=15)
        r.raise_for_status()
        return r.json()
    except Exception:
        return {}


# ---------------------------
# Core checker
# ---------------------------
def check_username(username, data):

    sites = data.get("sites", [])
    results = []

    for site in tqdm(sites, desc="WhatsMyName", unit="site", leave=False):

        name = site.get("name", "")
        uri_check = site.get("uri_check", "")
        e_code = site.get("e_code", 200)
        e_string = site.get("e_string", "")
        m_string = site.get("m_string", "")

        if not uri_check:
            continue

        url = uri_check.replace("{account}", username)

        try:
            r = requests.get(
                url,
                headers=headers,
                timeout=6,   # 🔥 slightly faster
                allow_redirects=True
            )

            status_ok = (r.status_code == e_code)
            presence_ok = (e_string and e_string in r.text) if e_string else status_ok
            absence_ok = (m_string not in r.text) if m_string else True

            if status_ok and presence_ok and absence_ok:
                results.append({
                    "platform": name.lower(),   # ✅ normalize
                    "url": url
                })

        except requests.exceptions.RequestException:
            continue

    return results


# ---------------------------
# MAIN ENTRY (ENGINE USES THIS)
# ---------------------------
def run(username):

    data = load_wimn_data()

    if not data:
        return []

    results = check_username(username, data)

    # 🔥 REMOVE duplicates (important)
    unique = []
    seen = set()

    for r in results:
        key = (r["platform"], r["url"])
        if key not in seen:
            seen.add(key)
            unique.append(r)

    return unique