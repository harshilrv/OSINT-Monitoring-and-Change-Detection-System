import requests

headers = {
    "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64)"
}


# ---------------------------
# HELPERS
# ---------------------------

def safe_request(url, timeout=10):
    try:
        return requests.get(url, headers=headers, timeout=timeout)
    except:
        return None


# ---------------------------
# CHECKERS
# ---------------------------

def check_instagram(username):
    url = f"https://www.instagram.com/{username}/"
    r = safe_request(url)

    if not r:
        return None

    html = r.text.lower()

    not_found = [
        "sorry, this page isn’t available",
        "sorry, this page isn't available",
        "the link you followed may be broken",
    ]

    if not any(s in html for s in not_found):
        return {"platform": "instagram", "url": url}


def check_twitter(username):
    url = f"https://x.com/{username}"
    r = safe_request(url)

    if not r:
        return None

    text = r.text.lower()

    not_found = [
        "this account doesn’t exist",
        "this account doesn't exist",
        "account suspended",
    ]

    if not any(s in text for s in not_found):
        return {"platform": "twitter", "url": url}


def check_reddit(username):
    url = f"https://www.reddit.com/user/{username}/about.json"
    r = safe_request(url)

    if not r:
        return None

    try:
        if r.status_code == 200 and r.json().get("data", {}).get("name"):
            return {
                "platform": "reddit",
                "url": f"https://www.reddit.com/user/{username}"
            }
    except:
        return None


def check_github(username):
    url = f"https://api.github.com/users/{username}"
    r = safe_request(url)

    if not r:
        return None

    if r.status_code == 200:
        return {
            "platform": "github",
            "url": f"https://github.com/{username}"
        }


def check_linkedin(username):
    url = f"https://www.linkedin.com/in/{username}"
    r = safe_request(url)

    if not r:
        return None

    if r.status_code == 200 and "profile-not-found" not in r.text.lower():
        return {"platform": "linkedin", "url": url}


def check_youtube(username):
    url = f"https://www.youtube.com/@{username}"
    r = safe_request(url)

    if not r:
        return None

    if r.status_code == 200 and '"error"' not in r.text:
        return {"platform": "youtube", "url": url}


# ---------------------------
# MAIN FUNCTION (IMPORTANT)
# ---------------------------

def run(username):

    results = []

    checks = [
        check_instagram,
        check_twitter,
        check_reddit,
        check_github,
        check_linkedin,
        check_youtube
    ]

    for check in checks:
        try:
            res = check(username)
            if res:
                results.append(res)
        except:
            continue

    return results