import json
import os
import time

SESSION_FILE = os.path.join(os.path.dirname(__file__), "session.json")


def login():

    try:
        from playwright.sync_api import sync_playwright
    except ImportError:
        print("[!] Playwright not installed")
        return False

    print("[*] Opening Truecaller login")

    with sync_playwright() as p:

        browser = p.chromium.launch(headless=False)
        context = browser.new_context()
        page = context.new_page()

        page.goto("https://www.truecaller.com/")

        logged_in = False

        for _ in range(100):

            time.sleep(3)

            cookies = context.cookies()

            cookie_names = [c["name"] for c in cookies]

            if "tc_user" in cookie_names:
                logged_in = True
                break

        if not logged_in:
            browser.close()
            return False

        cookies = context.cookies()

        cookie_dict = {c["name"]: c["value"] for c in cookies}

        with open(SESSION_FILE, "w") as f:
            json.dump(cookie_dict, f)

        browser.close()

        return True


def is_session_saved():

    return os.path.exists(SESSION_FILE) and os.path.getsize(SESSION_FILE) > 10


def clear_session():

    if os.path.exists(SESSION_FILE):
        os.remove(SESSION_FILE)