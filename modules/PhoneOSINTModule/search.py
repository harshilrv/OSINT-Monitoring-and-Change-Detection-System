import json
import os
import re

from bs4 import BeautifulSoup
from urllib.parse import unquote

SESSION_FILE = os.path.join(os.path.dirname(__file__), "session.json")


def load_session():

    if not os.path.exists(SESSION_FILE):
        return []

    with open(SESSION_FILE, "r") as f:
        data = json.load(f)

    return [{"name": k, "value": v, "domain": "www.truecaller.com", "path": "/"} for k, v in data.items()]


def search_number(phone_number, country_code="in"):

    try:
        from playwright.sync_api import sync_playwright
    except ImportError:
        return {"error": "playwright missing"}

    cookies = load_session()

    if not cookies:
        return {"error": "no truecaller session"}

    url = f"https://www.truecaller.com/search/{country_code}/{phone_number}"

    with sync_playwright() as p:

        browser = p.chromium.launch(headless=True)
        context = browser.new_context()

        context.add_cookies(cookies)

        page = context.new_page()

        page.goto(url, wait_until="networkidle", timeout=20000)

        html = page.content()

        browser.close()

    return parse_html(html, phone_number)


def parse_html(html, phone_number):

    soup = BeautifulSoup(html, "html.parser")

    article = soup.find("article")

    if not article:
        return {"not_found": True}

    name_div = article.find("div", class_=lambda c: c and "font-bold" in c)

    name = name_div.get_text(strip=True) if name_div else "Unknown"

    spam = bool(article.find(string=re.compile("fraud|spam", re.I)))

    return {
        "number": phone_number,
        "name": name,
        "is_spam": spam
    }