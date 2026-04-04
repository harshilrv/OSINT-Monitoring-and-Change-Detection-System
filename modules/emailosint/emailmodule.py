import dns.resolver
from matplotlib.style import context
import requests
import subprocess
import json
from bs4 import BeautifulSoup
from playwright.sync_api import sync_playwright
import whois


# -------------------------------
# CONFIG
# -------------------------------
disposable_domains = [
    "10minutemail.com",
    "mailinator.com",
    "tempmail.com",
    "guerrillamail.com",
    "yopmail.com"
]

common_domains = ["gmail.com", "yahoo.com", "hotmail.com", "outlook.com"]


# -------------------------------
# 1. EMAIL REPUTATION
# -------------------------------
def email_reputation(email):
    print("\n===== [1] EMAIL REPUTATION =====\n")

    domain = email.split("@")[1]

    print("Email:", email)
    print("Domain:", domain)

    # Disposable
    if domain.lower() in disposable_domains:
        print("Disposable email detected")
    else:
        print("Not disposable")

    # Type
    if domain.lower() in common_domains:
        print("Public email provider")
    else:
        print("Organization email")

    # MX Records
    print("\n--- MX Records ---")
    try:
        answers = dns.resolver.resolve(domain, 'MX')
        for rdata in answers:
            print("Mail Server:", rdata.exchange)
    except:
        print("No MX records")

    # Website
    print("\n--- Website ---")
    try:
        response = requests.get(f"http://{domain}", timeout=5)
        print("Status Code:", response.status_code)
    except:
        print("Website not reachable")

    # WHOIS
    print("\n--- WHOIS ---")
    try:
        domain_info = whois.whois(domain)
        print("Registrar:", domain_info.registrar)
        print("Created:", domain_info.creation_date)
        print("Expires:", domain_info.expiration_date)
        print("Country:", domain_info.country)
    except:
        print("WHOIS unavailable")

    # SPF
    print("\n--- SPF ---")
    try:
        records = dns.resolver.resolve(domain, 'TXT')
        found = any("v=spf1" in r.to_text() for r in records)
        print("SPF Found" if found else "No SPF")
    except:
        print("SPF check failed")

    # DMARC
    print("\n--- DMARC ---")
    try:
        records = dns.resolver.resolve(f"_dmarc.{domain}", 'TXT')
        found = any("v=DMARC1" in r.to_text() for r in records)
        print("DMARC Found" if found else "No DMARC")
    except:
        print("No DMARC")


# -------------------------------
# 2. BREACH CHECK
# -------------------------------
def breach_check(email):
    print("\n===== [2] BREACH CHECK =====\n")

    try:
        with sync_playwright() as p:
            browser = p.chromium.launch(headless=False)
            context = browser.new_context(
                user_agent="Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 Chrome/122.0.0.0 Safari/537.36"
            )
            page = context.new_page()

            page.goto("https://haveibeenpwned.com", timeout=60000)
            page.fill("input#emailInput", email)
            page.keyboard.press("Enter")

            page.wait_for_timeout(8000)

            html = page.content()
            browser.close()

        soup = BeautifulSoup(html, "html.parser")

        for tag in soup(["script", "style", "nav", "footer", "head"]):
            tag.decompose()

        text = soup.get_text("\n")
        lines = [l.strip() for l in text.splitlines() if l.strip()]

        print("\nTop Results:\n")
        for line in lines[:20]:
            print(line)

    except Exception as e:
        print("Error:", e)


# -------------------------------
# 3. USERNAME CHECK (HOLEHE)
# -------------------------------
def username_check(email):
    print("\n===== [3] ACCOUNT ENUMERATION =====\n")

    try:
        result = subprocess.run(
            ["holehe", email],
            capture_output=True,
            text=True,
            encoding="utf-8",
            errors="ignore"
        )

        lines = result.stdout.split("\n")

        found = False
        for line in lines:
            if "[+]" in line:
                print(line)
                found = True

        if not found:
            print("No accounts found")

    except Exception as e:
        print("Error running holehe:", e)


# -------------------------------
# MAIN
# -------------------------------
def main():
    email = input("Enter email: ").strip()

    email_reputation(email)
    breach_check(email)
    username_check(email)

    print("\n===== DONE =====\n")


if __name__ == "__main__":
    main()