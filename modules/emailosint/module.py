from typing import List
from core.base_module import BaseModule
from core.models import Finding

import dns.resolver
import requests
import subprocess
import whois
from bs4 import BeautifulSoup
from playwright.sync_api import sync_playwright


class EmailOSINTModule(BaseModule):

    name = "email_osint"
    supported_targets = ["email"]

    # -------------------------
    # MAIN ENTRY
    # -------------------------
    def run(self, target: str) -> List[Finding]:

        findings = []

        try:
            findings.append(self.email_reputation(target))
            findings.append(self.breach_check(target))
            findings.append(self.username_check(target))

        except Exception as e:
            print("[!] Email OSINT error:", e)

        return [f for f in findings if f]

    # -------------------------
    # 1. EMAIL REPUTATION
    # -------------------------
    def email_reputation(self, email):

        domain = email.split("@")[1]

        metadata = {
            "domain": domain,
            "mx_records": [],
            "spf": False,
            "dmarc": False,
            "whois": {}
        }

        # MX
        try:
            answers = dns.resolver.resolve(domain, 'MX')
            metadata["mx_records"] = [str(r.exchange) for r in answers]
        except:
            pass

        # SPF
        try:
            records = dns.resolver.resolve(domain, 'TXT')
            metadata["spf"] = any("v=spf1" in r.to_text() for r in records)
        except:
            pass

        # DMARC
        try:
            records = dns.resolver.resolve(f"_dmarc.{domain}", 'TXT')
            metadata["dmarc"] = any("v=DMARC1" in r.to_text() for r in records)
        except:
            pass

        # WHOIS
        try:
            info = whois.whois(domain)
            metadata["whois"] = {
                "registrar": str(info.registrar),
                "country": str(info.country)
            }
        except:
            pass

        return Finding(
            type="email",
            value=email,
            source="email_reputation",
            target=email,
            confidence=0.7,
            metadata=metadata
        )

    # -------------------------
    # 2. BREACH CHECK
    # -------------------------
    def breach_check(self, email):

        try:
            with sync_playwright() as p:
                browser = p.chromium.launch(headless=True)
                page = browser.new_page()

                page.goto("https://haveibeenpwned.com", timeout=60000)
                page.fill("input#emailInput", email)
                page.keyboard.press("Enter")

                page.wait_for_timeout(5000)

                html = page.content()
                browser.close()

            soup = BeautifulSoup(html, "html.parser")
            text = soup.get_text().lower()   # ✅ FIX

            if "no pwnage found" in text:
                breached = False
            elif "pwned" in text or "data breaches" in text:
                breached = True
            else:
                breached = None

        except:
            breached = None   # better than False (unknown vs safe)

        return Finding(
            type="email_breach",
            value=email,
            source="haveibeenpwned",
            target=email,
            confidence=0.6,
            metadata={"breached": breached}
        )

    # -------------------------
    # 3. HOLEHE CHECK
    # -------------------------
    def username_check(self, email):

        try:
            result = subprocess.run(
                ["holehe", email],
                capture_output=True,
                text=True,
                encoding="utf-8",
                errors="ignore"
            )

            platforms = set()   # ✅ FIX

            for line in result.stdout.split("\n"):
                if "[+]" in line:
                    site = line.replace("[+]", "").strip()

                    # ❌ filter garbage lines
                    if "Email used" in site or "Rate limit" in site:
                        continue

                    platforms.add(site)

            platforms = list(platforms)

        except:
            platforms = []

        return Finding(
            type="email_accounts",
            value=email,
            source="holehe",
            target=email,
            confidence=0.8,
            metadata={"accounts": platforms}
        )