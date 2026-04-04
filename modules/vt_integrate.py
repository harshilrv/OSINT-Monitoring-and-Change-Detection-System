import requests
import time
import os
from typing import List, Dict
from tqdm import tqdm
from dotenv import load_dotenv

load_dotenv()


class VirusTotalScanner:
    """
    VirusTotal integration for domain + subdomain reputation check
    Reads API key from .env automatically
    """

    def __init__(self):
        self.api_key = os.getenv("VT_API_KEY")
        self.base_url = "https://www.virustotal.com/api/v3/domains/"
        self.rate_limit_delay = 16  # Free API safe rate
        self.max_retries = 3
        self.retry_delay = 5

        if not self.api_key:
            print("[!] VT_API_KEY missing in .env")
            print("    Add: VT_API_KEY=xxxxxxxxxxxxxxxx")

    # ==============================
    # Extract subdomains
    # ==============================

    def extract_subdomains(self, findings) -> List[str]:
        subs = []

        for f in findings:
            if hasattr(f, "type") and f.type == "subdomain":
                subs.append(f.value)

            elif isinstance(f, dict) and f.get("type") == "subdomain":
                subs.append(f.get("value"))

        return list(set(subs))

    # ==============================
    # Query VirusTotal
    # ==============================

    def check_domain(self, domain, retry_count=0):

        if not self.api_key:
            return None

        headers = {"x-apikey": self.api_key}

        try:
            response = requests.get(
                self.base_url + domain,
                headers=headers,
                timeout=25
            )

            # Rate limit handling
            if response.status_code == 429:
                if retry_count < self.max_retries:
                    time.sleep(self.rate_limit_delay)
                    return self.check_domain(domain, retry_count + 1)
                return None

            if response.status_code == 404:
                return {
                    "domain": domain,
                    "status": "not_found",
                    "malicious": 0,
                    "suspicious": 0,
                    "harmless": 0,
                    "undetected": 0
                }

            if response.status_code != 200:
                return None

            data = response.json()
            stats = data["data"]["attributes"]["last_analysis_stats"]

            return {
                "domain": domain,
                "status": "success",
                "malicious": stats.get("malicious", 0),
                "suspicious": stats.get("suspicious", 0),
                "harmless": stats.get("harmless", 0),
                "undetected": stats.get("undetected", 0),
                "reputation": data["data"]["attributes"].get("reputation", 0)
            }

        except Exception:
            return None

    # ==============================
    # Full scan
    # ==============================

    def run_scan(self, main_domain, findings):

        if not self.api_key:
            print("[!] VirusTotal scan skipped (no API key)")
            return {}

        print("\n========= VIRUSTOTAL SCAN =========\n")

        subdomains = self.extract_subdomains(findings)
        targets = [main_domain] + subdomains

        results = []
        failed = []

        for domain in tqdm(targets, desc="VT scanning", unit="domain"):

            res = self.check_domain(domain)

            if res:
                results.append(res)
            else:
                failed.append(domain)

            time.sleep(self.rate_limit_delay)

        stats = self.generate_statistics(results, failed, len(targets))

        self.print_summary(results, stats, failed)

        return {
            "results": results,
            "statistics": stats,
            "failed": failed
        }

    # ==============================
    # Statistics
    # ==============================

    def generate_statistics(self, results, failed, total):

        stats = {
            "total_targets": total,
            "scanned": len(results),
            "failed": len(failed),
            "malicious": 0,
            "suspicious": 0,
            "clean": 0
        }

        for r in results:
            if r.get("malicious", 0) > 0:
                stats["malicious"] += 1
            elif r.get("suspicious", 0) > 0:
                stats["suspicious"] += 1
            else:
                stats["clean"] += 1

        return stats

    # ==============================
    # Print results
    # ==============================

    def print_summary(self, results, stats, failed):

        print("\n========= VT SUMMARY =========\n")

        print(f"Targets     : {stats['total_targets']}")
        print(f"Scanned     : {stats['scanned']}")
        print(f"Failed      : {stats['failed']}")
        print(f"Malicious   : {stats['malicious']}")
        print(f"Suspicious  : {stats['suspicious']}")
        print(f"Clean       : {stats['clean']}")

        if failed:
            print("\nFailed domains:")
            for d in failed:
                print(" -", d)
