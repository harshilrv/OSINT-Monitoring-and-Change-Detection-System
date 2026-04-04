import time
import re
import socket
import json
from datetime import datetime
from typing import List, Dict, Optional

import requests
import dns.resolver

from core.models import Finding


class Colors:
    R = '\033[91m'
    G = '\033[92m'
    Y = '\033[93m'
    B = '\033[94m'
    W = '\033[0m'


class SubdomainEnumerator:
    def __init__(
        self,
        domain: str,
        output_file: Optional[str] = "subdomains.json",
        threads: int = 30,
        timeout: int = 5,
        verbose: bool = False,
        bruteforce: bool = True,
        engines: str = None,
        silent: bool = False
    ):
        self.domain = domain.lower().strip()
        self.output_file = output_file
        self.threads = threads
        self.timeout = timeout
        self.verbose = verbose
        self.enable_bruteforce = bruteforce
        self.engines = engines
        self.silent = silent

        self.findings: List[Finding] = []
        self.subdomains_seen = set()

        self.stats = {
            "passive_sources": 0,
            "dns_bruteforce": 0,
            "total_unique": 0
        }

        if self.output_file:
            self.db_path = output_file.replace(".json", ".db")
        else:
            self.db_path = None

    # -----------------------------
    # LOGGING (SILENT SAFE)
    # -----------------------------
    def log(self, msg: str, level: str = "INFO"):
        if self.silent:
            return

        if self.verbose or level in ["SUCCESS", "ERROR"]:
            ts = datetime.now().strftime("%H:%M:%S")
            print(f"[{ts}] [{level}] {msg}")

    # -----------------------------
    # CORE LOGIC
    # -----------------------------
    def add_finding(self, subdomain: str, source: str, confidence: float = 0.8):
        subdomain = subdomain.lower().strip().rstrip(".")

        if not subdomain.endswith(f".{self.domain}"):
            return

        if subdomain in self.subdomains_seen:
            return

        self.subdomains_seen.add(subdomain)

        finding = Finding(
            type="subdomain",
            value=subdomain,
            source=source,
            target=self.domain,
            confidence=confidence,
            metadata={}
        )

        self.findings.append(finding)
        self.log(f"Found {subdomain}", "SUCCESS")

    def passive_enum(self):
        try:
            url = f"https://api.hackertarget.com/hostsearch/?q={self.domain}"
            r = requests.get(url, timeout=self.timeout)
            for line in r.text.splitlines():
                if "," in line:
                    sub = line.split(",")[0]
                    self.add_finding(sub, "hackertarget", 0.85)
                    self.stats["passive_sources"] += 1
        except Exception:
            pass

    def dns_bruteforce(self):
        words = ["www", "mail", "ftp", "api", "dev"]
        for w in words:
            sub = f"{w}.{self.domain}"
            try:
                socket.gethostbyname(sub)
                self.add_finding(sub, "dns_bruteforce", 1.0)
                self.stats["dns_bruteforce"] += 1
            except Exception:
                pass

    # -----------------------------
    # MAIN ENTRY
    # -----------------------------
    def run_enumeration(self) -> List[Finding]:
        if not self.silent:
            print(f"\n{Colors.G}=== SUBDOMAIN ENUMERATION: {self.domain} ==={Colors.W}")

        self.passive_enum()

        if self.enable_bruteforce:
            self.dns_bruteforce()

        self.stats["total_unique"] = len(self.findings)

        if not self.silent and self.output_file:
            self.save_report()

        return self.findings

    # -----------------------------
    # REPORTING (DISABLED WHEN SILENT)
    # -----------------------------
    def save_report(self):
        if self.silent:
            return

        data = {
            "domain": self.domain,
            "count": len(self.findings),
            "findings": [f.__dict__ for f in self.findings]
        }

        with open(self.output_file, "w") as f:
            json.dump(data, f, indent=2)
