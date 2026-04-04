import subprocess
import json
from typing import List, Dict, Set

from core.base_module import BaseModule
from core.models import Finding


# ===================== SOURCE CONFIDENCE =====================

SOURCE_CONFIDENCE = {
    "crtsh": 0.9,
    "zone_transfer": 0.95,
    "dns_bruteforce": 0.95,
    "srv_record": 0.9,
    "reverse_dns": 0.85,
    "virustotal": 0.85,
    "alienvault": 0.85,
    "hackertarget": 0.8,
    "threatcrowd": 0.8,
    "urlscan": 0.75,
    "wayback": 0.7,
    "dnsdumpster": 0.75,
    "google": 0.6,
    "bing": 0.6,
    "yahoo": 0.6,
    "baidu": 0.6,
    "netcraft": 0.65,
    "subfinder": 0.7,
    "unknown": 0.5
}


# ===================== CONFIDENCE CALC =====================

def calculate_confidence(sources: Set[str]) -> float:
    scores = [
        SOURCE_CONFIDENCE.get(src.lower(), SOURCE_CONFIDENCE["unknown"])
        for src in sources
    ]

    if not scores:
        return SOURCE_CONFIDENCE["unknown"]

    base = max(scores)

    # small boost if multiple tools confirm
    if len(sources) > 1:
        base += 0.05 * (len(sources) - 1)

    return round(min(base, 0.95), 2)


# ===================== SUBFINDER MODULE =====================

class SubfinderEnum(BaseModule):
    name = "subfinder_enum"
    supported_targets = ["domain"]

    def run(self, target: str) -> List[Finding]:

        store: Dict[str, Set[str]] = {}

        cmd = [
            "subfinder",
            "-d", target,
            "-all",
            "-oJ",
            "-silent"
        ]

        try:
            result = subprocess.run(
                cmd,
                capture_output=True,
                text=True
            )
        except FileNotFoundError:
            # tool not installed → fail silently (engine safe)
            return []

        if result.returncode != 0:
            return []

        for line in result.stdout.splitlines():
            try:
                entry = json.loads(line)
            except json.JSONDecodeError:
                continue

            subdomain = entry.get("host")
            sources = entry.get("sources", [])

            if not subdomain:
                continue

            store.setdefault(subdomain, set()).update(sources)
            store[subdomain].add("subfinder")

        # ===================== BUILD FINDINGS =====================

        findings: List[Finding] = []

        for subdomain, sources in store.items():
            confidence = calculate_confidence(sources)

            findings.append(
                Finding(
                    type="subdomain",
                    value=subdomain.lower(),
                    source="subfinder",
                    target=target,
                    confidence=confidence,
                    metadata={
                        "sources": sorted(sources)
                    }
                )
            )

        return findings
