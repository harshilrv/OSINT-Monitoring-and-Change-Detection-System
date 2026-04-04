import requests
import hashlib
import re
from typing import List, Set

from core.base_module import BaseModule
from core.models import Finding


WAYBACK_CDX = "https://web.archive.org/cdx/search/cdx"


class WaybackEnum(BaseModule):
    name = "wayback_enum"
    supported_targets = ["domain"]

    def run(self, target: str) -> List[Finding]:

        findings: List[Finding] = []

        params = {
            "url": f"{target}/*",
            "output": "json",
            "fl": "timestamp,original",
            "collapse": "urlkey",
            "limit": 20
        }

        try:
            r = requests.get(WAYBACK_CDX, params=params, timeout=15)
            data = r.json()
        except Exception:
            return []

        if len(data) <= 1:
            return []

        snapshots = data[1:]  # skip header

        seen_subdomains: Set[str] = set()

        for timestamp, original_url in snapshots:

            snapshot_url = f"https://web.archive.org/web/{timestamp}/{original_url}"

            try:
                page = requests.get(snapshot_url, timeout=15)
                html = page.text
            except Exception:
                continue

            # --------------------
            # Content hash (for change detection)
            # --------------------

            content_hash = hashlib.sha256(
                html.encode(errors="ignore")
            ).hexdigest()

            # --------------------
            # Extract subdomains from HTML + URLs
            # --------------------

            pattern = rf"https?://([a-zA-Z0-9\.-]+\.{re.escape(target)})"
            matches = re.findall(pattern, html)

            for sub in matches:
                sub = sub.lower()

                if not sub.endswith(target):
                    continue

                if sub in seen_subdomains:
                    continue

                seen_subdomains.add(sub)

                findings.append(
                    Finding(
                        type="subdomain",
                        value=sub,
                        source="wayback",
                        target=target,
                        confidence=0.65,
                        metadata={
                            "snapshot": snapshot_url,
                            "timestamp": timestamp,
                            "content_hash": content_hash
                        }
                    )
                )

            # --------------------
            # Save page snapshot itself as finding (for change detection)
            # --------------------

            findings.append(
                Finding(
                    type="web_snapshot",
                    value=original_url,
                    source="wayback",
                    target=target,
                    confidence=0.7,
                    metadata={
                        "snapshot": snapshot_url,
                        "timestamp": timestamp,
                        "content_hash": content_hash
                    }
                )
            )

        return findings
