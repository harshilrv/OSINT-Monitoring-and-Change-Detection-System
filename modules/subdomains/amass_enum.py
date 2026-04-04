import subprocess
from typing import List, Set

from core.base_module import BaseModule
from core.models import Finding


class AmassEnum(BaseModule):
    name = "amass_enum"
    supported_targets = ["domain"]

    def run(self, target: str) -> List[Finding]:

        amass_command = [
            "amass",
            "enum",
            "-passive",
            "-d",
            target
        ]

        try:
            result = subprocess.run(
                amass_command,
                capture_output=True,
                text=True
            )
        except FileNotFoundError:
            # Amass not installed → fail silently
            return []

        if result.returncode != 0:
            return []

        findings: List[Finding] = []
        seen: Set[str] = set()

        for line in result.stdout.splitlines():
            subdomain = line.strip().lower()

            if not subdomain:
                continue

            if not subdomain.endswith(target):
                continue

            if subdomain in seen:
                continue

            seen.add(subdomain)

            findings.append(
                Finding(
                    type="subdomain",
                    value=subdomain,
                    source="amass",
                    target=target,
                    confidence=0.7,
                    metadata={}
                )
            )

        return findings
