from typing import List

from core.base_module import BaseModule
from core.models import Finding
from modules.subdomains.subdomain_enum import SubdomainEnumerator


class AdvancedSubdomainEnum(BaseModule):
    name = "advanced_subdomain_enum"
    supported_targets = ["domain"]

    def run(self, target: str) -> List[Finding]:
        enumerator = SubdomainEnumerator(
            domain=target,
            output_file=None,
            silent=True
        )

        findings = enumerator.run_enumeration()

        normalized: List[Finding] = []
        for f in findings:
            normalized.append(
                Finding(
                    type=f.type,
                    value=f.value,
                    source=f.source,
                    target=f.target,
                    confidence=f.confidence,
                    metadata=f.metadata
                )
            )

        return normalized
