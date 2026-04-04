from typing import List
from core.models import Finding


def mark_verified(findings: List[Finding]) -> List[Finding]:

    for f in findings:

        http = f.metadata.get("http", {})

        if (
            f.metadata.get("resolves")
            and http.get("alive")
            and f.confidence >= 0.8
        ):
            f.metadata["verified"] = True
        else:
            f.metadata["verified"] = False

    return findings
