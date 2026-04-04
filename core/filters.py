from typing import List
from core.models import Finding


def apply_filters(
    findings: List[Finding],
    only_live: bool = False,
    only_http: bool = False,
    only_verified: bool = False,
    min_confidence: float = 0.0
) -> List[Finding]:

    filtered = []

    for f in findings:

        # -------------------------
        # Confidence filter
        # -------------------------
        if f.confidence < min_confidence:
            continue

        # -------------------------
        # Verified filter
        # -------------------------
        if only_verified and not f.metadata.get("verified", False):
            continue

        # -------------------------
        # DNS live filter
        # -------------------------
        if only_live and not f.metadata.get("resolves", False):
            continue

        # -------------------------
        # HTTP alive filter
        # -------------------------
        if only_http and not f.metadata.get("http", {}).get("alive", False):
            continue

        filtered.append(f)

    return filtered