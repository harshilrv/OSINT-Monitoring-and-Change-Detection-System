from collections import defaultdict
from typing import List, Dict

from core.models import Finding


# -----------------------------
# Confidence merge logic
# -----------------------------

def merge_confidence(confidences: List[float]) -> float:
    """
    Merge multiple confidence scores.
    Boost when multiple sources agree.
    """

    if not confidences:
        return 0.0

    base = max(confidences)

    # boost per additional confirmation
    boost = 0.05 * (len(confidences) - 1)

    merged = base + boost

    return round(min(merged, 0.99), 2)


# -----------------------------
# Correlate findings
# -----------------------------

def correlate_findings(findings: List[Finding]) -> List[Finding]:

    grouped: Dict[tuple, List[Finding]] = defaultdict(list)

    for f in findings:
        key = (f.type, f.value, f.target)
        grouped[key].append(f)

    correlated: List[Finding] = []

    for (_, value, target), group in grouped.items():

        sources = sorted({f.source for f in group})

        confidences = [f.confidence for f in group]

        merged_confidence = merge_confidence(confidences)

        # merge metadata
        merged_metadata = {}

        for f in group:
            for k, v in f.metadata.items():
                merged_metadata.setdefault(k, []).append(v)

        # flatten single values
        for k, v in merged_metadata.items():
            if len(v) == 1:
                merged_metadata[k] = v[0]

        merged_metadata["sources"] = sources

        correlated.append(
            Finding(
                type=group[0].type,
                value=value,
                source=",".join(sources),
                target=target,
                confidence=merged_confidence,
                metadata=merged_metadata
            )
        )

    return correlated
