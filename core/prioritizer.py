from typing import List
from core.models import Finding


KEYWORD_SCORES = {
    "admin": 5,
    "login": 5,
    "auth": 5,
    "vpn": 5,
    "portal": 4,
    "dashboard": 4,
    "dev": 3,
    "test": 3,
    "staging": 3,
    "api": 3,
    "mail": 2,
    "ftp": 2,
    "db": 4,
    "internal": 4
}


def calculate_risk_score(f: Finding) -> int:

    score = 0
    value = f.value.lower()

    # keyword analysis
    for word, pts in KEYWORD_SCORES.items():
        if word in value:
            score += pts

    # confidence
    score += int(f.confidence * 3)

    # DNS
    if f.metadata.get("resolves"):
        score += 2

    # HTTP
    http = f.metadata.get("http", {})

    if http.get("alive"):
        score += 3

    status = http.get("status")

    if status == 200:
        score += 2
    elif status == 403:
        score += 4
    elif status == 401:
        score += 5

    # tech fingerprint
    server = (http.get("server") or "").lower()

    if "apache" in server or "nginx" in server:
        score += 1

    if "iis" in server:
        score += 2

    # multiple sources boost
    sources = f.metadata.get("sources", [])
    score += len(sources)

    return score


def prioritize_findings(findings: List[Finding]) -> List[Finding]:

    return sorted(
        findings,
        key=lambda f: calculate_risk_score(f),
        reverse=True
    )
