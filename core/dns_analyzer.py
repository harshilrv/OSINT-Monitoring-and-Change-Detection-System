import dns.resolver
from typing import List
from core.models import Finding


def resolve_domain(domain: str):
    """
    Robust DNS resolver with fallback nameservers.
    Tries:
    1. System resolver
    2. Google DNS (8.8.8.8)
    3. Cloudflare DNS (1.1.1.1)
    """

    # Try system resolver first
    try:
        answers = dns.resolver.resolve(domain, "A")
        return answers[0].to_text()
    except Exception:
        pass

    # Fallback to public resolvers
    for ns in ["8.8.8.8", "1.1.1.1"]:
        try:
            resolver = dns.resolver.Resolver()
            resolver.nameservers = [ns]
            resolver.timeout = 3
            resolver.lifetime = 3
            answers = resolver.resolve(domain, "A")
            return answers[0].to_text()
        except Exception:
            continue

    return None


def enrich_findings_dns(findings: List[Finding]) -> List[Finding]:
    """
    Adds DNS resolution info to findings metadata.

    metadata added:
        ip
        resolves (True/False)
    """

    for f in findings:

        if f.type != "subdomain":
            continue

        ip = resolve_domain(f.value)

        f.metadata["ip"] = ip
        f.metadata["resolves"] = bool(ip)

    return findings